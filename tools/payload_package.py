#!/usr/bin/env python3
"""Package arbitrary input as CBOR records in JSON DDN envelopes.

The output is newline-delimited JSON: one complete Relay envelope per line.
Encryption is the default and requires ``cryptography``. Python 3.10 or newer.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROFILE = "openpayload:cbor-chunk:x25519-hkdf-sha256-chacha20poly1305:v1"
PLAINTEXT_PROFILE = "openpayload:plaintext-cbor:v1"
RECORD_FORMAT = "openpayload:binary-chunk:v1"
DEFAULT_DIRECTORY = "https://directory.openpayload.io"
DEFAULT_CHUNK_BYTES = 1024 * 1024
NETWORK_CHUNK_BYTES = 2 * 1024 * 1024
NETWORK_MESSAGE_BYTES = 16 * 1024 * 1024
NETWORK_HTTP_BYTES = 25 * 1024 * 1024
SAFETY_MARGIN = 4096
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def cbor_head(major: int, length: int) -> bytes:
    if length < 0 or length >= 2**64:
        raise ValueError("CBOR length is out of range")
    lead = major << 5
    if length < 24:
        return bytes([lead | length])
    if length < 256:
        return bytes([lead | 24, length])
    if length < 65536:
        return bytes([lead | 25]) + length.to_bytes(2, "big")
    if length < 2**32:
        return bytes([lead | 26]) + length.to_bytes(4, "big")
    return bytes([lead | 27]) + length.to_bytes(8, "big")


def cbor_encode(value) -> bytes:
    """Encode only the RFC 8949 types used by this fixed record schema."""
    if isinstance(value, bytes):
        return cbor_head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return cbor_head(3, len(data)) + data
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return cbor_head(0, value)
    if isinstance(value, dict):
        pairs = [(cbor_encode(key), cbor_encode(item)) for key, item in value.items()]
        pairs.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return cbor_head(5, len(pairs)) + b"".join(key + item for key, item in pairs)
    raise TypeError(f"unsupported CBOR value: {type(value).__name__}")


def decode_x25519_multibase(value: str) -> bytes:
    if not value.startswith("z"):
        raise ValueError("recipient key must be Base58BTC multibase (z...)")
    number = 0
    for char in value[1:]:
        if char not in ALPHABET:
            raise ValueError("recipient key contains a non-Base58BTC character")
        number = number * 58 + ALPHABET.index(char)
    raw = b"\0" * (len(value[1:]) - len(value[1:].lstrip("1")))
    raw += number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    if len(raw) == 34 and raw[:2] == b"\xec\x01":
        raw = raw[2:]
    if len(raw) != 32:
        raise ValueError("recipient X25519 public key must contain 32 bytes")
    X25519PublicKey.from_public_bytes(raw)
    return raw


def positive_limit(constraints: dict, name: str, ceiling: int) -> int:
    value = constraints.get(name, ceiling)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"Directory returned invalid {name}")
    return min(value, ceiling)


def resolve_recipient(args) -> tuple[str, bytes, dict]:
    if args.recipient_key or args.recipient_key_id:
        if not (args.recipient_key and args.recipient_key_id):
            raise ValueError("--recipient-key and --recipient-key-id must be supplied together")
        return args.recipient_key_id, decode_x25519_multibase(args.recipient_key), {}
    path = "/delivery-resolution/" + quote(args.to, safe="")
    if args.tag:
        path += "?" + urlencode({"tag": args.tag})
    url = args.directory_url.rstrip("/") + path
    if not url.startswith(("https://", "http://")):
        raise ValueError("--directory-url must be an HTTP(S) URL")
    try:
        tls = {"context": ssl._create_unverified_context()} if getattr(args, "allow_insecure", False) else {}
        with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=20, **tls) as response:
            result = json.load(response)
    except HTTPError as error:
        try:
            detail = error.read(1024).decode("utf-8", "replace")
        finally:
            error.close()
        raise ValueError(f"Directory returned HTTP {error.code}: {detail}") from error
    except (URLError, TimeoutError) as error:
        raise ValueError(f"Directory request failed: {error}") from error
    if not isinstance(result, dict):
        raise ValueError("Directory response is not a JSON object")
    if result.get("encryption_profile") != "direct":
        raise ValueError("recipient requires a delivery encryption profile this tool does not support")
    if result.get("target") != args.to:
        raise ValueError("Directory returned a different delivery target")
    key_id = result.get("recipient_key_id")
    key_value = result.get("recipient_public_key_multibase")
    if not isinstance(key_id, str) or not key_id or not isinstance(key_value, str):
        raise ValueError("Directory response has no recipient agreement key")
    policy = result.get("policy") or {}
    if not isinstance(policy, dict):
        raise ValueError("Directory returned invalid delivery policy")
    constraints = policy.get("effective_constraints") or {}
    if not isinstance(constraints, dict):
        raise ValueError("Directory returned invalid delivery constraints")
    return key_id, decode_x25519_multibase(key_value), constraints


def aad_bytes(message_id: str, target: str, group_id: str, index: int, total: int) -> bytes:
    return f"{PROFILE}|{message_id}|{target}|{group_id}|{index}|{total}".encode("utf-8")


def seal(record: dict, recipient_key: bytes, key_id: str, message_id: str,
         target: str, group_id: str, index: int, total: int) -> dict:
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_key))
    aad = aad_bytes(message_id, target, group_id, index, total)
    key = HKDF(algorithm=hashes.SHA256(), length=32,
               salt=hashlib.sha256(aad).digest(), info=PROFILE.encode("utf-8")).derive(shared)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, cbor_encode(record), aad)
    from cryptography.hazmat.primitives import serialization
    ephemeral_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "profile": PROFILE,
        "key_id": key_id,
        "ephemeral_x25519_b64": base64.b64encode(ephemeral_public).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }


def plaintext_payload(record: dict) -> dict:
    return {
        "profile": PLAINTEXT_PROFILE,
        "cbor_b64": base64.b64encode(cbor_encode(record)).decode("ascii"),
    }


def spool_input(path: str | None):
    """Take a stable snapshot and hash it before any envelope reaches the pipe."""
    source = open(path, "rb") if path else sys.stdin.buffer
    digest = hashlib.sha256()
    size = 0
    try:
        with tempfile.TemporaryFile(mode="w+b") as spool:
            while True:
                part = source.read(1024 * 1024)
                if not part:
                    break
                size += len(part)
                digest.update(part)
                spool.write(part)
            spool.seek(0)
            yield spool, size, digest.digest()
    finally:
        if path:
            source.close()


def package(args, output) -> int:
    if args.plaintext:
        if args.recipient_key or args.recipient_key_id:
            raise ValueError("recipient encryption key options cannot be used with --plaintext")
        key_id, recipient_key, constraints = None, None, {}
    else:
        key_id, recipient_key, constraints = resolve_recipient(args)
    max_unchunked = positive_limit(constraints, "max_unchunked_message_bytes", NETWORK_MESSAGE_BYTES)
    max_chunk = positive_limit(constraints, "max_chunk_bytes", NETWORK_CHUNK_BYTES)
    max_http = positive_limit(constraints, "max_http_envelope_bytes", NETWORK_HTTP_BYTES)
    # In plaintext mode the Relay counts the Base64 JSON size, since there is
    # no ciphertext_b64 field. Keep room for CBOR metadata and JSON framing.
    if args.plaintext:
        payload_unchunked_limit = (max_unchunked - SAFETY_MARGIN) * 3 // 4
        payload_chunk_limit = (max_chunk - SAFETY_MARGIN) * 3 // 4
    else:
        payload_unchunked_limit = max_unchunked - SAFETY_MARGIN
        payload_chunk_limit = max_chunk - SAFETY_MARGIN
    max_unchunked_plain = min(payload_unchunked_limit, (max_http - 8192) * 3 // 4)
    max_chunk_plain = min(args.chunk_size, payload_chunk_limit,
                          (max_http - 8192) * 3 // 4)
    if min(max_unchunked_plain, max_chunk_plain) <= 0:
        raise ValueError("recipient delivery limits are too small for this envelope format")
    name = args.name if args.name is not None else (Path(args.input).name if args.input else "stdin")
    if not name or len(name.encode("utf-8")) > 255 or "/" in name or "\\" in name:
        raise ValueError("--name must be a file name of at most 255 UTF-8 bytes")
    if not args.mime_type or len(args.mime_type.encode("utf-8")) > 255:
        raise ValueError("--mime-type must be 1-255 UTF-8 bytes")
    for spool, size, digest in spool_input(args.input):
        max_aggregate = constraints.get("max_message_bytes")
        if max_aggregate is not None and (not isinstance(max_aggregate, int) or size > max_aggregate):
            raise ValueError("file exceeds recipient's aggregate message limit")
        chunked = size > max_unchunked_plain
        part_size = max_chunk_plain if chunked else max(size, 1)
        total = max(1, (size + part_size - 1) // part_size)
        max_chunks = constraints.get("max_chunks")
        if max_chunks is not None and (not isinstance(max_chunks, int) or total > max_chunks):
            raise ValueError("file exceeds recipient's maximum chunk count")
        group_id = str(uuid.uuid4()) if chunked else ""
        created = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for index in range(total):
            part = spool.read(part_size)
            record = {
                "format": RECORD_FORMAT,
                "name": name,
                "media_type": args.mime_type,
                "size_bytes": size,
                "sha256": digest,
                "message_group_id": group_id,
                "sequence_number": index,
                "total_chunks": total,
                "data": part,
            }
            message_id = str(uuid.uuid4())
            envelope = {
                "message_id": message_id,
                "to": args.to,
                "timestamp": created,
                "ttl": args.ttl,
                "delivery_hint": "chunked" if chunked else "standard",
                "payload": (plaintext_payload(record) if args.plaintext else
                            seal(record, recipient_key, key_id, message_id,
                                 args.to, group_id, index, total)),
            }
            if args.tag:
                envelope["tag"] = args.tag
            if chunked:
                envelope.update(message_group_id=group_id,
                                sequence_number=index, total_chunks=total)
            line = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if len(line) > max_http:
                raise ValueError("generated envelope exceeds recipient's HTTP size limit")
            if args.plaintext:
                payload_size = len(json.dumps(envelope["payload"], separators=(",", ":")).encode("utf-8"))
            else:
                payload_size = len(base64.b64decode(envelope["payload"]["ciphertext_b64"]))
            if payload_size > (max_chunk if chunked else max_unchunked):
                raise ValueError("generated payload exceeds recipient's payload limit")
            output.write(line + b"\n")
        return total
    raise AssertionError("input snapshot was not created")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--to", required=True, help="Full recipient DID")
    parser.add_argument("--input", help="Binary file; omit to read standard input")
    parser.add_argument("--output", help="Write envelope JSONL to this new file instead of stdout")
    parser.add_argument("--directory-url", default=DEFAULT_DIRECTORY)
    parser.add_argument("--allow-insecure", action="store_true",
                        help="Skip Directory TLS certificate verification for CLI testing")
    parser.add_argument("--recipient-key", help="Offline recipient X25519 multibase public key")
    parser.add_argument("--recipient-key-id", help="Key ID paired with --recipient-key")
    parser.add_argument("--plaintext", action="store_true",
                        help="Do not encrypt; expose CBOR content as Base64 in the JSON envelope")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_BYTES,
                        help="Maximum source bytes per chunk (default: 1 MiB)")
    parser.add_argument("--name", help="File name stored inside the CBOR record")
    parser.add_argument("--mime-type", default="application/octet-stream")
    parser.add_argument("--tag", help="Optional public delivery policy tag")
    parser.add_argument("--ttl", default="24h")
    args = parser.parse_args(argv)
    try:
        if not args.to.startswith("did:openpayload:") or "@" in args.to:
            raise ValueError("--to must be a full DID; Persona delivery is not supported")
        if args.chunk_size <= 0:
            raise ValueError("--chunk-size must be positive")
        if args.plaintext:
            print("payload_package: warning: plaintext mode exposes file contents", file=sys.stderr)
        if args.output:
            created = False
            try:
                with open(args.output, "xb") as output:
                    created = True
                    package(args, output)
            except BaseException:
                if created:
                    Path(args.output).unlink(missing_ok=True)
                raise
        else:
            package(args, sys.stdout.buffer)
        return 0
    except (BrokenPipeError, KeyboardInterrupt):
        return 1
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"payload_package: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
