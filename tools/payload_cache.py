#!/usr/bin/env python3
"""Query and receive OpenPayload Cache messages for a DID.

Requires Python 3.10+ and cryptography. Cache proofs are signed locally; decrypted
bytes are acknowledged only after the selected output has been written.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import shutil
import ssl
import sys
import tarfile
import tempfile
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DIRECTORY = "https://directory.openpayload.io"
PROOF_VERSION = "openpayload:cache:retrieval-proof:v1"
ENCRYPTED = "openpayload:cbor-chunk:x25519-hkdf-sha256-chacha20poly1305:v1"
PLAINTEXT = "openpayload:plaintext-cbor:v1"
RECORD_FORMAT = "openpayload:binary-chunk:v1"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass(frozen=True)
class CacheTarget:
    service_id: str
    endpoint: str
    key_id: str


class CacheError(Exception):
    pass


def b58decode(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("z"):
        raise CacheError("verification public key is not Base58BTC multibase")
    number = 0
    for char in value[1:]:
        if char not in ALPHABET:
            raise CacheError("verification public key has invalid Base58BTC")
        number = number * 58 + ALPHABET.index(char)
    raw = b"\0" * (len(value[1:]) - len(value[1:].lstrip("1")))
    raw += number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return raw[2:] if raw.startswith(b"\xed\x01") else raw


def key_from_file(path: str, expected_type):
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, expected_type):
        raise CacheError(f"{path} is not a {expected_type.__name__} PEM private key")
    return key


def endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
        raise CacheError("Cache URL must be an HTTP(S) base URL without query or fragment")
    return value.rstrip("/")


def did_url(did: str, value: str) -> str:
    return did + value if value.startswith("#") else value


def request_json(url: str, *, headers=None, body=None, timeout=20, allow_insecure=False):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=data, headers={"Accept": "application/json", **(headers or {})},
                      method="POST" if body is not None else "GET")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        tls = {"context": ssl._create_unverified_context()} if allow_insecure else {}
        with urlopen(request, timeout=timeout, **tls) as response:
            result = json.load(response)
    except HTTPError as error:
        detail = error.read(2048).decode("utf-8", "replace")
        raise CacheError(f"HTTP {error.code} from {url}: {detail}") from error
    except (URLError, TimeoutError) as error:
        raise CacheError(f"request to {url} failed: {error}") from error
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CacheError(f"invalid JSON response from {url}") from error
    if not isinstance(result, dict):
        raise CacheError(f"non-object JSON response from {url}")
    return result


def discover(args, signing_key):
    if args.cache_url and args.service_id and args.key_id:
        if len(args.service_id) != 1:
            raise CacheError("direct Cache selection needs exactly one --service-id")
        service_id = did_url(args.did, args.service_id[0])
        key_id = did_url(args.did, args.key_id)
        return [CacheTarget(service_id, url, key_id)
                for url in dict.fromkeys(endpoint(value) for value in args.cache_url)]
    doc_result = request_json(args.directory_url.rstrip("/") + "/resolve/" + quote(args.did, safe=""),
                              timeout=args.timeout, allow_insecure=getattr(args, "allow_insecure", False))
    doc = doc_result.get("document")
    if not isinstance(doc, dict) or doc_result.get("deactivated") is True:
        raise CacheError("Directory did not return an active DID document")
    if doc.get("id") != args.did:
        raise CacheError("Directory returned a document for a different DID")
    signing_public = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    methods = {}
    for method in doc.get("verificationMethod", []):
        if isinstance(method, dict) and isinstance(method.get("id"), str):
            methods[did_url(args.did, method["id"])] = method
    authentication = {did_url(args.did, ref) for ref in doc.get("authentication", []) if isinstance(ref, str)}
    service_filters = {did_url(args.did, value) for value in args.service_id}
    url_filters = {endpoint(value) for value in args.cache_url}
    matches = []
    for service in doc.get("service", []):
        if not isinstance(service, dict) or service.get("type") != "OpenPayloadCacheService":
            continue
        service_id = did_url(args.did, service.get("id", ""))
        if service_filters and service_id not in service_filters:
            continue
        auth = service.get("authorization", [])
        if not isinstance(auth, list):
            continue
        authorized = []
        for ref in auth:
            if not isinstance(ref, str):
                continue
            key_id = did_url(args.did, ref)
            method = methods.get(key_id)
            if args.key_id and key_id != did_url(args.did, args.key_id):
                continue
            if authentication and key_id not in authentication:
                continue
            if method and method.get("type") == "Ed25519VerificationKey2020":
                try:
                    if b58decode(method.get("publicKeyMultibase")) == signing_public:
                        authorized.append(key_id)
                except CacheError:
                    pass
        if len(authorized) > 1 and not args.key_id:
            raise CacheError(f"multiple signing methods match {service_id}; choose --key-id")
        if not authorized:
            continue
        urls = service.get("serviceEndpoint", [])
        if isinstance(urls, str):
            urls = [urls]
        for raw_url in urls:
            if not isinstance(raw_url, str):
                continue
            url = endpoint(raw_url)
            if not url_filters or url in url_filters:
                matches.append(CacheTarget(service_id, url, authorized[0]))
    if not matches:
        raise CacheError("no published Cache service/endpoint authorizes the supplied signing key and filters")
    found_services = {target.service_id for target in matches}
    found_urls = {target.endpoint for target in matches}
    if service_filters - found_services or url_filters - found_urls:
        raise CacheError("a requested Cache service or URL is absent from the authorized DID document")
    # A node may be listed by more than one service. One valid proof per URL is enough.
    return list({target.endpoint: target for target in reversed(matches)}.values())


def proof(args, signing_key, target: CacheTarget, operation: str, subject: str):
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    nonce = str(uuid.uuid4())
    fields = [PROOF_VERSION, f"operation={operation}", f"did={args.did}",
              f"device_id={args.device_id or ''}", f"service_id={target.service_id}",
              f"cache_endpoint={target.endpoint}", f"key_id={target.key_id}",
              f"timestamp={timestamp}", f"nonce={nonce}", f"subject={subject}"]
    signature = base64.b64encode(signing_key.sign("\n".join(fields).encode("utf-8"))).decode("ascii")
    return {"did": args.did, "device_id": args.device_id or "", "service_id": target.service_id,
            "cache_endpoint": target.endpoint, "key_id": target.key_id, "timestamp": timestamp,
            "nonce": nonce, "signature_b64": signature}


def cache_request(args, signing_key, target, operation, subject, path, *, body=None):
    signed = proof(args, signing_key, target, operation, subject)
    headers = {"X-Recipient-DID": args.did, "X-Device-Id": signed["device_id"],
               "X-Service-Id": target.service_id, "X-Cache-Endpoint": target.endpoint,
               "X-Key-Id": target.key_id, "X-Timestamp": signed["timestamp"],
               "X-Nonce": signed["nonce"], "X-Signature": signed["signature_b64"]}
    return request_json(target.endpoint + path, headers=headers,
                        body=({**signed, **body} if body is not None else None), timeout=args.timeout,
                        allow_insecure=getattr(args, "allow_insecure", False))


def collect_summaries(args, signing_key, targets):
    entries = defaultdict(dict)
    errors = []
    per_cache = []
    path = "/cache/summary/" + quote(args.did, safe="")
    if args.device_id:
        path += "/" + quote(args.device_id, safe="")
    for target in targets:
        try:
            result = cache_request(args, signing_key, target, "summary", "*", path)
            messages = result.get("messages")
            if not isinstance(messages, list) or result.get("count") != len(messages):
                raise CacheError("invalid Cache summary response")
            for item in messages:
                if not isinstance(item, dict) or not isinstance(item.get("message_id"), str):
                    raise CacheError("invalid message in Cache summary")
                entries[item["message_id"]][target] = item
            per_cache.append({"service_id": target.service_id, "cache_url": target.endpoint,
                              "state": "available", "pending_messages": len(messages)})
        except CacheError as error:
            errors.append({"cache_url": target.endpoint, "state": "unavailable", "error": str(error)})
    return entries, per_cache, errors


def group_key(item):
    return item.get("message_group_id") or item["message_id"]


def parse_cbor(blob: bytes):
    def value(at, depth):
        if depth > 3 or at >= len(blob):
            raise CacheError("invalid CBOR record")
        lead = blob[at]
        major, additional = lead >> 5, lead & 31
        at += 1
        if additional < 24:
            size = additional
        elif additional in {24, 25, 26, 27}:
            width = {24: 1, 25: 2, 26: 4, 27: 8}[additional]
            if at + width > len(blob):
                raise CacheError("truncated CBOR length")
            size = int.from_bytes(blob[at:at + width], "big")
            at += width
        else:
            raise CacheError("unsupported CBOR value")
        if major == 0:
            return size, at
        if major in {2, 3}:
            if at + size > len(blob):
                raise CacheError("truncated CBOR value")
            chunk = blob[at:at + size]
            return (chunk if major == 2 else chunk.decode("utf-8")), at + size
        if major == 5 and size <= 32:
            result = {}
            for _ in range(size):
                key, at = value(at, depth + 1)
                item, at = value(at, depth + 1)
                if not isinstance(key, str) or key in result:
                    raise CacheError("invalid CBOR record key")
                result[key] = item
            return result, at
        raise CacheError("unsupported CBOR record type")
    decoded, offset = value(0, 0)
    if offset != len(blob) or not isinstance(decoded, dict):
        raise CacheError("invalid CBOR record framing")
    return decoded


def decode_entry(entry, decryption_key, did):
    envelope = entry.get("envelope")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
        raise CacheError("Cache returned an invalid envelope")
    payload = envelope["payload"]
    profile = payload.get("profile")
    if profile == PLAINTEXT:
        try:
            raw = base64.b64decode(payload["cbor_b64"], validate=True)
        except (KeyError, ValueError, binascii.Error) as error:
            raise CacheError("invalid plaintext CBOR payload") from error
    elif profile == ENCRYPTED:
        if decryption_key is None:
            raise CacheError("encrypted message requires --decryption-key-file")
        message_id = envelope.get("message_id")
        group_id = envelope.get("message_group_id") or ""
        index = envelope.get("sequence_number") or 0
        total = envelope.get("total_chunks") or 1
        aad = f"{ENCRYPTED}|{message_id}|{did}|{group_id}|{index}|{total}".encode("utf-8")
        try:
            peer = X25519PublicKey.from_public_bytes(base64.b64decode(payload["ephemeral_x25519_b64"], validate=True))
            nonce = base64.b64decode(payload["nonce_b64"], validate=True)
            ciphertext = base64.b64decode(payload["ciphertext_b64"], validate=True)
            shared = decryption_key.exchange(peer)
            key = HKDF(algorithm=hashes.SHA256(), length=32,
                       salt=hashlib.sha256(aad).digest(), info=ENCRYPTED.encode("utf-8")).derive(shared)
            raw = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
        except (KeyError, ValueError, binascii.Error, InvalidTag) as error:
            raise CacheError("message decryption failed or encrypted payload is invalid") from error
    else:
        raise CacheError(f"unsupported payload profile: {profile}")
    record = parse_cbor(raw)
    if record.get("format") != RECORD_FORMAT or not isinstance(record.get("data"), bytes):
        raise CacheError("unexpected CBOR record format")
    if record.get("message_group_id") != (envelope.get("message_group_id") or ""):
        raise CacheError("CBOR group does not match envelope")
    if record.get("sequence_number") != (envelope.get("sequence_number") or 0):
        raise CacheError("CBOR sequence does not match envelope")
    if record.get("total_chunks") != (envelope.get("total_chunks") or 1):
        raise CacheError("CBOR total does not match envelope")
    return record


def download_group(args, signing_key, target, metadata, decryption_key):
    first = metadata[0]
    gid = first.get("message_group_id")
    if gid:
        path = "/cache/chunks/" + quote(args.did, safe="") + "/" + quote(gid, safe="")
        result = cache_request(args, signing_key, target, "chunks", gid, path)
        if result.get("complete") is not True:
            raise CacheError("Cache chunk set is incomplete")
        entries = result.get("chunks")
    else:
        mid = first["message_id"]
        path = "/cache/message/" + quote(args.did, safe="") + "/" + quote(mid, safe="")
        result = cache_request(args, signing_key, target, "pull_message", mid, path)
        if result.get("state") != "active":
            raise CacheError(f"Cache message state is {result.get('state')}")
        entries = [result.get("message")]
    if not isinstance(entries, list) or not entries:
        raise CacheError("Cache returned no messages")
    records = [decode_entry(entry, decryption_key, args.did) for entry in entries]
    if any(not isinstance(record.get("sequence_number"), int) for record in records):
        raise CacheError("invalid CBOR sequence")
    records.sort(key=lambda record: record["sequence_number"])
    expected_ids = {item["message_id"] for item in metadata}
    actual_ids = {entry.get("message_id") for entry in entries if isinstance(entry, dict)}
    if expected_ids != actual_ids:
        raise CacheError("Cache group IDs differ from summary")
    total = records[0].get("total_chunks")
    if not isinstance(total, int) or len(records) != total or [r.get("sequence_number") for r in records] != list(range(total)):
        raise CacheError("Cache returned an incomplete or duplicate chunk set")
    expected = {key: records[0].get(key) for key in ("name", "media_type", "size_bytes", "sha256", "message_group_id")}
    if any(any(record.get(key) != value for key, value in expected.items()) for record in records):
        raise CacheError("chunk metadata differs within one payload")
    data = b"".join(record["data"] for record in records)
    if expected["size_bytes"] != len(data) or expected["sha256"] != hashlib.sha256(data).digest():
        raise CacheError("payload size or SHA-256 does not match")
    name = expected["name"]
    if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name or "\\" in name or "\0" in name:
        raise CacheError("unsafe payload file name")
    return name, data, sorted(actual_ids)


def ack_group(args, signing_key, copies, message_ids):
    errors = []
    ids = sorted(set(message_ids))
    for target, present in copies.items():
        selected = sorted(set(present) & set(ids))
        if not selected:
            continue
        try:
            cache_request(args, signing_key, target, "ack", ",".join(selected), "/cache/ack",
                          body={"message_ids": selected})
        except CacheError as error:
            errors.append({"cache_url": target.endpoint, "error": f"acknowledgement failed: {error}"})
    return errors


def purge(args, signing_key, entries, per_cache, errors):
    selected = sorted(entries) if args.all else ([args.message_id] if args.message_id in entries else [])
    copies = sum(len(entries[mid]) for mid in selected)
    if errors:
        report({"status": "failed", "would_purge": len(selected),
                "would_purge_copies": copies, "errors": errors})
        return 1
    if args.all and not args.force:
        report({"status": "preview", "would_purge": len(selected),
                "would_purge_copies": copies, "message_ids": selected,
                "caches": per_cache, "errors": []})
        return 0
    if not selected:
        report({"status": "absent", "purged": 0, "purged_copies": 0,
                "message_ids": [], "errors": []})
        return 0
    if args.message_id and not args.confirm:
        if not sys.stdin.isatty():
            raise CacheError("purge --message-id requires an interactive terminal or --confirm")
        sys.stderr.write(f"Permanently delete {args.message_id} from {copies} Cache node(s) "
                         "without download or recovery? Type yes to continue: ")
        sys.stderr.flush()
        if sys.stdin.readline().strip() != "yes":
            report({"status": "cancelled", "purged": 0, "message_ids": [], "errors": []})
            return 0
    by_target = defaultdict(list)
    for mid in selected:
        for target in entries[mid]:
            by_target[target].append(mid)
    removed = set()
    removed_copies = 0
    node_results = []
    ack_errors = []
    for target in sorted(by_target, key=lambda item: (item.endpoint, item.service_id)):
        ids = sorted(by_target[target])
        try:
            result = cache_request(args, signing_key, target, "ack", ",".join(ids), "/cache/ack",
                                   body={"message_ids": ids})
            acknowledged = result.get("message_ids")
            if (not isinstance(acknowledged, list) or
                    not all(isinstance(mid, str) for mid in acknowledged) or
                    isinstance(result.get("acked"), bool) or
                    not isinstance(result.get("acked"), int) or
                    result["acked"] != len(acknowledged) or
                    len(set(acknowledged)) != len(acknowledged) or
                    not set(acknowledged).issubset(ids)):
                raise CacheError("Cache returned an invalid acknowledgement response")
            removed.update(acknowledged)
            removed_copies += len(acknowledged)
            node_results.append({"cache_url": target.endpoint, "acked": len(acknowledged),
                                 "message_ids": acknowledged})
            missing = sorted(set(ids) - set(acknowledged))
            if missing:
                ack_errors.append({"cache_url": target.endpoint,
                                   "error": "Cache did not acknowledge requested message IDs",
                                   "message_ids": missing})
        except CacheError as error:
            ack_errors.append({"cache_url": target.endpoint, "error": str(error)})
    report({"status": "purged" if not ack_errors else "partial",
            "purged": len(removed), "purged_copies": removed_copies,
            "message_ids": sorted(removed), "caches": node_results, "errors": ack_errors})
    return 1 if ack_errors else 0


def report(result, *, data_stdout=False):
    stream = sys.stderr if data_stdout else sys.stdout
    stream.write(json.dumps(result, separators=(",", ":")) + "\n")
    stream.flush()


def copy_exclusive(source, destination: Path):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        source.seek(0)
        shutil.copyfileobj(source, output, 1024 * 1024)
        output.flush()
        os.fsync(output.fileno())


def stream_stdout(source):
    source.seek(0)
    shutil.copyfileobj(source, sys.stdout.buffer, 1024 * 1024)
    sys.stdout.buffer.flush()


def run(args):
    signing_key = key_from_file(args.signing_key_file, Ed25519PrivateKey)
    targets = discover(args, signing_key)
    entries, per_cache, errors = collect_summaries(args, signing_key, targets)
    if args.command == "purge":
        return purge(args, signing_key, entries, per_cache, errors)
    decryption_key = (key_from_file(args.decryption_key_file, X25519PrivateKey)
                      if args.decryption_key_file else None)
    groups = defaultdict(dict)
    for mid, copies in entries.items():
        for target, item in copies.items():
            key = group_key(item)
            groups[key].setdefault(target, []).append(item)
    if args.command == "query":
        if args.message_id:
            copies = entries.get(args.message_id, {})
            result = {"message_id": args.message_id, "state": "active" if copies else "absent",
                      "cache_urls": sorted(target.endpoint for target in copies), "errors": errors}
        else:
            result = {"pending_messages": len(entries), "pending_payloads": len(groups),
                      "message_ids": sorted(entries),
                      "caches": per_cache, "errors": errors}
        report(result)
        return 1 if errors else 0
    if args.message_id:
        selected = [key for key, copies in groups.items()
                    if any(args.message_id in {item["message_id"] for item in items}
                           for items in copies.values())]
    else:
        selected = sorted(groups)
    if not selected:
        report({"received": 0, "errors": errors, "message_id": args.message_id})
        return 1 if errors else 0
    should_acknowledge = args.output != "-" or args.acknowledge
    if args.output_dir and args.message_id:
        raise CacheError("--output-dir is for --all only")
    if args.output_dir and not Path(args.output_dir).is_dir():
        raise CacheError("--output-dir must name an existing directory")
    with tempfile.TemporaryDirectory(prefix="openpayload-cache-") as temporary:
        prepared = []
        for key in selected:
            copies = groups[key]
            for target, metadata in copies.items():
                try:
                    name, data, ids = download_group(args, signing_key, target, metadata, decryption_key)
                    part_path = Path(temporary) / f"{len(prepared)}.bin"
                    part_path.write_bytes(data)
                    prepared.append((key, name, part_path, ids, copies))
                    break
                except CacheError as error:
                    errors.append({"cache_url": target.endpoint, "group": key, "error": str(error)})
        if not prepared:
            report({"received": 0, "errors": errors})
            return 1
        if args.output_dir:
            outdir = Path(args.output_dir)
            for key, name, part_path, ids, copies in prepared:
                destination = outdir / name
                if destination.exists():
                    destination = outdir / (Path(name).stem + "-" + key + Path(name).suffix)
                with part_path.open("rb") as source:
                    copy_exclusive(source, destination)
                errors.extend(ack_group(args, signing_key,
                              {t: [item["message_id"] for item in items] for t, items in copies.items()}, ids))
        elif args.message_id:
            _, _, part_path, ids, copies = prepared[0]
            with part_path.open("rb") as source:
                if args.output == "-":
                    stream_stdout(source)
                else:
                    copy_exclusive(source, Path(args.output))
            if should_acknowledge:
                errors.extend(ack_group(args, signing_key,
                              {t: [item["message_id"] for item in items] for t, items in copies.items()}, ids))
        else:
            with tempfile.TemporaryFile(mode="w+b") as archive:
                with tarfile.open(fileobj=archive, mode="w") as tar:
                    used = set()
                    for key, name, part_path, _, _ in prepared:
                        if name in used:
                            name = Path(name).stem + "-" + key + Path(name).suffix
                        used.add(name)
                        info = tarfile.TarInfo(name)
                        info.size = part_path.stat().st_size
                        with part_path.open("rb") as source:
                            tar.addfile(info, source)
                if args.output == "-":
                    stream_stdout(archive)
                else:
                    copy_exclusive(archive, Path(args.output))
            if should_acknowledge:
                for _, _, _, ids, copies in prepared:
                    errors.extend(ack_group(args, signing_key,
                                  {t: [item["message_id"] for item in items] for t, items in copies.items()}, ids))
        result = {"received": len(prepared),
                  "message_ids": sorted({mid for _, _, _, ids, _ in prepared for mid in ids}),
                  "output": args.output_dir or args.output,
                  "acknowledgement_requested": should_acknowledge, "errors": errors}
        report(result, data_stdout=args.output == "-")
        return 1 if errors or len(prepared) != len(selected) else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("query", "receive", "purge"):
        purge_help = "Delete cached messages without downloading them; deletion cannot be recovered"
        p = sub.add_parser(command, help=purge_help if command == "purge" else None,
                           description=purge_help if command == "purge" else None)
        p.add_argument("--did", required=True)
        p.add_argument("--directory-url", default=DIRECTORY)
        p.add_argument("--allow-insecure", action="store_true",
                       help="Skip Directory and Cache TLS certificate verification for CLI testing")
        p.add_argument("--signing-key-file", required=True, help="Ed25519 PEM private key")
        if command != "purge":
            p.add_argument("--decryption-key-file", help="X25519 PEM private key for encrypted payloads")
        p.add_argument("--service-id", action="append", default=[], help="select a published CacheService; repeatable")
        p.add_argument("--cache-url", action="append", default=[], help="select a published Cache endpoint; repeatable")
        p.add_argument("--key-id", help="authorized verification method ID")
        p.add_argument("--device-id")
        p.add_argument("--timeout", type=float, default=20)
        if command == "query":
            p.add_argument("--message-id", help="query one message ID")
        if command == "receive":
            mode = p.add_mutually_exclusive_group(required=True)
            mode.add_argument("--all", action="store_true")
            mode.add_argument("--message-id", help="receive one payload by message ID")
            p.add_argument("--output", default="-", help="file path, or - for stdout")
            p.add_argument("--output-dir", help="write each bulk payload separately")
            p.add_argument("--acknowledge", action="store_true",
                           help="acknowledge stdout payloads after streaming; files are always acknowledged after saving")
        if command == "purge":
            mode = p.add_mutually_exclusive_group(required=True)
            mode.add_argument("--message-id", help="delete one exact message ID without downloading it")
            mode.add_argument("--all", action="store_true", help="preview deletion of all pending message IDs")
            p.add_argument("--confirm", action="store_true",
                           help="delete --message-id without an interactive confirmation prompt")
            p.add_argument("--force", action="store_true",
                           help="delete --all without a preview; messages cannot be recovered")
    args = parser.parse_args(argv)
    try:
        if args.timeout <= 0:
            raise CacheError("--timeout must be positive")
        if args.command == "purge" and (args.confirm and args.all or args.force and args.message_id):
            raise CacheError("--confirm applies only to --message-id; --force applies only to --all")
        if args.command == "receive" and args.output_dir:
            if args.output != "-":
                raise CacheError("--output and --output-dir cannot be combined")
            args.output = None
        return run(args)
    except (CacheError, OSError, ValueError, TypeError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
