#!/usr/bin/env python3
"""Read newline-delimited DDN envelopes from a file or stdin and send them to a Relay.

One JSON line is one HTTP POST. The complete stream is checked before network activity.
Python 3.10 or newer; standard library only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import secrets
import ssl
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

MAX_LINE_BYTES = 25 * 1024 * 1024
RETRY_STATUSES = {429, 502, 503, 507}
ENCRYPTED_PROFILE = "openpayload:cbor-chunk:x25519-hkdf-sha256-chacha20poly1305:v1"
PLAINTEXT_PROFILE = "openpayload:plaintext-cbor:v1"


class SendFailure(Exception):
    def __init__(self, message: str, *, status: int | None = None, response=None):
        super().__init__(message)
        self.status = status
        self.response = response


def relay_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("--relay-url must be an HTTP(S) base URL without query or fragment")
    path = parsed.path.rstrip("/")
    if not path.endswith("/relay"):
        path += "/relay"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def load_stream(source, spool, allow_plaintext: bool = False) -> tuple[int, str | None, str, bool]:
    """Validate framing and assured set before submitting any part of it."""
    count = 0
    group = None
    target = None
    declared_total = None
    seen_ids = set()
    plaintext = None
    while True:
        line = source.readline(MAX_LINE_BYTES + 2)
        if not line:
            break
        if len(line) > MAX_LINE_BYTES + 1 or (len(line) == MAX_LINE_BYTES + 1 and not line.endswith(b"\n")):
            raise ValueError("JSON envelope line exceeds 25 MiB")
        body = line.rstrip(b"\r\n")
        if not body:
            raise ValueError(f"blank line at envelope {count + 1}")
        if len(body) > MAX_LINE_BYTES:
            raise ValueError("JSON envelope line exceeds 25 MiB")
        try:
            envelope = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid JSON at envelope {count + 1}: {error}") from error
        if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
            raise ValueError(f"envelope {count + 1} must contain a payload object")
        payload = envelope["payload"]
        profile = payload.get("profile")
        if profile == PLAINTEXT_PROFILE:
            if not allow_plaintext:
                raise ValueError("plaintext envelope requires --allow-plaintext")
            encoded = payload.get("cbor_b64")
            if not isinstance(encoded, str) or "ciphertext_b64" in payload:
                raise ValueError("invalid plaintext CBOR payload")
            try:
                base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError("invalid plaintext CBOR Base64") from error
            current_plaintext = True
        elif profile == ENCRYPTED_PROFILE and isinstance(payload.get("ciphertext_b64"), str):
            if "cbor_b64" in payload:
                raise ValueError("encrypted payload contains plaintext CBOR")
            current_plaintext = False
        else:
            raise ValueError("unsupported payload profile")
        if plaintext is None:
            plaintext = current_plaintext
        elif plaintext != current_plaintext:
            raise ValueError("encrypted and plaintext envelopes cannot share a stream")
        message_id = envelope.get("message_id")
        try:
            uuid.UUID(message_id)
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError(f"envelope {count + 1} has no valid message_id") from error
        if message_id in seen_ids:
            raise ValueError("message_id is repeated in the input stream")
        seen_ids.add(message_id)
        recipient = envelope.get("to") or envelope.get("recipient")
        if not isinstance(recipient, str) or not recipient:
            raise ValueError(f"envelope {count + 1} has no recipient")
        if target is None:
            target = recipient
        elif target != recipient:
            raise ValueError("all envelopes in one stream must have the same recipient")
        fields = ("message_group_id", "sequence_number", "total_chunks")
        present = [field in envelope for field in fields]
        if any(present) and not all(present):
            raise ValueError("chunk envelopes need group ID, sequence number, and total count")
        if all(present):
            current_group = envelope["message_group_id"]
            index = envelope["sequence_number"]
            total = envelope["total_chunks"]
            try:
                uuid.UUID(current_group)
            except (ValueError, TypeError, AttributeError) as error:
                raise ValueError("invalid message_group_id") from error
            if (not isinstance(index, int) or isinstance(index, bool) or
                    not isinstance(total, int) or isinstance(total, bool) or
                    index != count or total <= 0 or index >= total):
                raise ValueError("chunk sequences must be consecutive, starting at zero")
            if count == 0:
                group, declared_total = current_group, total
            elif group != current_group or declared_total != total:
                raise ValueError("chunk group or total changed within the stream")
        elif group is not None or count > 0:
            raise ValueError("a stream must contain one unchunked envelope or one chunk set")
        spool.write(body + b"\n")
        count += 1
    if count == 0:
        raise ValueError("input contains no envelopes")
    if group is not None and count != declared_total:
        raise ValueError(f"incomplete chunk set: expected {declared_total}, found {count}")
    spool.seek(0)
    return count, group, target, plaintext


def parse_response(raw: bytes):
    try:
        return json.loads(raw) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"message": raw[:1000].decode("utf-8", "replace")}


def post(endpoint: str, body: bytes, timeout: float, max_retries: int, *, allow_insecure=False):
    for attempt in range(max_retries + 1):
        request = Request(endpoint, data=body, method="POST",
                          headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            tls = {"context": ssl._create_unverified_context()} if allow_insecure else {}
            with urlopen(request, timeout=timeout, **tls) as response:
                status = response.status
                result = parse_response(response.read())
        except HTTPError as error:
            try:
                status = error.code
                result = parse_response(error.read())
            finally:
                error.close()
        except (URLError, TimeoutError, OSError) as error:
            if attempt < max_retries:
                time.sleep(min(2 ** attempt, 8))
                continue
            raise SendFailure(f"Relay connection failed: {error}") from error
        if 200 <= status < 300:
            if isinstance(result, dict) and result.get("success") is True:
                return status, result
            raise SendFailure("Relay response did not confirm success", status=status, response=result)
        if status in RETRY_STATUSES and attempt < max_retries:
            time.sleep(min(2 ** attempt, 8))
            continue
        raise SendFailure(f"Relay returned HTTP {status}", status=status, response=result)
    raise AssertionError("retry loop did not finish")


def write_result(path: str | None, result: dict) -> None:
    line = json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n"
    if path:
        target = Path(path)
        temporary = target.with_name(target.name + ".tmp." + secrets.token_hex(4))
        try:
            with open(temporary, "x", encoding="utf-8") as stream:
                os.chmod(temporary, 0o600)
                stream.write(line)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    sys.stdout.write(line)


def run(args) -> int:
    endpoint = relay_endpoint(args.relay_url)
    if args.timeout <= 0 or args.retries < 0:
        raise ValueError("--timeout must be positive and --retries nonnegative")
    if args.input and args.output and Path(args.input).resolve() == Path(args.output).resolve():
        raise ValueError("--input and --output must be different files")
    source = open(args.input, "rb") if args.input else sys.stdin.buffer
    try:
        with tempfile.TemporaryFile(mode="w+b") as spool:
            count, group, recipient, plaintext = load_stream(source, spool, args.allow_plaintext)
            sent = 0
            last = None
            while True:
                body = spool.readline()
                if not body:
                    break
                try:
                    status, last = post(endpoint, body.rstrip(b"\n"), args.timeout, args.retries,
                                        allow_insecure=getattr(args, "allow_insecure", False))
                except SendFailure as error:
                    write_result(args.output, {
                        "status": "failed", "sent": sent, "total": count,
                        "message_group_id": group, "recipient": recipient,
                        "plaintext": plaintext,
                        "failed_sequence": sent if group else None,
                        "http_status": error.status, "error": str(error), "relay_response": error.response,
                    })
                    return 1
                sent += 1
            write_result(args.output, {
                "status": "submitted", "sent": sent, "total": count,
                "message_group_id": group, "recipient": recipient,
                "plaintext": plaintext,
                "http_status": status, "relay_response": last,
            })
            return 0
    finally:
        if args.input:
            source.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relay-url", required=True, help="Relay base URL or /relay endpoint")
    parser.add_argument("--allow-insecure", action="store_true",
                        help="Skip Relay TLS certificate verification for CLI testing")
    parser.add_argument("--input", help="Envelope JSONL file; omit to read standard input")
    parser.add_argument("--output", help="Also save a JSON delivery summary")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="Retries per envelope")
    parser.add_argument("--allow-plaintext", action="store_true",
                        help="Allow unencrypted CBOR envelopes to be posted to the Relay")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (ValueError, OSError, KeyboardInterrupt) as error:
        try:
            write_result(args.output, {"status": "failed", "sent": 0, "error": str(error)})
        except OSError as output_error:
            print(f"payload_send: cannot write result: {output_error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
