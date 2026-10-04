#!/usr/bin/env python3
"""Receive live OpenPayload messages and write their original bytes to stdout.

Requires Python 3.10+, cryptography, and websockets 15+. Keep this script next to
payload_cache.py, whose local CBOR/decryption helpers it shares. No Cache calls
are made. This receiver supports unchunked payload_package.py records.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
from urllib.parse import quote, urlsplit

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from payload_cache import CacheError, decode_entry, key_from_file

MAX_FRAME_BYTES = 25 * 1024 * 1024


def websocket_url(base: str, did: str, device_id: str) -> str:
    parsed = urlsplit(base)
    if (parsed.scheme not in {"ws", "wss"} or not parsed.hostname or
            parsed.query or parsed.fragment or parsed.username or parsed.password):
        raise ValueError("--relay-ws-url must be a WS(S) base URL without credentials, query, or fragment")
    if not did.startswith("did:openpayload:") or "@" in did or any(c.isspace() for c in did):
        raise ValueError("--did must be a full OpenPayload DID without a Persona suffix")
    if not did.removeprefix("did:openpayload:") or not device_id.strip():
        raise ValueError("DID identifier and --device-id must not be empty")
    if device_id != device_id.strip():
        raise ValueError("--device-id must not have leading or trailing whitespace")
    return base.rstrip("/") + "/ws/" + quote(did, safe="") + "/" + quote(device_id, safe="")


def parse_frame(frame) -> dict:
    value = json.loads(frame)
    if not isinstance(value, dict):
        raise ValueError("Relay frame must be a JSON object")
    return value


def message_bytes(envelope: dict, did: str, decryption_key=None) -> bytes:
    if envelope.get("to") != did:
        raise ValueError("received envelope has a different recipient")
    if not isinstance(envelope.get("message_id"), str) or not envelope["message_id"]:
        raise ValueError("received envelope has no message_id")
    record = decode_entry({"envelope": envelope}, decryption_key, did)
    if (record.get("message_group_id") != "" or
            type(record.get("sequence_number")) is not int or record["sequence_number"] != 0 or
            type(record.get("total_chunks")) is not int or record["total_chunks"] != 1):
        raise ValueError("chunked messages are not supported by this live receiver; use payload_cache.py")
    data = record["data"]
    if (type(record.get("size_bytes")) is not int or record["size_bytes"] != len(data) or
            record.get("sha256") != hashlib.sha256(data).digest()):
        raise ValueError("payload size or SHA-256 does not match")
    return data


def notice(status: str, **fields) -> None:
    print(json.dumps({"status": status, **fields}, separators=(",", ":")),
          file=sys.stderr, flush=True)


def run(args, output) -> int:
    from websockets.sync.client import connect

    url = websocket_url(args.relay_ws_url, args.did, args.device_id)
    decryption_key = (key_from_file(args.decryption_key_file, X25519PrivateKey)
                      if args.decryption_key_file else None)
    options = dict(open_timeout=20, close_timeout=5, max_size=MAX_FRAME_BYTES,
                   max_queue=4, ping_interval=20, ping_timeout=20)
    if url.startswith("wss://"):
        options["ssl"] = (ssl._create_unverified_context() if args.allow_insecure
                          else ssl.create_default_context())
    if args.allow_insecure:
        notice("warning", message="TLS certificate verification is disabled for this test")
    with connect(url, **options) as websocket:
        welcome = parse_frame(websocket.recv(timeout=20))
        if (welcome.get("type") != "welcome" or welcome.get("status") != "ok" or
                welcome.get("connectionKey") != f"{args.did}::{args.device_id}"):
            raise ValueError("Relay did not confirm the requested receiving session")
        notice("listening", did=args.did, device_id=args.device_id)
        for frame in websocket:
            envelope = parse_frame(frame)
            data = message_bytes(envelope, args.did, decryption_key)
            output.write(data)
            output.flush()
            notice("received", message_id=envelope["message_id"], bytes=len(data))
            if args.once:
                return 0
    raise ValueError("Relay closed the receiving connection; restart the receiver before sending again")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--did", required=True, help="Full recipient DID")
    parser.add_argument("--relay-ws-url", required=True,
                        help="Relay WebSocket base URL, such as wss://relay.example.com")
    parser.add_argument("--device-id", default="cli", help="Local session label (default: cli)")
    parser.add_argument("--decryption-key-file", help="Local X25519 PEM key for encrypted records")
    parser.add_argument("--once", action="store_true", help="Exit after writing one complete message")
    parser.add_argument("--allow-insecure", action="store_true",
                        help="Skip WebSocket TLS certificate verification for CLI testing")
    args = parser.parse_args(argv)
    try:
        return run(args, sys.stdout.buffer)
    except KeyboardInterrupt:
        notice("stopped")
        return 130
    except BrokenPipeError:
        # Prevent a second broken-pipe exception when Python flushes stdout at exit.
        import os
        with open(os.devnull, "wb") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        return 1
    except ImportError as error:
        notice("failed", error=f"{error}; install cryptography and 'websockets>=15,<18'")
        return 1
    except (OSError, ValueError, TypeError, CacheError, TimeoutError) as error:
        notice("failed", error=str(error))
        return 1
    except Exception as error:
        # WebSocket handshake, protocol, and abnormal-close errors have their own
        # exception hierarchy. Keep CLI failures on stderr without a traceback.
        from websockets.exceptions import WebSocketException
        if not isinstance(error, WebSocketException):
            raise
        notice("failed", error=str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
