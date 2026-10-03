"""Offline framing, encryption, and Relay submission checks for the payload tools."""

import argparse
import base64
import contextlib
import io
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import payload_package as package
import payload_send as send

ROOT = Path(__file__).resolve().parent
DID = "did:openpayload:1111111111111111111111"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(raw):
    number = int.from_bytes(raw, "big")
    value = ""
    while number:
        number, digit = divmod(number, 58)
        value = ALPHABET[digit] + value
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + value


def cbor_decode(raw):
    def item(pos):
        first = raw[pos]
        pos += 1
        major, info = first >> 5, first & 31
        if info < 24:
            length = info
        else:
            width = {24: 1, 25: 2, 26: 4, 27: 8}[info]
            length = int.from_bytes(raw[pos:pos + width], "big")
            pos += width
        if major == 0:
            return length, pos
        if major in (2, 3):
            value = raw[pos:pos + length]
            return (value if major == 2 else value.decode("utf-8")), pos + length
        if major == 5:
            result = {}
            for _ in range(length):
                key, pos = item(pos)
                value, pos = item(pos)
                result[key] = value
            return result, pos
        raise AssertionError(f"unexpected CBOR major type {major}")
    value, consumed = item(0)
    if consumed != len(raw):
        raise AssertionError("trailing CBOR bytes")
    return value


class PayloadToolTests(unittest.TestCase):
    def setUp(self):
        self.recipient = X25519PrivateKey.generate()
        public = self.recipient.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key = "z" + base58(public)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def package(self, source, extra=()):
        command = [sys.executable, str(ROOT / "payload_package.py"), "--to", DID,
                   "--recipient-key", self.key, "--recipient-key-id", DID + "#x25519-1", *extra]
        return subprocess.run(command, input=source, capture_output=True, check=False)

    def package_plaintext(self, source, extra=()):
        command = [sys.executable, str(ROOT / "payload_package.py"), "--to", DID,
                   "--plaintext", *extra]
        return subprocess.run(command, input=source, capture_output=True, check=False)

    def decrypt(self, envelope):
        payload = envelope["payload"]
        group = envelope.get("message_group_id", "")
        index = envelope.get("sequence_number", 0)
        total = envelope.get("total_chunks", 1)
        aad = package.aad_bytes(envelope["message_id"], DID, group, index, total)
        shared = self.recipient.exchange(
            package.X25519PublicKey.from_public_bytes(base64.b64decode(payload["ephemeral_x25519_b64"])))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(aad).digest(),
                   info=package.PROFILE.encode()).derive(shared)
        plaintext = ChaCha20Poly1305(key).decrypt(
            base64.b64decode(payload["nonce_b64"]),
            base64.b64decode(payload["ciphertext_b64"]), aad)
        return cbor_decode(plaintext)

    def test_binary_stdin_chunk_round_trip(self):
        source = bytes(range(256)) * (17 * 4096 + 1)
        result = self.package(source)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        envelopes = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(envelopes), 18)
        self.assertEqual([part["sequence_number"] for part in envelopes], list(range(18)))
        self.assertEqual(len({part["message_group_id"] for part in envelopes}), 1)
        records = [self.decrypt(envelope) for envelope in envelopes]
        self.assertEqual(b"".join(record["data"] for record in records), source)
        self.assertTrue(all(record["sha256"] == hashlib.sha256(source).digest() for record in records))
        self.assertTrue(all(record["format"] == package.RECORD_FORMAT for record in records))

    def test_file_input_small_and_empty(self):
        for data in (b"hello\x00world", b""):
            path = self.root / "test.img"
            path.write_bytes(data)
            result = self.package(None, ("--input", str(path)))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            lines = result.stdout.splitlines()
            self.assertEqual(len(lines), 1)
            envelope = json.loads(lines[0])
            self.assertNotIn("message_group_id", envelope)
            self.assertEqual(self.decrypt(envelope)["data"], data)

    def test_plaintext_text_and_json_preserve_input_bytes(self):
        for source, media_type in ((b"hello from stdin\n", "text/plain"),
                                   (b'{"count": 1, "ok": true}\n', "application/json")):
            result = self.package_plaintext(source, ("--mime-type", media_type))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            envelope = json.loads(result.stdout)
            payload = envelope["payload"]
            self.assertEqual(payload["profile"], package.PLAINTEXT_PROFILE)
            self.assertNotIn("ciphertext_b64", payload)
            record = cbor_decode(base64.b64decode(payload["cbor_b64"]))
            self.assertEqual(record["data"], source)
            self.assertEqual(record["media_type"], media_type)

    def test_plaintext_chunks_stay_within_relay_payload_limit(self):
        source = b"x" * (13 * 1024 * 1024)
        result = self.package_plaintext(source)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        envelopes = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertGreater(len(envelopes), 1)
        records = [cbor_decode(base64.b64decode(envelope["payload"]["cbor_b64"]))
                   for envelope in envelopes]
        self.assertEqual(b"".join(record["data"] for record in records), source)
        self.assertTrue(all(len(json.dumps(envelope["payload"], separators=(",", ":")).encode())
                            <= package.NETWORK_CHUNK_BYTES for envelope in envelopes))

    def test_directory_resolution_uses_finalized_key_and_limits(self):
        args = argparse.Namespace(to=DID, recipient_key=None, recipient_key_id=None,
                                  tag="Public", directory_url="https://directory.example")
        response = {
            "target": DID, "encryption_profile": "direct",
            "recipient_key_id": DID + "#x25519-1",
            "recipient_public_key_multibase": self.key,
            "policy": {"effective_constraints": {"max_chunk_bytes": 524288}},
        }

        class Response:
            def __enter__(self):
                return io.BytesIO(json.dumps(response).encode())
            def __exit__(self, *_args):
                return False

        with patch.object(package, "urlopen", return_value=Response()) as open_url:
            key_id, key, limits = package.resolve_recipient(args)
        self.assertEqual(key_id, DID + "#x25519-1")
        self.assertEqual(len(key), 32)
        self.assertEqual(limits["max_chunk_bytes"], 524288)
        self.assertIn("tag=Public", open_url.call_args.args[0].full_url)
        response["encryption_profile"] = "openpayload:persona-release:v1"
        with patch.object(package, "urlopen", return_value=Response()):
            with self.assertRaisesRegex(ValueError, "does not support"):
                package.resolve_recipient(args)

    def test_sender_retries_identical_body_and_rejects_incomplete_set(self):
        packaged = self.package(b"example")
        self.assertEqual(packaged.returncode, 0)
        input_file = self.root / "envelopes.jsonl"
        input_file.write_bytes(packaged.stdout)
        requests = []

        class Response:
            status = 202
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self):
                return b'{"success":true,"code":"accepted"}'

        def fake_urlopen(request, timeout):
            requests.append(request.data)
            if len(requests) == 1:
                raise HTTPError(request.full_url, 503, "unavailable", {},
                                io.BytesIO(b'{"success":false,"code":"unavailable"}'))
            return Response()

        args = argparse.Namespace(relay_url="https://relay.example.com", input=str(input_file),
                                  output=None, timeout=1, retries=1, allow_plaintext=False)
        with patch.object(send, "urlopen", side_effect=fake_urlopen), \
             patch.object(send.time, "sleep"), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(send.run(args), 0)
        self.assertEqual(requests, [packaged.stdout.strip()] * 2)
        self.assertEqual(json.loads(output.getvalue())["sent"], 1)
        invalid = json.loads(packaged.stdout)
        invalid.update(message_group_id=str(package.uuid.uuid4()), sequence_number=0,
                       total_chunks=2, delivery_hint="chunked")
        input_file.write_text(json.dumps(invalid) + "\n")
        with patch.object(send, "urlopen", side_effect=AssertionError("network request")):
            with tempfile.TemporaryFile(mode="w+b") as spool, input_file.open("rb") as source:
                with self.assertRaisesRegex(ValueError, "incomplete chunk set"):
                    send.load_stream(source, spool)

    def test_sender_requires_explicit_plaintext_permission(self):
        packaged = self.package_plaintext(b"public text")
        self.assertEqual(packaged.returncode, 0, packaged.stderr.decode())
        input_file = self.root / "plain.jsonl"
        input_file.write_bytes(packaged.stdout)
        args = argparse.Namespace(relay_url="https://relay.example.com", input=str(input_file),
                                  output=None, timeout=1, retries=0, allow_plaintext=False)
        with patch.object(send, "urlopen", side_effect=AssertionError("network request")):
            with self.assertRaisesRegex(ValueError, "--allow-plaintext"):
                send.run(args)

        class Response:
            status = 202
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self):
                return b'{"success":true,"code":"accepted"}'

        args.allow_plaintext = True
        with patch.object(send, "urlopen", return_value=Response()) as open_url, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(send.run(args), 0)
        self.assertEqual(open_url.call_count, 1)
        self.assertTrue(json.loads(output.getvalue())["plaintext"])


if __name__ == "__main__":
    unittest.main()
