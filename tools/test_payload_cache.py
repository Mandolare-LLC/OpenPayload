"""Offline Cache discovery, decryption, and safe receive checks."""
import argparse
import base64
import contextlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import payload_cache as cache
import payload_package as package

DID = "did:openpayload:1111111111111111111111"
ALPHABET = cache.ALPHABET


def multibase(raw):
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = ALPHABET[digit] + encoded
    return "z" + "1" * (len(raw) - len(raw.lstrip(b"\0"))) + encoded


class CacheToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.signer = Ed25519PrivateKey.generate()
        self.xkey = X25519PrivateKey.generate()
        self.signing_file = self.root / "signing.pem"
        self.signing_file.write_bytes(self.signer.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.xkey_file = self.root / "agreement.pem"
        self.xkey_file.write_bytes(self.xkey.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.key_id = DID + "#auth"
        self.urls = ["https://cache-one.example", "https://cache-two.example"]
        self.args = argparse.Namespace(did=DID, directory_url="https://directory.example",
                                       service_id=[], cache_url=[], key_id=None, device_id=None,
                                       timeout=2, signing_key_file=str(self.signing_file),
                                       decryption_key_file=str(self.xkey_file), command="query",
                                       message_id=None)

    def document(self):
        pub = self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"document": {"id": DID,
                "verificationMethod": [{"id": self.key_id, "type": "Ed25519VerificationKey2020",
                                        "publicKeyMultibase": multibase(b"\xed\x01" + pub)}],
                "authentication": [self.key_id],
                "service": [
                    {"id": DID + "#first", "type": "OpenPayloadCacheService",
                     "serviceEndpoint": self.urls, "authorization": [self.key_id]},
                    {"id": DID + "#second", "type": "OpenPayloadCacheService",
                     "serviceEndpoint": ["https://cache-three.example"], "authorization": [self.key_id]},
                ]}}

    def test_discovers_every_service_endpoint_and_applies_overrides(self):
        with patch.object(cache, "request_json", return_value=self.document()):
            targets = cache.discover(self.args, self.signer)
            self.assertEqual({t.endpoint for t in targets}, set(self.urls + ["https://cache-three.example"]))
            self.args.service_id = ["#first"]
            self.args.cache_url = [self.urls[1]]
            chosen = cache.discover(self.args, self.signer)
            self.assertEqual([t.endpoint for t in chosen], [self.urls[1]])
            self.args.cache_url = ["https://unknown.example"]
            with self.assertRaises(cache.CacheError):
                cache.discover(self.args, self.signer)

    def test_direct_override_skips_directory(self):
        self.args.service_id = ["#first"]
        self.args.key_id = "#auth"
        self.args.cache_url = self.urls
        with patch.object(cache, "request_json", side_effect=AssertionError("Directory called")):
            targets = cache.discover(self.args, self.signer)
        self.assertEqual([target.endpoint for target in targets], self.urls)
        self.assertTrue(all(target.key_id == self.key_id for target in targets))

    def test_decrypts_packaged_chunks_and_validates_complete_payload(self):
        data = b"arbitrary\x00binary" * 15
        digest = package.hashlib.sha256(data).digest()
        group = "a4f0047c-0892-4d76-8e67-29a0b2fbd47a"
        pub = self.xkey.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        entries = []
        for index in range(2):
            part = data[index * 60:(index + 1) * 60] if index == 0 else data[60:]
            mid = f"00000000-0000-4000-8000-00000000000{index}"
            record = {"format": package.RECORD_FORMAT, "name": "sample.bin",
                      "media_type": "application/octet-stream", "size_bytes": len(data),
                      "sha256": digest, "message_group_id": group,
                      "sequence_number": index, "total_chunks": 2, "data": part}
            envelope = {"message_id": mid, "to": DID, "message_group_id": group,
                        "sequence_number": index, "total_chunks": 2,
                        "payload": package.seal(record, pub, DID + "#x", mid, DID, group, index, 2)}
            entries.append({"message_id": mid, "envelope": envelope})
        target = cache.CacheTarget(DID + "#first", self.urls[0], self.key_id)
        metadata = [{"message_id": e["message_id"], "message_group_id": group,
                     "sequence_number": i, "total_chunks": 2} for i, e in enumerate(entries)]
        with patch.object(cache, "cache_request", return_value={"complete": True, "chunks": entries}):
            name, recovered, ids = cache.download_group(self.args, self.signer, target,
                                                         metadata, self.xkey)
        self.assertEqual((name, recovered), ("sample.bin", data))
        self.assertEqual(ids, sorted(e["message_id"] for e in entries))
        entries[0]["envelope"]["payload"]["ciphertext_b64"] = base64.b64encode(b"tampered").decode()
        with patch.object(cache, "cache_request", return_value={"complete": True, "chunks": entries}):
            with self.assertRaises(cache.CacheError):
                cache.download_group(self.args, self.signer, target, metadata, self.xkey)

    def test_query_deduplicates_replicas_and_stdout_ack_is_explicit(self):
        target1 = cache.CacheTarget(DID + "#first", self.urls[0], self.key_id)
        target2 = cache.CacheTarget(DID + "#first", self.urls[1], self.key_id)
        item = {"message_id": "00000000-0000-4000-8000-000000000000"}
        entries = {item["message_id"]: {target1: item, target2: item}}
        per_cache = [{"cache_url": url, "pending_messages": 1} for url in self.urls]
        with patch.object(cache, "discover", return_value=[target1, target2]), \
             patch.object(cache, "collect_summaries", return_value=(entries, per_cache, [])), \
             contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(cache.run(self.args), 0)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary["pending_messages"], 1)
        self.assertEqual(summary["message_ids"], [item["message_id"]])
        self.args.command = "receive"
        self.args.message_id = item["message_id"]
        self.args.output = "-"
        self.args.output_dir = None
        for acknowledge in (False, True):
            self.args.acknowledge = acknowledge
            stdout = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
            stderr = io.StringIO()
            with patch.object(cache, "discover", return_value=[target1, target2]), \
                 patch.object(cache, "collect_summaries", return_value=(entries, per_cache, [])), \
                 patch.object(cache, "download_group", return_value=("message.bin", b"bytes", [item["message_id"]])), \
                 patch.object(cache, "ack_group", return_value=[]) as ack_mock, \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(cache.run(self.args), 0)
            self.assertEqual(stdout.buffer.getvalue(), b"bytes")
            self.assertEqual(ack_mock.call_count, int(acknowledge))
            self.assertEqual(json.loads(stderr.getvalue())["acknowledgement_requested"], acknowledge)

    def test_purge_all_previews_then_force_acknowledges_each_cache_copy(self):
        first = cache.CacheTarget(DID + "#first", self.urls[0], self.key_id)
        second = cache.CacheTarget(DID + "#first", self.urls[1], self.key_id)
        ids = ["00000000-0000-4000-8000-000000000000",
               "00000000-0000-4000-8000-000000000001"]
        entries = {ids[0]: {first: {"message_id": ids[0]}, second: {"message_id": ids[0]}},
                   ids[1]: {first: {"message_id": ids[1]}}}
        self.args.command = "purge"
        self.args.all = True
        self.args.force = False
        self.args.confirm = False
        with patch.object(cache, "discover", return_value=[first, second]), \
             patch.object(cache, "collect_summaries", return_value=(entries, [], [])), \
             patch.object(cache, "cache_request", side_effect=AssertionError("ack called")), \
             contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(cache.run(self.args), 0)
        preview = json.loads(stdout.getvalue())
        self.assertEqual((preview["status"], preview["would_purge"], preview["would_purge_copies"]),
                         ("preview", 2, 3))
        self.args.force = True
        calls = []

        def acknowledge(_args, _signer, target, operation, _subject, path, *, body):
            self.assertEqual((operation, path), ("ack", "/cache/ack"))
            calls.append((target.endpoint, body["message_ids"]))
            return {"acked": len(body["message_ids"]), "message_ids": body["message_ids"]}

        with patch.object(cache, "discover", return_value=[first, second]), \
             patch.object(cache, "collect_summaries", return_value=(entries, [], [])), \
             patch.object(cache, "cache_request", side_effect=acknowledge), \
             contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(cache.run(self.args), 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual((result["status"], result["purged"], result["purged_copies"]),
                         ("purged", 2, 3))
        self.assertEqual(calls, [(self.urls[0], ids), (self.urls[1], ids[:1])])

    def test_purge_message_id_requires_confirmation_and_fails_closed_on_summary_error(self):
        target = cache.CacheTarget(DID + "#first", self.urls[0], self.key_id)
        mid = "00000000-0000-4000-8000-000000000000"
        entries = {mid: {target: {"message_id": mid}}}
        self.args.command = "purge"
        self.args.message_id = mid
        self.args.all = False
        self.args.confirm = False
        self.args.force = False
        with patch.object(cache, "discover", return_value=[target]), \
             patch.object(cache, "collect_summaries", return_value=(entries, [], [])), \
             patch.object(cache, "cache_request", side_effect=AssertionError("ack called")):
            with self.assertRaisesRegex(cache.CacheError, "--confirm"):
                cache.run(self.args)
        class TerminalInput(io.StringIO):
            def isatty(self):
                return True
        with patch.object(cache, "discover", return_value=[target]), \
             patch.object(cache, "collect_summaries", return_value=(entries, [], [])), \
             patch.object(cache, "cache_request", side_effect=AssertionError("ack called")), \
             patch.object(cache.sys, "stdin", TerminalInput("no\n")), \
             contextlib.redirect_stdout(io.StringIO()) as stdout, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cache.run(self.args), 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "cancelled")
        self.args.confirm = True
        with patch.object(cache, "discover", return_value=[target]), \
             patch.object(cache, "collect_summaries", return_value=(entries, [], [])), \
             patch.object(cache, "cache_request", return_value={"acked": 1, "message_ids": [mid]}) as ack, \
             contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(cache.run(self.args), 0)
        self.assertEqual(json.loads(stdout.getvalue())["message_ids"], [mid])
        self.assertEqual(ack.call_count, 1)
        with patch.object(cache, "discover", return_value=[target]), \
             patch.object(cache, "collect_summaries", return_value=(entries, [], [{"cache_url": self.urls[1]}])), \
             patch.object(cache, "cache_request", side_effect=AssertionError("ack called")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cache.run(self.args), 1)


    def test_receive_saves_before_acknowledging_each_replica(self):
        target1 = cache.CacheTarget(DID + "#first", self.urls[0], self.key_id)
        target2 = cache.CacheTarget(DID + "#first", self.urls[1], self.key_id)
        mid = "00000000-0000-4000-8000-000000000000"
        item = {"message_id": mid}
        entries = {mid: {target1: item, target2: item}}
        self.args.command = "receive"
        self.args.message_id = mid
        self.args.output = str(self.root / "received.bin")
        self.args.output_dir = None
        self.args.acknowledge = False
        seen = []

        def network(_args, _signer, target, operation, _subject, _path, *, body=None):
            if operation == "pull_message":
                record = {"format": package.RECORD_FORMAT, "name": "received.bin",
                          "media_type": "application/octet-stream", "size_bytes": 4,
                          "sha256": package.hashlib.sha256(b"data").digest(),
                          "message_group_id": "", "sequence_number": 0,
                          "total_chunks": 1, "data": b"data"}
                envelope = {"message_id": mid, "to": DID,
                            "payload": package.plaintext_payload(record)}
                return {"state": "active", "message": {"message_id": mid, "envelope": envelope}}
            if operation == "ack":
                self.assertEqual(Path(self.args.output).read_bytes(), b"data")
                seen.append((target.endpoint, body["message_ids"]))
                return {"acked": 1, "message_ids": [mid]}
            raise AssertionError(operation)

        with patch.object(cache, "discover", return_value=[target1, target2]), \
             patch.object(cache, "collect_summaries", return_value=(entries, [], [])), \
             patch.object(cache, "cache_request", side_effect=network), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cache.run(self.args), 0)
        self.assertEqual({url for url, _ in seen}, set(self.urls))
        self.assertEqual(len(seen), 2)


    def test_bulk_tar_contains_deduplicated_files_before_ack(self):
        target1 = cache.CacheTarget(DID + "#first", self.urls[0], self.key_id)
        target2 = cache.CacheTarget(DID + "#first", self.urls[1], self.key_id)
        ids = ["00000000-0000-4000-8000-000000000000",
               "00000000-0000-4000-8000-000000000001"]
        entries = {mid: {target1: {"message_id": mid}, target2: {"message_id": mid}}
                   for mid in ids}
        self.args.command = "receive"
        self.args.message_id = None
        self.args.output = str(self.root / "received.tar")
        self.args.output_dir = None
        self.args.acknowledge = False
        seen = []

        def network(_args, _signer, target, operation, subject, _path, *, body=None):
            if operation == "pull_message":
                data = subject.encode()
                record = {"format": package.RECORD_FORMAT, "name": "same-name.txt",
                          "media_type": "text/plain", "size_bytes": len(data),
                          "sha256": package.hashlib.sha256(data).digest(),
                          "message_group_id": "", "sequence_number": 0,
                          "total_chunks": 1, "data": data}
                envelope = {"message_id": subject, "to": DID,
                            "payload": package.plaintext_payload(record)}
                return {"state": "active", "message": {"message_id": subject, "envelope": envelope}}
            if operation == "ack":
                with tarfile.open(self.args.output) as archive:
                    self.assertEqual(len(archive.getmembers()), 2)
                seen.append((target.endpoint, body["message_ids"]))
                return {"acked": 1, "message_ids": body["message_ids"]}
            raise AssertionError(operation)

        with patch.object(cache, "discover", return_value=[target1, target2]), \
             patch.object(cache, "collect_summaries", return_value=(entries, [], [])), \
             patch.object(cache, "cache_request", side_effect=network), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cache.run(self.args), 0)
        with tarfile.open(self.args.output) as archive:
            self.assertEqual(len(set(archive.getnames())), 2)
            self.assertEqual({archive.extractfile(member).read() for member in archive.getmembers()},
                             {mid.encode() for mid in ids})
        self.assertEqual(len(seen), 4)


if __name__ == "__main__":
    unittest.main()
