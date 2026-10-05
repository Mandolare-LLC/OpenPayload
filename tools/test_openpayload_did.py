import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("openpayload_did", Path(__file__).with_name("openpayload_did.py"))
did = importlib.util.module_from_spec(spec)
spec.loader.exec_module(did)


def prepared_registration(body):
    request = copy.deepcopy(body)
    if request.get("alias"):
        request["alias"] = request["alias"].strip().lower()
    request["timestamp"] = "v2:0:" + str(int(time.time() * 1000) + 300000)
    # Opaque binary response fixture: the CLI must decode, never SCALE-encode or sign hex text.
    payload = b"openpayload:register:v2|\x00\xff" + request["timestamp"].encode()
    return {"request": request, "payload_to_sign": "0x" + payload.hex()}


def registration_http(_directory, _method, path, body=None, **_kwargs):
    if path == "/register-did/prepare":
        return prepared_registration(body)
    if path == "/register-did":
        return {"tx_id": "0x123", "registration_status": "pending"}
    raise AssertionError("unexpected request: " + path)


class DidCliTests(unittest.TestCase):
    def test_document_only_is_offline_and_saves_private_key_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            document = Path(directory) / "document.json"
            key = Path(directory) / "root.key"
            with patch.object(did, "request", side_effect=AssertionError("network call")):
                with contextlib.redirect_stdout(io.StringIO()):
                    code = did.main(["create", "--document-only", "--output", str(document),
                                     "--key-out", str(key)])
            self.assertEqual(0, code)
            saved = json.loads(document.read_text())
            self.assertEqual(saved["id"], saved["verificationMethod"][0]["controller"])
            self.assertEqual(saved["authentication"], [saved["verificationMethod"][0]["id"]])
            self.assertTrue(key.exists())
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
            self.assertNotIn("PRIVATE KEY", document.read_text())

    def test_no_wait_returns_transaction_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            key = Path(directory) / "root.key"
            with patch.object(did, "request", side_effect=registration_http) as http:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = did.main(["create", "--key-out", str(key), "--no-wait", "--output", str(output)])
            self.assertEqual(0, code)
            self.assertEqual("0x123", json.loads(output.read_text())["tx_id"])
            self.assertEqual(2, http.call_count)
            self.assertEqual("/register-did/prepare", http.call_args_list[0].args[2])
            self.assertEqual("/register-did", http.call_args.args[2])
            submitted = http.call_args.args[3]
            prepared = prepared_registration(http.call_args_list[0].args[3])
            prepared["request"]["timestamp"] = submitted["timestamp"]
            payload = b"openpayload:register:v2|\x00\xff" + submitted["timestamp"].encode()
            did.load_private(str(key)).public_key().verify(base64.b64decode(submitted["signature"]), payload)
            self.assertNotIn("signature", http.call_args_list[0].args[3])
            self.assertNotIn("timestamp", http.call_args_list[0].args[3])

    def test_mutation_routes_cover_each_component_and_retirement(self):
        base = {"did": "did:openpayload:1111111111111111", "id": "#one",
                "verification_method": {"id": "#one"}, "key_agreement": {"id": "#one"},
                "service": {"id": "#one"}, "device_id": "phone", "alias": "alpha",
                "old_alias": "alpha"}
        for action in did.ACTIONS.values():
            method, path = did.endpoint(action, base)
            self.assertIn(method, ("POST", "PUT", "PATCH", "DELETE"), action)
            self.assertIn("/dids/", path, action)

    def test_delete_waits_for_chain_missing_state(self):
        class Args:
            no_wait = False
            timeout = 1
            poll_interval = 0.01
        with patch.object(did, "request", return_value={"registration_status": "missing"}):
            result = did.wait_for(did.DIRECTORY, "delete_did", "did:openpayload:1111111111111111",
                                  "0x456", Args(), {"nonce_domain": "control_nonce", "request": {"nonce": "1"}})
        self.assertEqual("confirmed", result["status"])
        self.assertTrue(result["deleted"])

    def test_wait_requires_requested_state_not_just_nonce_advance(self):
        class Args:
            no_wait = False
            timeout = 0.02
            poll_interval = 0.01
        identity = "did:openpayload:1111111111111111"
        prepared = {"nonce_domain": "alias_nonce", "request": {"did": identity, "alias": "team", "nonce": "1"}}
        def response(_directory, _method, path, _body=None, **_kwargs):
            if path.startswith("/registration-status/"):
                return {"registration_status": "confirmed"}
            if path.endswith("/nonces"):
                return {"alias_nonce": "2"}
            return {"aliases": ["someone-else"], "document": {}}
        with patch.object(did, "request", side_effect=response):
            result = did.wait_for(did.DIRECTORY, "add_alias", identity, "0x123", Args(), prepared)
        self.assertEqual("timeout", result["status"])

    def test_mutation_uses_directory_preparation_and_returns_tx_id(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "root.key"
            did.save_private(str(key), did.Ed25519PrivateKey.generate())
            output = Path(directory) / "receipt.json"
            identity = "did:openpayload:1111111111111111"
            prepared = {"did": identity, "action": "add_alias", "nonce_domain": "alias_nonce",
                        "payload_to_sign": "0x0102", "request": {"did": identity, "action": "add_alias",
                                                           "alias": "team", "nonce": "4"}}
            with patch.object(did, "request", side_effect=[prepared, {"tx_hash": "0xbeef"}]) as http:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = did.main(["alias", "add", "--did", identity, "--alias", "team",
                                     "--signing-key-file", str(key), "--no-wait", "--output", str(output)])
            self.assertEqual(0, code)
            self.assertEqual("0xbeef", json.loads(output.read_text())["tx_id"])
            self.assertEqual("/dids/" + did.did_path(identity) + "/prepare", http.call_args_list[0].args[2])
            self.assertEqual("POST", http.call_args_list[1].args[1])
            self.assertIn("signature", http.call_args_list[1].args[3])

    def test_failed_submission_writes_structured_response(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "failure.json"
            key = Path(directory) / "root.key"
            with patch.object(did, "request", side_effect=did.DirectoryError(
                    "Directory returned HTTP 403", status=403, details={"error": "invalid_signature"})):
                with contextlib.redirect_stdout(io.StringIO()):
                    code = did.main(["create", "--key-out", str(key), "--output", str(output)])
            result = json.loads(output.read_text())
            self.assertEqual(1, code)
            self.assertEqual("failed", result["status"])
            self.assertEqual("preparation", result["phase"])
            self.assertEqual(403, result["http_status"])
            self.assertEqual("invalid_signature", result["response"]["error"])


    def test_registration_external_signer_round_trip_and_local_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            private = did.Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(did.serialization.Encoding.Raw, did.serialization.PublicFormat.Raw)
            identity = "did:openpayload:1111111111111111111111"
            source = {"did": identity, "root_pubkey": did.multibase(public),
                      "did_document": {"id": identity, "verificationMethod": [], "service": []},
                      "alias": " Alice "}
            source_path, prepared_path = Path(directory) / "input.json", Path(directory) / "prepared.json"
            source_path.write_text(json.dumps(source))
            with patch.object(did, "request", side_effect=registration_http) as http:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = did.main(["prepare-registration", "--request-file", str(source_path),
                                     "--output", str(prepared_path), "--directory-url", "https://directory.example",
                                     "--allow-insecure"])
                self.assertEqual(0, code)
                self.assertEqual(1, http.call_count)
                prepared = json.loads(prepared_path.read_text())
                self.assertEqual("alice", prepared["request"]["alias"])
                signature = base64.b64encode(private.sign(bytes.fromhex(prepared["payload_to_sign"][2:]))).decode()
                with contextlib.redirect_stdout(io.StringIO()):
                    code = did.main(["submit-prepared", "--prepared-file", str(prepared_path),
                                     "--signature-base64", signature, "--no-wait",
                                     "--directory-url", "https://directory.example", "--allow-insecure"])
                self.assertEqual(0, code)
                self.assertEqual("/register-did", http.call_args.args[2])
                self.assertEqual({**prepared["request"], "signature": signature}, http.call_args.args[3])
                self.assertTrue(all(call.kwargs["allow_insecure"] for call in http.call_args_list))
                self.assertTrue(all(call.args[0] == "https://directory.example" for call in http.call_args_list))
                self.assertNotIn("PRIVATE KEY", prepared_path.read_text())
                http.reset_mock()
                with contextlib.redirect_stdout(io.StringIO()):
                    code = did.main(["submit-prepared", "--prepared-file", str(prepared_path),
                                     "--signature-base64", base64.b64encode(b"x" * 64).decode(), "--no-wait"])
                self.assertEqual(1, code)
                http.assert_not_called()

    def test_registration_rejects_expired_legacy_and_changed_preparation_without_submission(self):
        def expired(prepared):
            prepared["request"]["timestamp"] = "v2:0:1"
        def legacy(prepared):
            prepared["request"]["timestamp"] = "2026-07-16T12:00:00Z"
        def changed(prepared):
            prepared["request"]["did_document"]["injected"] = True
        def old_payload(prepared):
            prepared["payload_to_sign"] = "0x" + b"DID|timestamp".hex()
        for alter in (expired, legacy, changed, old_payload):
            with self.subTest(alter=alter.__name__), tempfile.TemporaryDirectory() as directory:
                def bad_response(_directory, _method, path, body, **_kwargs):
                    self.assertEqual("/register-did/prepare", path)
                    prepared = prepared_registration(body)
                    alter(prepared)
                    return prepared
                with patch.object(did, "request", side_effect=bad_response) as http:
                    with contextlib.redirect_stdout(io.StringIO()):
                        code = did.main(["create", "--key-out", str(Path(directory) / "key"), "--no-wait"])
                self.assertEqual(1, code)
                self.assertEqual(1, http.call_count)

    def test_full_replacement_signs_returned_v2_binary_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            key, document = Path(directory) / "key", Path(directory) / "document.json"
            did.save_private(str(key), did.Ed25519PrivateKey.generate())
            identity = "did:openpayload:1111111111111111111111"
            body = {"did": identity, "document": {"id": identity, "verificationMethod": []},
                    "timestamp": "v2:7:" + str(int(time.time() * 1000) + 300000), "pubkey": "0x" + "11" * 32}
            document.write_text(json.dumps(body["document"]))
            payload = b"openpayload:set_document:v2|\x00\xff"
            prepared = {"action": "replace_document", "request": body, "nonce_domain": "document_nonce",
                        "payload_to_sign": "0x" + payload.hex(), "previous_version": 2}
            with patch.object(did, "request", side_effect=[prepared, {"version": 2}, {"tx_hash": "0xbeef"}]) as http:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = did.main(["document", "replace", "--did", identity, "--document-file", str(document),
                                     "--signing-key-file", str(key), "--no-wait"])
            self.assertEqual(0, code)
            self.assertEqual("PUT", http.call_args.args[1])
            self.assertTrue(http.call_args.args[2].endswith("/document/proof"))
            submitted = http.call_args.args[3]
            self.assertEqual(body["timestamp"], submitted["timestamp"])
            did.load_private(str(key)).public_key().verify(base64.b64decode(submitted["signature"]), payload)

    def test_registration_submission_failure_preserves_phase_and_did(self):
        with tempfile.TemporaryDirectory() as directory:
            def http_response(*args, **kwargs):
                if args[2] == "/register-did/prepare":
                    return registration_http(*args, **kwargs)
                raise did.DirectoryError("rejected", status=403)
            output = io.StringIO()
            with patch.object(did, "request", side_effect=http_response):
                with contextlib.redirect_stdout(output):
                    code = did.main(["create", "--key-out", str(Path(directory) / "key"), "--no-wait"])
            self.assertEqual(1, code)
            result = json.loads(output.getvalue())
            self.assertEqual("submission", result["phase"])
            self.assertTrue(result["did"].startswith("did:openpayload:"))


if __name__ == "__main__":
    unittest.main()
