import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("openpayload_did", Path(__file__).with_name("openpayload_did.py"))
did = importlib.util.module_from_spec(spec)
spec.loader.exec_module(did)


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
            with patch.object(did, "request", return_value={"tx_id": "0x123", "registration_status": "pending"}) as http:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = did.main(["create", "--key-out", str(key), "--no-wait", "--output", str(output)])
            self.assertEqual(0, code)
            self.assertEqual("0x123", json.loads(output.read_text())["tx_id"])
            self.assertEqual(1, http.call_count)
            self.assertEqual("/register-did", http.call_args.args[2])

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
            self.assertEqual("submission", result["phase"])
            self.assertEqual(403, result["http_status"])
            self.assertEqual("invalid_signature", result["response"]["error"])


if __name__ == "__main__":
    unittest.main()
