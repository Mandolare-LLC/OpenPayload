import base64
import contextlib
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote

import openpayload_register as register
import openpayload_did as did

DID = "did:openpayload:1111111111111111111111"


class Directory:
    def __init__(self, key):
        self.key = key
        self.personas = {}
        self.applications = {}
        self.nonce = 0
        self.calls = []
        self.dns_present = True
        self.recovery = None
        self.mail_confirmed = False
        self.recovery_id = "0x" + "77" * 32

    def __call__(self, directory, method, path, body=None, **kwargs):
        self.calls.append((directory, method, path, body, kwargs))
        decoded = unquote(path)
        if decoded.startswith("/resolve/"):
            owner = decoded.split("/resolve/", 1)[1]
            raw = self.key.public_key().public_bytes(did.serialization.Encoding.Raw, did.serialization.PublicFormat.Raw)
            return {"document": {"verificationMethod": [{"id": owner + "#root", "controller": owner,
                "type": "Ed25519VerificationKey2020", "publicKeyMultibase": did.multibase(raw)}]}}
        if "/recovery" in path:
            name = decoded.split("/")[2]
            challenge = {"recovery_id": self.recovery_id, "record_name": "_openpayload-persona." + name,
                "record_value": "recovery-value", "expires_at": register.timestamp() + 48 * 3600000}
            if method == "POST" and path.endswith("/challenges"):
                return challenge
            if path.endswith("/email/confirm"):
                if body != {"token": "secret-token"}:
                    raise AssertionError("bad token")
                self.mail_confirmed = True
                return {"status": "email_verified"}
            if path.endswith("/email"):
                return {"status": "email_sent"}
            if method == "GET":
                if not self.recovery:
                    return {**challenge, "status": "awaiting_proof"}
                ready = self.recovery["email_valid_until"] > register.timestamp()
                return {"source": "chain", "status": "ready" if ready else "pending", "record": self.recovery,
                        "eligible": ready, "ready_at": self.recovery["started_at"] + 7 * register.DAY_MS}
            if path.endswith("/prepare"):
                prepared = dict(body)
                prepared.update(nonce=str(self.nonce), valid_until=str(register.timestamp() + 300000))
                if body["action"] in {"start_recovery", "prove_recovery"}:
                    prepared["proof"] = {"factors": 3 if self.mail_confirmed else 1,
                        "proof_valid_until": register.timestamp() + 48 * 3600000}
                return {"canonical_payload": "0x0102", "request": prepared}
            if method == "PUT":
                self.key.public_key().verify(base64.b64decode(body["signature"]), b"\x01\x02")
                if body["action"] == "start_recovery":
                    self.recovery = {"operator_did": body["operator_did"], "controller_keys": [DID + "#root"],
                        "preserve_policy": True, "started_at": register.timestamp(), "cancelled": True,
                        "dns_valid_until": body["proof"]["proof_valid_until"], "email_valid_until": 0}
                elif body["action"] == "prove_recovery":
                    self.recovery["email_valid_until"] = body["proof"]["proof_valid_until"]
                    self.recovery["dns_valid_until"] = body["proof"]["proof_valid_until"]
                elif body["action"] == "finalize_recovery":
                    self.personas[name] = {"operator_did": DID, "active": True}
                self.nonce += 1
                return {"tx_id": "0xrecovery"}
        if path.startswith("/personas/"):
            name = decoded.split("/")[2]
            if method == "GET":
                if name not in self.personas:
                    raise did.DirectoryError("missing", status=404)
                return {"persona": self.personas[name]}
            if path.endswith("/dns-challenges"):
                return {"challenge_id": "challenge-1", "operator_nonce": str(self.nonce),
                        "record_name": "_openpayload-persona." + name, "record_value": "TXT-value",
                        "expires_at": register.timestamp() + 48 * 3600000,
                        "directory_url": "https://issuer.example.com"}
            if path.endswith("/verify"):
                if not self.dns_present:
                    raise did.DirectoryError("DNS missing", status=422, details={"error": "dns_verification_failed"})
                return {"canonical_payload": "0x0102", "dnssec_proof": "0x010203",
                        "verification_expires_at": register.timestamp() + body["verification_days"] * register.DAY_MS}
            if path.endswith("/named/prepare"):
                return {"canonical_payload": "0x0102", "nonce": str(self.nonce)}
            if method == "PUT":
                self.key.public_key().verify(base64.b64decode(body["signature"]), b"\x01\x02")
                self.nonce += 1
                self.personas[name] = {"operator_did": body["operator_did"], "active": True,
                    "verification_expires_at": body.get("verification_expires_at", 0),
                    "controller_keys": body.get("controller_keys", [DID + "#root"]),
                    "dns_required": body["action"] != "register_named_persona"}
                return {"tx_hash": "0xpersona"}
        if path.startswith("/applications/"):
            name = decoded.split("/")[2]
            if method == "GET":
                if name not in self.applications:
                    raise did.DirectoryError("missing", status=404)
                return self.applications[name]
            if path.endswith("/prepare"):
                return {"canonical_payload": "0x0102", "nonce": 0}
            if method == "PUT":
                if path.endswith("/registration"):
                    self.applications[name] = {"control_did": body["control_did"], "status": "active", "domain": None}
                else:
                    self.applications[name]["domain"] = body["domain"]
                return {"tx_hash": "0xapplication"}
        raise AssertionError((method, path, body))


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.key = did.Ed25519PrivateKey.generate()
        self.key_file = self.path / "key.pem"
        did.save_private(str(self.key_file), self.key)
        self.state = self.path / "state.json"
        self.http = Directory(self.key)

    def run_cli(self, *argv):
        output = io.StringIO()
        progress = io.StringIO()
        with patch.object(did, "request", side_effect=self.http), contextlib.redirect_stdout(output), contextlib.redirect_stderr(progress):
            code = register.main([*argv, "--state-file", str(self.state), "--signing-key-file", str(self.key_file),
                                  "--timeout", "0.2", "--poll-interval", "0.001"])
        self.progress_output = progress.getvalue()
        return code, json.loads(output.getvalue())

    def test_persona_create_signs_directory_bytes_and_pins_challenge_issuer(self):
        code, result = self.run_cli("persona", "register", "--name", "Example.COM.", "--operator-did", DID)
        self.assertEqual(0, code)
        self.assertEqual("confirmed", result["status"])
        verify = next(call for call in self.http.calls if call[2].endswith("/verify"))
        self.assertEqual("https://issuer.example.com", verify[0])
        self.assertEqual(365, verify[3]["verification_days"])
        self.assertEqual(0o600, os.stat(self.state).st_mode & 0o777)
        self.assertNotIn("PRIVATE KEY", self.state.read_text())

    def test_confirmed_chain_rejection_stops_and_resume_does_not_resubmit(self):
        original = self.http
        def rejected(directory, method, path, body=None, **kwargs):
            if method == "PUT":
                original.calls.append((directory, method, path, body, kwargs))
                raise did.DirectoryError("Directory returned HTTP 422", status=422,
                    details={"error": "chain_submission_rejected", "message": "Transaction would exhaust the block limits"})
            return original(directory, method, path, body, **kwargs)
        self.http = rejected
        code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID)
        self.assertEqual(1, code)
        self.assertEqual("submission_rejected", result["phase"])
        self.assertEqual(422, result["http_status"])
        self.assertIn("Chain rejected the transaction", self.progress_output)
        task = json.loads(self.state.read_text())["tasks"][0]
        self.assertFalse(task["submission_unknown"])
        code, result = self.run_cli("resume")
        self.assertEqual(1, code)
        self.assertIn("start a fresh registration", result["error"])
        self.assertEqual(1, sum(call[1] == "PUT" for call in original.calls))

    def test_application_registers_persona_then_application_then_domain(self):
        code, result = self.run_cli("application", "register", "--application-id", "example", "--domain", "example.com", "--control-did", DID)
        self.assertEqual(0, code)
        self.assertEqual("confirmed", result["status"])
        mutations = [call[2] for call in self.http.calls if call[1] == "PUT"]
        self.assertEqual(["/personas/example.com", "/applications/example/registration", "/applications/example/authorization"], mutations)
        self.assertEqual("example.com", self.http.applications["example"]["domain"])

    def test_no_wait_can_resume_remaining_application_phases(self):
        code, result = self.run_cli("application", "register", "--application-id", "example", "--domain", "example.com", "--control-did", DID, "--no-wait")
        self.assertEqual("accepted", result["status"])
        self.assertEqual("0xpersona", result["tx_id"])
        self.assertEqual(3, result["remaining_phases"])
        code, result = self.run_cli("resume")
        self.assertEqual(0, code)
        self.assertEqual("confirmed", result["status"])
        self.assertEqual(1, sum(call[1] == "PUT" and call[2] == "/personas/example.com" for call in self.http.calls))

    def test_resume_reports_missing_dns_and_preserves_error_in_json(self):
        self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID, "--challenge-only")
        self.http.dns_present = False
        code, result = self.run_cli("resume")
        self.assertEqual(2, code)
        self.assertEqual("timeout", result["status"])
        self.assertIn("Resuming saved operation", self.progress_output)
        self.assertIn("Checking the DNS TXT", self.progress_output)
        self.assertIn("DNS proof is not ready", self.progress_output)
        self.assertEqual(422, result["last_error"]["http_status"])
        self.assertEqual("dns_verification_failed", result["last_error"]["response"]["error"])
        self.assertFalse(any(call[1] == "PUT" for call in self.http.calls))

    def test_resume_redisplays_saved_challenge_once_and_does_not_republish_hook(self):
        with patch.object(register.subprocess, "run") as hook:
            self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID,
                         "--challenge-only", "--dns-auth-hook", "/tmp/publish")
            self.assertEqual(1, hook.call_count)
            saved_challenge = json.loads(self.state.read_text())["tasks"][0]["challenge"]
            self.http.dns_present = False
            code, result = self.run_cli("resume")
            self.assertEqual(2, code)
            self.assertEqual(1, self.progress_output.count('DNS TXT: _openpayload-persona.example.com "TXT-value"'))
            self.assertEqual(saved_challenge, result["challenge"])
            self.assertEqual(1, hook.call_count)
            self.run_cli("resume", "--no-wait", "--quiet")
            self.assertEqual("", self.progress_output)

    def test_ctrl_c_during_dns_wait_returns_json_and_same_resumable_challenge(self):
        self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID, "--challenge-only")
        saved_challenge = json.loads(self.state.read_text())["tasks"][0]["challenge"]
        self.http.dns_present = False
        with patch.object(register.time, "sleep", side_effect=KeyboardInterrupt):
            code, result = self.run_cli("resume")
        self.assertEqual(130, code)
        self.assertEqual("interrupted", result["status"])
        self.assertEqual(saved_challenge, result["challenge"])
        self.assertIn("saved state is retained", self.progress_output)
        self.assertNotIn("Traceback", self.progress_output)
        self.http.dns_present = True
        code, result = self.run_cli("resume")
        self.assertEqual(0, code)
        self.assertEqual("confirmed", result["status"])
        self.assertEqual(1, sum(call[2].endswith("/dns-challenges") for call in self.http.calls))

    def test_ctrl_c_after_submission_is_reconciled_without_duplicate_send(self):
        original = self.http
        interrupted = [False]
        def stop_after_acceptance(directory, method, path, body=None, **kwargs):
            result = original(directory, method, path, body, **kwargs)
            if method == "PUT" and not interrupted[0]:
                interrupted[0] = True
                raise KeyboardInterrupt
            return result
        self.http = stop_after_acceptance
        code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID)
        self.assertEqual(130, code)
        self.assertEqual("interrupted", result["status"])
        task = json.loads(self.state.read_text())["tasks"][0]
        self.assertEqual("waiting", task["phase"])
        self.assertTrue(task["submission_unknown"])
        code, result = self.run_cli("resume")
        self.assertEqual(0, code)
        self.assertEqual("confirmed", result["status"])
        self.assertEqual(1, sum(call[1] == "PUT" for call in original.calls))

    def test_resume_no_wait_unknown_submission_returns_after_one_chain_check(self):
        self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID, "--challenge-only")
        saved = json.loads(self.state.read_text())
        saved["tasks"][0].update(phase="waiting", submission_unknown=True,
            body={"action": "register_persona", "valid_until": "2030-01-01T00:00:00Z", "nonce": "0"},
            last_error={"http_status": 502, "response": {"message": "Chain submission failed"}})
        self.state.write_text(json.dumps(saved))
        self.http.calls.clear()
        code, result = self.run_cli("resume", "--no-wait")
        self.assertEqual(2, code)
        self.assertEqual("submission_unknown", result["status"])
        self.assertEqual(1, sum(call[1] == "GET" and call[2] == "/personas/example.com" for call in self.http.calls))
        self.assertFalse(any(call[1] == "PUT" for call in self.http.calls))
        self.assertIn("submission outcome is unknown", self.progress_output)
        self.assertIn("Chain submission failed", self.progress_output)
        code, result = self.run_cli("resume", "--no-wait", "--quiet")
        self.assertEqual(2, code)
        self.assertEqual("", self.progress_output)

    def test_renewal_not_due_does_not_request_dns_or_submit(self):
        self.http.personas["example.com"] = {"operator_did": DID, "active": True, "dns_required": True,
                                            "verification_expires_at": register.timestamp() + 180 * register.DAY_MS}
        code, result = self.run_cli("persona", "renew", "--name", "example.com", "--operator-did", DID, "--non-interactive")
        self.assertEqual("not_due", result["status"])
        self.assertFalse(any(call[1] != "GET" for call in self.http.calls))

    def test_named_persona_uses_directory_nonce_and_no_dns(self):
        code, result = self.run_cli("persona", "register", "--name", "compliance", "--operator-did", DID)
        self.assertEqual("confirmed", result["status"])
        self.assertFalse(any("dns-challenges" in call[2] for call in self.http.calls))
        self.assertEqual(0, code)

    def test_challenge_only_saves_state_without_submission(self):
        code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID, "--challenge-only")
        self.assertEqual(0, code)
        self.assertEqual("awaiting_proof", result["status"])
        self.assertFalse(any(call[1] == "PUT" for call in self.http.calls))
        self.assertEqual("challenge-1", result["challenge"]["challenge_id"])

    def test_timeout_and_rejection_write_structured_output(self):
        self.http.dns_present = False
        output = self.path / "result.json"
        code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID, "--output", str(output))
        self.assertEqual(2, code)
        self.assertEqual("timeout", json.loads(output.read_text())["status"])
        code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID, "--output", str(output))
        self.assertEqual(1, code)
        self.assertEqual("failed", result["status"])

    def test_cron_renewal_resumes_unfinished_matching_state(self):
        self.http.personas["example.com"] = {"operator_did": DID, "active": True, "dns_required": True,
                                            "verification_expires_at": register.timestamp() + register.DAY_MS}
        code, result = self.run_cli("persona", "renew", "--name", "example.com", "--operator-did", DID, "--no-wait")
        self.assertEqual("accepted", result["status"])
        code, result = self.run_cli("persona", "renew", "--name", "example.com", "--operator-did", DID, "--non-interactive")
        self.assertEqual(0, code)
        self.assertEqual("confirmed", result["status"])

    def test_email_recovery_is_rejected_before_network(self):
        code, result = self.run_cli("persona", "recover", "--name", "example.com", "--operator-did", DID, "--request-email")
        self.assertEqual(1, code)
        self.assertIn("Email cannot authorize", result["error"])
        self.assertEqual([], self.http.calls)

    def test_all_requests_forward_allow_insecure(self):
        code, _ = self.run_cli("persona", "register", "--name", "compliance", "--operator-did", DID, "--allow-insecure")
        self.assertEqual(0, code)
        self.assertTrue(all(call[4]["allow_insecure"] for call in self.http.calls))

    def test_invalid_period_fails_before_network(self):
        code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID, "--verification-days", "366")
        self.assertEqual(1, code)
        self.assertEqual([], self.http.calls)



class SubmissionResumeTests(unittest.TestCase):
    setUp = RegistrationTests.setUp
    run_cli = RegistrationTests.run_cli
    def test_uncertain_submission_is_reconciled_without_duplicate_registration(self):
        original = self.http
        raised = [False]
        def interrupted(directory, method, path, body=None, **kwargs):
            result = original(directory, method, path, body, **kwargs)
            if method == "PUT" and not raised[0]:
                raised[0] = True
                raise did.DirectoryError("connection lost after send", status=None)
            return result
        self.http = interrupted
        code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID, "--no-wait")
        self.assertEqual(2, code)
        self.assertEqual("submission_unknown", result["status"])
        code, result = self.run_cli("resume")
        self.assertEqual(0, code)
        self.assertEqual("confirmed", result["status"])
        self.assertEqual(1, sum(call[1] == "PUT" for call in original.calls))

    def test_clear_policy_is_an_explicit_choice_in_the_bound_challenge(self):
        self.http.personas["example.com"] = {"operator_did": "did:openpayload:old", "active": True}
        code, result = self.run_cli("persona", "recover", "--name", "example.com", "--operator-did", DID,
                                    "--policy", "clear", "--challenge-only")
        self.assertEqual(0, code)
        challenge = next(call for call in self.http.calls if call[2].endswith("/challenges"))
        self.assertEqual("clear", challenge[3]["policy"])

    def test_dns_hooks_receive_only_challenge_json_and_cleanup_after_confirmation(self):
        calls = []
        with patch.object(register.subprocess, "run", side_effect=lambda *a, **kw: calls.append((a, kw))):
            code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID,
                                        "--dns-auth-hook", "/tmp/publish", "--dns-cleanup-hook", "/tmp/cleanup")
        self.assertEqual(0, code)
        self.assertEqual([str(Path("/tmp/publish").resolve()), str(Path("/tmp/cleanup").resolve())], [item[0][0][0] for item in calls])
        for _, kwargs in calls:
            data = json.loads(kwargs["input"])
            self.assertEqual("TXT-value", data["record_value"])
            self.assertNotIn("PRIVATE KEY", kwargs["input"].decode())
            self.assertNotIn("shell", kwargs)

    def test_output_cannot_overwrite_the_private_key(self):
        original = self.key_file.read_bytes()
        code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID,
                                    "--output", str(self.key_file))
        self.assertEqual(1, code)
        self.assertEqual(original, self.key_file.read_bytes())
        self.assertEqual([], self.http.calls)

    def test_output_cannot_overwrite_saved_state_even_when_validation_fails(self):
        self.state.write_text('{"saved":true}')
        code, result = self.run_cli("persona", "register", "--name", "example.com", "--operator-did", DID,
                                    "--output", str(self.state))
        self.assertEqual(1, code)
        self.assertEqual('{"saved":true}', self.state.read_text())

if __name__ == "__main__":
    unittest.main()
