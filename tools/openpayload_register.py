#!/usr/bin/env python3
"""Register Applications and Personas, renew domain proof, or recover a Persona.

Requires cryptography and sibling openpayload_did.py. Directory performs all SCALE
encoding, DNSSEC evidence collection/verification and RPC. Domain Personas require DNSSEC. This tool signs only returned bytes.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import openpayload_did as did_tool
from cryptography.hazmat.primitives import serialization

DAY_MS = 86400000


def origin(value):
    value = value if "://" in value else "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("directory-url must be an HTTP(S) origin without credentials")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("directory-url must not contain a path, query or fragment")
    return value.rstrip("/")


def canonical_name(value):
    value = value.rstrip(".").lower()
    labels = value.split(".")
    value = ".".join(label.encode("idna").decode("ascii") for label in labels)
    if len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in value.split(".")):
        raise ValueError("Invalid Persona name")
    return value


def timestamp():
    return int(time.time() * 1000)


def expiry(value):
    return value if isinstance(value, (int, float)) else int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp." + secrets.token_hex(6))
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextlib.contextmanager
def state_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another process is using this state file")
        yield


def emit(result, output):
    if output and output != "-":
        atomic_json(output, result)
    print(json.dumps(result, sort_keys=True))


def parser():
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="kind", required=True)
    for kind, operations in {
        "persona": ("register", "renew", "status", "recover", "recovery-status", "recovery-confirm-email", "recovery-cancel", "recovery-finalize"),
        "application": ("register", "status"),
    }.items():
        sub = commands.add_parser(kind).add_subparsers(dest="operation", required=True)
        for operation in operations:
            item = sub.add_parser(operation)
            common(item)
            if kind == "persona":
                item.add_argument("--name")
                item.add_argument("--operator-did", dest="did")
            else:
                item.add_argument("--application-id")
                item.add_argument("--control-did", dest="did")
                item.add_argument("--domain", help="Bind an active DNS Persona; register or renew it first when needed")
            if operation == "renew":
                item.add_argument("--renew-before-days", type=int, default=30)
                item.add_argument("--force-renew", action="store_true", help="Renew even when expiry is more than renew-before-days away")
            if operation.startswith("recovery-"):
                item.add_argument("--recovery-id")
            if operation == "recover":
                item.add_argument("--policy", choices=("preserve", "clear"), default="preserve",
                                  help="Retain existing policy graphs (default), or remove them during recovery")
                item.add_argument("--request-email", action="store_true", help="Unavailable with DNSSEC: email cannot authorize takeover")
                item.add_argument("--email-only", action="store_true", help="Unavailable with DNSSEC: recovery requires a signed DNS TXT record")
            if operation == "recovery-confirm-email":
                item.add_argument("--email-token-file", help="File containing the token delivered by email; use - for stdin")
    item = commands.add_parser("resume", help="Resume a saved operation; private keys are never saved in state")
    common(item)
    item.add_argument("--email-token-file", help="Confirm a recovery token from a file, or - for stdin")
    item.add_argument("--request-email", action="store_true", help="Unavailable with DNSSEC: email cannot authorize takeover")
    return cli


def common(item):
    item.add_argument("--directory-url", default=did_tool.DIRECTORY)
    item.add_argument("--signing-key-file")
    item.add_argument("--signer-key-id", help="Default: infer a published Ed25519 key matching the local key")
    item.add_argument("--controller-key-id", action="append", default=[], help="Initial controller; repeat for multiple keys")
    item.add_argument("--constraints-file", help="Optional requested delivery constraints JSON")
    item.add_argument("--verification-days", type=int, default=365)
    item.add_argument("--state-file", help="Saved progress for resume/cron (default: openpayload-TARGET.json)")
    item.add_argument("--dns-auth-hook", help="Executable receiving challenge JSON on stdin; publish exactly that TXT value")
    item.add_argument("--dns-cleanup-hook", help="Executable receiving the same JSON; remove only that TXT value")
    item.add_argument("--hook-timeout", type=float, default=120)
    item.add_argument("--challenge-only", action="store_true", help="Save/print the challenge and exit before submitting")
    item.add_argument("--no-wait", action="store_true", help="Return after the first submission with tx_id; resume completes remaining phases")
    item.add_argument("--quiet", action="store_true", help="Suppress progress messages on stderr; JSON results still go to stdout")
    item.add_argument("--output", help="Save JSON result to a file, or - for stdout")
    item.add_argument("--timeout", type=float, default=600)
    item.add_argument("--poll-interval", type=float, default=10)
    item.add_argument("--allow-insecure", action="store_true", help="Skip TLS certificate verification for CLI testing; DNSSEC verification remains mandatory")
    group = item.add_mutually_exclusive_group()
    group.add_argument("--interactive", action="store_true", help="Prompt for missing required values")
    group.add_argument("--non-interactive", action="store_true", help="Never prompt; suitable for cron")


class Runner:
    def __init__(self, args, state_path):
        self.args = args
        self.state_path = state_path
        self.job = None
        self.key = None
        self.deadline = time.monotonic() + args.timeout
        self.shown_challenges = set()

    def progress(self, message):
        if not self.args.quiet:
            print("openpayload_register: " + message, file=sys.stderr, flush=True)

    def http(self, method, path, body=None):
        if path.startswith("/resolve/"):
            self.progress("Checking the signing key against the published DID.")
        elif method == "POST" and path.endswith("/verify"):
            self.progress("Checking the DNS TXT record and DNSSEC proof with Directory.")
        elif method == "PUT":
            self.progress("Submitting the signed request to Directory.")
        return did_tool.request(self.job["directory_url"] if self.job else origin(self.args.directory_url),
                                method, path, body, allow_insecure=self.args.allow_insecure)

    def optional(self, path):
        try:
            return self.http("GET", path)
        except did_tool.DirectoryError as error:
            if error.status == 404:
                return None
            raise

    def save(self):
        atomic_json(self.state_path, self.job)

    def persona(self, name):
        result = self.optional("/personas/" + quote(name, safe=""))
        return result.get("persona", result) if result else None

    def prompt(self, value, label):
        return did_tool.ask(value, label, self.args.interactive)

    def load_key(self, owner):
        path = self.args.signing_key_file or (self.job or {}).get("key_file")
        path = self.prompt(path, "Signing key file")
        if self.args.non_interactive and b"ENCRYPTED" in Path(path).read_bytes() and not os.environ.get("OPENPAYLOAD_KEY_PASSWORD"):
            raise ValueError("Encrypted key requires OPENPAYLOAD_KEY_PASSWORD in non-interactive mode")
        key_path = Path(path).resolve()
        if self.args.output and self.args.output != "-" and Path(self.args.output).resolve() == key_path:
            self.args.output = None
            raise ValueError("output must not overwrite the signing key")
        if self.state_path == key_path:
            raise ValueError("state-file must not overwrite the signing key")
        self.progress("Loading the signing key.")
        self.key = did_tool.load_private(path)
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        resolved = self.http("GET", "/resolve/" + quote(owner, safe=""))
        record = resolved.get("record", resolved)
        document = record.get("document", record.get("did_document", record))
        methods = document.get("verificationMethod", [])
        matches = [method["id"] for method in methods
                   if method.get("type") == "Ed25519VerificationKey2020" and method.get("controller") == owner
                   and did_tool.public_key(method.get("publicKeyMultibase")) == raw]
        root = record.get("root_pubkey")
        if isinstance(root, list):
            root = "0x" + bytes(root).hex()
        if root and did_tool.public_key(root) == raw:
            matches.append("root")
        selected = self.args.signer_key_id or (self.job or {}).get("signer_key_id")
        if selected and selected not in matches:
            raise ValueError("signer-key-id does not match the local key and published DID")
        if not selected:
            selected = next((x for x in matches if x == owner + "#root"), matches[0] if matches else None)
        if not selected:
            raise ValueError("Local signing key is not published as an Ed25519 key on this DID")
        return str(Path(path).resolve()), selected

    def initialize(self):
        args = self.args
        owner = args.did
        if args.operation == "recovery-cancel" and not owner:
            current = self.persona(args.name)
            if not current:
                raise ValueError("Persona does not exist")
            owner = current["operator_did"]
        owner = self.prompt(owner, "Operator/control DID")
        key_file, signer = self.load_key(owner)
        controllers = args.controller_key_id or [signer]
        self.job = {"format": "openpayload:registration-state:v1", "directory_url": origin(args.directory_url),
                    "kind": args.kind, "operation": args.operation, "operator_did": owner, "dns_proof_format": "openpayload:persona:dnssec:v1",
                    "key_file": key_file, "signer_key_id": signer, "controller_keys": controllers,
                    "verification_days": args.verification_days, "dns_auth_hook": args.dns_auth_hook,
                    "dns_cleanup_hook": args.dns_cleanup_hook, "tasks": [], "index": 0}
        if args.constraints_file:
            self.job["constraints"] = did_tool.read_json(args.constraints_file)
        if args.kind == "persona":
            name = canonical_name(self.prompt(args.name, "Persona name"))
            self.job["name"] = name
            current = self.persona(name)
            if args.operation in {"register", "renew"}:
                if args.operation == "renew":
                    if not current or current["operator_did"] != owner:
                        raise ValueError("Renewal requires the current operator DID")
                    if not current.get("dns_required", True):
                        return {"status": "not_due", "reason": "Single-label Personas have no DNS expiry", "persona": current}
                    if not args.force_renew and current.get("active") and current["verification_expires_at"] > timestamp() + args.renew_before_days * DAY_MS:
                        return {"status": "not_due", "persona": current}
                elif current:
                    raise ValueError("Persona already exists; use renew or recover")
                self.job["tasks"].append({"kind": "persona", "name": name,
                                          "action": args.operation + "_persona"})
            elif args.operation == "recover":
                if not current:
                    raise ValueError("Persona does not exist")
                self.job.update(policy=args.policy, request_email=args.request_email or args.email_only,
                                use_dns=not args.email_only)
                self.job["tasks"].append({"kind": "recovery", "name": name, "action": "start_recovery"})
            else:
                self.job["recovery_id"] = self.prompt(args.recovery_id, "Recovery ID")
                self.job["tasks"].append({"kind": "recovery", "name": name,
                                          "action": "cancel_recovery" if args.operation == "recovery-cancel" else "finalize_recovery"})
        else:
            application = self.prompt(args.application_id, "Application ID")
            if not re.fullmatch(r"[a-z0-9._-]{1,64}", application):
                raise ValueError("Invalid Application ID")
            self.job["application_id"] = application
            if self.optional("/applications/" + quote(application, safe="")):
                raise ValueError("Application already exists")
            if args.domain:
                domain = canonical_name(args.domain)
                if "." not in domain:
                    raise ValueError("Application domain must be a DNS name")
                current = self.persona(domain)
                if current and current["operator_did"] != owner:
                    raise ValueError("Domain Persona belongs to another DID; recover it before binding")
                if not current or not current.get("active") or current["verification_expires_at"] <= timestamp():
                    self.job["tasks"].append({"kind": "persona", "name": domain,
                                              "action": "renew_persona" if current else "register_persona"})
                self.job["domain"] = domain
            self.job["tasks"].append({"kind": "application", "name": application, "action": "register"})
            if args.domain:
                self.job["tasks"].append({"kind": "domain", "name": application, "domain": domain, "action": "set_domain"})
        self.save()
        return None

    def hook(self, name, challenge):
        executable = self.job.get(name)
        if not executable:
            return
        # An executable path is passed without a shell. Hooks receive no signing key or email token.
        subprocess.run([str(Path(executable).resolve())], input=json.dumps(challenge).encode(), check=True,
                       timeout=self.args.hook_timeout, stdout=sys.stderr)

    def adopt_issuer(self, challenge):
        issuer = challenge.get("directory_url")
        if issuer:
            issuer = origin(issuer)
            if self.job["directory_url"].startswith("https:") and not issuer.startswith("https:"):
                raise ValueError("Directory challenge issuer must not downgrade HTTPS")
            self.job["directory_url"] = issuer

    def show_challenge(self, task):
        challenge = task["challenge"]
        identity = (challenge["record_name"], challenge["record_value"], challenge["expires_at"])
        if identity not in self.shown_challenges:
            if not self.args.quiet:
                print(f'DNS TXT: {challenge["record_name"]} "{challenge["record_value"]}"; expires {challenge["expires_at"]}', file=sys.stderr, flush=True)
            self.shown_challenges.add(identity)
            task["displayed"] = True
        if not task.get("published") and self.job.get("dns_auth_hook"):
            self.hook("dns_auth_hook", challenge)
            task["published"] = True
        self.save()

    def confirm_token(self):
        path = getattr(self.args, "email_token_file", None)
        if not path:
            return
        token = sys.stdin.read().strip() if path == "-" else Path(path).read_text().strip()
        self.http("POST", self.recovery_path() + "/email/confirm", {"token": token})
        self.args.email_token_file = None
        self.job["email_confirmed"] = True
        if self.job["index"] < len(self.job["tasks"]):
            self.job["tasks"][self.job["index"]]["email_requested"] = True
        self.save()

    def recovery_path(self):
        return "/personas/" + quote(self.job["name"], safe="") + "/recovery/" + quote(self.job["recovery_id"], safe="")

    def cleanup(self, task):
        if task.get("challenge") and self.job.get("dns_cleanup_hook") and not task.get("cleaned"):
            self.hook("dns_cleanup_hook", task["challenge"])
            task["cleaned"] = True
            self.save()

    def prepare_task(self, task):
        owner = self.job["operator_did"]
        signer = self.job["signer_key_id"]
        valid = datetime.fromtimestamp(time.time() + 300, timezone.utc).isoformat().replace("+00:00", "Z")
        path = "/personas/" + quote(task["name"], safe="")
        if task["kind"] == "persona":
            body = {"operator_did": owner, "persona": task["name"], "signer_key_id": signer,
                    "action": task["action"], "valid_until": valid}
            if self.job.get("constraints") is not None:
                body["delivery_constraints"] = self.job["constraints"]
            if task["action"] == "register_persona":
                body.update(controller_keys=self.job["controller_keys"], controller_threshold=1)
            if "." not in task["name"]:
                body["action"] = "register_named_persona"
                prepared = self.http("POST", path + "/named/prepare", body)
                body["nonce"] = str(prepared["nonce"])
                task["submit_path"] = path + "/named"
            else:
                challenge = task.get("challenge")
                if challenge and expiry(challenge["expires_at"]) <= timestamp():
                    self.cleanup(task)
                    for key in ("challenge", "displayed", "published", "cleaned"):
                        task.pop(key, None)
                    challenge = None
                if not challenge:
                    task["challenge"] = self.http("POST", path + "/dns-challenges",
                                                   {"operator_did": owner, "action": task["action"]})
                    self.adopt_issuer(task["challenge"])
                self.show_challenge(task)
                if self.args.challenge_only:
                    return False
                challenge = task["challenge"]
                body.update(challenge_id=challenge["challenge_id"], nonce=challenge["operator_nonce"],
                            verification_days=self.job["verification_days"])
                prepared = self.http("POST", path + "/dns-challenges/" + quote(challenge["challenge_id"], safe="") + "/verify", body)
                body.update(dnssec_proof=prepared["dnssec_proof"],
                            verification_expires_at=prepared["verification_expires_at"])
                task["submit_path"] = path
        elif task["kind"] in {"application", "domain"}:
            path = "/applications/" + quote(task["name"], safe="")
            body = ({"control_did": owner, "signer_key_id": signer} if task["kind"] == "application"
                    else {"action": "set_domain", "domain": task["domain"], "control_signer_key_id": signer})
            task["submit_path"] = path + ("/registration" if task["kind"] == "application" else "/authorization")
            prepared = self.http("POST", task["submit_path"] + "/prepare", body)
            body["nonce"] = prepared["nonce"]
        else:
            body = {"operator_did": owner, "signer_key_id": signer, "action": task["action"],
                    "use_dns": self.job.get("use_dns", True),
                    "verification_days": self.job["verification_days"]}
            if task["action"] in {"start_recovery", "prove_recovery"}:
                if not task.get("challenge"):
                    suffix = "/challenges"
                    path = "/personas/" + quote(task["name"], safe="") + "/recovery"
                    if self.job.get("recovery_id"):
                        path = self.recovery_path()
                    challenge = self.http("POST", path + suffix, {"operator_did": owner,
                        "controller_keys": self.job["controller_keys"], "policy": self.job.get("policy", "preserve")})
                    self.job["recovery_id"] = challenge["recovery_id"]
                    task["challenge"] = challenge
                    self.adopt_issuer(challenge)
                    self.save()
                if self.job.get("use_dns", True):
                    self.show_challenge(task)
                if self.job.get("request_email") and not task.get("email_requested") and not self.job.get("email_confirmed"):
                    self.http("POST", self.recovery_path() + "/email", {})
                    task["email_requested"] = True
                    self.save()
                self.confirm_token()
                if self.args.challenge_only:
                    return False
            prepared = self.http("POST", self.recovery_path() + "/prepare", body)
            body = prepared["request"]
            task["submit_path"] = self.recovery_path()
        if task["kind"] == "recovery":
            self.job["email_confirmed"] = False
        body["canonical_payload"] = prepared["canonical_payload"]
        signature = base64.b64encode(self.key.sign(bytes.fromhex(prepared["canonical_payload"][2:]))).decode()
        body["control_signature" if task["kind"] == "domain" else "signature"] = signature
        task["body"] = body
        task["phase"] = "submitting"
        self.save()  # Save exact signed intent before sending; resume checks state before resubmitting.
        return True

    def completed(self, task):
        body = task.get("body", {})
        if task["kind"] == "persona":
            record = self.persona(task["name"])
            if not record or not record.get("active") or record["operator_did"] != self.job["operator_did"]:
                return None
            if body.get("action") == "register_named_persona":
                return record if not record.get("dns_required", True) and record["controller_keys"] == body["controller_keys"] else None
            return record if record["verification_expires_at"] == body.get("verification_expires_at") else None
        if task["kind"] in {"application", "domain"}:
            record = self.optional("/applications/" + quote(task["name"], safe=""))
            if not record or record.get("status") != "active" or record["control_did"] != self.job["operator_did"]:
                return None
            return record if task["kind"] == "application" or record.get("domain") == task["domain"] else None
        if task["action"] == "finalize_recovery":
            record = self.persona(task["name"])
            return record if record and record.get("active") and record["operator_did"] == self.job["operator_did"] else None
        result = self.optional(self.recovery_path())
        if not result or result.get("source") != "chain":
            return None
        record = result["record"]
        if task["action"] == "cancel_recovery":
            return result if record.get("cancelled") else None
        if record["operator_did"] != self.job["operator_did"]:
            return None
        proof = body.get("proof", {})
        factors = proof.get("factors", 0)
        if (factors & 1 and record["dns_valid_until"] < proof["proof_valid_until"]) or (factors & 2 and record["email_valid_until"] < proof["proof_valid_until"]):
            return None
        return result

    def pending_result(self, status, task=None):
        result = {"status": status, "state_file": str(self.state_path), "phase": (task or {}).get("phase", "dns_verification"),
                  "tx_id": (task or {}).get("tx_id"), "remaining_phases": len(self.job["tasks"]) - self.job["index"]}
        for key in ("name", "application_id", "recovery_id"):
            if key in self.job:
                result[key] = self.job[key]
        if task and task.get("last_error"):
            result["last_error"] = task["last_error"]
        if task and task.get("challenge"):
            result["challenge"] = task["challenge"]
        return result

    def interrupted_result(self):
        # Called while the state lock is still held. A stop during PUT must be
        # reconciled with chain state before any retry, just like a lost response.
        if not self.job or not self.state_path.exists():
            self.progress("Interrupted before progress was saved.")
            return {"status": "interrupted"}
        tasks = self.job.get("tasks", [])
        index = self.job.get("index", 0)
        task = tasks[index] if index < len(tasks) else None
        if task and task.get("phase") == "submitting":
            task.update(phase="waiting", submission_unknown=True,
                        last_error={"http_status": None, "response": {"message": "Interrupted during submission; acceptance is unknown"}})
            self.save()
        self.progress("Interrupted; saved state is retained. Run resume to continue.")
        return self.pending_result("interrupted", task)

    def run(self):
        if self.args.kind == "resume":
            self.progress(f"Resuming saved operation from {self.state_path}.")
            self.job = did_tool.read_json(self.state_path)
            if self.job.get("format") != "openpayload:registration-state:v1":
                raise ValueError("State file is not an OpenPayload registration state")
            if self.job.get("request_email") or not self.job.get("use_dns", True):
                raise ValueError("Email recovery is unsupported with DNSSEC; start a DNSSEC recovery")
            if self.job.get("dns_proof_format") != "openpayload:persona:dnssec:v1" and any(
                    task.get("challenge") for task in self.job.get("tasks", [])[self.job.get("index", 0):]):
                raise ValueError("State contains an obsolete DNS attestation challenge; start a new DNSSEC operation with a new state file")
            if self.args.directory_url != did_tool.DIRECTORY:
                self.job["directory_url"] = origin(self.args.directory_url)
            _, signer = self.load_key(self.job["operator_did"])
            if signer != self.job["signer_key_id"]:
                raise ValueError("Resume key must match the saved signing key")
            if self.args.request_email:
                self.job["request_email"] = True
                self.job["request_new_email"] = True
            for option in ("dns_auth_hook", "dns_cleanup_hook"):
                if getattr(self.args, option):
                    self.job[option] = getattr(self.args, option)
            self.confirm_token()
        else:
            resume_renewal = False
            if self.state_path.exists():
                saved = did_tool.read_json(self.state_path)
                if saved.get("index", 0) < len(saved.get("tasks", [])):
                    if (self.args.kind == "persona" and self.args.operation == "renew"
                            and saved.get("operation") == "renew" and saved.get("name") == canonical_name(self.args.name)
                            and saved.get("operator_did") == self.args.did):
                        self.job = saved
                        _, signer = self.load_key(self.job["operator_did"])
                        if signer != self.job["signer_key_id"]:
                            raise ValueError("Renewal key must match saved work")
                        resume_renewal = True
                    else:
                        raise ValueError("State file contains unfinished work; use resume")
            if not resume_renewal:
                result = self.initialize()
                if result:
                    return result
        while self.job["index"] < len(self.job["tasks"]):
            task = self.job["tasks"][self.job["index"]]
            if time.monotonic() >= self.deadline:
                self.progress("Timed out; saved state can be resumed. Last error is included in the JSON result.")
                return self.pending_result("timeout", task)
            try:
                if task.get("phase") == "submission_rejected":
                    reason = task.get("last_error", {}).get("response", {}).get("message", "Chain rejected the transaction")
                    raise ValueError(reason + "; start a fresh registration after resolving the rejection because the DNS challenge was consumed")
                if task.get("phase") == "recovery_wait":
                    status = self.http("GET", self.recovery_path())
                    if status.get("status") == "expired":
                        raise ValueError("Pending recovery expired; start a new recovery")
                    record = status["record"]
                    confirmed_email = self.job.pop("email_confirmed", False)
                    request_email = self.job.pop("request_new_email", False)
                    if confirmed_email or request_email:
                        task["action"] = "prove_recovery"
                        for key in ("phase", "body"):
                            task.pop(key, None)
                        if task.get("challenge") and expiry(task["challenge"]["expires_at"]) <= timestamp():
                            for key in ("challenge", "displayed", "published", "cleaned", "email_requested"):
                                task.pop(key, None)
                    elif status.get("eligible"):
                        task["action"] = "finalize_recovery"
                        task.pop("phase")
                    elif timestamp() >= status["ready_at"]:
                        # Refresh the expired 48-hour proof without restarting the chain timer.
                        task["action"] = "prove_recovery"
                        for key in ("phase", "challenge", "displayed", "published", "cleaned", "email_requested", "body"):
                            task.pop(key, None)
                    else:
                        result = self.pending_result("pending", task)
                        result["ready_at"] = status["ready_at"]
                        result["cancelled"] = record["cancelled"]
                        return result  # Cron can resume; do not keep a process alive for seven days.
                    self.save()
                if task.get("phase") in {"submitting", "waiting"}:
                    label = "submission outcome is unknown" if task.get("submission_unknown") else "awaiting finalized chain inclusion"
                    detail = task.get("last_error", {}).get("response", {})
                    if isinstance(detail, dict) and detail.get("message"):
                        label += "; Directory reported: " + detail["message"]
                    self.progress(f"Checking {task['name']}: {label}.")
                    record = self.completed(task)
                    if record:
                        task["record"] = record
                        self.cleanup(task)
                        if task["kind"] == "recovery" and task["action"] in {"start_recovery", "prove_recovery"}:
                            task["phase"] = "recovery_wait"
                            self.save()
                            continue
                        self.job["index"] += 1
                        self.save()
                        continue
                if task.get("phase") == "waiting" and self.args.no_wait:
                    return self.pending_result("submission_unknown" if task.get("submission_unknown") else "pending", task)
                if task.get("phase") == "waiting" and task.get("submission_unknown"):
                    body = task["body"]
                    valid_until = body.get("valid_until")
                    if valid_until and (int(valid_until) if str(valid_until).isdigit() else expiry(valid_until)) <= timestamp():
                        nonce = self.http("GET", "/persona-operators/" + quote(self.job["operator_did"], safe="") + "/nonce")["operator_nonce"]
                        if int(nonce) != int(body["nonce"]):
                            raise ValueError("Submission outcome is unknown and its nonce changed; inspect chain state before retrying")
                        self.cleanup(task)
                        for field in ("phase", "body", "challenge", "displayed", "published", "cleaned", "email_requested", "submission_unknown"):
                            task.pop(field, None)
                        if task["kind"] == "recovery" and task["action"] == "start_recovery":
                            self.job.pop("recovery_id", None)
                        self.save()
                if task.get("phase") not in {"submitting", "waiting"}:
                    if not self.prepare_task(task):
                        return self.pending_result("awaiting_proof", task)
                if task["phase"] == "submitting":
                    response = self.http("PUT", task["submit_path"], task["body"])
                    task["tx_id"] = response.get("tx_id", response.get("tx_hash"))
                    if not task["tx_id"]:
                        raise ValueError("Directory accepted submission without a transaction ID")
                    task["phase"] = "waiting"
                    task.pop("last_error", None)
                    self.save()
                    self.progress(f"Directory accepted transaction {task['tx_id']}; waiting for chain confirmation.")
                    if self.args.no_wait:
                        return self.pending_result("accepted", task)
                self.progress(f"Still waiting; checking again in {self.args.poll_interval:g} seconds.")
                time.sleep(min(self.args.poll_interval, max(0, self.deadline - time.monotonic())))
            except did_tool.DirectoryError as error:
                code = (error.details or {}).get("error") if isinstance(error.details, dict) else None
                if task.get("phase") == "submitting" and code == "chain_submission_rejected" and error.status is not None and 400 <= error.status < 500:
                    task.update(phase="submission_rejected", submission_unknown=False,
                                last_error={"http_status": error.status, "response": error.details})
                    self.save()
                    self.progress("Chain rejected the transaction: " + error.details.get("message", str(error)))
                    raise
                if task.get("phase") == "submitting" and (error.status is None or error.status >= 500):
                    task.update(phase="waiting", submission_unknown=True,
                                last_error={"http_status": error.status, "response": error.details})
                    self.save()
                    self.progress(f"Directory submission returned {error}; acceptance is unknown. Checking chain state before retrying.")
                    if self.args.no_wait:
                        result = self.pending_result("submission_unknown", task)
                        result.update(task["last_error"])
                        return result
                    continue
                if task.get("phase") not in {"submitting", "waiting"} and code in {"nonce_mismatch", "challenge_expired", "challenge_not_found"}:
                    self.progress("The saved challenge expired or changed; requesting a fresh DNS challenge.")
                    self.cleanup(task)
                    for field in ("challenge", "displayed", "published", "cleaned", "email_requested"):
                        task.pop(field, None)
                    if task["kind"] == "recovery" and task["action"] == "start_recovery":
                        self.job.pop("recovery_id", None)
                    self.save()
                    time.sleep(min(self.args.poll_interval, max(0, self.deadline - time.monotonic())))
                    continue
                if task.get("phase") not in {"submitting", "waiting"} and code in {"dns_verification_failed", "recovery_proof_missing"}:
                    task["last_error"] = {"http_status": error.status, "response": error.details}
                    self.save()
                    reason = (error.details or {}).get("message", str(error))
                    self.progress(f"DNS proof is not ready: {reason}. Checking again in {self.args.poll_interval:g} seconds.")
                    if self.args.no_wait:
                        return self.pending_result("awaiting_proof", task)
                    time.sleep(min(self.args.poll_interval, max(0, self.deadline - time.monotonic())))
                    continue
                raise
        self.progress("All registration phases confirmed on chain.")
        self.job["status"] = "confirmed"
        self.save()
        return {"status": "confirmed", "state_file": str(self.state_path),
                "records": [task.get("record") for task in self.job["tasks"]],
                "transactions": [task.get("tx_id") for task in self.job["tasks"]]}


def main(argv=None):
    args = parser().parse_args(argv)
    runner = None
    try:
        if args.output and args.output != "-" and args.signing_key_file and Path(args.output).resolve() == Path(args.signing_key_file).resolve():
            args.output = None
            raise ValueError("output must not overwrite the signing key")
        if args.timeout <= 0 or args.poll_interval <= 0 or args.hook_timeout <= 0:
            raise ValueError("timeout, poll-interval and hook-timeout must be positive")
        if not 1 <= args.verification_days <= 365:
            raise ValueError("verification-days must be between 1 and 365")
        if getattr(args, "request_email", False) or getattr(args, "email_only", False) or getattr(args, "email_token_file", None) or getattr(args, "operation", None) == "recovery-confirm-email":
            raise ValueError("Email cannot authorize Persona recovery in the DNSSEC model; use DNSSEC recovery with the seven-day delay")
        if args.kind != "resume" and args.operation == "renew" and not 1 <= args.renew_before_days <= 365:
            raise ValueError("renew-before-days must be between 1 and 365")
        if args.kind != "resume" and args.operation in {"status", "recovery-status", "recovery-confirm-email"}:
            target = canonical_name(did_tool.ask(getattr(args, "name", None), "Persona name", args.interactive)) if args.kind == "persona" else did_tool.ask(args.application_id, "Application ID", args.interactive)
            path = ("/personas/" if args.kind == "persona" else "/applications/") + quote(target, safe="")
            method, body = "GET", None
            if args.operation.startswith("recovery-"):
                path += "/recovery/" + quote(did_tool.ask(args.recovery_id, "Recovery ID", args.interactive), safe="")
            if args.operation == "recovery-confirm-email":
                file = did_tool.ask(args.email_token_file, "Email token file", args.interactive)
                token = sys.stdin.read().strip() if file == "-" else Path(file).read_text().strip()
                method, path, body = "POST", path + "/email/confirm", {"token": token}
            result = did_tool.request(origin(args.directory_url), method, path, body, allow_insecure=args.allow_insecure)
        else:
            target = getattr(args, "name", None) or getattr(args, "application_id", None)
            if args.kind == "resume" and not args.state_file:
                raise ValueError("resume requires --state-file")
            if not target and args.kind != "resume":
                target = did_tool.ask(None, "Persona name" if args.kind == "persona" else "Application ID", args.interactive)
                setattr(args, "name" if args.kind == "persona" else "application_id", target)
            state = Path(args.state_file or "openpayload-" + re.sub(r"[^a-zA-Z0-9._-]", "_", target) + ".json").resolve()
            if args.output and args.output != "-" and Path(args.output).resolve() == state:
                args.output = None
                raise ValueError("output and state-file must be different files")
            with state_lock(state):
                runner = Runner(args, state)
                try:
                    result = runner.run()
                except KeyboardInterrupt:
                    result = runner.interrupted_result()
        emit(result, args.output)
        if result.get("status") == "interrupted":
            return 130
        return 2 if result.get("status") in {"timeout", "submission_unknown"} else 0
    except KeyboardInterrupt:
        emit({"status": "interrupted"}, args.output)
        return 130
    except (did_tool.DirectoryError, ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result = {"status": "failed", "error": str(error)}
        if runner and runner.job:
            index = runner.job["index"]
            task = runner.job["tasks"][index] if index < len(runner.job["tasks"]) else None
            result.update(runner.pending_result("failed", task))
        if isinstance(error, did_tool.DirectoryError):
            result.update(http_status=error.status, response=error.details)
        emit(result, args.output)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
