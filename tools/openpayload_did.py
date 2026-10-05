#!/usr/bin/env python3
"""Manage an OpenPayload DID through an OpenDispatch Directory.

Requires: pip install cryptography
Private keys stay local. All network requests use the Directory HTTP API.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import secrets
import ssl
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DIRECTORY = "https://directory.openpayload.io"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ACTIONS = {
    ("verification-method", "add"): "AddVerificationMethod",
    ("verification-method", "update"): "UpdateVerificationMethod",
    ("verification-method", "remove"): "RemoveVerificationMethod",
    ("authentication", "add"): "AddAuthentication",
    ("authentication", "remove"): "RemoveAuthentication",
    ("key-agreement", "add"): "AddKeyAgreement",
    ("key-agreement", "update"): "UpdateKeyAgreement",
    ("key-agreement", "remove"): "RemoveKeyAgreement",
    ("service", "add"): "AddService",
    ("service", "update"): "UpdateService",
    ("service", "remove"): "RemoveService",
    ("alias", "add"): "add_alias",
    ("alias", "update"): "update_alias",
    ("alias", "remove"): "remove_alias",
    ("device", "add"): "add_device",
    ("device", "update"): "update_device",
    ("device", "remove"): "remove_device",
    ("device", "tombstone"): "tombstone_device",
    ("root-key", "rotate"): "UpdateRootPubkey",
    ("document", "replace"): "replace_document",
    ("deactivate", None): "deactivate_did",
    ("delete", None): "delete_did",
}


class DirectoryError(Exception):
    def __init__(self, message: str, *, status: int | None = None, details=None, phase="request"):
        super().__init__(message)
        self.status = status
        self.details = details
        self.phase = phase


def base58(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    chars = ""
    while number:
        number, digit = divmod(number, 58)
        chars = ALPHABET[digit] + chars
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + chars


def unbase58(value: str) -> bytes:
    number = 0
    for char in value:
        if char not in ALPHABET:
            raise ValueError("public key is not Base58BTC")
        number = number * 58 + ALPHABET.index(char)
    return b"\0" * (len(value) - len(value.lstrip("1"))) + (
        number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    )


def public_key(value: str | None, file: str | None = None) -> bytes | None:
    if file:
        raw = Path(file).read_bytes()
        if raw.startswith(b"-----BEGIN"):
            key = serialization.load_pem_public_key(raw)
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("public key must be Ed25519")
            return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if len(raw) == 32:
            return raw
        value = raw.decode().strip()
    if value is None:
        return None
    if value.startswith("0x"):
        result = bytes.fromhex(value[2:])
    elif value.startswith("z"):
        result = unbase58(value[1:])
        if result.startswith(b"\xed\x01") and len(result) == 34:
            result = result[2:]
    else:
        result = bytes.fromhex(value)
    if len(result) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return result


def multibase(raw: bytes) -> str:
    return "z" + base58(raw)


def load_private(path: str) -> Ed25519PrivateKey:
    data = Path(path).read_bytes()
    password = os.environ.get("OPENPAYLOAD_KEY_PASSWORD")
    if b"ENCRYPTED" in data and password is None and sys.stdin.isatty():
        password = getpass.getpass("Private key password: ")
    key = serialization.load_pem_private_key(data, password=password.encode() if password else None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key must be Ed25519")
    return key


def save_private(path: str, key: Ed25519PrivateKey) -> None:
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def read_json(path: str):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str, data) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp." + secrets.token_hex(4))
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def emit(data, output: str | None = None) -> None:
    if output:
        write_json(output, data)
    print(json.dumps(data, sort_keys=True))


def ask(value, label: str, interactive: bool) -> str:
    if value is not None:
        return value
    if interactive and sys.stdin.isatty():
        answer = input(f"{label}: ").strip()
        if answer:
            return answer
    raise ValueError(f"{label} is required")


def request(directory: str, method: str, path: str, body=None, *, allow_insecure=False):
    url = directory.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    call = Request(url, data=data, headers=headers, method=method)
    try:
        tls = {"context": ssl._create_unverified_context()} if allow_insecure else {}
        with urlopen(call, timeout=20, **tls) as response:
            text = response.read().decode("utf-8")
            return json.loads(text) if text else {}
    except HTTPError as error:
        text = error.read().decode("utf-8", "replace")
        try:
            details = json.loads(text)
        except ValueError:
            details = {"message": text[:1000]}
        raise DirectoryError(f"Directory returned HTTP {error.code}", status=error.code, details=details)
    except URLError as error:
        raise DirectoryError(f"Directory connection failed: {error.reason}")


def did_path(did: str) -> str:
    return quote(did, safe="")


def endpoint(action: str, body: dict) -> tuple[str, str]:
    root = "/dids/" + did_path(body["did"])
    component = lambda name: quote(body[name], safe="")
    if action == "replace_document":
        return "PUT", root + "/document/proof"
    if action in {"add_alias", "update_alias", "remove_alias"}:
        if action == "add_alias":
            return "POST", root + "/aliases"
        if action == "update_alias":
            return "PATCH", root + "/aliases/" + component("old_alias")
        return "DELETE", root + "/aliases/" + component("alias")
    if action in {"add_device", "update_device", "remove_device", "tombstone_device"}:
        if action == "add_device":
            return "POST", root + "/devices"
        if action == "update_device":
            return "PATCH", root + "/devices/" + component("device_id")
        if action == "remove_device":
            return "DELETE", root + "/devices/" + component("device_id")
        return "POST", root + "/devices/" + component("device_id") + "/tombstone"
    if action == "deactivate_did":
        return "POST", root + "/deactivate"
    if action == "delete_did":
        return "DELETE", root
    if action == "UpdateRootPubkey":
        return "PUT", root + "/root-pubkey"
    parts = {
        "VerificationMethod": "verification-methods",
        "Authentication": "authentication",
        "KeyAgreement": "key-agreements",
        "Service": "services",
    }
    verb = next((prefix for prefix in ("Add", "Update", "Remove") if action.startswith(prefix)), "")
    name = action[len(verb):]
    if name not in parts:
        raise ValueError(f"Unsupported action: {action}")
    path = root + "/document/" + parts[name]
    if verb == "Add":
        return "POST", path
    key = "id" if verb == "Remove" else {
        "VerificationMethod": "verification_method", "KeyAgreement": "key_agreement", "Service": "service"
    }[name]
    identifier = body[key] if key == "id" else body[key]["id"]
    return ("DELETE" if verb == "Remove" else "PUT"), path + "/" + quote(identifier, safe="")


def document_for(did: str, root: bytes, args) -> dict:
    if args.document_file:
        document = read_json(args.document_file)
        if document.get("id") != did:
            raise ValueError("document id must match DID")
        return document
    root_id = did + "#root"
    document = {
        "id": did,
        "verificationMethod": [{"id": root_id, "type": "Ed25519VerificationKey2020",
                                "controller": did, "publicKeyMultibase": multibase(root)}],
        "authentication": [root_id], "keyAgreement": [], "service": [],
    }
    if args.key_agreement_public_key:
        document["keyAgreement"].append({
            "id": did + "#x25519-1", "type": "X25519KeyAgreementKey2020",
            "controller": did, "publicKeyMultibase": args.key_agreement_public_key,
        })
    for kind, address in (("relay", args.relay_url), ("cache", args.cache_url), ("archive", args.archive_url)):
        if address:
            item = {"id": did + "#" + kind,
                    "type": "OpenPayload" + kind.capitalize() + "Service", "serviceEndpoint": [address]}
            if kind == "cache":
                item["authorization"] = [root_id]
            document["service"].append(item)
    if args.services_file:
        extra = read_json(args.services_file)
        document["service"].extend(extra if isinstance(extra, list) else [extra])
    return document


def common_write(parser):
    parser.add_argument("--directory-url", default=DIRECTORY)
    parser.add_argument("--allow-insecure", action="store_true", help="Skip TLS certificate verification for CLI testing")
    parser.add_argument("--no-wait", action="store_true")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--poll-interval", type=float, default=5)
    parser.add_argument("--output")
    parser.add_argument("--interactive", action="store_true")


def parser_for():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    create = commands.add_parser("create", help="Build and register a DID, or save its document offline")
    common_write(create)
    for flag in ("did", "alias", "document-file", "public-key", "public-key-file",
                 "private-key-file", "key-out",
                 "key-agreement-public-key", "relay-url", "cache-url", "archive-url", "services-file"):
        create.add_argument("--" + flag)
    create.add_argument("--document-only", action="store_true")
    for name in ("status", "resolve", "nonces"):
        item = commands.add_parser(name)
        item.add_argument("--directory-url", default=DIRECTORY)
        item.add_argument("--allow-insecure", action="store_true", help="Skip TLS certificate verification for CLI testing")
        item.add_argument("--did")
        item.add_argument("--output")
        item.add_argument("--interactive", action="store_true")
    for name in ("document", "verification-method", "authentication", "key-agreement", "service",
                 "alias", "device", "root-key", "deactivate", "delete"):
        parent = commands.add_parser(name)
        verbs = {"document": ["replace"], "verification-method": ["add", "update", "remove"],
                 "authentication": ["add", "remove"], "key-agreement": ["add", "update", "remove"],
                 "service": ["add", "update", "remove"], "alias": ["add", "update", "remove"],
                 "device": ["add", "update", "remove", "tombstone"], "root-key": ["rotate"]}.get(name)
        if verbs is None:
            targets = [parent]
        else:
            subcommands = parent.add_subparsers(dest="verb", required=True)
            targets = [subcommands.add_parser(v) for v in verbs]
        for target in targets:
            common_write(target)
            target.add_argument("--did")
            target.add_argument("--signing-key-file")
            target.add_argument("--signer-key-id", default="root")
            target.add_argument("--document-file")
            target.add_argument("--data-file")
            target.add_argument("--id")
            target.add_argument("--alias")
            target.add_argument("--old-alias")
            target.add_argument("--new-alias")
            target.add_argument("--device-id")
            target.add_argument("--new-device-id")
            target.add_argument("--new-public-key")
    registration = commands.add_parser("prepare-registration", help="Prepare a DID registration for an external signer")
    registration.add_argument("--directory-url", default=DIRECTORY)
    registration.add_argument("--allow-insecure", action="store_true", help="Skip TLS certificate verification for CLI testing")
    registration.add_argument("--request-file", required=True)
    registration.add_argument("--output")
    prepare = commands.add_parser("prepare", help="Prepare an externally signed mutation from JSON")
    prepare.add_argument("--directory-url", default=DIRECTORY)
    prepare.add_argument("--allow-insecure", action="store_true", help="Skip TLS certificate verification for CLI testing")
    prepare.add_argument("--did", required=True)
    prepare.add_argument("--request-file", required=True)
    prepare.add_argument("--output")
    submit = commands.add_parser("submit-prepared", help="Submit an externally signed mutation")
    common_write(submit)
    submit.add_argument("--prepared-file", required=True)
    submit.add_argument("--signature-base64", required=True)
    return parser


def mutation_input(args) -> dict:
    did = ask(args.did, "DID", args.interactive)
    action = ACTIONS[(args.command, getattr(args, "verb", None))]
    body = {"did": did, "action": action, "signer_key_id": args.signer_key_id}
    if action == "replace_document":
        body["document"] = read_json(ask(args.document_file, "Document JSON path", args.interactive))
    elif args.command in {"verification-method", "key-agreement", "service"}:
        if args.verb == "remove":
            body["id"] = ask(args.id, "Component ID", args.interactive)
        else:
            body[{"verification-method": "verification_method", "key-agreement": "key_agreement",
                  "service": "service"}[args.command]] = read_json(ask(args.data_file, "Component JSON path", args.interactive))
    elif args.command == "authentication":
        body["id"] = ask(args.id, "Method ID", args.interactive)
    elif args.command == "alias":
        if args.verb == "update":
            body["old_alias"] = ask(args.old_alias, "Current alias", args.interactive)
            body["new_alias"] = ask(args.new_alias, "New alias", args.interactive)
        else:
            body["alias"] = ask(args.alias, "Alias", args.interactive)
    elif args.command == "device":
        body["device_id"] = ask(args.device_id, "Device ID", args.interactive)
        if args.verb == "update":
            body["new_device_id"] = ask(args.new_device_id, "New device ID", args.interactive)
    elif args.command == "root-key":
        body["new_root_pubkey"] = ask(args.new_public_key, "New root public key", args.interactive)
    return body


def registration_payload(prepared: dict, expected: dict | None = None) -> bytes:
    body = prepared["request"]
    if not isinstance(body, dict) or set(body) - {"did", "alias", "root_pubkey", "did_document", "timestamp"}:
        raise ValueError("unexpected registration preparation fields")
    if body["did"] != body["did_document"]["id"]:
        raise ValueError("prepared document id must match DID")
    public_key(body["root_pubkey"])
    parts = body["timestamp"].split(":")
    if len(parts) != 3 or parts[:2] != ["v2", "0"] or not parts[2].isascii() or not parts[2].isdigit():
        raise ValueError("registration requires a v2 nonce/expiry token")
    until = int(parts[2])
    now = int(time.time() * 1000)
    if parts[2] != str(until) or not now < until <= now + 3600000:
        raise ValueError("registration preparation is expired or exceeds one hour; prepare again")
    if expected is not None:
        for name in ("did", "root_pubkey", "did_document"):
            if body.get(name) != expected.get(name):
                raise ValueError("Directory changed the registration " + name)
        alias = expected.get("alias")
        if body.get("alias") != (alias.strip().lower() if alias else alias):
            raise ValueError("Directory changed the registration alias")
    encoded = prepared["payload_to_sign"]
    if not isinstance(encoded, str) or not encoded.startswith("0x"):
        raise ValueError("payload_to_sign must be 0x-prefixed hex")
    payload = bytes.fromhex(encoded[2:])
    if not payload.startswith(b"openpayload:register:v2|"):
        raise ValueError("Directory did not prepare a v2 registration proof")
    return payload


def prepare_registration(directory: str, body: dict, *, allow_insecure=False) -> dict:
    try:
        prepared = request(directory, "POST", "/register-did/prepare", body,
                           allow_insecure=allow_insecure)
    except DirectoryError as error:
        error.phase = "preparation"
        error.did = body.get("did")
        raise
    registration_payload(prepared, body)
    return prepared


def prepare_mutation(directory: str, body: dict, *, allow_insecure=False) -> dict:
    return request(directory, "POST", "/dids/" + did_path(body["did"]) + "/prepare", body,
                   allow_insecure=allow_insecure)


def submit_mutation(directory: str, prepared: dict, signature: str, args) -> dict:
    body = dict(prepared["request"])
    if "did_document" in body:
        payload = registration_payload(prepared)
        Ed25519PublicKey.from_public_bytes(public_key(body["root_pubkey"])).verify(
            base64.b64decode(signature, validate=True), payload)
        action, method, path = "create", "POST", "/register-did"
    else:
        action = prepared["action"]
        method, path = endpoint(action, body)
    body["signature"] = signature
    try:
        response = request(directory, method, path, body, allow_insecure=getattr(args, "allow_insecure", False))
    except DirectoryError as error:
        error.phase = "submission"
        error.did = body["did"]
        raise
    tx = response.get("tx_hash") or response.get("tx_id")
    if not tx:
        raise DirectoryError("Directory accepted operation without transaction ID", details=response,
                             phase="submission")
    try:
        return wait_for(directory, action, body["did"], tx, args, prepared)
    except DirectoryError as error:
        error.phase = "status"
        error.did = body["did"]
        error.tx_id = tx
        raise


def matches_state(action: str, body: dict, record: dict) -> bool:
    document = record.get("document") or {}
    if action == "deactivate_did":
        return record.get("deactivated") is True
    if action == "replace_document":
        desired = body["document"]
        return all(document.get(name, []) == desired.get(name, []) for name in
                   ("verificationMethod", "authentication", "keyAgreement", "service"))
    if action in {"add_alias", "update_alias", "remove_alias"}:
        aliases = record.get("aliases") or []
        if action == "add_alias":
            return body["alias"] in aliases
        if action == "update_alias":
            return body["new_alias"] in aliases and body["old_alias"] not in aliases
        return body["alias"] not in aliases
    if action in {"add_device", "update_device", "remove_device", "tombstone_device"}:
        devices = {item.get("deviceId"): item for item in record.get("devices") or []}
        old = body["device_id"]
        if action == "add_device":
            return old in devices and not devices[old].get("tombstoned")
        if action == "update_device":
            return old not in devices and body["new_device_id"] in devices
        if action == "remove_device":
            return old not in devices
        return old in devices and devices[old].get("tombstoned") is True
    if action == "UpdateRootPubkey":
        current = record.get("root_pubkey")
        return current is not None and public_key(current) == public_key(body["new_root_pubkey"])
    groups = {"VerificationMethod": ("verificationMethod", "verification_method"),
              "KeyAgreement": ("keyAgreement", "key_agreement"),
              "Service": ("service", "service")}
    if "Authentication" in action:
        references = document.get("authentication") or []
        return (body["id"] in references) == action.startswith("Add")
    for suffix, (field, request_field) in groups.items():
        if action.endswith(suffix):
            entries = document.get(field) or []
            if action.startswith("Remove"):
                return all(entry.get("id") != body["id"] for entry in entries)
            wanted = body[request_field]
            return any(all(entry.get(key) == value for key, value in wanted.items())
                       for entry in entries)
    return False


def wait_for(directory: str, action: str, did: str, tx: str, args, prepared=None) -> dict:
    base = {"did": did, "operation": action, "tx_id": tx}
    if args.no_wait:
        return {"status": "submitted", **base}
    if args.timeout <= 0 or args.poll_interval <= 0:
        raise ValueError("timeout and poll interval must be positive")
    deadline = time.monotonic() + args.timeout
    last = "pending"
    initial_nonce = None
    domain = prepared.get("nonce_domain") if prepared else None
    if prepared and domain:
        initial_nonce = int(prepared["request"]["nonce"])
    while True:
        try:
            state = request(directory, "GET", "/registration-status/" + did_path(did),
                            allow_insecure=getattr(args, "allow_insecure", False))
            last = state.get("registration_status", last)
            if action == "create" and last == "confirmed":
                record = request(directory, "GET", "/resolve/" + did_path(did),
                                 allow_insecure=getattr(args, "allow_insecure", False))
                return {"status": "confirmed", **base, "record": record}
            if action == "delete_did" and last == "missing":
                return {"status": "confirmed", **base, "deleted": True}
            if action not in {"create", "delete_did"} and last == "confirmed":
                advanced = False
                if domain:
                    nonces = request(directory, "GET", "/dids/" + did_path(did) + "/nonces",
                                     allow_insecure=getattr(args, "allow_insecure", False))
                    advanced = int(nonces[domain]) > initial_nonce
                else:
                    advanced = state.get("version", 0) > prepared.get("previous_version", -1)
                if advanced:
                    record = request(directory, "GET", "/resolve/" + did_path(did),
                                     allow_insecure=getattr(args, "allow_insecure", False))
                    if matches_state(action, prepared["request"], record):
                        return {"status": "confirmed", **base, "record": record}
        except DirectoryError as error:
            if error.status not in (None, 425, 429, 500, 502, 503, 504):
                raise
            last = f"lookup_error:{error.status or 'network'}"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"status": "timeout", **base, "last_registration_status": last}
        time.sleep(min(args.poll_interval, remaining))


def create_did(args):
    if args.document_only and not args.output:
        raise ValueError("--document-only requires --output")
    if args.interactive and sys.stdin.isatty() and not any((args.private_key_file, args.public_key,
                                                              args.public_key_file)):
        existing = input("Existing Ed25519 private key PEM (blank to generate): ").strip()
        if existing:
            args.private_key_file = existing
        elif not args.key_out:
            args.key_out = ask(None, "New private key output path", True)
    if args.interactive and sys.stdin.isatty():
        args.did = args.did or input("DID (blank to generate): ").strip() or None
        args.alias = args.alias or input("Alias (blank for none): ").strip() or None
        if not args.document_file:
            args.key_agreement_public_key = (args.key_agreement_public_key
                                              or input("X25519 public key multibase (blank for none): ").strip() or None)
            args.relay_url = args.relay_url or input("Relay URL (blank for none): ").strip() or None
            args.cache_url = args.cache_url or input("Cache URL (blank for none): ").strip() or None
            args.archive_url = args.archive_url or input("Archive URL (blank for none): ").strip() or None
    private = load_private(args.private_key_file) if args.private_key_file else None
    public = public_key(args.public_key, args.public_key_file)
    if private:
        derived = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if public is not None and public != derived:
            raise ValueError("public key does not match private key")
        public = derived
    if public is None:
        if not args.key_out:
            raise ValueError("--key-out is required when generating a new root key")
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        save_private(args.key_out, private)
    did = args.did or "did:openpayload:" + base58(secrets.token_bytes(16))
    document = document_for(did, public, args)
    if args.document_only:
        emit(document, args.output)
        return 0
    if private is None:
        raise ValueError("use prepare-registration and submit-prepared with an external signer")
    body = {"did": did, "root_pubkey": multibase(public), "did_document": document}
    if args.alias:
        body["alias"] = args.alias
    prepared = prepare_registration(args.directory_url, body, allow_insecure=args.allow_insecure)
    payload = registration_payload(prepared, body)
    signature = base64.b64encode(private.sign(payload)).decode("ascii")
    body = dict(prepared["request"])
    body["signature"] = signature
    if args.interactive and sys.stdin.isatty():
        print(json.dumps(body, indent=2, sort_keys=True))
        if input("Submit this DID request? [y/N]: ").strip().lower() != "y":
            raise ValueError("Submission cancelled")
    result = submit_mutation(args.directory_url, prepared, signature, args)
    emit(result, args.output)
    return 2 if result["status"] == "timeout" else 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["create", "--interactive"]
    args = parser_for().parse_args(argv)
    if args.command is None:
        raise ValueError("Choose an operation")
    try:
        if args.command == "create":
            return create_did(args)
        if args.command in ("status", "resolve", "nonces"):
            did = ask(args.did, "DID", args.interactive)
            path = {"status": "/registration-status/", "resolve": "/resolve/",
                    "nonces": "/dids/"}[args.command] + did_path(did)
            if args.command == "nonces":
                path += "/nonces"
            emit(request(args.directory_url, "GET", path, allow_insecure=args.allow_insecure), args.output)
            return 0
        if args.command == "prepare-registration":
            body = read_json(args.request_file)
            emit(prepare_registration(args.directory_url, body, allow_insecure=args.allow_insecure), args.output)
            return 0
        if args.command == "prepare":
            body = read_json(args.request_file)
            body["did"] = args.did
            emit(prepare_mutation(args.directory_url, body, allow_insecure=args.allow_insecure), args.output)
            return 0
        if args.command == "submit-prepared":
            prepared = read_json(args.prepared_file)
            result = submit_mutation(args.directory_url, prepared, args.signature_base64, args)
        else:
            body = mutation_input(args)
            prepared = prepare_mutation(args.directory_url, body, allow_insecure=args.allow_insecure)
            if args.interactive and sys.stdin.isatty():
                print(json.dumps(prepared["request"], indent=2, sort_keys=True))
                if input("Submit this DID change? [y/N]: ").strip().lower() != "y":
                    raise ValueError("Submission cancelled")
            if body["action"] == "replace_document":
                current = request(args.directory_url, "GET", "/registration-status/" + did_path(body["did"]),
                                  allow_insecure=args.allow_insecure)
                prepared["previous_version"] = current.get("version", 0)
            key = load_private(ask(args.signing_key_file, "Signing key file", args.interactive))
            payload = bytes.fromhex(prepared["payload_to_sign"][2:])
            signature = base64.b64encode(key.sign(payload)).decode()
            result = submit_mutation(args.directory_url, prepared, signature, args)
        emit(result, args.output)
        return 2 if result["status"] == "timeout" else 0
    except DirectoryError as error:
        result = {"status": "failed", "phase": error.phase, "error": str(error)}
        if error.status:
            result["http_status"] = error.status
        if error.details is not None:
            result["response"] = error.details
        if getattr(error, "did", None) or getattr(args, "did", None):
            result["did"] = getattr(error, "did", None) or args.did
        if getattr(error, "tx_id", None):
            result["tx_id"] = error.tx_id
        emit(result, getattr(args, "output", None))
        return 1
    except (ValueError, OSError, KeyError, TypeError, InvalidSignature) as error:
        emit({"status": "failed", "phase": "input", "error": str(error)}, getattr(args, "output", None))
        return 1


if __name__ == "__main__":
    sys.exit(main())
