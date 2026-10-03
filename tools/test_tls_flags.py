"""Verify opt-in TLS bypass stays local to one CLI request."""

import argparse
import ssl
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import openpayload_did as did
import payload_cache as cache
import payload_package as package
import payload_send as send

ROOT = Path(__file__).resolve().parent
DID = "did:openpayload:1111111111111111111111"


class TlsFlagTests(unittest.TestCase):
    def check_transport(self, module, action, error_type):
        for allow_insecure in (False, True):
            with self.subTest(module=module.__name__, allow_insecure=allow_insecure):
                with patch.object(module, "urlopen", side_effect=URLError("test stop")) as opened:
                    with self.assertRaises(error_type):
                        action(allow_insecure)
                options = opened.call_args.kwargs
                self.assertEqual("context" in options, allow_insecure)
                if allow_insecure:
                    self.assertEqual(options["context"].verify_mode, ssl.CERT_NONE)
                    self.assertFalse(options["context"].check_hostname)

    def test_did_requests(self):
        self.check_transport(did,
            lambda insecure: did.request("https://directory.example", "GET", "/resolve/" + DID,
                                         allow_insecure=insecure), did.DirectoryError)

    def test_package_directory_lookup(self):
        def lookup(insecure):
            args = argparse.Namespace(to=DID, recipient_key=None, recipient_key_id=None,
                                      tag=None, directory_url="https://directory.example",
                                      allow_insecure=insecure)
            package.resolve_recipient(args)
        self.check_transport(package, lookup, ValueError)

    def test_relay_send(self):
        self.check_transport(send,
            lambda insecure: send.post("https://relay.example/relay", b"{}", 1, 0,
                                       allow_insecure=insecure), send.SendFailure)

    def test_cache_requests(self):
        self.check_transport(cache,
            lambda insecure: cache.request_json("https://cache.example/cache/summary/" + DID,
                                                allow_insecure=insecure), cache.CacheError)

    def test_help_lists_flag_for_each_cli(self):
        for script, command in (("openpayload_did.py", ["create"]),
                                ("openpayload_did.py", ["service", "add"]),
                                ("payload_package.py", []), ("payload_send.py", []),
                                ("payload_cache.py", ["query"]),
                                ("payload_cache.py", ["receive"])):
            with self.subTest(script=script, command=command):
                result = subprocess.run([sys.executable, str(ROOT / script), *command, "--help"],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--allow-insecure", result.stdout)


if __name__ == "__main__":
    unittest.main()
