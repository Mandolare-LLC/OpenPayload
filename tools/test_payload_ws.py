"""Live WebSocket receiving checks against a local server, with no public calls."""
import argparse
import contextlib
import io
import json
import ssl
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from websockets.sync.server import serve
from websockets.exceptions import ConnectionClosedOK

import payload_package as package
import payload_ws as receiver
import openpayload_did as did_tool

DID = "did:openpayload:1111111111111111111111"


def envelope(data=b"Hello World!\n", key=None):
    record = {"format": package.RECORD_FORMAT, "name": "stdin", "media_type": "text/plain",
              "size_bytes": len(data), "sha256": package.hashlib.sha256(data).digest(),
              "message_group_id": "", "sequence_number": 0, "total_chunks": 1, "data": data}
    payload = (package.plaintext_payload(record) if key is None else
               package.seal(record, key, DID + "#x", "test-message", DID, "", 0, 1))
    return {"message_id": "test-message", "to": DID, "payload": payload}


class WebSocketReceiverTests(unittest.TestCase):
    def args(self, url="wss://relay.example.com", once=True):
        return argparse.Namespace(did=DID, relay_ws_url=url, device_id="cli",
                                  decryption_key_file=None, once=once, allow_insecure=False)

    def test_hello_world_package_pipeline_reaches_stdout_with_no_wrapper(self):
        packaged = subprocess.run(
            [sys.executable, str(Path(package.__file__)), "--to", DID, "--plaintext"],
            input=b"Hello World!\n", capture_output=True, check=True)
        received_paths = []

        def handler(websocket):
            received_paths.append(websocket.request.path)
            websocket.send(json.dumps({"type": "welcome", "status": "ok",
                                       "connectionKey": DID + "::cli"}))
            websocket.send(packaged.stdout.decode().strip())
            try:
                websocket.recv()  # Wait for the receiver to close after --once.
            except ConnectionClosedOK:
                pass

        with serve(handler, "127.0.0.1", 0) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            port = server.socket.getsockname()[1]
            result = subprocess.run(
                [sys.executable, str(Path(receiver.__file__)), "--did", DID,
                 "--relay-ws-url", f"ws://127.0.0.1:{port}", "--once"],
                capture_output=True, timeout=10)
            server.shutdown()
            worker.join(timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"Hello World!\n")
        notices = [json.loads(line) for line in result.stderr.splitlines()]
        self.assertEqual([n["status"] for n in notices], ["listening", "received"])
        self.assertEqual(received_paths, ["/ws/did%3Aopenpayload%3A1111111111111111111111/cli"])

    def test_multiple_binary_messages_flush_without_inserted_separators(self):
        data = [b"binary\0\xff", b"next\n"]
        welcome = json.dumps({"type": "welcome", "status": "ok", "connectionKey": DID + "::cli"})

        class Socket:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def recv(self, **_):
                return welcome
            def __iter__(self):
                return iter(json.dumps(envelope(part)) for part in data)

        class Output(io.BytesIO):
            def flush(self):
                flushed.append(self.getvalue())

        flushed = []
        output = Output()
        with patch("websockets.sync.client.connect", return_value=Socket()), \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "closed"):
                receiver.run(self.args(once=False), output)
        self.assertEqual(output.getvalue(), b"".join(data))
        self.assertEqual(flushed, [data[0], b"".join(data)])

    def test_encrypted_messages_require_correct_x25519_key(self):
        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        message = envelope(b"secret\0bytes", public)
        self.assertEqual(receiver.message_bytes(message, DID, private), b"secret\0bytes")
        with self.assertRaisesRegex(receiver.CacheError, "decryption-key-file"):
            receiver.message_bytes(message, DID)
        with self.assertRaisesRegex(receiver.CacheError, "decryption failed"):
            receiver.message_bytes(message, DID, X25519PrivateKey.generate())

    def test_wrong_recipient_corrupt_record_and_chunked_message_fail(self):
        message = envelope()
        with self.assertRaisesRegex(ValueError, "recipient"):
            receiver.message_bytes(message, DID + "other")
        record = receiver.decode_entry({"envelope": message}, None, DID)
        record["data"] = b"corrupt"
        message["payload"] = package.plaintext_payload(record)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            receiver.message_bytes(message, DID)
        record.update(message_group_id="group", total_chunks=2)
        message.update(message_group_id="group", total_chunks=2)
        message["payload"] = package.plaintext_payload(record)
        with self.assertRaisesRegex(ValueError, "chunked"):
            receiver.message_bytes(message, DID)
        with self.assertRaisesRegex(ValueError, "JSON object"):
            receiver.parse_frame("[]")

    def test_tls_verified_by_default_and_insecure_is_explicit(self):
        for insecure in (False, True):
            args = self.args()
            args.allow_insecure = insecure
            with patch("websockets.sync.client.connect", side_effect=OSError("test stop")) as connect, \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(OSError):
                    receiver.run(args, io.BytesIO())
            tls = connect.call_args.kwargs["ssl"]
            self.assertEqual(tls.verify_mode, ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED)
            self.assertEqual(connect.call_args.kwargs["max_size"], 25 * 1024 * 1024)
            self.assertEqual(connect.call_args.kwargs["ping_interval"], 20)

    def test_invalid_welcome_cannot_emit_payload_bytes(self):
        socket = unittest.mock.MagicMock()
        socket.__enter__.return_value = socket
        socket.recv.return_value = json.dumps({"type": "welcome", "status": "ok", "connectionKey": "other"})
        output = io.BytesIO()
        with patch("websockets.sync.client.connect", return_value=socket):
            with self.assertRaisesRegex(ValueError, "receiving session"):
                receiver.run(self.args(), output)
        self.assertEqual(output.getvalue(), b"")

    def test_url_encodes_both_components_and_rejects_invalid_origins(self):
        self.assertEqual(receiver.websocket_url("wss://relay.example.com/prefix/", DID, "cli/test"),
                         "wss://relay.example.com/prefix/ws/" + package.quote(DID, safe="") + "/cli%2Ftest")
        for url in ("https://relay.example.com", "wss://relay.example.com?x=1", "wss://user@relay.example.com"):
            with self.assertRaises(ValueError):
                receiver.websocket_url(url, DID, "cli")

    def test_registration_publishes_relay_alongside_cache(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            key = str(Path(directory) / "root.pem")
            def directory_response(_directory, _method, path, body, **_kwargs):
                if path == "/register-did/prepare":
                    import time
                    return {"request": {**body, "timestamp": "v2:0:" + str(int(time.time() * 1000) + 300000)},
                            "payload_to_sign": "0x" + b"openpayload:register:v2|\x00\xff".hex()}
                return {"tx_id": "test", "registration_status": "pending"}
            with patch.object(did_tool, "request", side_effect=directory_response) as request, \
                 contextlib.redirect_stdout(io.StringIO()):
                result = did_tool.main(["create", "--key-out", key, "--no-wait",
                                       "--relay-url", "https://relay.example.com",
                                       "--cache-url", "https://cache.example.com"])
            self.assertEqual(result, 0)
            document = request.call_args.args[3]["did_document"]
            services = {s["type"]: s for s in document["service"]}
            self.assertEqual(services["OpenPayloadRelayService"]["serviceEndpoint"], ["https://relay.example.com"])
            self.assertEqual(services["OpenPayloadCacheService"]["authorization"], [document["id"] + "#root"])


if __name__ == "__main__":
    unittest.main()
