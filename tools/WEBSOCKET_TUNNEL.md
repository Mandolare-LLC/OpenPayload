# Live WebSocket tunnel to stdout

This companion to [Hello World](HELLO_WORLD.md) replaces the Cache fetcher with
a live WebSocket receiver. The Hello World sending pipeline stays the same.
Like `nc -l 9000 > received.txt`, the receiver writes incoming payload bytes to
stdout so you can redirect them to a file or pipe them into another command.
It adds no prompts, JSON wrappers, or newlines to the received bytes.

This demonstration uses plaintext test data, which is visible to the Relay and
any Cache used for fallback. Use only non-sensitive data. The receiver can also
decode the tools' encrypted records with a local X25519 key.

Run from the OpenPayload repository root. You need Python 3.10+:

```sh
python3 -m pip install cryptography 'websockets>=15,<18'
OP="$(pwd)/tools"
set -o pipefail
```

## 1. Register the receiving DID with a Relay endpoint

The DID tool already supports `--relay-url`. Publish the Relay's HTTPS base URL
as an `OpenPayloadRelayService`; use that same Relay's WebSocket base URL when
opening the receiver. Keep the Cache endpoint from Hello World for fallback.
Run in a directory where `hello-root.key` does not already exist:

```sh
python3 "$OP/openpayload_did.py" create \
  --relay-url https://relay-1.use2.openpayload.io \
  --cache-url https://cache-1.use2.openpayload.io \
  --key-out hello-root.key \
  --output hello-did.json

DID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["did"])' hello-did.json)
```

Creation waits for confirmation. Keep `hello-root.key` safe and local. If you
already have the Hello World DID, add its Relay service instead of creating
another identity:

```sh
python3 - "$DID" > hello-relay-service.json <<'PY'
import json, sys
did = sys.argv[1]
json.dump({"id": did + "#relay", "type": "OpenPayloadRelayService",
           "serviceEndpoint": ["https://relay-1.use2.openpayload.io"]}, sys.stdout)
PY

python3 "$OP/openpayload_did.py" service add \
  --did "$DID" --data-file hello-relay-service.json \
  --signing-key-file hello-root.key
```

Use `service update` if `#relay` already exists. Both commands wait for
confirmation by default.

## 2. Start the receiver before sending

In a second terminal, set `OP` to the repository's `tools` directory and `DID`
to the identifier from `hello-did.json`. Start the receiver:

```sh
python3 "$OP/payload_ws.py" \
  --did "$DID" \
  --relay-ws-url wss://relay-1.use2.openpayload.io \
  --device-id hello-ws
```

Wait for `"status":"listening"` on stderr before sending. The script connects
to `/ws/{encoded-did}/{encoded-device-id}`, checks the Relay's welcome frame,
and stays open for subsequent messages. Welcome frames and receipt notices
stay on stderr; stdout contains only decoded payload bytes.

For the file redirection version, use this command instead:

```sh
python3 "$OP/payload_ws.py" \
  --did "$DID" \
  --relay-ws-url wss://relay-1.use2.openpayload.io \
  --device-id hello-ws --once > received.txt
```

`--once` exits successfully after one complete message has been written and
flushed. Shell `>` overwrites an existing file; use `>>` to append. To display
and save successive messages, omit `--once` and pipe into `tee`:

```sh
python3 "$OP/payload_ws.py" \
  --did "$DID" \
  --relay-ws-url wss://relay-1.use2.openpayload.io \
  --device-id hello-ws | tee received.txt
```

## 3. Send Hello World unchanged

Return to the first terminal and run the same sending sequence as Hello World:

```sh
echo 'Hello World!' | python3 "$OP/payload_package.py" --to "$DID" --plaintext | python3 "$OP/payload_send.py" --relay-url https://relay-1.use2.openpayload.io --allow-plaintext
```

The receiver prints `Hello World!` followed by the newline supplied by `echo`.
For the file version, wait for the receiver to exit, then run `cat received.txt`.
The sender's `"status":"submitted"` means the Relay accepted the request;
the received bytes demonstrate delivery to this client.

## Behavior and limits

- This is a receiving tunnel. Send envelopes through `payload_send.py` and
  `POST /relay`; typing into the WebSocket does not submit messages.
- It receives new live messages only. Start it before sending. If the recipient
  is offline, the existing Cache fallback can accept the envelope; retrieve that
  copy with the Hello World Cache sequence. The receiver makes no Cache requests
  and does not acknowledge cached copies.
- It supports the unchunked CBOR records created by `payload_package.py`, checks
  size and SHA-256 before writing, and flushes each message immediately. It
  rejects unsupported profiles, chunked files, malformed records, and different
  recipients without writing their data. For chunked transfers use the Cache
  receiver. Successive messages are concatenated in arrival order without extra
  separators; message boundaries are described only in stderr receipts.
- For encrypted records, add `--decryption-key-file recipient-x25519.pem` with
  the local X25519 private key matching the recipient agreement key used by the
  sender. The Ed25519 `hello-root.key` signs DID/Cache requests and cannot decrypt
  payloads. The record hash checks content consistency; it does not authenticate
  the sender of plaintext data.
- Keepalive pings maintain the session. Ctrl-C stops it with exit code `130`;
  connection, decoding, or output failures return `1`. A closed connection
  requires restarting the receiver. There is no automatic reconnect or replay.
- TLS certificates are verified by default. For Alpha testing with local TLS
  inspection, `--allow-insecure` skips certificate checks for this run.

## 4. Clean up

Stop the continuous receiver with Ctrl-C before deleting the test DID. Follow
[Hello World cleanup](HELLO_WORLD.md#4-delete-the-example-did), including fetching
and acknowledging any test messages that fell back to Cache, then deleting the
DID with the root signing key.
