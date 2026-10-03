# Hello World: DID, Relay, and Cache

This is the smallest end-to-end example using the Python tools. It creates a
new DID with a Cache service, sends one plaintext message through the Relay,
then reads and acknowledges that message from Cache. Plaintext exposes the
message to the Relay and Cache; use it only for this demonstration.

Run these commands from the OpenPayload repository root. You need Python 3.10+
and `cryptography` (`python3 -m pip install cryptography`).

## Alpha endpoints

- Directory (shared): `https://directory.openpayload.io`
- Directory (direct node): `https://directory-1.use2.openpayload.io`
- Relay: `https://relay-1.use2.openpayload.io`
- Cache: `https://cache-1.use2.openpayload.io`

The Cache URL goes in the DID document. The receive tool discovers it through
Directory, so no `--cache-url` is needed for the fetch below. The Python tools
use the shared Directory URL by default.
The commands verify TLS certificates by default. If local TLS inspection makes
Python reject the certificate during Alpha testing, add `--allow-insecure` to
each network command.

```sh
OP="$(pwd)/tools"
set -o pipefail
```

## 1. Create a DID with Cache

Run this in a directory where `hello-root.key` does not already exist. Keep that
private key safe; the Cache uses it to verify your retrieval and acknowledgement
requests.

```sh
python3 "$OP/openpayload_did.py" create \
  --cache-url https://cache-1.use2.openpayload.io \
  --key-out hello-root.key \
  --output hello-did.json

DID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["did"])' hello-did.json)
```

Creation waits for confirmation by default.

## 2. Send Hello World

This is one shell pipeline. `payload_package.py` wraps the text in a CBOR record
inside a JSON envelope; `payload_send.py` submits the envelope to the Relay.
`echo` adds a newline to the message.

```sh
echo 'Hello World!' | python3 "$OP/payload_package.py" --to "$DID" --plaintext | python3 "$OP/payload_send.py" --relay-url https://relay-1.use2.openpayload.io --allow-plaintext
```

Continue when the sender reports `"status":"submitted"`. A newly created DID
with no live recipient connection uses its Cache service for delivery.

## 3. Fetch the message to stdout and acknowledge it

The Cache query returns IDs without downloading messages. On this fresh DID,
the single ID belongs to Hello World:

```sh
MESSAGE_ID=$(python3 "$OP/payload_cache.py" query \
  --did "$DID" \
  --signing-key-file hello-root.key \
  | python3 -c 'import json,sys; ids=json.load(sys.stdin)["message_ids"]; assert len(ids)==1, ids; print(ids[0])')
  
python3 "$OP/payload_cache.py" receive \
  --did "$DID" \
  --signing-key-file hello-root.key \
  --message-id "$MESSAGE_ID" \
  --acknowledge
```

The second command prints `Hello World!` to stdout. It acknowledges the Cache
copy only after writing the bytes. The JSON receipt goes to stderr. Once
acknowledged, the Cache copy cannot be fetched again. If the query finds more
than one ID, inspect its `message_ids` list and select the intended ID instead.

## 4. Delete the example DID

After the message has been acknowledged, remove the DID from the chain:

```sh
python3 "$OP/openpayload_did.py" delete \
  --did "$DID" \
  --signing-key-file hello-root.key
```

The command waits for deletion to be confirmed. Once it succeeds, this DID and
its Cache service can no longer be used.
