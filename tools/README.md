# OpenPayload DID tool

For a minimal end-to-end example, see [Hello World](HELLO_WORLD.md).

`openpayload_did.py` creates and manages a DID through an OpenDispatch Directory. It never connects to a chain RPC node or SCALE-encodes an authorization payload. Private keys remain on the local machine. The Directory defaults to `https://directory.openpayload.io`; use `--directory-url` on any network command to select another Directory.

Install Python 3.9 or newer and `cryptography`:

```sh
python3 -m pip install cryptography
```

## TLS testing

All four CLI scripts accept `--allow-insecure` to skip HTTPS certificate
verification for a single test run. For commands with subcommands, place it
after the command (and verb, when present), for example:

```sh
python3 scripts/openpayload_did.py resolve --did DID --allow-insecure
python3 scripts/payload_cache.py query --did DID --signing-key-file root.pem --allow-insecure
```

`payload_package.py --allow-insecure` applies to its Directory lookup;
`payload_send.py --allow-insecure` applies to Relay submission. DID operations
and Cache receive/poll requests use the flag for all of their network calls,
including repeated status checks and Cache acknowledgements. Without the flag,
the scripts verify TLS certificates normally. The flag does not disable DID
proof checks, Cache authorization, or payload encryption.

## Create

Generate a root Ed25519 key, build a minimal DID document, submit it, and wait for on-chain confirmation:

```sh
python3 scripts/openpayload_did.py create \
  --key-out "$HOME/openpayload-root.key" \
  --output "$HOME/openpayload-registration.json"
```

The key file is created with mode `0600` and will not overwrite an existing file. Keep it outside a repository and back it up securely. The default document contains a root verification method and authentication reference. Add `--key-agreement-public-key z...`, `--relay-url`, `--cache-url`, `--archive-url`, or `--services-file services.json` as needed. `--document-file document.json` supplies a complete document instead. Use `--did` to select a DID; otherwise a random canonical DID is generated. `--alias` is optional.

Reuse an Ed25519 pair with `--private-key-file root.pem` and optionally `--public-key 0x...` or `--public-key-file root-public.pem`. To use a hardware or external signer, supply `--public-key`, `--timestamp`, and `--signature-base64`; sign the exact UTF-8 bytes `DID|timestamp`. The tool verifies that a supplied private and public key match.

To create a complete public DID document without *any* network request:

```sh
python3 scripts/openpayload_did.py create --document-only \
  --key-out "$HOME/openpayload-root.key" \
  --output "$HOME/openpayload-did-document.json"
```

In this mode `--output` contains the DID document itself. Run `create --interactive` to answer prompts, or run the script without arguments to start interactive creation.

## Read and manage

Read status, the public DID record, or authorization nonces:

```sh
python3 scripts/openpayload_did.py status --did 'did:openpayload:...'
python3 scripts/openpayload_did.py resolve --did 'did:openpayload:...'
python3 scripts/openpayload_did.py nonces --did 'did:openpayload:...'
```

Mutations use `--signing-key-file root.pem` and `--did DID`. The Directory prepares and validates the request, including the current nonce and exact bytes to sign. The tool signs those bytes locally, submits the request, and waits for confirmation. Examples:

```sh
python3 scripts/openpayload_did.py alias add --did DID --alias team.one --signing-key-file root.pem
python3 scripts/openpayload_did.py document replace --did DID --document-file document.json --signing-key-file root.pem
python3 scripts/openpayload_did.py service add --did DID --data-file service.json --signing-key-file root.pem
python3 scripts/openpayload_did.py device tombstone --did DID --device-id phone-1 --signing-key-file root.pem
python3 scripts/openpayload_did.py delete --did DID --signing-key-file root.pem
```

Available groups and verbs are:

- `document replace`
- `verification-method add|update|remove`
- `authentication add|remove`
- `key-agreement add|update|remove`
- `service add|update|remove`
- `alias add|update|remove`
- `device add|update|remove|tombstone`
- `root-key rotate`
- `deactivate` and `delete`

For `verification-method`, `key-agreement`, and `service` add/update, `--data-file` is the JSON object for that component. Remove uses `--id`. Authentication uses `--id` for the referenced method. Alias update uses `--old-alias` and `--new-alias`. Device update uses `--device-id` and `--new-device-id`. Root rotation uses `--new-public-key`; retain the new private key before submitting. Deactivate and delete are alternative retirement paths: a deactivated DID cannot subsequently be deleted with a DID-key proof.

External signers can call `prepare --did DID --request-file request.json --output prepared.json`, sign the decoded `payload_to_sign` bytes, then call `submit-prepared --prepared-file prepared.json --signature-base64 SIGNATURE`. The preparation file contains public data only. Submit before its authorization expiry and prepare again if its nonce becomes stale.

## Automation output

Every network command prints one JSON result to stdout. `--output PATH` also saves it as JSON. Writes wait by default, checking every 5 seconds for up to 10 minutes; change these with `--poll-interval` and `--timeout`.

- `--no-wait` returns `status: "submitted"`, `did`, and `tx_id` after HTTP acceptance.
- Confirmed writes return `status: "confirmed"`, `tx_id`, and the full public `record`; confirmed deletion returns `deleted: true`.
- A timeout returns `status: "timeout"`, `tx_id`, and the last known registration status.
- A failed request returns `status: "failed"`, `phase`, `error`, and the Directory's HTTP response when available.

Exit codes are `0` for success or accepted submission, `1` for failure, and `2` for timeout. A Directory HTTP `202` means submitted, not yet finalized. Mutations require an OpenDispatch Directory version that implements `POST /dids/{did}/prepare`.

Run the offline tests with:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```

# Binary payload to Relay

`payload_package.py` reads an arbitrary binary file or standard input. It encodes each
piece as a CBOR record, encrypts that record for the recipient's X25519 agreement key,
and writes one JSON DDN envelope per line. `payload_send.py` reads those lines and
posts each envelope to a Relay. The Relay treats the payload as opaque data; no
Relay CBOR changes are needed. These two tools require Python 3.10 or newer.
`payload_package.py` uses the same `cryptography` dependency as the DID tool.
Text and pre-assembled JSON inputs are accepted as bytes and preserved exactly;
`--mime-type text/plain` or `--mime-type application/json` records their type.
The package tool does not parse or rewrite JSON input.

```sh
python3 scripts/payload_package.py --to 'did:openpayload:...' --input file.img \
  | python3 scripts/payload_send.py --relay-url https://relay.example.com
```

Omit `--input` to read binary standard input:

```sh
python3 scripts/payload_package.py --to 'did:openpayload:...' < file.img \
  | python3 scripts/payload_send.py --relay-url https://relay.example.com
```

In `zsh` or `bash`, run `set -o pipefail` first if you want the pipeline's exit status
to report a packaging error as well as a sending error. For a resumable submission,
save the exact encrypted envelopes and send that file:

```sh
python3 scripts/payload_package.py --to 'did:openpayload:...' --input file.img \
  --output file.envelopes.jsonl
python3 scripts/payload_send.py --relay-url https://relay.example.com \
  --input file.envelopes.jsonl --output send-result.json
```

The package step defaults to `https://directory.openpayload.io` for finalized
recipient key and delivery-limit resolution. Use `--directory-url` for another
Directory. To package fully offline, supply both `--recipient-key z...` (X25519
Base58BTC multibase) and `--recipient-key-id DID#key-id`; this skips current
policy/key resolution, so use a key you have verified. `--to` must be a full DID.
Persona release delivery is not supported by this general-purpose format.
`--name`, `--mime-type`, `--tag`, and `--ttl` set optional file and envelope
metadata. The name and media type are inside the encrypted CBOR; the tag is
public. The default chunk size is 1 MiB; `--chunk-size` changes it when chunking
is needed. The package step applies the recipient's published size limits and
spools input to a private temporary file so it knows the complete length,
SHA-256, and chunk count before writing any envelopes.

For an intentionally unencrypted example, use both explicit flags:

```sh
python3 scripts/payload_package.py --to 'did:openpayload:...' --input file.img \
  --plaintext \
  | python3 scripts/payload_send.py --relay-url https://relay.example.com \
      --allow-plaintext
```

Plaintext mode encodes each CBOR record in Base64 as `payload.cbor_b64` with the
`openpayload:plaintext-cbor:v1` profile. Base64 is a text transport encoding,
not encryption: anyone who can read the envelope can recover the file bytes and
metadata. `--plaintext` does not need a recipient key and does not query the
Directory; it uses network size ceilings, and a recipient's tighter policy may
reject the submission. The sender accepts this profile only with
`--allow-plaintext` and checks the whole stream before posting. It accepts the
encrypted profile without that flag. The Relay does not decode either profile.

One small file produces one unchunked envelope. A larger file produces one
envelope per chunk with consecutive zero-based `sequence_number`, shared
`message_group_id`, and common `total_chunks`. `payload_send.py` checks that the
entire set is present before any network request. It submits lines in order,
retries transient failures using the **identical JSON bytes**, and prints one
JSON summary. `--retries` and `--timeout` control submission. A failed summary
includes the number accepted, the failed sequence, HTTP status, and Relay
response when available. The Relay may acknowledge staging before it reports
`chunk_set_delivered`; check the final `relay_response.code` for that outcome.

## Generic CBOR record format

This is a generic file format defined by these scripts. Receiving software must
implement decryption when used and reassembly; OpenPayload Relay and Cache do not
inspect or decode it. Each CBOR map has these keys:

| Key | CBOR type | Meaning |
| --- | --- | --- |
| `format` | text | `openpayload:binary-chunk:v1` |
| `name` | text | File name, or `stdin` |
| `media_type` | text | MIME type |
| `size_bytes` | unsigned integer | Original file size |
| `sha256` | byte string | SHA-256 of the whole original file |
| `message_group_id` | text | Shared UUID for chunks, empty for one envelope |
| `sequence_number` | unsigned integer | Zero-based part number |
| `total_chunks` | unsigned integer | Number of parts |
| `data` | byte string | Original file bytes for this part |

The CBOR map uses RFC 8949 deterministic key ordering. Each record is independently
sealed with an ephemeral X25519 key and ChaCha20-Poly1305. The JSON payload
`profile` is `openpayload:cbor-chunk:x25519-hkdf-sha256-chacha20poly1305:v1`;
`key_id`, `ephemeral_x25519_b64`, `nonce_b64`, and `ciphertext_b64` carry the
public key reference and Base64 encryption values. The 32-byte AEAD key is
HKDF-SHA256 over the X25519 shared secret, with salt `SHA256(AAD)` and UTF-8
profile text as `info`. The UTF-8 AEAD associated data is
`profile|message_id|to|message_group_id|sequence_number|total_chunks`.
For an unchunked envelope, use an empty group ID, sequence `0`, and total `1`.
After decryption, check the protected group/index against the outer envelope,
concatenate `data` in sequence, and verify `size_bytes` and `sha256`.

# Cache query and receive

`payload_cache.py` uses the recipient DID's published `OpenPayloadCacheService`
entries. It signs each Cache request with an authorized Ed25519 key, visits every
service and endpoint, and deduplicates message IDs replicated across Caches.
The Directory defaults to `https://directory.openpayload.io`.

For an automation or cron check, this command requests only Cache summary
metadata (IDs and chunk positions), not message envelopes:

```sh
python3 scripts/payload_cache.py query --did 'did:openpayload:...' \
  --signing-key-file "$HOME/openpayload-root.key"
```

The JSON result includes `pending_messages` (unique message IDs), a sorted
`message_ids` list for selecting individual messages, `pending_payloads` (whole
files, with chunks grouped), a per-Cache count and
availability state, and endpoint errors. A failed endpoint makes the exit code nonzero so automation can
recognize a partial result. `query --message-id UUID` checks whether that
message is active in a Cache summary.

Receive one file by any of its message IDs, decrypt and decode its CBOR records,
verify their SHA-256 and chunk sequence, then save the original bytes:

```sh
python3 scripts/payload_cache.py receive --did 'did:openpayload:...' \
  --signing-key-file "$HOME/openpayload-root.key" \
  --decryption-key-file "$HOME/openpayload-agreement.key" \
  --message-id UUID --output received.img
```

For all available files, use `--all --output-dir existing-directory` to save
separate files, or `--all --output received.tar` to save a tar archive. Existing
output files are not overwritten. `--output -` streams a single file or, with
`--all`, a tar archive to stdout. Stdout receipt leaves Cache copies available
for replay by default. Add `--acknowledge` to remove those copies after stdout
finishes writing. Status JSON goes to stderr when stdout carries file bytes;
its `acknowledgement_requested` field records which behavior was used. Files
and directories are acknowledged automatically after writing and syncing.
Acknowledgement is sent to each Cache that holds a copy. If an acknowledgement
fails, the result lists that endpoint so it can be retried before expiry.

`purge` calls the Cache acknowledgement endpoint to delete messages **without
downloading them**. Deleted messages cannot be recovered from Cache. Purge one
exact message ID interactively, or add `--confirm` for automation:

```sh
python3 scripts/payload_cache.py purge --did 'did:openpayload:...' \
  --signing-key-file "$HOME/openpayload-root.key" --message-id UUID
```

`purge --all` is a what-if preview: it reports the number of unique messages,
Cache copies, and message IDs that would be deleted. Add `--force` to actually
delete all pending messages without a confirmation prompt. Purge refuses to
delete if any selected Cache summary is unavailable, and reports a partial
result if an acknowledgement fails. `--confirm` applies only to `--message-id`;
`--force` applies only to `--all`.

Use `--service-id ID` to select a published Cache service, `--cache-url URL` to
select a published endpoint, or repeat either flag to select several. Use
`--key-id ID` when choosing a specific authorized verification method.
Supply all three of `--service-id`, `--cache-url`, and `--key-id` to skip
the Directory lookup and use those explicit settings directly. The Cache still
checks the service, endpoint, key authorization, and signature against the DID.
Direct selection accepts one service ID and multiple Cache URLs.
`--signing-key-file` and `--decryption-key-file` accept unencrypted PEM private
keys; they may be different files. `--device-id` restricts retrieval to one
device. `--directory-url` and `--timeout` support alternate environments.
Cache URLs still need to be published under the selected DID's Cache service,
even when supplied explicitly, because the Cache verifies that authorization.

The generic payload format is the one produced by `payload_package.py`:
encrypted CBOR records are decoded locally after retrieval. Its explicit
`--plaintext` mode can be received without `--decryption-key-file`.

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```
