# OpenPayload CLI tools

For a minimal end-to-end example, see [Hello World](HELLO_WORLD.md).
For a live receiver with shell redirection, see [WebSocket tunnel to stdout](WEBSOCKET_TUNNEL.md).

`openpayload_did.py` creates and manages a DID through an OpenDispatch Directory. It never connects to a chain RPC node or SCALE-encodes an authorization payload. Private keys remain on the local machine. The Directory defaults to `https://directory.openpayload.io`; use `--directory-url` on any network command to select another Directory.

Install Python 3.9 or newer and `cryptography`:

```sh
python3 -m pip install cryptography
```

## TLS testing

All CLI tools accept `--allow-insecure` to skip HTTPS certificate
verification for a single test run. For commands with subcommands, place it
after the command (and verb, when present), for example:

```sh
python3 tools/openpayload_did.py resolve --did DID --allow-insecure
python3 tools/payload_cache.py query --did DID --signing-key-file root.pem --allow-insecure
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
python3 tools/openpayload_did.py create \
  --key-out "$HOME/openpayload-root.key" \
  --output "$HOME/openpayload-registration.json"
```

The key file is created with mode `0600` and will not overwrite an existing file. Keep it outside a repository and back it up securely. The default document contains a root verification method and authentication reference. Add `--key-agreement-public-key z...`, `--relay-url`, `--cache-url`, `--archive-url`, or `--services-file services.json` as needed. `--document-file document.json` supplies a complete document instead. Use `--did` to select a DID; otherwise a random canonical DID is generated. `--alias` is optional.

Reuse an Ed25519 pair with `--private-key-file root.pem` and optionally `--public-key 0x...` or `--public-key-file root-public.pem`. The tool verifies that a supplied private and public key match. Online creation first calls `POST /register-did/prepare`, signs the decoded binary `payload_to_sign` locally, then submits the returned request plus its Base64 signature. This requires a Directory and chain runtime supporting v2 DID proofs (runtime spec 125); there is no fallback to the old `DID|timestamp` signature. Preparation defaults to a five-minute expiry in `timestamp: "v2:0:<expiry-milliseconds>"`. This changes the signing proof, not key generation or the DID format.

For a hardware or external signer, create `registration-input.json` containing `did`, `root_pubkey`, `did_document`, and optional `alias`, then run:

```sh
python3 tools/openpayload_did.py prepare-registration \
  --request-file registration-input.json --output prepared-registration.json
# Review request, decode payload_to_sign from hex, and sign those binary bytes externally.
python3 tools/openpayload_did.py submit-prepared \
  --prepared-file prepared-registration.json --signature-base64 SIGNATURE
```

Use the same `--directory-url` for both commands. Private keys never go in either JSON file. Submit before expiry; prepare and sign again if it expires. The former `create --timestamp --signature-base64` flow is replaced by this preparation flow.

To create a complete public DID document without *any* network request:

```sh
python3 tools/openpayload_did.py create --document-only \
  --key-out "$HOME/openpayload-root.key" \
  --output "$HOME/openpayload-did-document.json"
```

In this mode `--output` contains the DID document itself. Run `create --interactive` to answer prompts, or run the script without arguments to start interactive creation.

## Read and manage

Read status, the public DID record, or authorization nonces:

```sh
python3 tools/openpayload_did.py status --did 'did:openpayload:...'
python3 tools/openpayload_did.py resolve --did 'did:openpayload:...'
python3 tools/openpayload_did.py nonces --did 'did:openpayload:...'
```

Mutations use `--signing-key-file root.pem` and `--did DID`. The Directory prepares and validates the request, including the current nonce and exact bytes to sign. The tool signs those bytes locally, submits the request, and waits for confirmation. Examples:

```sh
python3 tools/openpayload_did.py alias add --did DID --alias team.one --signing-key-file root.pem
python3 tools/openpayload_did.py document replace --did DID --document-file document.json --signing-key-file root.pem
python3 tools/openpayload_did.py service add --did DID --data-file service.json --signing-key-file root.pem
python3 tools/openpayload_did.py device tombstone --did DID --device-id phone-1 --signing-key-file root.pem
python3 tools/openpayload_did.py delete --did DID --signing-key-file root.pem
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

External signers can call `prepare --did DID --request-file request.json --output prepared.json`, sign the decoded `payload_to_sign` bytes, then call `submit-prepared --prepared-file prepared.json --signature-base64 SIGNATURE`. Full document replacement also uses v2 proofs binding the encoded document and current document nonce; it still uses the same prepare/sign/submit workflow. The preparation file contains public data only. Submit before its authorization expiry and prepare again if its nonce becomes stale.

## Automation output

Every network command prints one JSON result to stdout. `--output PATH` also saves it as JSON. Writes wait by default, checking every 5 seconds for up to 10 minutes; change these with `--poll-interval` and `--timeout`.

- `--no-wait` returns `status: "submitted"`, `did`, and `tx_id` after HTTP acceptance.
- Confirmed writes return `status: "confirmed"`, `tx_id`, and the full public `record`; confirmed deletion returns `deleted: true`.
- A timeout returns `status: "timeout"`, `tx_id`, and the last known registration status.
- A failed request returns `status: "failed"`, `phase`, `error`, and the Directory's HTTP response when available.

Exit codes are `0` for success or accepted submission, `1` for failure, and `2` for timeout. A Directory HTTP `202` means submitted, not yet finalized. Mutations require an OpenDispatch Directory version that implements `POST /dids/{did}/prepare`.

Run the offline tests with:

```sh
python3 -m unittest discover -s tools -p 'test_*.py'
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
python3 tools/payload_package.py --to 'did:openpayload:...' --input file.img \
  | python3 tools/payload_send.py --relay-url https://relay.example.com
```

Omit `--input` to read binary standard input:

```sh
python3 tools/payload_package.py --to 'did:openpayload:...' < file.img \
  | python3 tools/payload_send.py --relay-url https://relay.example.com
```

In `zsh` or `bash`, run `set -o pipefail` first if you want the pipeline's exit status
to report a packaging error as well as a sending error. For a resumable submission,
save the exact encrypted envelopes and send that file:

```sh
python3 tools/payload_package.py --to 'did:openpayload:...' --input file.img \
  --output file.envelopes.jsonl
python3 tools/payload_send.py --relay-url https://relay.example.com \
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
python3 tools/payload_package.py --to 'did:openpayload:...' --input file.img \
  --plaintext \
  | python3 tools/payload_send.py --relay-url https://relay.example.com \
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

# Live WebSocket receive

`payload_ws.py` opens a receiving session on a Relay and writes each message's
original bytes to stdout. Publish that Relay's HTTPS endpoint on the DID with
`openpayload_did.py create --relay-url https://relay.example.com` (or add an
`OpenPayloadRelayService` to an existing DID), then connect before sending.
Install the additional dependency with Python 3.10+:

```sh
python3 -m pip install cryptography 'websockets>=15,<18'
python3 tools/payload_ws.py --did 'did:openpayload:...' \
  --relay-ws-url wss://relay.example.com --device-id cli --once > received.bin
```

Wait for `"status":"listening"` on stderr, then use the existing package/send
pipeline. Omit `--once` to receive continuously; stdout concatenates payload
bytes in arrival order with no added separators. Welcome and receipt notices
go to stderr. `--decryption-key-file` selects a local X25519 PEM key for
encrypted records; plaintext Hello World records need no key. Size and SHA-256
are checked before each write. This tool supports unchunked records from
`payload_package.py`; use the Cache receiver for chunked files. It makes no
Directory or Cache requests, retrieves no earlier messages, and requires a
restart if the WebSocket closes. `--allow-insecure` applies only to WebSocket
TLS verification. See [WebSocket tunnel to stdout](WEBSOCKET_TUNNEL.md) for the
complete Hello World variant and shell redirection examples.

# Cache query and receive

`payload_cache.py` uses the recipient DID's published `OpenPayloadCacheService`
entries. It signs each Cache request with an authorized Ed25519 key, visits every
service and endpoint, and deduplicates message IDs replicated across Caches.
The Directory defaults to `https://directory.openpayload.io`.

For an automation or cron check, this command requests only Cache summary
metadata (IDs and chunk positions), not message envelopes:

```sh
python3 tools/payload_cache.py query --did 'did:openpayload:...' \
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
python3 tools/payload_cache.py receive --did 'did:openpayload:...' \
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
python3 tools/payload_cache.py purge --did 'did:openpayload:...' \
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
python3 -m unittest discover -s tools -p 'test_*.py'
```

## Register an Application or Persona

`openpayload_register.py` registers a Persona or Application through the Directory,
renews DNS verification, and recovers a domain Persona into a replacement DID.
It signs Directory-prepared bytes locally; it never performs SCALE encoding,
chain RPC, or its own DNS lookup. It requires the sibling `openpayload_did.py`.
Use Python on Linux or macOS for the cron and file-locking examples below.

The DNSSEC migration requires runtime **spec 126** and the corresponding
OpenDispatch release. It is prepared locally and has not been deployed. Installing
this tool alone does not enable that runtime capability. Domain Personas require
DNSSEC signing and a valid DS delegation from the parent registrar through to a
configured DNS root trust anchor. Unsigned DNS and Directory attestations are
rejected. Named Personas remain DNS-free.

The Directory collects the complete signed TXT/key/delegation evidence and checks
it using the finalized runtime verifier. It performs all SCALE encoding and RPC;
no Directory account is an approved Persona attestor. The chain independently
verifies the evidence and the operator DID signature when processing a mutation.

DNSSEC algorithms 8, 10, 13 and 14 are supported. Delegated DS digests must use
SHA-256 or SHA-384. The canonical domain is limited to 232 characters so its
challenge name fits DNS limits. Algorithm 15, CNAME challenges,
and wildcard challenges are unsupported. Publish an exact TXT record at the
returned name. TXT signatures must be no more than 48 hours old. DNS challenges
last 48 hours and verification defaults to 365 days; proof validity is also
limited by DNS signature expiration. DID signing keys remain Ed25519.

Existing confirmed domain Personas retain their stored lease. Renewals and
transfers require fresh DNSSEC proof. Unfinished state files created by the old
attestor model are rejected before network activity; start a new challenge with a
new state-file path after upgrading, leaving the original file for reference.

Register a domain Persona and save progress:

```sh
python3 tools/openpayload_register.py persona register \
  --name example.com --operator-did "$DID" --signing-key-file root.key \
  --state-file persona-state.json --output persona-result.json
```

The tool displays the TXT name and value on stderr, then polls the Directory.
Publish the exact value in DNS. `--challenge-only` saves and prints the challenge
without submission. Resume after coordinating with a DNS administrator:

```sh
python3 tools/openpayload_register.py resume --state-file persona-state.json
```

The state file records the issuing Directory URL, exact signed intent, and
progress, with mode `0600`. It contains no private key or email confirmation
token. Keep the signing key at its saved local path, or pass
`--signing-key-file` when resuming. For an encrypted key in unattended operation,
set `OPENPAYLOAD_KEY_PASSWORD` in the process environment.

Register an Application and bind its domain:

```sh
python3 tools/openpayload_register.py application register \
  --application-id example --control-did "$DID" --domain example.com \
  --signing-key-file root.key --state-file application-state.json
```

An Application ID itself does not require DNS and does not expire. `--domain`
requires an active DNS Persona under its control DID. The tool registers or
renews that Persona when necessary, waits for confirmation, then registers the
Application and binds the domain. An existing Persona owned by another DID must
be recovered separately. Multiple Applications can share the same domain and
control DID. A single-label Persona such as `compliance` skips DNS entirely.

### Automation and renewal

Use `persona renew` daily from cron. It renews only within the configured window
(default 30 days before expiry), requesting 365 days by default. It automatically
resumes unfinished matching renewal state. Named Personas have no DNS expiry.

```sh
python3 tools/openpayload_register.py persona renew \
  --name example.com --operator-did "$DID" --signing-key-file /secure/root.key \
  --dns-auth-hook /opt/openpayload/publish-txt \
  --dns-cleanup-hook /opt/openpayload/remove-txt \
  --state-file /var/lib/openpayload/example-renewal.json --non-interactive
```

For example, a cron entry can run the same command at `03:15` each day. Use
absolute paths, provide `DID` and the DNS provider credentials in that job's
environment, and retain its result/error logs. No renewal runs without the local
signing key and fresh domain proof.

Each DNS hook is an executable path, invoked without a shell command string.
It receives the Directory challenge JSON on stdin, including `record_name` and
`record_value`. The authentication hook publishes that exact TXT value; the
cleanup hook removes only that value after confirmed processing. Hooks obtain
provider credentials from their own environment; the Directory receives none.
`--hook-timeout` defaults to 120 seconds.

Common options:

| Option | Behavior |
| --- | --- |
| `--directory-url` | Defaults to `https://directory.openpayload.io`; accepts a hostname without a scheme |
| `--signer-key-id` | Default: infer a published Ed25519 key matching the local key |
| `--controller-key-id` | Repeat to select initial controllers; default is the signer |
| `--verification-days` | 1–365 days, default 365 |
| `--renew-before-days` | Renewal window, default 30 days |
| `--force-renew` | Renew now even outside the normal renewal window |
| `--constraints-file` | Requested Persona delivery constraints JSON |
| `--no-wait` | Return the first accepted `tx_id`; resume finishes remaining phases |
| `--output` | Save the JSON result to a file; `-` means stdout |
| `--timeout` / `--poll-interval` | Default 600 seconds / 10 seconds |
| `--interactive` / `--non-interactive` | Prompt for missing input, or never prompt |
| `--allow-insecure` | Skip TLS verification for CLI testing; DNSSEC remains mandatory |

Every run emits one JSON result. `--output` also saves that result. Exit code
`0` covers confirmation, no renewal due, saved challenge, accepted submission,
or a pending recovery window; `1` covers failure; `2` covers timeout or an unknown
submission outcome. A lost submission response is reconciled against chain
state before retrying. `--no-wait` cannot produce a transaction ID until a proof
has been verified; it reports `awaiting_proof` when submission is not yet possible.

### Recover a domain Persona

Create a replacement DID first and publish its signing key. Then start recovery:

```sh
python3 tools/openpayload_register.py persona recover \
  --name example.com --operator-did "$NEW_DID" --signing-key-file new-root.key \
  --policy preserve --state-file recovery-state.json
```

`--policy preserve` is the default. Recovery retains policy graph rules and
references and assigns the new operator metadata. `--policy clear` atomically
removes the Persona's V2 and V3 policies. Existing Persona delivery constraints
remain in either mode. References to the old DID inside graphs are not rewritten.
The new controller set is bound to the recovery request.

Recovery requires fresh DNSSEC evidence and seven elapsed days. Controller
cancellation records an objection and cannot veto or restart that window. The
former email factor and immediate DNS-plus-email takeover are disabled: a
Directory's mailbox observation cannot be independently verified by the chain.
`--request-email`, `--email-only`, `--email-token-file`, and
`persona recovery-confirm-email` fail before network activity.

The timer begins with the first verified request included in finalized chain
state. DNS proofs last at most 48 hours and can expire sooner with their
signatures, so refresh proof near day seven. Resume preserves the original chain
timer. A pending chain recovery expires after 14 days; expired entries are pruned
when a new request is submitted, with at most eight pending requests per domain.
Directory challenges expire and are periodically purged after 48 hours.

Status and controller objection commands:

```sh
python3 tools/openpayload_register.py persona recovery-status \
  --name example.com --recovery-id '0x<64-hex-characters>'
python3 tools/openpayload_register.py persona recovery-cancel \
  --name example.com --recovery-id '0x<64-hex-characters>' \
  --signing-key-file old-root.key
```

`persona recovery-finalize` submits an eligible recovery explicitly. Ordinary
`resume` handles proof refresh and finalization automatically. You can schedule
`resume --state-file recovery-state.json --non-interactive` to check a pending
recovery; it returns promptly during the seven-day window. DNS hooks are needed
for unattended proof refresh.

Recovery changes the Persona operator. It does not restore a lost DID key or
transfer separately registered Application ownership. Single-label Personas
cannot use domain recovery. No SMTP configuration can authorize chain changes
in the DNSSEC model.

Registration progress is printed to stderr and flushed immediately, including DNS verification, retry waits, accepted transaction IDs and uncertain submission outcomes. JSON results remain on stdout. Use `--quiet` to suppress progress for automation. `resume --no-wait` checks chain state once and returns the saved pending or unknown outcome without resubmitting it. DNS timeout results include the last Directory rejection.

When waiting for DNS, each run prints the exact saved TXT name, value, and
expiry once, including on resume. Publish the value for that state file; a
challenge from an earlier attempt will not satisfy a replacement challenge.
An already completed DNS publishing hook is not rerun merely to redisplay the
instructions. `--quiet` suppresses these stderr instructions; the challenge
remains available in the JSON result.

Ctrl+C returns an `interrupted` JSON result and exit code 130, retaining the
state file and DNS challenge for resume. If interrupted during submission, the
script records an uncertain outcome and checks chain state before any retry.
