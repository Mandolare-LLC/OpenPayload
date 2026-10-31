# Native node security release — October 31, 2026

The targeted native security release is deployed and independently verified on four production consensus authorities and two observer/RPC nodes. The existing runtime remains spec 130 / transaction version 6. Genesis, chain specifications, service definitions, node identities and persistent chain state were retained.

## Changes and validation

This release includes the compatible resolver, QUIC, TLS and LRU backports prepared October 29. Wasmtime and its compatible Cranelift packages advance to 36.0.20 to address the additional RUSTSEC-2026-0424 advisory published after the previous patch was prepared. See the historical October 29 report for individual patch provenance and scanner limitations.

Validation passed: 107 security-backport regressions; 192 workspace release tests (excluding the upstream dnssec-prover crate); public-package compilation; macOS isolated block production; and isolated Linux ParityDB block production for x86_64 and aarch64. ARM validation on the builder used QEMU, followed by successful native operation on four ARM production nodes. Both Linux smoke tests also verified the public built-in-genesis guard and exact embedded runtime bytes.

Both architecture builds use frozen public-source snapshot `7b61ea99c8eb`, Rust 1.98.0 and the exact retained runtime SHA-256 `8048955d893a678aadb8d1665b7f848ec2bd49b179fe96a53cdd68778ce3e032`.

| Architecture | Native executable SHA-256 |
| --- | --- |
| Linux aarch64 | `941979465ead0c48ebd7f27a56592e6bb731125ea23de695f410038e0772e4fa` |
| Linux x86_64 | `f3b2ef48206ce4173b3b91d7a3b95111c5bad2a93898b49f85c8156bf915a9c0` |

## Deployment and rollback

An observer canary was verified first, then the remaining observer and each authority were replaced sequentially. Every node passed running-executable checksum, identity/genesis, unchanged runtime/spec/unit, peer/sync, advancing finality and independent-observer checks. Final observations showed all services active with no automatic restarts. The prior executables remain installed for a one-node-at-a-time rollback; restore the recorded prior selector and restart only that service, then verify chain and finality before proceeding. No on-chain upgrade was submitted.

## Remaining security work

The dependency graph is **not audit-clean**. The refreshed RustSec database still reports 11 vulnerability entries, plus 8 unmaintained and 21 unsoundness warnings. Residual findings concern crypto-bigint, Rust h2 HTTP/2, libz-sys, ruzstd, certificate bundles and the zstd family. Some are optional or target-specific; their presence or omission is not an exploitability determination. Local-path backports require source and executable evidence because scanners can skip them. No blanket ignores or advisory dismissals were applied.

The Rust h2 advisory is unrelated to the Java H2 database. PostgreSQL migration does not remediate it. TAL-63 remains open for residual advisory disposition and remediation; the PostgreSQL work remains gated behind security completion.

See `security-release-20261031.json` for checksums, target verification and the complete remaining advisory list. Full operator evidence and artifacts are retained in the private release record. Historical `security-dependencies-20261029.md` remains an accurate record of its earlier, undeployed checkpoint.

Reference: [RUSTSEC-2026-0424](https://rustsec.org/advisories/RUSTSEC-2026-0424.html).
