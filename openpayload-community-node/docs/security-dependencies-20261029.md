# Dependency security update — 2026-10-29

This change addresses the ten reported community-node Dependabot alerts while retaining the pinned Polkadot SDK APIs. It changes node dependencies, not pallet behavior or application endorsement state. The production runtime and genesis are not upgraded by this work.

## Changes and alert disposition

| Alert | Dependency | Resolution |
| --- | --- | --- |
| #10 | Wasmtime / Cranelift | Wasmtime 36.0.18 → 36.0.19, including compatible Cranelift packages. Fixes GHSA-897f-g5gm-fmxm and the additional AArch64 `br_table` advisory RUSTSEC-2026-0379. |
| #9 | libp2p-quic | Backport upstream post-handshake certificate error propagation to 0.11.1+openpayload.1. Optional QUIC is absent from default node features but is built and tested separately. |
| #8, #7, #6 | rustls-webpki | Remove 0.101.7 by updating the compatible libp2p TLS dependency. Resolve 0.103.16, also addressing newer RUSTSEC-2026-0382. |
| #3 | ring | Remove 0.16.20 by changing the TLS certificate generator to rcgen 0.12.1. Retain ring 0.17.14. |
| #4 | lru | Backport the iterator fix to 0.12.5+openpayload.1. Also backport the separately discovered `pop()` panic-safety fix to both 0.7.8+openpayload.1 and 0.12.5+openpayload.1. |
| #1 | hickory-resolver | Backport bogus-answer rejection before return/cache to 0.25.2+openpayload.1. Its negative-proof errors already propagate. Legacy 0.24.4 uses error-based verification and filters out unverified records; it does not use the newer proof-status API described by the advisory. Default node resolver features do not enable DNSSEC on either resolver. |
| #2 | hickory-resolver | The affected recursive-resolver routine is absent from both locked resolver versions. Their stub CNAME chains already follow matching answer records only. A regression confirms irrelevant answer, authority, and additional CNAMEs cause no follow-up queries on 0.25.2. No CNAME source fix or upstream upgrade is claimed. |
| #5 | yamux | 0.13.10 already contains the upstream fix. The legacy 0.12.1 implementation rejects oversized SYN Data before stream creation. A real malformed-frame test passes against both versions; no source patch or advisory dismissal is claimed for this alert. |

The scanner's broad version ranges can continue to flag legacy resolver and Yamux versions even where their implementation lacks the reported behavior. Upstream range corrections or a separately reviewed alert disposition may be necessary. This change does not dismiss alerts or relabel old code as an upstream patched release.

## Backport evidence

Each new vendor directory contains `SECURITY-PATCH.md` with the upstream crate checksum, source commit or pull request, exact scope, and regression evidence. Existing crate licenses and source headers are retained. The `+openpayload.1` suffix identifies local source modifications.

RustSec skips local path dependencies and does not include every GHSA-only advisory. A scanner omission is not proof of remediation. Source comparison and executable regression tests substantiate the backports.

Relevant upstream sources:

- [Wasmtime security advisory](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-897f-g5gm-fmxm)
- [QUIC patch](https://github.com/libp2p/rust-libp2p/commit/e8f35e12c2418b04df6e9cdf036005e8aee3c7a2)
- [Resolver DNSSEC patch](https://github.com/hickory-dns/hickory-dns/commit/92f93c0b889f6a292bc943304d88c4c6561fe1b9)
- [CNAME advisory](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-6f2x-v7q7-m7m5)
- [Yamux advisory](https://github.com/libp2p/rust-yamux/security/advisories/GHSA-vxx9-2994-q338)
- [LRU iterator patch](https://github.com/jeromefroe/lru-rs/pull/224), [panic-safety patch](https://github.com/jeromefroe/lru-rs/pull/238)

## Verification

Run the reusable regression suite from the workspace root:

```sh
python3 scripts/check-security-backports.py --online
```

Subsequent runs may omit `--online`. The suite runs both LRU unit suites, TLS certificate tests, QUIC identity-error regressions and a local QUIC connection, resolver DNSSEC/CNAME regressions, and malformed-frame tests for both Yamux branches. The temporary Yamux project is generated outside the repository; no extra vulnerable test lockfile is published. Test build outputs and standalone vendor lockfiles are ignored.

Build the actual node separately:

```sh
cargo build --release --locked -p openpayload-node
```

On macOS the documented `LIBCLANG_PATH` and `DYLD_FALLBACK_LIBRARY_PATH` settings in `rust-setup.md` are required for RocksDB. The patched release node was started on an isolated temporary development chain and produced a block using the updated Wasmtime executor.

The public community package receives the same dependency changes while retaining its own license, workspace membership, runtime source, and node restrictions. The public lockfile excludes operator-only tools.

## Remaining audit findings

A fresh RustSec scan found **19 vulnerability entries before these changes and 11 afterward**, plus existing informational/unsoundness warnings. These counts are RustSec entries, not the ten supplied Dependabot alerts. The remaining findings involve crypto-bigint, h2, libz-sys, ruzstd, certificate root bundles, and zstd/zstd-safe/zstd-sys. Some are optional or target-specific; presence in a dependency tree does not establish exploitability.

`security-dependencies-20261029.json` records the exact advisory IDs, versions, patched ranges, database revision, default-tree presence, warning counts, and lockfile hash. Several remaining fixes require breaking dependency changes or SDK-compatible backports and are outside this targeted patch. The dependency graph is **not audit-clean**.

No production node was replaced, no runtime upgrade was submitted, and no security alerts were dismissed. Shipping these changes requires committing/publishing the source, building the intended deployment target, and a separate production rollout.
