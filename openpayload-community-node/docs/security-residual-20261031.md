# Follow-up advisory remediation — October 31, 2026

This native-only follow-up is deployed and verified on four consensus authorities and two observer/RPC nodes. It addresses ten of the eleven vulnerability entries left after the initial October 31 release. The crypto-bigint advisory remains open. Production runtime spec 130 / transaction version 6 must retain its exact compressed bytes (SHA-256 `8048955d893a678aadb8d1665b7f848ec2bd49b179fe96a53cdd68778ce3e032`) for this deployment. No runtime upgrade is included.

## Changes and applicability

| Advisory | Resolution | Production applicability |
| --- | --- | --- |
| RUSTSEC-2026-0381 | WebSocket TLS adapter uses webpki-roots 1.0.11 and current rustls anchors; regression excludes the distrusted emSign ECC Root CA G3 SPKI. | Included in native networking. |
| RUSTSEC-2026-0383 | webpki-root-certs 1.0.10. | Platform-specific verifier path, absent default Linux node. |
| RUSTSEC-2026-0418 | libz-sys 1.1.31. | Optional RocksDB build path. The previous locked graph used cc 1.2.66 and static zlib; no environment-secret disclosure is established. |
| RUSTSEC-2026-0410 | zstd-sys 2.1.2, compatible with both older safe wrappers. | Advisory concerns wasm32 allocator shim; native Linux uses a different allocator path. zstd is absent from the no-default-features runtime dependency graph. |
| RUSTSEC-2026-0391 | Backport session resets in zstd 0.13.3 borrowed encoder/decoder constructors, retaining dictionary/parameters. | Native Wasmtime cache uses ordinary encode_all/decode_all; borrowed-context support is nevertheless patched and tested. |
| RUSTSEC-2026-0403 (two versions) | Backport success-only input/output buffer position commits in zstd-safe 6.0.6 and 7.2.4, including every streaming wrapper. | Both wrappers are in native graph. Production has std enabled, legacy disabled. Malformed legacy cases are tested explicitly. |
| RUSTSEC-2026-0398 | Backport end-of-stream clamping and FFI output-count validation in zstd-safe 7.2.4, including extreme u64 offsets. | Seekable feature is disabled in production; explicitly enabled for regressions. |
| RUSTSEC-2026-0258 | Backport bounded connection-wide small-DATA framing overhead and discard empty non-final events in h2 0.3.27. | Optional igd-next/hyper 0.14 path; absent default Linux node. Active HTTP/2 is h2 0.4.20. |
| RUSTSEC-2026-0344 | Backport decoded-block limit min(window, 128 KiB) in ruzstd 0.8.3. Additional checks reject oversized literal/sequence output before allocation/copy and include trailing literals. | Optional smoldot path; absent default Linux node. |

These remain compatible local forks at their original version numbers, rather than being represented as new official upstream releases. Their licenses and original package metadata are retained. `security-residual-provenance-20261031.json` identifies original registry archive hashes and every changed/new file.

Upstream patch sources:

* [WebPKI trust-store update](https://github.com/rustls/webpki-roots/pull/133).
* [zstd context isolation](https://github.com/gyscos/zstd-rs/commit/74ace2dcdca62a2ce0f034895d6079458311e003), [stream error handling](https://github.com/gyscos/zstd-rs/commit/006e1d1ad1eeaf6b5d4c28329e70217adabcec43), [seek bounds](https://github.com/gyscos/zstd-rs/commit/80506be743fae2ed0c2fe8b21c374c6a2eab0be7).
* [HTTP/2 DATA framing budget](https://github.com/hyperium/h2/commit/c4de88e687fcd18f057059ae31330f039735f099).
* [ruzstd decoded-block bounds](https://github.com/KillingSpark/zstd-rs/commit/d3907c960ca4a1aa44cc38340137c5679dd98f5a).
* [libz build-script fix](https://github.com/rust-lang/libz-sys/pull/280), [zstd wasm allocator fix](https://github.com/gyscos/zstd-rs/commit/165d1625553c236b9700ca794b8a7c51f5d98314).

## Verification

The new reproducible runner, `python3 scripts/check-residual-security.py --online` on its first run, downloads hash-pinned public upstream test corpora into an ignored build cache and tests isolated copies of the selected source. Later runs are offline. Large corpora are excluded from the distributable source tree. It runs 547 tests: WebSocket 8, zstd-safe 6.x 6, zstd-safe 7.x 11, zstd 34, h2 library 419, raw-wire empty/tiny DATA floods 2, and ruzstd 67. The h2 suite retains one pre-existing ignored test. Standalone test dependencies resolve separately from the locked node dependency graph.

The full locked workspace release suite passed 192 tests, excluding the upstream dnssec-prover crate. All 107 previous backport regressions passed as a separate check. The macOS release and both Linux architectures passed isolated ParityDB block production, the public genesis guard and exact retained-runtime byte checks. ARM smoke on the builder used QEMU, followed by native production verification. Safe negative controls reproduced failures against original h2, both original zstd-safe versions and original zstd context constructors.

## Open crypto gate: RUSTSEC-2026-0387

crypto-bigint 0.5.5 is selected by elliptic-curve 0.13.8 (`^0.5`), including k256 0.13.4 through sp-core/frame-support. The [fixed upstream release](https://github.com/RustCrypto/crypto-bigint/pull/1365) is 0.7.6, outside this API requirement. Both native and no-default-features runtime graphs include this package. This advisory is **not remediated or dismissed** by the native follow-up.

The 0.7 fixes cannot be applied mechanically to 0.5: UintRef and BoxedMontyForm do not exist there, limb subtraction and Montgomery reduction use different implementations, and 0.5 division explicitly documents variability with respect to the divisor. Source similarity alone does not demonstrate constant-time behavior after optimization. Do not copy individual 0.7 patches and claim that the complete advisory is fixed.

The next crypto change must either use a supported SDK/RustCrypto combination selecting the fixed package, or a reviewed 0.5 compatibility backport covering the applicable primitives. Acceptance requires differential arithmetic/signature tests, no_std/Wasm compilation, constant-time analysis of optimized code for both Linux architectures, runtime/state/weight compatibility qualification and a separately versioned runtime release if the Wasm changes. Unit tests or timing averages alone are insufficient constant-time evidence. Prepare the runtime and upgrade artifacts for the established offline signing/review process; never replace the retained runtime implicitly during a native binary rollout.

The refreshed audit reports one vulnerability entry (crypto-bigint), eight unmaintained warnings and three unsoundness warnings. Scanner counts decrease partly because local path dependencies are omitted; prior warnings on vendored packages remain review obligations. No blanket ignore or alert dismissal has been added. TAL-63 stays In Progress, and PostgreSQL cutover work remains gated.

## Verified native deployment

Both Linux builds use frozen public-source snapshot `11c8a2df20f4` and Rust 1.98.0. The published report adds deployment evidence after that source freeze; node code is unchanged from the frozen build input.

| Architecture | Executable SHA-256 |
| --- | --- |
| Linux aarch64 | `66ddd7e7edfb31d1602fc314dc5ed887fedd752b6f56ca9891b0895571afb33a` |
| Linux x86_64 | `6744155a442ac68570f7a3f5c302e16b7cebca166fd59a4d90433ea08814833b` |

An observer canary passed first, then the other observer and each authority were updated sequentially. All four authorities were checked before each authority restart. Selected and running executable checksums, unchanged runtime/genesis/spec/service hashes, peers, sync status and independent advancing finality passed throughout. Final observations showed six active nodes, five peers each and zero automatic restarts, with finalized blocks 718403–718404. Directory, Relay, Cache and push health checks passed. The temporary release builder is confirmed stopped.

The previous executables remain installed. Rollback restores the recorded previous selector and restarts one service at a time, verifying health and independent finality before continuing. No chain keys, persistent state, service definitions or on-chain code were changed. Full operator evidence remains private; the companion JSON contains public aggregate results.

Crypto exposure review found that native std sp-core ECDSA signing selects the separate secp256k1 backend; the inspected frame-support k256 path handles public-key uncompression/address derivation. p256 is a delivery-policy test dependency. These observations narrow the identified exposure but do not establish complete constant-time safety or remediate RUSTSEC-2026-0387. The compatible crypto fix and separate runtime qualification remain the next security gate before PostgreSQL cutover.
