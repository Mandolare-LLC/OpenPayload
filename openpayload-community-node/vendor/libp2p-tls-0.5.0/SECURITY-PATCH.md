# Compatible security backport

Base: crates.io `libp2p-tls 0.5.0`; upstream crate SHA-256 `47b23dddc2b9c355f73c1e36eb0c3ae86f7dc964a3715f0731cfad352db4d847`. Upstream source and license headers are retained. `+openpayload.1` identifies a local patch, not an upstream patched release.

Upgrade rcgen to 0.12.1 (ring 0.17) and rustls-webpki to >=0.103.16. This removes ring 0.16.20 and webpki 0.101.7 from the workspace lockfile, addressing RUSTSEC-2025-0009, RUSTSEC-2026-0098/0099/0104 and the newer RUSTSEC-2026-0382. The libp2p transport API is unchanged. Upstream certificate tests (including an expired certificate regression) pass. Public DER fixtures omitted from crates.io come from rust-libp2p commit 302b4c767c0c2274115bacded11eadc944de82cf; they are certificates, not private keys.

References: https://rustsec.org/advisories/RUSTSEC-2025-0009.html and https://rustsec.org/advisories/RUSTSEC-2026-0382.html

Other modifications are limited to the local version suffix, standalone test configuration, regression tests, and this provenance note. Remove the patch when the SDK accepts upstream releases containing these fixes. RustSec skips path dependencies: scanner omission alone is not evidence of remediation.
