# Compatible security backport

Base: crates.io `libp2p-quic 0.11.1`; upstream crate SHA-256 `46352ac5cd040c70e88e7ff8257a2ae2f891a4076abad2c439584a31c15fd24e`. Upstream source and license headers are retained. `+openpayload.1` identifies a local patch, not an upstream patched release.

Backport rust-libp2p commit e8f35e12c2418b04df6e9cdf036005e8aee3c7a2 (GHSA-5hq8-qhww-jm7q). Return a QUIC protocol error for missing/unexpected peer identity, empty certificates, and certificate revalidation failure instead of panicking. The identity conversion is factored into a private helper for four regression tests. Add quinn-proto 0.11 to construct the upstream transport error. Default node features do not enable QUIC, but the optional transport is patched and independently tested.

Reference: https://github.com/libp2p/rust-libp2p/commit/e8f35e12c2418b04df6e9cdf036005e8aee3c7a2

Other modifications are limited to the local version suffix, standalone test configuration, regression tests, and this provenance note. Remove the patch when the SDK accepts upstream releases containing these fixes. RustSec skips path dependencies: scanner omission alone is not evidence of remediation.
