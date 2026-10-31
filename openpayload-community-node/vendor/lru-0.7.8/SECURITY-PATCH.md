# Compatible security backport

Base: crates.io `lru 0.7.8`; upstream crate SHA-256 `e999beba7b6e8345721bd280141ed958096a2e4abdf74f67ff4ce49b4b54e47a`. Upstream source and license headers are retained. `+openpayload.1` identifies a local patch, not an upstream patched release.

Backport lru-rs PR 238, commit 2776ded569ee89a99c515bca8194f65639182c96 (RUSTSEC-2026-0253): unlink pop() nodes before dropping a possibly-panicking key. Adapt the upstream regression test to the older capacity API. This version is unaffected by RUSTSEC-2026-0002 (the advisory excludes <0.9.0), so no iterator change is made.

Reference: https://github.com/jeromefroe/lru-rs/pull/238

Other modifications are limited to the local version suffix, standalone test configuration, regression tests, and this provenance note. Remove the patch when the SDK accepts upstream releases containing these fixes. RustSec skips path dependencies: scanner omission alone is not evidence of remediation.
