# Compatible security backport

Base: crates.io `lru 0.12.5`; upstream crate SHA-256 `234cf4f4a04dc1f57e24b96cc0cd600cf2af460d4161ac5ecdd0af8e1f3b2a38`. Upstream source and license headers are retained. `+openpayload.1` identifies a local patch, not an upstream patched release.

Backport lru-rs PR 224 (commits b9bca3492d75139097df3b018b6abdf5825ee868 and 25669e76110133c73d72f1db0069934ba590162a), RUSTSEC-2026-0002: IterMut borrows keys immutably instead of temporarily creating exclusive key references. Also backport PR 238, commit 2776ded569ee89a99c515bca8194f65639182c96, RUSTSEC-2026-0253: unlink pop() nodes before dropping a possibly-panicking key. Include both upstream regression tests.

References: https://github.com/jeromefroe/lru-rs/pull/224 and https://github.com/jeromefroe/lru-rs/pull/238

Other modifications are limited to the local version suffix, standalone test configuration, regression tests, and this provenance note. Remove the patch when the SDK accepts upstream releases containing these fixes. RustSec skips path dependencies: scanner omission alone is not evidence of remediation.
