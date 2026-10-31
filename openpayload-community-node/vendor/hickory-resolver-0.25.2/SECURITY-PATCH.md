# Compatible security backport

Base: crates.io `hickory-resolver 0.25.2`; upstream crate SHA-256 `dc62a9a99b0bfb44d2ab95a7208ac952d31060efc16241c87eaf36406fecf87a`. Upstream source and license headers are retained. `+openpayload.1` identifies a local patch, not an upstream patched release.

Adapt the bogus-answer rejection from hickory-dns commit 92f93c0b889f6a292bc943304d88c4c6561fe1b9 (GHSA-5j98-2g5x-46v6). When DNSSEC verification is enabled, reject answers carrying Proof::Bogus before returning or caching them. This branch already propagates negative-proof Nsec errors and does not attach authority records to those errors. Insecure (unsigned) answers remain permitted. Tests exercise a bogus answer followed by a secure response and a bogus negative proof.

GHSA-6f2x-v7q7-m7m5 concerns the later recursive resolver. This version has no recursor module and its stub follows only answer-section CNAMEs whose owner matches the current query chain. A regression covers irrelevant CNAMEs in all three sections; no extra queries occur. No CNAME source change is claimed.

The omitted dev-only test-support dependency is restored using the existing hickory-proto logging helper. Default node DNS resolution does not enable DNSSEC on this resolver; the fix covers that optional configuration too.

Reference: https://github.com/hickory-dns/hickory-dns/commit/92f93c0b889f6a292bc943304d88c4c6561fe1b9

Other modifications are limited to the local version suffix, standalone test configuration, regression tests, and this provenance note. Remove the patch when the SDK accepts upstream releases containing these fixes. RustSec skips path dependencies: scanner omission alone is not evidence of remediation.
