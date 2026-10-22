# Compatible security backports

Source: crates.io hickory-proto 0.24.4 (MIT OR Apache-2.0), unmodified upstream files except the changes listed below.

- RUSTSEC-2026-0119: adapt hickory-dns PR 3613's limits of 64 stored compression candidates and 120 compressed names per message; skip searches for canonical names. Upstream commits c7c366bffc742b10d3608b694078dc2fe38e7491, 560f7d6ab57d41c83222be5dbdf5584d43841c30, 21208ce33a92c7eb9b1f0a947ce361f05b14caf4. https://github.com/hickory-dns/hickory-dns/pull/3613

The +openpayload.1 version identifies this source patch; it is not an upstream release. Added regression tests cover the changed behavior. Remove the local patch when the SDK moves to compatible upstream releases containing these fixes. Do not treat an audit scanner skipping a local source as independent evidence of remediation.
