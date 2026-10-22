# Vendored DNSSEC verifier

Source: dnssec-prover 0.6.8 from crates.io, MIT/Apache-2.0.

The only validation change is `verify_rr_stream_with_trust_anchors`, which accepts authenticated caller-provided root DS records instead of consulting compiled-in root hints. The existing upstream entry point remains unchanged. The runtime exclusively uses the explicit-anchor entry point. Cryptographic verification and DNS canonicalization remain upstream code.

The pallet adds strict proof/record/key/signature bounds and accepts only exact TXT records with non-wildcard signatures. Algorithms 8, 10, 13 and 14 are supported; unsupported algorithms fail closed.

The upstream root-DNSKEY test fixture calls `root_hints()` rather than referring to the function item, allowing its library tests to compile. This test-only correction does not change runtime verification.
