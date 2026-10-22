# sc-tracing 47.0.0 dependency patch

Source: crates.io sc-tracing 47.0.0 (Polkadot SDK, Apache-2.0).
Only change: permit tracing-subscriber 0.3.23 instead of the exact 0.3.19
pin, to address RUSTSEC-2025-0055. No tracing implementation or runtime
storage changes. Remove this override when the compatible upstream SDK
release relaxes the pin. The original crate metadata retains licensing.
