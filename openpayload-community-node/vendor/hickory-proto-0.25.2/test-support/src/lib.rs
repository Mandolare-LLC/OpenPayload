//! Test-only replacement for the upstream workspace logging helper omitted from crates.io.
pub fn subscribe() { let _ = tracing_subscriber::fmt().with_test_writer().try_init(); }
