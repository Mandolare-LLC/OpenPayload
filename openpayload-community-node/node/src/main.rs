//! OpenPayload node CLI binary.
#![allow(clippy::result_large_err)]
#![warn(missing_docs)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
mod chain_spec;
mod cli;
mod command;
mod rpc;
mod service;

fn main() -> sc_cli::Result<()> {
    command::run()
}
