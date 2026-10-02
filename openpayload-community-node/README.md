# OpenPayload community full node

This directory contains the source needed to build a non-authority OpenPayload
full node. The runtime and its pallets are included because the node depends on
them to compile and verify chain state. This source does not include operator
infrastructure, signing material, launch ceremonies, or private deployment
documentation.

The current runtime source targets spec version 123. The included raw chain
specification defines the permanent network genesis and advertises four current
authority P2P bootnodes. It contains public chain data, not signing material.
The raw spec contains the original genesis runtime; nodes follow the chain's
subsequent upgrades to reach the current runtime.

## Build

Use the Rust toolchain pinned in `rust-toolchain.toml`:

```sh
cargo build --locked --release -p openpayload-node
```

The binary is `target/release/openpayload-node`.

Building requires a C/C++ compiler and LLVM/Clang with `libclang` available for
the RocksDB dependency. On macOS with Command Line Tools, if the build cannot
find `libclang.dylib`, set `LIBCLANG_PATH` and `DYLD_LIBRARY_PATH` to
`/Library/Developer/CommandLineTools/usr/lib` and retry.

## Join the live network

The canonical live raw chain specification is
[`chain-spec/openpayload.raw.json`](chain-spec/openpayload.raw.json). Verify its
SHA-256 against [`chain-spec/SHA256SUMS`](chain-spec/SHA256SUMS) before starting.
Its expected genesis hash is
`0x359e9cc1d491594fa3428f19cde68ad5d2ef8442de0367dcd039455f3180fd7e`;
confirm this from your own node after it starts.

Run an ordinary full node with the verified specification:

```sh
./target/release/openpayload-node \
  --chain chain-spec/openpayload.raw.json \
  --sync warp \
  --base-path /absolute/path/to/node-data \
  --name community-full-node \
  --rpc-methods safe
```

Use warp sync for a fresh node. It verifies chain finality, downloads current
state, and then follows new blocks. The advertised peers did not serve the
earliest blocks during our full-sync test, so a default sync from genesis
stayed at block zero. Warp sync does not provide historical block bodies; an
archive node or a suitable snapshot is needed if you require complete history.

Do not add `--validator` or install authority, sudo, sponsor, or resource-validator
keys. Keep RPC bound to loopback unless you have separately secured a public RPC
service. The node's built-in `openpayload` chain-spec alias is a launch scaffold;
this distribution refuses to run it as a live chain.

The development and local presets are only for disposable testing.

## Verify the source

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

## Security and licensing

Report suspected vulnerabilities using the parent repository's
[Security Policy](../.github/SECURITY.md). Do not post exploit details in a
public issue.

Project-authored source is released under the [Unlicense](LICENSE). The
upstream-derived `runtime/src/genesis_config_presets.rs` retains its
Apache-2.0 notice; see [LICENSE-APACHE](LICENSE-APACHE).
