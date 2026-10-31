#!/usr/bin/env python3
"""Run security-backport regressions with the repository's pinned toolchain.

Defaults to offline operation; pass --online once to fetch vendor test dependencies.
Build the actual node separately with cargo build --release --locked -p openpayload-node.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--online', action='store_true')
    args = parser.parse_args()
    env = dict(os.environ)
    env.setdefault('CARGO_TARGET_DIR', str(ROOT / 'target' / 'security-regressions'))
    def cargo(*command):
        subprocess.run(['cargo', command[0], *([] if args.online else ['--offline']), *command[1:]], cwd=ROOT, env=env, check=True)
    for crate in ['lru-0.12.5', 'lru-0.7.8', 'libp2p-tls-0.5.0', 'libp2p-quic-0.11.1']:
        cargo('test', '--manifest-path', str(ROOT/'vendor'/crate/'Cargo.toml'), '--lib')
    cargo('test', '--manifest-path', str(ROOT/'vendor/hickory-resolver-0.25.2/Cargo.toml'), '--features', 'dnssec-ring', '--lib', 'openpayload_')
    cargo('test', '--manifest-path', str(ROOT/'vendor/libp2p-quic-0.11.1/Cargo.toml'), '--features', 'tokio', '--test', 'smoke', 'tokio_smoke', '--', '--exact')
    with tempfile.TemporaryDirectory(prefix='openpayload-yamux-regression-') as directory:
        project = Path(directory)
        (project/'src').mkdir()
        (project/'Cargo.toml').write_text(MANIFEST)
        (project/'src/lib.rs').write_text(TESTS)
        cargo('test', '--manifest-path', str(project/'Cargo.toml'))

MANIFEST = r"""[package]
name = "openpayload-network-regressions"
version = "0.0.0"
edition = "2021"
[dependencies]
yamux012 = { package = "yamux", version = "=0.12.1" }
yamux013 = { package = "yamux", version = "=0.13.10" }
futures = "0.3.32"
"""

TESTS = r"""#[cfg(test)]
mod tests {
    use futures::{executor::block_on, future::poll_fn, io::Cursor};
    fn oversized_data_syn() -> Cursor<Vec<u8>> {
        let mut frame = vec![0, 0, 0, 1, 0, 0, 0, 1];
        frame.extend_from_slice(&262145u32.to_be_bytes());
        frame.resize(12 + 262145, 0);
        Cursor::new(frame)
    }
    #[test]
    fn legacy_yamux_rejects_oversized_data_syn_without_panicking() {
        let mut c = yamux012::Connection::new(oversized_data_syn(), yamux012::Config::default(), yamux012::Mode::Server);
        assert!(!matches!(block_on(poll_fn(|cx| c.poll_next_inbound(cx))), Some(Ok(_))));
    }
    #[test]
    fn current_yamux_rejects_oversized_data_syn_without_panicking() {
        let mut c = yamux013::Connection::new(oversized_data_syn(), yamux013::Config::default(), yamux013::Mode::Server);
        assert!(!matches!(block_on(poll_fn(|cx| c.poll_next_inbound(cx))), Some(Ok(_))));
    }
}
"""

if __name__ == '__main__':
    main()
