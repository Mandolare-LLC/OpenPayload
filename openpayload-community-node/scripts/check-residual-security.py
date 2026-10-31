#!/usr/bin/env python3
"""Test residual security backports, including optional compression/HTTP2 paths.

Use --online once to cache hash-pinned public test fixtures and Cargo test
requirements. Later runs work offline. Tests run in isolated source copies;
large upstream corpora are never copied into the distributable node sources.
The actual production dependency graph is tested separately with --locked.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = {
    'h2': ('hyperium/h2', 'f6237accb3e37668a8d7fb2331f22eb7b808c1e8',
           '93036db9036946897c7b6955f5d522850a0420316c4b45765a1396967613b719'),
    'zstd': ('gyscos/zstd-rs', '52e9d41a645fb49edcf1ed3df765f380dbcf13b2',
             'eae36dcfdb49b89a128e3168cede00b4d48ddc3e3ba9969909cb94aa408f9a50'),
    'ruzstd': ('KillingSpark/zstd-rs', '1c7aafb8e668f9ea2f44e6155bb7429e2442a3c1',
               'd9111bf16992af8bb6dd53437167a189ce253114c3533766a6812fd873d7ab36'),
}
CRATES = ['libp2p-websocket-0.44.0', 'zstd-0.13.3', 'zstd-safe-6.0.6',
          'zstd-safe-7.2.4', 'h2-0.3.27', 'ruzstd-0.8.3']


def add_fixtures(archive, destination, prefix, selected):
    with tarfile.open(archive) as stream:
        for member in stream:
            if not member.isfile() or not member.name.startswith(prefix):
                continue
            relative = Path(member.name[len(prefix):])
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('Unsafe fixture archive path')
            if not selected(relative.as_posix()):
                continue
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(stream.extractfile(member).read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--online', action='store_true')
    args = parser.parse_args()
    cache = Path(os.environ.get('OPENPAYLOAD_SECURITY_FIXTURE_CACHE', ROOT/'target/security-upstream'))
    cache.mkdir(parents=True, exist_ok=True)
    for name, (repository, revision, digest) in FIXTURES.items():
        archive = cache / (name + '.tar.gz')
        if not archive.exists():
            if not args.online:
                parser.error('Missing fixture archive; run once with --online: ' + str(archive))
            subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                            'https://codeload.github.com/' + repository + '/tar.gz/' + revision,
                            '-o', str(archive)], check=True)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise ValueError('Fixture archive checksum mismatch: ' + str(archive))
    env = dict(os.environ)
    env.setdefault('CARGO_TARGET_DIR', str(ROOT/'target/security-regressions'))
    with tempfile.TemporaryDirectory(prefix='openpayload-residual-tests-') as directory:
        work = Path(directory)
        for crate in CRATES:
            shutil.copytree(ROOT/'vendor'/crate, work/crate,
                            ignore=shutil.ignore_patterns('target', 'Cargo.lock', '.cargo-ok',
                                                         'fixtures', 'decodecorpus_files', 'dict_tests', 'fuzz'))
        add_fixtures(cache/'h2.tar.gz', work/'h2-0.3.27',
                     'h2-' + FIXTURES['h2'][1] + '/', lambda p: p.startswith('fixtures/'))
        add_fixtures(cache/'zstd.tar.gz', work/'zstd-0.13.3',
                     'zstd-rs-' + FIXTURES['zstd'][1] + '/',
                     lambda p: p.startswith('assets/') or p == 'zstd-safe/zstd-sys/src/bindings_zstd.rs')
        add_fixtures(cache/'ruzstd.tar.gz', work/'ruzstd-0.8.3',
                     'zstd-rs-' + FIXTURES['ruzstd'][1] + '/ruzstd/',
                     lambda p: p.startswith(('decodecorpus_files/', 'dict_tests/', 'fuzz/artifacts/decode/')))

        def cargo(crate, *options):
            command = ['cargo', 'test', '--manifest-path', str(work/crate/'Cargo.toml')]
            if not args.online:
                command.append('--offline')
            subprocess.run(command + list(options), cwd=work/crate, env=env, check=True)

        cargo('libp2p-websocket-0.44.0', '--lib')
        cargo('zstd-safe-6.0.6', '--features', 'std', '--lib')
        cargo('zstd-safe-7.2.4', '--features', 'std,seekable', '--lib')
        cargo('zstd-0.13.3', '--lib')
        cargo('h2-0.3.27', '--lib')
        cargo('h2-0.3.27', '--test', 'openpayload_data_budget')
        cargo('ruzstd-0.8.3', '--lib')


if __name__ == '__main__':
    main()
