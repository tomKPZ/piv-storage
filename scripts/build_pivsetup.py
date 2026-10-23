#!/usr/bin/env python3
"""Build the static pivsetup binary rootlessly on the host.

Uses the system rustc/cargo, a project-local CARGO_HOME under ignored
downloads/cargo, the committed Cargo.lock (--locked) and static glibc
(-C target-feature=+crt-static). Prints the binary path and SHA-256.

The default build is the release binary (no PIVSETUP_TEST_* hooks; what
packaging/install.sh installs). --test-hooks builds the guest-test binary with
the `test-hooks` cargo feature into its own target directory.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'x86_64-unknown-linux-gnu'
BINARY = ROOT / 'rust/target' / TARGET / 'release/pivsetup'
HOOKS_TARGET_DIR = ROOT / 'rust/target/test-hooks'
HOOKS_BINARY = HOOKS_TARGET_DIR / TARGET / 'release/pivsetup'


def build(quiet=False, test_hooks=False):
    env = dict(os.environ, CARGO_HOME=str(ROOT / 'downloads/cargo'),
               RUSTFLAGS='-C target-feature=+crt-static')
    output = subprocess.DEVNULL if quiet else None
    # Fetch once (network) into the ignored cache; builds then run offline.
    subprocess.run(['cargo', 'fetch', '--locked'], cwd=ROOT / 'rust', env=env, check=True,
                   stdout=output, stderr=output)
    command = ['cargo', 'build', '--release', '--locked', '--offline', '--target', TARGET]
    binary = BINARY
    if test_hooks:
        command += ['--features', 'test-hooks', '--target-dir', str(HOOKS_TARGET_DIR)]
        binary = HOOKS_BINARY
    subprocess.run(command, cwd=ROOT / 'rust', env=env, check=True, stdout=output, stderr=output)
    description = subprocess.run(['file', '-b', str(binary)], capture_output=True, text=True).stdout
    if 'static' not in description:
        raise RuntimeError(f'pivsetup is not statically linked: {description.strip()}')
    return binary


def main():
    path = build(quiet='--quiet' in sys.argv, test_hooks='--test-hooks' in sys.argv)
    print(path)
    print(hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
