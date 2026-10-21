#!/usr/bin/env python3
"""Build the newer-kernel port guest image (Debian trixie-backports), in guests.

1. install: boot the provisioned image, install the pinned backports kernel and
   headers (scripts/guest-port-install.sh), compile the staged module against
   them (port-build.log), select that kernel and mark the image
   (/etc/piv-port-kernel) for the guest guards;
2. freeze that run's overlay as a read-only base image under downloads/ with a
   provenance record; 3. verify it boots the port kernel.

Use the result with: suite.py --base-image PATH. Nothing touches the host kernel.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RELEASE = '7.2.9+deb13-amd64'


def vm(script, run_dir, *, shares=(), extra=(), timeout=1800):
    command = [sys.executable, str(ROOT / 'scripts/vm.py'), 'run', '--accel', 'kvm', '--script', str(script),
               '--run-dir', str(run_dir), '--timeout', str(timeout), *extra]
    for path in shares:
        command += ['--share-file', str(path)]
    with open(str(run_dir) + '.log', 'wb') as log:
        if subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT).returncode:
            raise RuntimeError(f'{script.name} failed; see {run_dir}')


def sha256(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--prefix', type=Path, required=True, help='New directory for the runs')
    parser.add_argument('--scaffold', type=Path, required=True, help='Staged module scaffold.tar to test-compile')
    args = parser.parse_args()
    prefix = args.prefix.resolve()
    prefix.mkdir(parents=True, exist_ok=False)
    install = prefix / 'install'
    vm(ROOT / 'scripts/guest-port-install.sh', install, shares=[args.scaffold], extra=['--provisioned'])
    marker = (install / 'share/piv-port-kernel.txt').read_text()
    if f'release={RELEASE}\n' not in marker:
        raise RuntimeError(f'Installed kernel differs from {RELEASE}: {marker}')
    packages = (install / 'share/port-packages.tsv').read_text()
    digest = hashlib.sha256(packages.encode()).hexdigest()[:16]
    image = ROOT / 'downloads' / f'port-kernel-{digest}.qcow2'
    if image.exists():
        raise FileExistsError(f'{image} already exists')
    shutil.copyfile(install / 'guest.qcow2', image)
    image.chmod(0o444)
    provisioned = json.loads(next((ROOT / 'downloads').glob('provisioned-*.json')).read_text())
    image.with_suffix('.json').write_text(json.dumps(dict(
        kind='newer-kernel port image', release=RELEASE, backing=provisioned, image_sha256=sha256(image),
        packages=packages, install_run=str(install),
        note='Derived from the provisioned image (qcow2 backing chain); apt repositories were live. '
             f'Guest guards accept {RELEASE} only with /etc/piv-port-kernel present.'), indent=2) + '\n')
    vm(ROOT / 'scripts/guest-port-verify.sh', prefix / 'verify', extra=['--base-image', str(image)])
    print(image)


if __name__ == '__main__':
    main()
