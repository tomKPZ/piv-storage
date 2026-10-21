#!/usr/bin/env python3
"""Build the sanitizer (KASAN/UBSAN/lockdep) guest image, entirely in guests.

1. build: compile the debug kernel packages in a large disposable guest
   (scripts/guest-debug-kernel.sh), unless --debs-from reuses a finished run;
2. install: boot the provisioned image, install and select the debug kernel
   and mark the image (/etc/piv-debug-kernel) for the guest guards;
3. freeze that run's overlay as a read-only base image under downloads/ with a
   provenance record; 4. verify it boots the sanitizer kernel.

Use the result with: vm.py run --base-image PATH (or suite.py --base-image).
Nothing touches the host kernel.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RELEASE = '6.12.113+deb13-amd64-pivdbg'


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
    parser.add_argument('--debs-from', type=Path, help='Finished guest-debug-kernel run directory to reuse')
    args = parser.parse_args()
    prefix = args.prefix.resolve()
    prefix.mkdir(parents=True, exist_ok=False)
    build = args.debs_from.resolve() if args.debs_from else prefix / 'build'
    if not args.debs_from:
        vm(ROOT / 'scripts/guest-debug-kernel.sh', build, extra=['--provisioned', '--smp', '32',
           '--memory-mib', '32768'], timeout=5400)
    debs = sorted((build / 'share').glob(f'linux-*-{RELEASE}_*.deb'))
    if len(debs) != 2:
        raise RuntimeError(f'Expected linux-image and linux-headers packages in {build}/share')
    install = prefix / 'install'
    vm(ROOT / 'scripts/guest-debug-install.sh', install, shares=debs, extra=['--provisioned'])
    digest = hashlib.sha256(''.join(sha256(d) for d in debs).encode()).hexdigest()[:16]
    image = ROOT / 'downloads' / f'debug-kernel-{digest}.qcow2'
    if image.exists():
        raise FileExistsError(f'{image} already exists')
    shutil.copyfile(install / 'guest.qcow2', image)
    image.chmod(0o444)
    provisioned = json.loads(next((ROOT / 'downloads').glob('provisioned-*.json')).read_text())
    image.with_suffix('.json').write_text(json.dumps(dict(
        kind='sanitizer debug kernel image', release=RELEASE, backing=provisioned, image_sha256=sha256(image),
        debs={d.name: sha256(d) for d in debs}, build_run=str(build), install_run=str(install),
        config=(build / 'share/debug-config-check.txt').read_text(),
        note='Derived from the provisioned image (qcow2 backing chain). Guest guards accept '
             f'{RELEASE} only with /etc/piv-debug-kernel present.'), indent=2) + '\n')
    vm(ROOT / 'scripts/guest-debug-verify.sh', prefix / 'verify', extra=['--base-image', str(image),
       '--memory-mib', '2048'])
    print(image)


if __name__ == '__main__':
    main()
