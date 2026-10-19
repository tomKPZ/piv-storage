#!/usr/bin/env python3
"""Boot private test initramfs on RAM root; attach no persistent OS filesystem."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--initrd', type=Path, required=True)
    parser.add_argument('--data-image', type=Path, required=True)
    parser.add_argument('--run-dir', type=Path, required=True)
    args = parser.parse_args()
    run = args.run_dir.resolve()
    run.mkdir(mode=0o700, parents=True, exist_ok=False)
    data = run / 'control.img'
    shutil.copyfile(args.data_image, data)
    # Keep the test device named vdb, as required by the strict guest guard.
    dummy = run / 'empty-boot-disk.img'
    with dummy.open('wb') as stream:
        stream.truncate(1024 * 1024)
    command = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-cpu', 'max',
               '-m', '1024', '-smp', '2', '-nographic', '-no-reboot',
               '-kernel', str(args.kernel.resolve()), '-initrd', str(args.initrd.resolve()),
               '-append', 'console=ttyS0 panic=1 rdinit=/init',
               '-drive', f'file={dummy},format=raw,if=virtio',
               '-drive', f'file={data},format=raw,if=virtio']
    with (run / 'console.log').open('wb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    output = (run / 'console.log').read_bytes()
    if (result.returncode or b'PIV_EARLY_BOOT_EXIT=0' not in output or
            b'PIV_EARLY_BOOT_PASS:' not in output):
        raise RuntimeError(f'RAM-root boot test failed; inspect {run}/console.log')
    print(f'RAM-root early activation passed: {run}')


if __name__ == '__main__':
    main()
