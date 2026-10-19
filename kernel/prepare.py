#!/usr/bin/env python3
"""Stage the reviewed source and patch; never modify a kernel installation."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = '5bc8fa46f16a8c977c795eef8b9a41231b70b3eacb0fa4666b500d70b4442991'


def main():
    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'vendor/dm-crypt-v6.12.113.c'
    if hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise RuntimeError('Reviewed dm-crypt source mismatch')
    shutil.copyfile(source, destination / 'dm-crypt.c')
    for name in ('Makefile', 'piv-control.h', 'piv-control.inc', 'piv-native.inc'):
        shutil.copyfile(ROOT / 'kernel' / name, destination / name)
    subprocess.run(['patch', '--batch', '-p1', '-i',
                    str(ROOT / 'kernel/dm-crypt-piv.patch')],
                   cwd=destination, check=True)


if __name__ == '__main__':
    main()
