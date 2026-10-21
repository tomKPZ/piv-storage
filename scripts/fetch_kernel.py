#!/usr/bin/env python3
"""Stage the complete standalone dm-piv module for an in-guest build.

The module no longer vendors or patches dm-crypt, so no kernel source archive
is needed; the build uses the pinned guest's signed matching headers package.
Kept under this name so existing reproduction commands remain valid.
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    destination = Path(sys.argv[1]).resolve()
    subprocess.run([sys.executable, str(ROOT / 'kernel/prepare.py'), str(destination)], check=True)
    print(f'Staged standalone module: {destination}')


if __name__ == '__main__':
    main()
