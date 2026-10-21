#!/usr/bin/env python3
"""Stage the standalone module sources; never modify a kernel installation."""
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = ('Makefile', 'dm-piv.c', 'piv-control.h', 'piv-control.inc', 'piv-native.inc')


def main():
    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    for name in FILES:
        shutil.copyfile(ROOT / 'kernel' / name, destination / name)


if __name__ == '__main__':
    main()
