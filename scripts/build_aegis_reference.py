#!/usr/bin/env python3
"""Build the pinned SUPERCOP oracle for diagnostics only (x86 AES-NI)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    entry = next(e for e in json.loads((ROOT / 'environment/sources.json').read_text())
                 if e['filename'] == 'aegis128-supercop.c')
    source = ROOT / 'vendor' / entry['filename']
    if hashlib.sha256(source.read_bytes()).hexdigest() != entry['sha256']:
        raise RuntimeError('Reference source checksum mismatch; run scripts/fetch_sources.py')
    if 'aes' not in Path('/proc/cpuinfo').read_text().split():
        raise RuntimeError('This diagnostic reference requires x86 AES-NI')
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'crypto_aead.h').write_text('/* SUPERCOP supplies this generated header; no declarations needed here. */\n')
    target = args.output / 'libaegis128-reference.so'
    subprocess.run(['cc', '-O2', '-std=gnu99', '-maes', '-msse2', '-shared', '-fPIC',
                    '-I', str(args.output), str(source), '-o', str(target)], check=True)
    print(target.resolve())


if __name__ == '__main__':
    main()
