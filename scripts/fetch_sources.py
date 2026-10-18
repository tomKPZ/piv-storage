#!/usr/bin/env python3
"""Fetch the small upstream source subset used to review the pinned profile."""

import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    destination = ROOT / 'vendor'
    destination.mkdir(exist_ok=True)
    for entry in json.loads((ROOT / 'environment/sources.json').read_text()):
        path = destination / entry['filename']
        data = path.read_bytes() if path.exists() else urllib.request.urlopen(
            entry['url'], timeout=30).read()
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise RuntimeError(f'Source checksum mismatch: {path.name}')
        if not path.exists():
            path.write_bytes(data)
        print(path.relative_to(ROOT))


if __name__ == '__main__':
    main()
