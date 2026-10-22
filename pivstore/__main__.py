"""Independent read-only image diagnostics. Setup (open-blocks, close-blocks,
keyslot, keygen) is the Rust pivsetup binary; see rust/ and docs/native-blocks.md."""

import argparse
import json
import os
from pathlib import Path
import sys
import subprocess

from .profile import Image, UnsupportedImage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    inspect = sub.add_parser('inspect')
    inspect.add_argument('image', type=Path)
    verify = sub.add_parser('verify')
    verify.add_argument('image', type=Path)
    verify.add_argument('--volume-key-file', type=Path, required=True)
    extract = sub.add_parser('extract-ivs')
    extract.add_argument('image', type=Path)
    extract.add_argument('--output', type=Path, required=True)
    extraction = sub.add_parser('unpack')
    extraction.add_argument('image', type=Path)
    extraction.add_argument('--output', type=Path, required=True)
    extraction.add_argument('--hidden-key-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'unpack':
            from .records_v4 import unpack
            with args.hidden_key_file.open('rb') as stream:
                hidden_key = stream.read(33)
            result = unpack(args.image, args.output, hidden_key)
            print(json.dumps(result, indent=2))
            return 0
        with Image(args.image) as image:
            if args.action == 'inspect':
                result = image.summary()
            elif args.action == 'extract-ivs':
                fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as destination:
                    for iv in image.iv_slots():
                        destination.write(iv)
                result = {'extracted_bytes': image.layout.sectors * image.layout.iv_bytes,
                          'primary_authentication': 'not performed'}
            else:
                with args.volume_key_file.open('rb') as stream:
                    key = stream.read(33)
                result = {'primary_sha256': image.verify(key),
                          'authenticated_sectors': image.layout.sectors}
        print(json.dumps(result, indent=2))
    except (UnsupportedImage, OSError, ValueError, TimeoutError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        print(f'pivstore: {exc}', file=sys.stderr)
        for note in getattr(exc, '__notes__', ()):
            print(f'pivstore: {note}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
