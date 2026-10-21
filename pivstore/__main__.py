"""Native paired block devices and independent read-only image diagnostics."""

import argparse
import json
import os
from pathlib import Path
import sys
import subprocess
import secrets

from .profile import Image, UnsupportedImage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    keygen = sub.add_parser('keygen')
    keygen.add_argument('--output', type=Path, required=True)
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
    extraction.add_argument('--format', type=int, choices=(3, 4), default=3,
                            help='4: the hidden key file is a keyslot KEK')
    for action in ('open-blocks', 'close-blocks'):
        block = sub.add_parser(action, help={'open-blocks': 'Configure two native writable DM views',
                                            'close-blocks': 'Remove native writable views'}[action])
        block.add_argument('--device', type=Path, default=Path('/dev/vdb'))
        block.add_argument('--key-file', type=Path, required=True)
        block.add_argument('--name', default='piv-native')
        if action == 'open-blocks':
            secret = block.add_mutually_exclusive_group(required=True)
            secret.add_argument('--hidden-key-file', type=Path)
            secret.add_argument('--hidden-passphrase-file', type=Path,
                                help='Format v4 only: scrypt-derived keyslot key')
            if action == 'open-blocks':
                block.add_argument('--initialize', action='store_true')
                block.add_argument('--format', type=int, choices=(3, 4),
                                   help='Initialization format (default 3); at open, 4 requires a v4 '
                                        'keyslot (otherwise detected). 4 needs a 16-byte IV profile')
                block.add_argument('--ab', action='store_true',
                                   help='With --initialize --format 4: A/B record slots')
                block.add_argument('--uninitialized', action='store_true',
                                   help='Accept a carrier with no authenticating hidden record; '
                                        'decoy writes then cannot preserve hidden data under a wrong key')
    slots = sub.add_parser('keyslot', help='Add or remove a format v4 keyslot on active views')
    slots.add_argument('operation', choices=('add', 'remove'))
    slots.add_argument('--device', type=Path, default=Path('/dev/vdb'))
    slots.add_argument('--key-file', type=Path, required=True)
    slots.add_argument('--name', default='piv-native')
    slots.add_argument('--slot', type=int, choices=range(4), required=True)
    new = slots.add_mutually_exclusive_group()
    new.add_argument('--new-key-file', type=Path)
    new.add_argument('--new-passphrase-file', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'keyslot':
            from .blocks import keyslot, base_identity, passphrase_kek
            kek = None
            if args.operation == 'add':
                if args.new_key_file:
                    with args.new_key_file.open('rb') as stream:
                        kek = stream.read(33)
                elif args.new_passphrase_file:
                    from .kernel_owner import GuestOwner
                    owner = GuestOwner(args.device, args.key_file, args.name)
                    try:
                        identity = base_identity(owner)
                    finally:
                        owner.close()
                    with args.new_passphrase_file.open('rb') as stream:
                        kek = passphrase_kek(stream.read().rstrip(b'\n'), identity)
                else:
                    parser.error('keyslot add needs --new-key-file or --new-passphrase-file')
            keyslot(args.device, args.key_file, args.slot, kek, name=args.name)
            return 0
        if args.action in ('open-blocks', 'close-blocks'):
            from .blocks import open_blocks, close_blocks
            if args.action == 'open-blocks':
                hidden_key = passphrase = None
                if args.hidden_key_file:
                    with args.hidden_key_file.open('rb') as stream:
                        hidden_key = stream.read(33)
                else:
                    with args.hidden_passphrase_file.open('rb') as stream:
                        passphrase = stream.read().rstrip(b'\n')
                result = open_blocks(args.device, args.key_file, hidden_key,
                                     name=args.name,
                                     initialize=args.initialize,
                                     uninitialized=args.uninitialized,
                                     format=args.format, ab=args.ab,
                                     hidden_passphrase=passphrase)
                print(json.dumps(result, indent=2))
            else:
                close_blocks(args.device, args.key_file, name=args.name)
            return 0
        if args.action == 'keygen':
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
            print('Created a private 32-byte key file')
            return 0
        if args.action == 'unpack':
            from .records import unpack
            with args.hidden_key_file.open('rb') as stream:
                hidden_key = stream.read(33)
            result = unpack(args.image, args.output, hidden_key, format=args.format)
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
