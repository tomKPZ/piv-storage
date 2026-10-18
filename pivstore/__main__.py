"""Experimental offline persistent-IV storage with copy-output updates."""

import argparse
import json
import os
from pathlib import Path
import sys
import subprocess
import secrets

from .profile import Image, UnsupportedImage
from .writer import randomize_copy
from .blob import pack, unpack


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
    rewrite = sub.add_parser('randomize-ivs')
    rewrite.add_argument('image', type=Path)
    rewrite.add_argument('--output', type=Path, required=True)
    rewrite.add_argument('--volume-key-file', type=Path, required=True)
    rewrite.add_argument('--sector', type=int, action='append', required=True)
    packing = sub.add_parser('pack')
    packing.add_argument('image', type=Path)
    packing.add_argument('--output', type=Path, required=True)
    packing.add_argument('--payload', type=Path, required=True)
    packing.add_argument('--volume-key-file', type=Path, required=True)
    packing.add_argument('--hidden-key-file', type=Path, required=True)
    extraction = sub.add_parser('unpack')
    extraction.add_argument('image', type=Path)
    extraction.add_argument('--output', type=Path, required=True)
    extraction.add_argument('--hidden-key-file', type=Path, required=True)
    service = sub.add_parser('serve', help='Run coordinated read-only NBD and one hidden FUSE file')
    service.add_argument('image', type=Path)
    service.add_argument('--volume-key-file', type=Path, required=True)
    service.add_argument('--hidden-key-file', type=Path, required=True)
    service.add_argument('--socket', type=Path, required=True)
    service.add_argument('--mountpoint', type=Path, required=True)
    service.add_argument('--initialize', action='store_true',
                         help='Start empty; replaces any existing hidden payload on flush')
    service.add_argument('--max-sector-encryptions', type=int, default=1 << 20,
                         help='Per-session ceiling; does not track historical key usage')
    kernel = sub.add_parser('serve-kernel', help='Experimental pinned-QEMU native primary and hidden FUSE file')
    kernel.add_argument('--device', type=Path, default=Path('/dev/vdb'))
    kernel.add_argument('--key-file', type=Path, required=True)
    kernel.add_argument('--hidden-key-file', type=Path, required=True)
    kernel.add_argument('--state-directory', type=Path, required=True)
    kernel.add_argument('--mountpoint', type=Path, required=True)
    kernel.add_argument('--name', default='piv-native')
    kernel.add_argument('--initialize', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'serve-kernel':
            from .kernel_owner import GuestOwner
            from .kernel_store import KernelStore
            from .fuse_frontend import mount
            with args.hidden_key_file.open('rb') as stream:
                hidden_key = stream.read(33)
            if len(hidden_key) != 32:
                raise ValueError('Hidden key must contain exactly 32 bytes')
            owner = GuestOwner(args.device, args.key_file, args.name)
            try:
                with KernelStore(owner.device, args.state_directory, hidden_key, owner.uuid,
                                 initialize=args.initialize) as store:
                    primary = owner.presentation()
                    fsname = 'pivstore-kernel-' + owner.uuid
                    # The UUID/global lock prove no live controller owns this mount.
                    existing = subprocess.run(['findmnt', '-n', '-o', 'SOURCE', '--mountpoint',
                                               str(args.mountpoint.absolute())],
                                              stdout=subprocess.PIPE, text=True)
                    if existing.returncode == 0:
                        if existing.stdout.strip() != fsname:
                            raise ValueError('Mountpoint belongs to a different filesystem')
                        subprocess.run(['fusermount3', '-uz', str(args.mountpoint)], check=True)
                    args.mountpoint.mkdir(mode=0o700, parents=True, exist_ok=True)
                    print('Native read-only primary: ' + str(primary), flush=True)
                    mount(store, args.mountpoint, fsname=fsname)
            finally:
                owner.close()
            return 0
        if args.action == 'serve':
            from .online import OnlineStore
            from .nbd import PrimaryServer
            try:
                from .fuse_frontend import mount
            except ImportError as exc:
                raise ValueError('Online mounting needs pyfuse3 and trio (guest packages)') from exc
            with args.volume_key_file.open('rb') as stream:
                primary_key = stream.read(33)
            with args.hidden_key_file.open('rb') as stream:
                hidden_key = stream.read(33)
            with OnlineStore(args.image, primary_key, hidden_key,
                             initialize=args.initialize,
                             max_sector_encryptions=args.max_sector_encryptions) as store:
                server = PrimaryServer(args.socket, store)
                server.start()
                try:
                    mount(store, args.mountpoint)
                finally:
                    server.stop()
            return 0
        if args.action == 'keygen':
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
            print('Created a private 32-byte key file')
            return 0
        if args.action in ('pack', 'unpack'):
            with args.hidden_key_file.open('rb') as stream:
                hidden_key = stream.read(33)
            if args.action == 'unpack':
                result = unpack(args.image, args.output, hidden_key)
            else:
                with args.volume_key_file.open('rb') as stream:
                    primary_key = stream.read(33)
                with Image(args.image) as image:
                    maximum = image.layout.sectors * 12 - 64
                with args.payload.open('rb') as stream:
                    payload = stream.read(maximum + 1)
                result = pack(args.image, args.output, primary_key, hidden_key, payload)
            print(json.dumps(result, indent=2))
            return 0
        if args.action == 'randomize-ivs':
            with args.volume_key_file.open('rb') as stream:
                key = stream.read(33)
            result = randomize_copy(args.image, args.output, key, args.sector)
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
                result = {'extracted_bytes': image.layout.sectors * 12,
                          'primary_authentication': 'not performed'}
            else:
                with args.volume_key_file.open('rb') as stream:
                    key = stream.read(33)
                result = {'primary_sha256': image.verify(key),
                          'authenticated_sectors': image.layout.sectors}
        print(json.dumps(result, indent=2))
    except (UnsupportedImage, OSError, ValueError, TimeoutError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        print(f'pivstore: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
