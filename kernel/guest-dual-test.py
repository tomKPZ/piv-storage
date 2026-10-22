#!/usr/bin/env python3
"""Both writable block devices outlive the setup process; no NBD/FUSE service."""
import errno
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import subprocess
import shutil
import threading

from pivstore.kernel_owner import GuestOwner, crypt
from pivstore.blocks import native_status

W = Path('/mnt/piv-work')
DECOY = '/dev/mapper/piv-native-decoy'
HIDDEN = '/dev/mapper/piv-native-hidden'

NAMES = ('piv-native-hidden', 'piv-native-decoy', 'piv-native', 'piv-native_dif')
# Format v4 layout (docs/format-v4.md): 112 keyslot sectors, 90-sector records,
# two directory groups; hidden block 0 starts at primary sector 112 + 2 * 90.
V4_KEYSLOT_AREA, V4_GROUP = 112, 90
V4_BLOCK0 = V4_KEYSLOT_AREA + 2 * V4_GROUP

def absent():
    for name in NAMES:
        assert subprocess.run(['dmsetup', 'info', name], capture_output=True).returncode, name

def setup(initialize=False, rejected=False):
    args = ['pivsetup', 'open-blocks', '--device', '/dev/vdb',
            '--key-file', str(W / 'passphrase.key'), '--hidden-key-file', str(W / 'hidden.key'),
            ]
    if initialize: args.append('--initialize')
    if os.environ.get('PIV_ALLOW_NO_JOURNAL') == '1': args.append('--allow-no-journal')
    result = subprocess.run(args, capture_output=True, text=True)
    if rejected:
        # Wrong-key guard: no keyslot authenticates, so setup must refuse and
        # remove every mapping it created rather than expose a destructive decoy.
        assert result.returncode == 1 and 'No keyslot authenticated' in result.stderr, result
        absent()
        return None
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    primary_bytes = int(subprocess.check_output(['blockdev', '--getsize64', DECOY]))
    segment = json.loads(crypt('luksDump', '--dump-json-metadata', '/dev/vdb').stdout)['segments']['0']
    assert segment['encryption'] in ('aegis128-random', 'aes-xts-random', 'serpent-xts-random',
                                     'twofish-xts-random'), segment
    sectors = primary_bytes // segment['sector_size']
    expected = ((sectors - V4_KEYSLOT_AREA) // V4_GROUP - 2) * 512
    assert value['hidden_bytes'] == expected, (value, expected)
    assert value['decoy'] == DECOY and value['hidden'] == HIDDEN
    return value

def close():
    subprocess.run(['pivsetup', 'close-blocks', '--device', '/dev/vdb',
                    '--key-file', str(W / 'passphrase.key')], check=True)

# A stock random-IV carrier has no keyslot: the wrong-key guard refuses it and
# removes everything it created (the decoy alone stays usable with stock dm-crypt).
absent()
setup(rejected=True)
print('Stock carrier refused without --initialize; no mappings left', flush=True)
print('Creating two native writable DM devices', flush=True)
geometry = setup(True)
capacity = geometry['hidden_bytes']
assert subprocess.check_output(['blockdev', '--getro', HIDDEN]).strip() == b'0'
assert subprocess.check_output(['blockdev', '--getro', DECOY]).strip() == b'0'
owner = GuestOwner('/dev/vdb', W / 'passphrase.key')
iv_size = owner.device.iv_size
status = native_status(owner.device)
assert status['active'] and status['views'] == 3 and not status['failed']
# The former userspace IV/tuple controls are gone (ENOTTY), not merely refused.
for number, size, direction in ((1, 48, 3), (2, 48, 3), (3, 4176, 3), (4, 4176, 1), (8, 48, 1),
                                (9, 4176, 3), (10, 4176, 3), (11, 4176, 1)):
    try:
        fcntl.ioctl(owner.device.fd, direction << 30 | size << 16 | ord('P') << 8 | number, bytearray(size), True)
    except OSError as exc:
        assert exc.errno == errno.ENOTTY, (number, exc)
    else:
        raise AssertionError(f'Removed control {number} still accepted')
owner.close()
# Native hidden decryption returns a fixed zero-filled raw block volume.
assert Path(HIDDEN).read_bytes() == bytes(capacity)
fd = os.open(HIDDEN, os.O_RDWR)
value = hashlib.shake_256(b'native-hidden-block-partial').digest(1700)
assert os.pwrite(fd, value, 511) == len(value)
os.fsync(fd); os.close(fd)
assert Path(HIDDEN).read_bytes() == bytes(511) + value + bytes(capacity - 511 - len(value))
# A decoy write affecting those IV records must preserve the logical hidden data.
before_hidden = Path(HIDDEN).read_bytes()
fd = os.open(DECOY, os.O_RDWR)
old = os.pread(fd, 4096, 32 * 4096)
os.pwrite(fd, old, 32 * 4096); os.fsync(fd); os.close(fd)
assert Path(HIDDEN).read_bytes() == before_hidden
# Exercise actual changed decoy data across carrier and metadata boundaries,
# including the incomplete carrier tail when present. Restore with fresh IVs.
primary_size = int(subprocess.check_output(['blockdev', '--getsize64', DECOY]))
sector_size = json.loads(crypt('luksDump', '--dump-json-metadata', '/dev/vdb').stdout)['segments']['0']['sector_size']
# The first record boundary (block 0 -> 1), the 32768-sector interleave and the tail.
positions = ((V4_BLOCK0 + V4_GROUP) * sector_size - 512, 32768 * 512 - 512, primary_size - 512)
fd = os.open(DECOY, os.O_RDWR | os.O_DIRECT)
for position in positions:
    length = min(1024, primary_size - position)
    start = max(0, position - 512)
    span = min(length + 1024, primary_size - start)
    page = mmap.mmap(-1, span)
    assert os.preadv(fd, [page], start) == span
    original = page[:]
    patch = mmap.mmap(-1, length); patch[:] = b'Z' * length
    assert os.pwritev(fd, [patch], position) == length
    os.fsync(fd)
    assert os.preadv(fd, [page], start) == span
    expected = bytearray(original)
    expected[position - start:position - start + length] = patch[:]
    assert page[:] == expected
    assert Path(HIDDEN).read_bytes() == before_hidden
    page[:] = original
    assert os.pwritev(fd, [page], start) == span
    os.fsync(fd); page.close(); patch.close()
os.close(fd)
assert Path(HIDDEN).read_bytes() == before_hidden
# Include the last hidden block, and restore it before filesystem tests.
fd = os.open(HIDDEN, os.O_RDWR | os.O_DIRECT)
page = mmap.mmap(-1, 512); page[:] = b'T' * 512
assert os.pwritev(fd, [page], capacity - 512) == 512
os.fsync(fd)
assert Path(HIDDEN).read_bytes() == before_hidden[:-512] + b'T' * 512
page[:] = before_hidden[-512:]
assert os.pwritev(fd, [page], capacity - 512) == 512
os.fsync(fd); os.close(fd); page.close()
close(); setup()
assert Path(HIDDEN).read_bytes() == before_hidden
print('Native block RMW, hidden preservation and reopen passed', flush=True)
# An uncoordinated stock dm-crypt rewrite of one primary sector (same plaintext,
# fresh random IV) destroys one record. Sector 0 is a keyslot replica, so damage
# the first sector of block 0's record.
close()
damaged = V4_BLOCK0
unit = json.loads(crypt('luksDump', '--dump-json-metadata', '/dev/vdb').stdout)['segments']['0']['sector_size']
subprocess.run(['cryptsetup', 'open', '--key-file', str(W / 'passphrase.key'), '/dev/vdb', 'piv-stock-rw'], check=True)
try:
    fd = os.open('/dev/mapper/piv-stock-rw', os.O_RDWR | os.O_DIRECT)
    with mmap.mmap(-1, unit) as buf:
        assert os.preadv(fd, [buf], damaged * unit) == unit
        assert os.pwritev(fd, [buf], damaged * unit) == unit
        os.fsync(fd)
    os.close(fd)
finally:
    subprocess.run(['cryptsetup', 'close', 'piv-stock-rw'], check=True)
setup()
def unavailable(index):
    fd = os.open(HIDDEN, os.O_RDONLY)
    try:
        try: os.pread(fd, 512, index * 512)
        except OSError as exc: assert exc.errno == 5
        else: raise AssertionError('Unavailable block was returned as valid')
    finally: os.close(fd)
unavailable(0)
assert Path(HIDDEN).open('rb').read(0) == b''
fd = os.open(DECOY, os.O_RDWR)
decoy_offset = damaged * sector_size // 4096 * 4096
original = os.pread(fd, 4096, decoy_offset)
os.pwrite(fd, original, decoy_offset); os.fsync(fd); os.close(fd)
# Decoy write keeps unavailable data unavailable; it must not manufacture zeros:
# it re-randomizes only the written sectors and preserves their (damaged)
# fragments.
subprocess.run(['blockdev', '--flushbufs', HIDDEN], check=True)
unavailable(0)
owner = GuestOwner('/dev/vdb', W / 'passphrase.key')
assert not native_status(owner.device)['failed']
owner.close()
fd = os.open(HIDDEN, os.O_RDWR | os.O_DIRECT)
page = mmap.mmap(-1, 512); page[:] = before_hidden[:512]
os.pwritev(fd, [page], 0); os.fsync(fd); os.close(fd); page.close()
assert Path(HIDDEN).read_bytes() == before_hidden
close()
# A wrong hidden key is rejected before any view exists (the guard).
import errno
from pivstore.blocks import open_blocks, close_blocks
try:
    open_blocks('/dev/vdb', W / 'passphrase.key', bytes(32))
except OSError as exc:
    assert exc.errno == errno.EKEYREJECTED, exc
else:
    raise AssertionError('Wrong hidden key was accepted')
absent()
setup()
assert Path(HIDDEN).read_bytes() == before_hidden
print('Damaged-record isolation, damage preservation on decoy writes, repair and wrong-key refusal passed', flush=True)
# Real filesystems mounted on BOTH native block devices, simultaneously.
primary = Path('/run/piv-primary'); primary.mkdir(exist_ok=True)
hidden = Path('/run/piv-hidden-volume'); hidden.mkdir(exist_ok=True)
# v4 on 4096-byte sectors gives only 158,720 hidden bytes: use 1 KiB blocks there.
block = '4096' if capacity >= 256 * 1024 else '1024'
subprocess.run(['mkfs.ext2', '-q', '-F', '-b', block, '-N', '32', HIDDEN], check=True)
subprocess.run(['mount', DECOY, str(primary)], check=True)
subprocess.run(['mount', HIDDEN, str(hidden)], check=True)
errors = []

def writer(path, seed, size):
    try:
        value = hashlib.shake_256(seed).digest(size)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.write(fd, value); os.fsync(fd)
        for i in range(3):
            os.pwrite(fd, bytes([i + 1]) * 512, i * 512)
            os.fsync(fd)
        os.close(fd)
        expected = bytearray(value)
        for i in range(3): expected[i * 512:(i + 1) * 512] = bytes([i + 1]) * 512
        assert path.read_bytes() == expected
        (W / ('expected-' + path.name)).write_bytes(expected)
    except BaseException as exc:
        errors.append(repr(exc))

a = threading.Thread(target=writer, args=(primary / 'decoy-new', b'native decoy file', 8192))
b = threading.Thread(target=writer, args=(hidden / 'hidden-new', b'native hidden file', 8192))
a.start(); b.start(); a.join(timeout=600); b.join(timeout=600)
assert not a.is_alive() and not b.is_alive() and not errors, errors
assert hashlib.sha256((primary / 'primary.bin').read_bytes()).hexdigest() == (W / 'primary-file.sha256').read_text().strip()
subprocess.run(['umount', str(hidden)], check=True)
subprocess.run(['umount', str(primary)], check=True)
# Capture complete logical views before teardown for independent crypto checks.
subprocess.run(['blockdev', '--flushbufs', DECOY], check=True)
subprocess.run(['blockdev', '--flushbufs', HIDDEN], check=True)
(W / 'expected-primary.sha256').write_text(subprocess.check_output(['sha256sum', DECOY], text=True).split()[0] + '\n')
(W / 'expected-hidden-volume').write_bytes(Path(HIDDEN).read_bytes())
close(); setup()
subprocess.run(['mount', DECOY, str(primary)], check=True)
subprocess.run(['mount', HIDDEN, str(hidden)], check=True)
assert (primary / 'decoy-new').read_bytes() == (W / 'expected-decoy-new').read_bytes()
assert (hidden / 'hidden-new').read_bytes() == (W / 'expected-hidden-new').read_bytes()
subprocess.run(['umount', str(hidden)], check=True); subprocess.run(['umount', str(primary)], check=True)
# Refresh expected primary: RW filesystem mounts change ordinary primary metadata.
(W / 'expected-primary.sha256').write_text(subprocess.check_output(['sha256sum', DECOY], text=True).split()[0] + '\n')
(W / 'expected-hidden-volume').write_bytes(Path(HIDDEN).read_bytes())
close()
subprocess.run(['rmmod', 'dm_piv'], check=True)
assert Path('/sys/module/dm_crypt').is_dir()
assert subprocess.check_output(['dmsetup', 'table', 'piv-stock-live'], text=True).split()[2] == 'crypt'
crypt('open', '--readonly', '--key-file', W / 'passphrase.key', '/dev/vdb', 'piv-stock')
actual = subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0]
assert actual == (W / 'expected-primary.sha256').read_text().strip()
crypt('close', 'piv-stock')
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'dual-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'result.txt').write_text('Two native writable block views, concurrent ext4/ext2, reopen and stock full-primary readback passed\n')
print('Dual native filesystem and stock readback checks passed', flush=True)
