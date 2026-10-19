#!/usr/bin/env python3
"""Both writable block devices outlive the setup process; no NBD/FUSE service."""
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

def setup(initialize=False):
    args = ['python3', '-m', 'pivstore', 'open-blocks', '--device', '/dev/vdb',
            '--key-file', str(W / 'passphrase.key'), '--hidden-key-file', str(W / 'hidden.key'),
            ]
    if initialize: args.append('--initialize')
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    primary_bytes = int(subprocess.check_output(['blockdev', '--getsize64', DECOY]))
    segment = json.loads(crypt('luksDump', '--dump-json-metadata', '/dev/vdb').stdout)['segments']['0']
    sector_size = segment['sector_size']
    iv_size = 16 if segment['encryption'] == 'aegis128-random' else 12
    assert value['hidden_bytes'] == primary_bytes // sector_size // (576 // iv_size) * 512
    assert value['decoy'] == DECOY and value['hidden'] == HIDDEN
    return value

def close():
    subprocess.run(['python3', '-m', 'pivstore', 'close-blocks', '--device', '/dev/vdb',
                    '--key-file', str(W / 'passphrase.key')], check=True)

# A stock random-IV carrier is not a valid hidden block. That must not gate decoy.
setup()
fd = os.open(HIDDEN, os.O_RDONLY)
try:
    os.pread(fd, 512, 0)
except OSError as exc:
    assert exc.errno == 5
else:
    raise AssertionError('Uninitialized hidden block was readable')
os.close(fd)
assert subprocess.check_output(['sha256sum', DECOY], text=True).split()[0] == (W / 'primary-before.sha256').read_text().strip()
fd = os.open(HIDDEN, os.O_RDWR | os.O_DIRECT)
page = mmap.mmap(-1, 512); page[:] = b'A' * 512
os.pwritev(fd, [page], 0); os.fsync(fd)
page[:] = bytes(512)
assert os.preadv(fd, [page], 0) == 512 and page[:] == b'A' * 512
os.close(fd); page.close()
close()
print('Uninitialized hidden EIO isolation and individual repair passed', flush=True)
print('Creating two native writable DM devices', flush=True)
geometry = setup(True)
capacity = geometry['hidden_bytes']
assert subprocess.check_output(['blockdev', '--getro', HIDDEN]).strip() == b'0'
assert subprocess.check_output(['blockdev', '--getro', DECOY]).strip() == b'0'
owner = GuestOwner('/dev/vdb', W / 'passphrase.key')
iv_size = owner.device.iv_size
status = native_status(owner.device)
assert status['active'] and status['views'] == 3 and not status['failed']
# Legacy controls cannot bypass the shared native owner.
try:
    owner.device.read_primary_sector(0)
except OSError:
    pass
else:
    raise AssertionError('Legacy primary control escaped native ownership')
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
positions = ((576 // iv_size) * sector_size - 512, 32768 * 512 - 512, primary_size - 512)
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
# Re-encode one primary sector with a different IV through the authenticated
# control helper, simulating a legitimate stock write that destroys one record.
close()
owner = GuestOwner('/dev/vdb', W / 'passphrase.key')
owner.device.suspend(); owner.device.begin()
old_iv = owner.device.read_iv(0, quiesced=True)
new_iv = os.urandom(owner.device.iv_size)
prepared = owner.device.prepare(0, old_iv, new_iv)
owner.device.apply(0, old_iv, prepared)
owner.device.end(); owner.device.resume(); owner.remove(); owner.close()
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
original = os.pread(fd, 4096, 0)
os.pwrite(fd, original, 0); os.fsync(fd); os.close(fd)
# Decoy write marks unavailable data invalid; it must not manufacture zeros.
subprocess.run(['blockdev', '--flushbufs', HIDDEN], check=True)
unavailable(0)
owner = GuestOwner('/dev/vdb', W / 'passphrase.key')
assert native_status(owner.device)['invalidations'] >= 1
assert not native_status(owner.device)['failed']
owner.close()
fd = os.open(HIDDEN, os.O_RDWR | os.O_DIRECT)
page = mmap.mmap(-1, 512); page[:] = before_hidden[:512]
os.pwritev(fd, [page], 0); os.fsync(fd); os.close(fd); page.close()
assert Path(HIDDEN).read_bytes() == before_hidden
close()
# A wrong hidden key must not make the decoy unavailable; no writes in this case.
from pivstore.blocks import open_blocks, close_blocks
open_blocks('/dev/vdb', W / 'passphrase.key', bytes(32))
unavailable(0)
assert subprocess.check_output(['sha256sum', DECOY], text=True).split()[0] == (W / 'primary-before.sha256').read_text().strip()
close_blocks('/dev/vdb', W / 'passphrase.key')
setup()
assert Path(HIDDEN).read_bytes() == before_hidden
print('Damaged-record isolation, invalid-marker preservation, repair and wrong-key decoy access passed', flush=True)
# Real filesystems mounted on BOTH native block devices, simultaneously.
primary = Path('/run/piv-primary'); primary.mkdir(exist_ok=True)
hidden = Path('/run/piv-hidden-volume'); hidden.mkdir(exist_ok=True)
subprocess.run(['mkfs.ext2', '-q', '-F', '-b', '4096', '-N', '32', HIDDEN], check=True)
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
subprocess.run(['rmmod', 'dm_crypt'], check=True); subprocess.run(['modprobe', 'dm_crypt'], check=True)
crypt('open', '--readonly', '--key-file', W / 'passphrase.key', '/dev/vdb', 'piv-stock')
actual = subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0]
assert actual == (W / 'expected-primary.sha256').read_text().strip()
crypt('close', 'piv-stock')
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'dual-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'result.txt').write_text('Two native writable block views, concurrent ext4/ext2, reopen and stock full-primary readback passed\n')
print('Dual native filesystem and stock readback checks passed', flush=True)
