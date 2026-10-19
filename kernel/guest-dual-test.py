#!/usr/bin/env python3
"""Both writable block devices outlive the setup process; no NBD/FUSE service."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import threading

from pivstore.kernel_owner import GuestOwner, crypt
from pivstore.blocks import native_status

W = Path('/mnt/piv-work')
STATE = '/var/tmp/piv-dual/state'
DECOY = '/dev/mapper/piv-native-decoy'
HIDDEN = '/dev/mapper/piv-native-hidden'

def setup(initialize=False):
    args = ['python3', '-m', 'pivstore', 'open-blocks', '--device', '/dev/vdb',
            '--key-file', str(W / 'passphrase.key'), '--hidden-key-file', str(W / 'hidden.key'),
            '--state-directory', STATE]
    if initialize: args.append('--initialize')
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    value = json.loads(result.stdout)
    assert value['hidden_bytes'] == 281600
    assert value['decoy'] == DECOY and value['hidden'] == HIDDEN
    return value

def close():
    subprocess.run(['python3', '-m', 'pivstore', 'close-blocks', '--device', '/dev/vdb',
                    '--key-file', str(W / 'passphrase.key')], check=True)

print('Creating two native writable DM devices', flush=True)
setup(True)
assert subprocess.check_output(['blockdev', '--getro', HIDDEN]).strip() == b'0'
assert subprocess.check_output(['blockdev', '--getro', DECOY]).strip() == b'0'
owner = GuestOwner('/dev/vdb', W / 'passphrase.key')
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
assert Path(HIDDEN).read_bytes() == bytes(281600)
fd = os.open(HIDDEN, os.O_RDWR)
value = hashlib.shake_256(b'native-hidden-block-partial').digest(1700)
assert os.pwrite(fd, value, 511) == len(value)
os.fsync(fd); os.close(fd)
assert Path(HIDDEN).read_bytes() == bytes(511) + value + bytes(281600 - 511 - len(value))
# A decoy write affecting those IV records must preserve the logical hidden data.
before_hidden = Path(HIDDEN).read_bytes()
fd = os.open(DECOY, os.O_RDWR)
old = os.pread(fd, 4096, 32 * 4096)
os.pwrite(fd, old, 32 * 4096); os.fsync(fd); os.close(fd)
assert Path(HIDDEN).read_bytes() == before_hidden
close(); setup()
assert Path(HIDDEN).read_bytes() == before_hidden
print('Native block RMW, hidden preservation and reopen passed', flush=True)
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
shutil.copyfile(Path(STATE) / 'native.log', W / 'native.log')
subprocess.run(['rmmod', 'dm_crypt'], check=True); subprocess.run(['modprobe', 'dm_crypt'], check=True)
crypt('open', '--readonly', '--key-file', W / 'passphrase.key', '/dev/vdb', 'piv-stock')
actual = subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0]
assert actual == (W / 'expected-primary.sha256').read_text().strip()
crypt('close', 'piv-stock')
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'dual-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'result.txt').write_text('Two native writable block views, concurrent ext4/ext2, reopen and stock full-primary readback passed\n')
print('Dual native filesystem and stock readback checks passed', flush=True)
