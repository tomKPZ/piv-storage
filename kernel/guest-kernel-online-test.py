#!/usr/bin/env python3
"""Disposable guest: whole-record recovery, real FUSE, native readonly primary."""
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

from pivstore.kernel_owner import GuestOwner, crypt
from pivstore.kernel_api import dm
from pivstore.kernel_store import KernelStore
from pivstore.profile import UnsupportedImage

WORK = Path('/mnt/piv-work')
BASE = Path('/var/tmp/piv-native')
STATE = BASE / 'state'
MOUNT = Path('/run/piv-hidden')
PRIMARY = Path('/run/piv-primary')
BASE.mkdir(mode=0o700, exist_ok=True)
MOUNT.mkdir(mode=0o700, exist_ok=True)
PRIMARY.mkdir(mode=0o700, exist_ok=True)
KEY = (WORK / 'hidden.key').read_bytes()
expected_hash = (WORK / 'primary-before.sha256').read_text().strip()


def primary_hash(path='/dev/mapper/piv-native-view'):
    subprocess.run(['blockdev', '--flushbufs', path], check=True)
    return subprocess.check_output(['sha256sum', path], text=True).split()[0]


def open_store(initialize=False, state=STATE):
    owner = GuestOwner('/dev/vdb', WORK / 'passphrase.key')
    try:
        store = KernelStore(owner.device, state, KEY, owner.uuid, initialize=initialize)
        owner.presentation()
        return owner, store
    except BaseException:
        owner.close()
        raise


print('Native initialization and first durable commit', flush=True)
owner, store = open_store(True)
store.write_hidden(0, b'initial native payload')
store.flush()
assert primary_hash() == expected_hash
store.close(); owner.close()
print('Testing controller SIGKILL and exact-tuple replay', flush=True)
# A real controller SIGKILL during partially applied carrier writes.
ready_r, ready_w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(ready_r)
    owner, store = open_store()
    store.truncate_hidden(0)
    store.write_hidden(0, b'recovered after controller death')
    def die(phase):
        if phase == 'applied:40':
            os.write(ready_w, b'1')
            os.kill(os.getpid(), signal.SIGKILL)
    store._checkpoint = die
    store.flush()
    os._exit(3)
os.close(ready_w)
assert os.read(ready_r, 1) == b'1'
os.close(ready_r)
assert os.WIFSIGNALED(os.waitpid(pid, 0)[1])
assert (STATE / 'pending').exists()
owner, store = open_store()
assert store.read_hidden(0, 100) == b'recovered after controller death'
assert primary_hash() == expected_hash
store.close(); owner.close()
# Corrupt recovery data is refused before allowing primary resume or any apply.
# The unit suite covers journal corruption; actual kernel restart above covers replay.

# Mounted demo with simultaneous uncached primary reads and hidden fsync.
subprocess.run(['mount', '-o', 'ro,noload', '/dev/mapper/piv-native-view', str(PRIMARY)], check=True)
errors = []
stop = threading.Event()

def reader():
    try:
        while not stop.is_set():
            value = hashlib.sha256((PRIMARY / 'primary.bin').read_bytes()).hexdigest()
            assert value == (WORK / 'primary-file.sha256').read_text().strip()
            assert primary_hash() == expected_hash
    except BaseException as exc:
        errors.append(repr(exc))

reader_thread = threading.Thread(target=reader)
reader_thread.start()


def start_service(crash=False):
    log = (WORK / 'native-service.log').open('ab', buffering=0)
    args = (['python3', str(WORK / 'guest-kernel-fuse-crash.py')] if crash else
            ['python3', '-m', 'pivstore', 'serve-kernel',
             '--device', '/dev/vdb', '--key-file', str(WORK / 'passphrase.key'),
             '--hidden-key-file', str(WORK / 'hidden.key'), '--state-directory', str(STATE),
             '--mountpoint', str(MOUNT)])
    process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    log.close()
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError('service exited; see native-service.log')
        if subprocess.run(['mountpoint', '-q', str(MOUNT)]).returncode == 0:
            try:
                # Dead old sessions return ENOTCONN. Do not assume mount IDs
                # change: legacy IDs can be reused after stale-mount cleanup.
                (MOUNT / 'payload').read_bytes()
                return process
            except OSError as exc:
                if exc.errno not in (errno.ENOTCONN, errno.EIO, errno.ENOENT):
                    raise
        time.sleep(.25)
    raise AssertionError('service startup timeout')

print('Mounted FUSE write/truncate/fsync with concurrent native reads', flush=True)
service = start_service()
fd = os.open(MOUNT / 'payload', os.O_RDWR)
assert os.pread(fd, 100, 0) == b'recovered after controller death'
os.ftruncate(fd, 0)
assert os.pwrite(fd, b'mounted native update', 0) == 21
os.fsync(fd)
os.ftruncate(fd, 14)
os.fsync(fd)
os.close(fd)
subprocess.run(['fusermount3', '-u', str(MOUNT)], check=True)
assert service.wait(timeout=120) == 0
print('Testing mounted service death during fsync', flush=True)
service = start_service(crash=True)
fd = os.open(MOUNT / 'payload', os.O_RDWR)
os.ftruncate(fd, 0)
os.pwrite(fd, b'mounted crash recovered', 0)
try:
    os.fsync(fd)
except OSError as exc:
    assert exc.errno in (errno.ENOTCONN, errno.EIO, errno.ECONNABORTED)
else:
    raise AssertionError('Interrupted FUSE fsync unexpectedly acknowledged')
try:
    os.close(fd)
except OSError as exc:
    assert exc.errno in (errno.ENOTCONN, errno.EIO, errno.ECONNABORTED)
assert service.wait(timeout=60) == -signal.SIGKILL
service = start_service()
assert (MOUNT / 'payload').read_bytes() == b'mounted crash recovered'
print('Mounted transaction recovered; testing idle stale-FUSE cleanup', flush=True)
service.kill(); service.wait(timeout=20)
service = start_service()
assert (MOUNT / 'payload').read_bytes() == b'mounted crash recovered'
subprocess.run(['fusermount3', '-u', str(MOUNT)], check=True)
assert service.wait(timeout=120) == 0
stop.set(); reader_thread.join(timeout=120)
assert not reader_thread.is_alive() and not errors, errors
fd = os.open('/dev/mapper/piv-native-view', os.O_WRONLY)
try:
    os.pwrite(fd, bytes(4096), 0)
except OSError as exc:
    assert exc.errno in (errno.EPERM, errno.EROFS)
else:
    raise AssertionError('primary presentation accepted write')
os.close(fd)
subprocess.run(['umount', str(PRIMARY)], check=True)
owner, store = open_store()
assert store.read_hidden(0, 100) == b'mounted crash recovered'
store.close(); owner.remove(); owner.close()
# Independent unmodified-module readback after all native control mappings close.
subprocess.run(['rmmod', 'dm_crypt'], check=True)
subprocess.run(['modprobe', 'dm_crypt'], check=True)
crypt('open', '--readonly', '--key-file', WORK / 'passphrase.key', '/dev/vdb', 'piv-stock')
assert primary_hash('/dev/mapper/piv-stock') == expected_hash
crypt('close', 'piv-stock')
(WORK / 'result.txt').write_text('Native journal/controller recovery, mounted FUSE/read-only primary and stock readback passed\n')
# Export final disposable image for independent host parser/blob validation.
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(WORK / 'native-final.img'), 'bs=1M', 'status=none'], check=True)
(WORK / 'expected-payload').write_bytes(b'mounted crash recovered')
