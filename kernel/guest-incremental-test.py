#!/usr/bin/env python3
"""Real guest: sparse writes, controller recovery, mounted RW NBD and hidden FUSE.

Ends with an in-flight QEMU cut; guest-incremental-recover.sh checks both journals.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

from pivstore.kernel_api import dm
from pivstore.kernel_owner import GuestOwner, crypt
from pivstore.incremental_store import IncrementalStore

W = Path('/mnt/piv-work')
STATE = Path('/var/tmp/piv-incremental/state')
KEY = (W / 'hidden.key').read_bytes()
HIDDEN = b'incremental hidden data survives primary writes'

def open_store(initialize=False, source='/dev/vdb'):
    owner = GuestOwner(source, W / 'passphrase.key', allow_test_stack=source != '/dev/vdb')
    try:
        return owner, IncrementalStore(owner.device, STATE, KEY, owner.uuid, initialize=initialize)
    except BaseException:
        owner.close()
        raise

owner, store = open_store(True)
store.write_hidden(0, HIDDEN)
store.flush()
# Same-size edits touch exactly one data record, not metadata or other records.
before = [store.device.read_iv(i) for i in range(store.device.sectors)]
store.write_hidden(0, b'I')
store.flush()
after = [store.device.read_iv(i) for i in range(store.device.sectors)]
assert {i for i in range(len(before)) if before[i] != after[i]} == set(range(32, 64))
store.write_hidden(0, b'i'); store.flush()
store.close(); owner.close()
print('Incremental hidden rewrite isolation passed', flush=True)

# Real controller death midway through a sparse primary update; replay must not
# encrypt again, and both hidden bytes and the partial-sector primary write survive.
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    owner, store = open_store()
    def crash(phase):
        if phase == 'applied:15':
            os.write(w, b'1')
            os.kill(os.getpid(), signal.SIGKILL)
    store._checkpoint = crash
    # Synthetic scratch region; mounted filesystem verification precedes later
    # raw scratch writes if they could overlap filesystem allocation.
    offset = 100 * 1024 * 1024 + 3
    store.write_primary(offset, b'controller recovered primary')
    os._exit(5)
os.close(w)
assert os.read(r, 1) == b'1'; os.close(r)
assert os.WIFSIGNALED(os.waitpid(pid, 0)[1])
owner, store = open_store()
assert store.read_hidden(0, 100) == HIDDEN
assert store.read_primary(100 * 1024 * 1024 + 3, 28) == b'controller recovered primary'
store.close(); owner.close()
print('Sparse primary controller-death recovery passed', flush=True)

mount = Path('/run/piv-hidden'); mount.mkdir(exist_ok=True)
primary = Path('/run/piv-primary'); primary.mkdir(exist_ok=True)
sock = Path('/run/piv-rw.sock')
log = (W / 'incremental-service.log').open('ab', buffering=0)
service = subprocess.Popen(['python3', '-m', 'pivstore', 'serve-kernel',
    '--device', '/dev/vdb', '--key-file', str(W / 'passphrase.key'),
    '--hidden-key-file', str(W / 'hidden.key'), '--state-directory', str(STATE),
    '--mountpoint', str(mount), '--incremental', '--socket', str(sock)],
    stdout=log, stderr=subprocess.STDOUT)
log.close()
try:
    deadline = time.monotonic() + 300
    while not (mount / 'payload').exists():
        assert service.poll() is None, 'service exited; inspect incremental-service.log'
        assert time.monotonic() < deadline
        time.sleep(.2)
    subprocess.run(['nbd-client', '-unix', str(sock), '/dev/nbd0'], check=True)
    subprocess.run(['mount', '/dev/nbd0', str(primary)], check=True)
    value = hashlib.shake_256(b'incremental-primary-new-file').digest(48 * 1024)
    fd = os.open(primary / 'new-file', os.O_CREAT | os.O_RDWR, 0o600)
    assert os.write(fd, value) == len(value)
    os.fsync(fd); os.close(fd)
    assert (primary / 'new-file').read_bytes() == value
    assert (mount / 'payload').read_bytes() == HIDDEN
    # Concurrent normal filesystem I/O and hidden edits are serialized by one owner.
    errors = []
    def primary_writer():
        try:
            fd = os.open(primary / 'new-file', os.O_RDWR)
            for i in range(3):
                os.pwrite(fd, bytes([i + 1]) * 4096, 4096 * i)
                os.fsync(fd)
            os.close(fd)
        except BaseException as exc:
            errors.append(repr(exc))
    thread = threading.Thread(target=primary_writer); thread.start()
    fd = os.open(mount / 'payload', os.O_RDWR)
    os.pwrite(fd, b'INCREMENTAL', 0); os.fsync(fd); os.close(fd)
    thread.join(timeout=300)
    assert not thread.is_alive() and not errors, errors
    expected_file = bytearray(value)
    for i in range(3):
        expected_file[i * 4096:(i + 1) * 4096] = bytes([i + 1]) * 4096
    assert (primary / 'new-file').read_bytes() == bytes(expected_file)
    expected_hidden = b'INCREMENTAL' + HIDDEN[11:]
    assert (mount / 'payload').read_bytes() == expected_hidden
    subprocess.run(['umount', str(primary)], check=True)
    subprocess.run(['nbd-client', '-d', '/dev/nbd0'], check=True)
    subprocess.run(['fusermount3', '-u', str(mount)], check=True)
    assert service.wait(timeout=120) == 0
finally:
    if service.poll() is None:
        service.kill(); service.wait(timeout=20)
(W / 'expected-payload').write_bytes(expected_hidden)
(W / 'expected-new-file').write_bytes(expected_file)
# Verify real filesystem writes with UNMODIFIED dm-crypt before the power test.
owner, store = open_store()
assert store.read_hidden(0, 100) == expected_hidden
store.close(); owner.remove(); owner.close()
subprocess.run(['rmmod', 'dm_crypt'], check=True); subprocess.run(['modprobe', 'dm_crypt'], check=True)
crypt('open', '--readonly', '--key-file', W / 'passphrase.key', '/dev/vdb', 'piv-stock')
subprocess.run(['mount', '-o', 'ro,noload', '/dev/mapper/piv-stock', str(primary)], check=True)
assert (primary / 'new-file').read_bytes() == bytes(expected_file)
assert hashlib.sha256((primary / 'primary.bin').read_bytes()).hexdigest() == (W / 'primary-file.sha256').read_text().strip()
subprocess.run(['umount', str(primary)], check=True); crypt('close', 'piv-stock')
subprocess.run(['rmmod', 'dm_crypt'], check=True)
subprocess.run(['insmod', '/root/piv-module/dm-crypt.ko'], check=True)
print('Mounted RW ext4, concurrent hidden FUSE and independent stock readback passed', flush=True)

# Planned raw block write after filesystem checks. Compute expected complete
# primary digest independently before cutting QEMU during native journal I/O.
owner, store = open_store()
offset = 64 * 1024 * 1024
replacement = hashlib.shake_256(b'incremental-power-write').digest(512 * 1024)
digest = hashlib.sha256()
for at in range(0, store.primary_bytes, 1024 * 1024):
    value = bytearray(store.read_primary(at, min(1024 * 1024, store.primary_bytes - at)))
    lo, hi = max(at, offset), min(at + len(value), offset + len(replacement))
    if lo < hi:
        value[lo - at:hi - at] = replacement[lo - offset:hi - offset]
    digest.update(value)
(W / 'expected-primary.sha256').write_text(digest.hexdigest() + '\n')
store.close(); owner.remove(); owner.close()
dm('create', 'piv-test-delay', input='0 262144 delay /dev/vdb 0 0 /dev/vdb 0 1000\n')
owner, store = open_store(source='/dev/mapper/piv-test-delay')
# Observe in a SEPARATE process: some guest Python ioctl paths can retain the
# GIL while blocked, making a monitoring thread miss the entire I/O window.
number = Path('/dev/mapper/piv-test-delay').stat().st_rdev
inflight = Path(f'/sys/dev/block/{os.major(number)}:{os.minor(number)}/inflight')
ready_r, ready_w = os.pipe()
monitor = os.fork()
if monitor == 0:
    os.close(ready_w)
    # Do not retain controller/ownership references in the observer.
    os.close(store.device.fd)
    os.close(store.lock_fd)
    os.close(owner.lock_fd)
    assert os.read(ready_r, 1) == b'1'
    os.close(ready_r)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        writes = list(map(int, inflight.read_text().split()))[1]
        if writes:
            assert (STATE / 'pending-v2').exists()
            (W / 'cut-boundary.json').write_text(json.dumps({
                'prefix': 96, 'inflight_writes': writes, 'delay_ms': 1000,
                'observer': 'independent process'}) + '\n')
            print('\nPIV_POWER_CUT', flush=True)
            while True:
                time.sleep(.2)
        time.sleep(.001)
    raise AssertionError('No delayed write observed by independent process')
os.close(ready_r)
def checkpoint(phase):
    if phase == 'applied:95':
        os.write(ready_w, b'1')
store._checkpoint = checkpoint
try:
    store.write_primary(offset, replacement)
finally:
    os.close(ready_w)
os.waitpid(monitor, 0)
raise AssertionError('Expected QEMU interruption before normal completion')
