#!/usr/bin/env python3
"""Disposable guest: concurrent decoy/hidden I/O against exact and history oracles,
then a lower write fault during concurrent I/O (fail-stop without hangs).

Phase A: threads own interleaved decoy stripes of whole primary sectors (the
decoy's logical block size; on 512-byte volumes 4 KiB pages and hidden
records are shared between threads), large decoy chunks
(DM-split across work items) and hidden blocks whose carriers lie in the
striped region. Owners read back exact values; other threads read concurrently
and must see a value the owner has written (old or new), never EIO or a torn
sector. Phase B: all threads write overlapping decoy ranges and one
shared hidden block; every unit ends as one of the values written to it.
Phase M: phase A's workload plus buffered decoy writes while a memory hog
leaves about 48 MiB available: no I/O errors, no fail-stop, exact oracles.
Phase C: lower writes start failing while all threads run; every request must
return, the owner must fail-stop, and after recreation every primary sector is
whole and each hidden block holds a written value (EIO only for blocks written
in that phase, then repaired). Finishes with reopen, stock full-primary readback and a
closed image for host verification.
"""
from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import random
import subprocess
import threading
import time

import pivstore.blocks as blocks
import pivstore.kernel_owner as owners
from pivstore.kernel_api import dm, mapping_identity
from pivstore.records import shaped_extent

W = Path('/mnt/piv-work')
SOURCE = '/dev/mapper/piv-test-fault'
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
NAMES = ('piv-native-hidden', 'piv-native-decoy', 'piv-native', 'piv-native_dif')
GROUP, BLOCK = 687, 4096
# Decoy oracle unit: the primary sector size, which the decoy view advertises
# as its logical block size (as stock dm-crypt does).
UNIT = json.loads(subprocess.check_output(['cryptsetup', 'luksDump', '--dump-json-metadata', '/dev/vdb'],
                                          text=True))['segments']['0']['sector_size']
THREADS = 8
OPS = int(os.environ.get('PIV_STRESS_OPS', '48'))
results = dict(threads=THREADS, ops_per_thread=OPS)
# Fixture persists stock --integrity-no-journal (guest_code sets this).
NO_JOURNAL = os.environ.get('PIV_NO_JOURNAL') == '1'
RAW_SECTORS = int(subprocess.check_output(['blockdev', '--getsz', '/dev/vdb']))


def table(mode='linear'):
    line = 'linear /dev/vdb 0' if mode == 'linear' else f'flakey /dev/vdb 0 0 3600 1 error_{mode}'
    return f'0 {RAW_SECTORS} {line}\n'


def fault(mode='linear'):
    dm('suspend', '--noflush', 'piv-test-fault')
    dm('reload', 'piv-test-fault', input=table(mode))
    dm('resume', 'piv-test-fault')


def open_views():
    value = blocks.open_blocks(SOURCE, KEY, HKEY)
    subprocess.run(['udevadm', 'settle'], check=True)
    return value


def close_views():
    blocks.close_blocks(SOURCE, KEY)


def status():
    handle = owners.GuestOwner(SOURCE, KEY)
    try:
        return blocks.native_status(handle.device), handle.device.sector_size, handle.device.sectors
    finally:
        handle.close()


def io(path, offset, size, data=None, sync=False):
    """One O_DIRECT request (each opens its own descriptor)."""
    buf = mmap.mmap(-1, size)
    fd = os.open(path, os.O_RDWR | os.O_DIRECT | (os.O_DSYNC if sync else 0))
    try:
        if data is None:
            assert os.preadv(fd, [buf], offset) == size
            return buf[:]
        buf[:] = data
        assert os.pwritev(fd, [buf], offset) == size
        if sync:
            os.fsync(fd)
    finally:
        os.close(fd)
        buf.close()


def unreadable_units(path, count, chunk=256):
    """Decoy units whose O_DIRECT reads fail with EIO (per unit on error)."""
    bad = []
    for first in range(0, count, chunk):
        n = min(chunk, count - first)
        try:
            io(path, first * UNIT, n * UNIT)
            continue
        except OSError as exc:
            assert exc.errno == errno.EIO, exc
        for u in range(first, first + n):
            try:
                io(path, u * UNIT, UNIT)
            except OSError as exc:
                assert exc.errno == errno.EIO, exc
                bad.append(u)
    return bad


def value(*parts, size=UNIT):
    return hashlib.shake_256('/'.join(map(str, parts)).encode()).digest(size)


class History:
    """Every value ever written (or initially present) per decoy unit (primary sector) or
    hidden block. Writers record a value before issuing it, so a concurrent read
    may return any recorded value."""
    def __init__(self):
        self.lock = threading.Lock()
        self.values = {}

    def add(self, key, data, initial):
        with self.lock:
            self.values.setdefault(key, {initial}).add(data)

    def allowed(self, key, initial):
        with self.lock:
            return self.values.get(key, {initial})


image = bytearray()          # current primary oracle (decoy bytes)
hidden = bytearray()         # current hidden oracle
decoy_history, hidden_history = History(), History()


def check_decoy_read(offset, data):
    for at in range(0, len(data), UNIT):
        unit = (offset + at) // UNIT
        piece = data[at:at + UNIT]
        initial = bytes(image[unit * UNIT:(unit + 1) * UNIT])
        assert piece in decoy_history.allowed(unit, initial), ('decoy unit', unit)


def check_hidden_read(index, data):
    initial = bytes(hidden[index * BLOCK:(index + 1) * BLOCK])
    assert data in hidden_history.allowed(index, initial), ('hidden block', index)


def decoy_write(views, offset, data, sync=False):
    for at in range(0, len(data), UNIT):
        unit = (offset + at) // UNIT
        decoy_history.add(unit, data[at:at + UNIT], bytes(image[unit * UNIT:(unit + 1) * UNIT]))
    io(views['decoy'], offset, len(data), data, sync)


def hidden_write(views, index, data, sync=False):
    hidden_history.add(index, data, bytes(hidden[index * BLOCK:(index + 1) * BLOCK]))
    io(views['hidden'], index * BLOCK, BLOCK, data, sync)


absent = lambda: all(mapping_identity(name) is None for name in NAMES)
assert absent()
dm('create', 'piv-test-fault', input=table())
views = open_views()
_, unit, sectors = status()
records = len((W / 'expected-hidden-volume').read_bytes()) // BLOCK
image[:] = Path(views['decoy']).read_bytes()
assert hashlib.sha256(image).hexdigest() == PRIMARY
hidden[:] = (W / 'expected-hidden-volume').read_bytes()
assert Path(views['hidden']).read_bytes() == hidden
first_record = (112 + 2 * GROUP) * unit
R = min(4, records - 1)                       # striped hidden blocks; block R is shared
striped = (first_record, first_record + R * GROUP * unit)
CHUNK = 256 * 1024
big = (striped[1] // CHUNK + 1) * CHUNK      # large-write chunks after the striped region
big_end = big + 2 * THREADS * CHUNK
shared = (big_end, big_end + 64 * UNIT)      # phase B overlapping writes
assert shared[1] <= len(image)
STRIPE = 3                                    # units; crosses page and record boundaries


def stripes_of(thread):
    count = (striped[1] - striped[0]) // UNIT // STRIPE
    return [striped[0] + s * STRIPE * UNIT for s in range(thread, count, THREADS)]


def phase_a(views, thread, ops):
    rng = random.Random(f'stress-a/{thread}')
    mine = stripes_of(thread)
    chunks = [big + c * CHUNK for c in range(thread, 2 * THREADS, THREADS)]
    blocks_mine = [b for b in range(R) if b % THREADS == thread]
    counts = dict(stripe_writes=0, chunk_writes=0, hidden_writes=0, foreign_reads=0, fsyncs=0)
    for op in range(ops):
        kind = rng.randrange(6)
        sync = rng.random() < 0.2
        if kind == 0:
            start = rng.choice(mine)
            first = rng.randrange(STRIPE)
            length = rng.randrange(1, STRIPE - first + 1)
            offset = start + first * UNIT
            data = b''.join(value('a', thread, op, k) for k in range(length))
            decoy_write(views, offset, data, sync)
            assert io(views['decoy'], offset, len(data)) == data
            image[offset:offset + len(data)] = data
            counts['stripe_writes'] += 1
        elif kind == 1:
            start = rng.choice(chunks)
            first = rng.randrange(CHUNK // UNIT)
            length = rng.randrange(1, CHUNK // UNIT - first + 1) * UNIT
            offset = start + first * UNIT
            data = value('chunk', thread, op, size=length)
            decoy_write(views, offset, data, sync)
            assert io(views['decoy'], offset, length) == data
            image[offset:offset + length] = data
            counts['chunk_writes'] += 1
        elif kind == 2 and blocks_mine:
            index = rng.choice(blocks_mine)
            data = value('hidden', thread, op, size=BLOCK)
            hidden_write(views, index, data, sync)
            assert io(views['hidden'], index * BLOCK, BLOCK) == data
            hidden[index * BLOCK:(index + 1) * BLOCK] = data
            counts['hidden_writes'] += 1
        elif kind == 3:
            # Any hidden block (others' included): old or new, never EIO.
            index = rng.randrange(R + 1)
            check_hidden_read(index, io(views['hidden'], index * BLOCK, BLOCK))
            counts['foreign_reads'] += 1
        elif kind == 4:
            # A decoy span across other threads' stripes and record carriers.
            offset = rng.randrange(striped[0] // 4096, striped[1] // 4096 - 4) * 4096
            check_decoy_read(offset, io(views['decoy'], offset, 16384))
            counts['foreign_reads'] += 1
        else:
            fd = os.open(views[rng.choice(('decoy', 'hidden'))], os.O_RDWR)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            counts['fsyncs'] += 1
    return counts


def phase_b(views, thread, ops):
    rng = random.Random(f'stress-b/{thread}')
    units = (shared[1] - shared[0]) // UNIT
    for op in range(ops):
        if rng.random() < 0.3:
            data = value('shared-hidden', thread, op, size=BLOCK)
            hidden_write(views, R, data)
            check_hidden_read(R, io(views['hidden'], R * BLOCK, BLOCK))
        else:
            first = rng.randrange(units)
            length = rng.randrange(1, min(16, units - first) + 1)
            offset = shared[0] + first * UNIT
            data = b''.join(value('b', thread, op, k) for k in range(length))
            decoy_write(views, offset, data)
            check_decoy_read(offset, io(views['decoy'], offset, len(data)))


def run_threads(fn, *args):
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = [pool.submit(fn, views, t, *args) for t in range(THREADS)]
        return [f.result(timeout=1800) for f in futures]


def verify_all(views):
    assert hashlib.sha256(Path(views['decoy']).read_bytes()).digest() == hashlib.sha256(image).digest()
    assert Path(views['hidden']).read_bytes() == hidden


start = time.monotonic()
before = status()[0]
results['phase_a'] = run_threads(phase_a, OPS)
results['phase_a_seconds'] = time.monotonic() - start
verify_all(views)
print(f'Phase A: {results["phase_a"]} in {results["phase_a_seconds"]:.1f}s; exact oracles passed', flush=True)

start = time.monotonic()
run_threads(phase_b, OPS // 2)
# Overlapping writes: every unit ends as one written value; adopt it.
final = io(views['decoy'], shared[0], shared[1] - shared[0])
check_decoy_read(shared[0], final)
image[shared[0]:shared[1]] = final
data = io(views['hidden'], R * BLOCK, BLOCK)
check_hidden_read(R, data)
hidden[R * BLOCK:(R + 1) * BLOCK] = data
results['phase_b_seconds'] = time.monotonic() - start
after = status()[0]
assert not after['failed'] and after['encryptions'] > before['encryptions']
verify_all(views)
close_views()
views = open_views()
verify_all(views)
print(f'Phase B: overlapping writes settled to written values in {results["phase_b_seconds"]:.1f}s; reopen passed',
      flush=True)

# Phase M: memory pressure. A hog (first OOM victim) fills RAM until about
# 48 MiB remain available, then phase A's workload runs again and buffered
# (page-cache writeback) decoy writes are synced. Allocation failures inside
# the module must not surface as I/O errors (workers retry -ENOMEM before
# writing) and the owner must not fail-stop.
HOG = r'''
import mmap, os, sys, time
open('/proc/self/oom_score_adj', 'w').write('1000')
def available():
    for line in open('/proc/meminfo'):
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
chunks = []
while available() > 48 << 20:
    m = mmap.mmap(-1, 16 << 20)
    for at in range(0, len(m), 4096):
        m[at] = 1
    chunks.append(m)
print(len(chunks) * 16, flush=True)
time.sleep(3600)
'''


def mem_available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024


start = time.monotonic()
hog = subprocess.Popen(['python3', '-c', HOG], stdout=subprocess.PIPE, text=True)
try:
    results['phase_m_hog_mib'] = int(hog.stdout.readline())
    results['phase_m_available_mib'] = mem_available() >> 20
    results['phase_m'] = run_threads(phase_a, OPS // 2)
    # Buffered writes: dirty page cache written back through the decoy view.
    data = b''.join(value('m', k) for k in range((shared[1] - shared[0]) // UNIT))
    for k in range(0, len(data), UNIT):
        decoy_history.add((shared[0] + k) // UNIT, data[k:k + UNIT], bytes(image[shared[0] + k:shared[0] + k + UNIT]))
    fd = os.open(views['decoy'], os.O_WRONLY)
    try:
        assert os.pwrite(fd, data, shared[0]) == len(data)
        os.fsync(fd)
    finally:
        os.close(fd)
    image[shared[0]:shared[1]] = data
    results['phase_m_hog_alive'] = hog.poll() is None
finally:
    hog.kill()
    hog.wait()
results['phase_m_seconds'] = time.monotonic() - start
assert not status()[0]['failed']
verify_all(views)
print(f'Phase M: workload under memory pressure (hog {results["phase_m_hog_mib"]} MiB, '
      f'{results["phase_m_available_mib"]} MiB available, hog alive at end: {results["phase_m_hog_alive"]}) '
      f'in {results["phase_m_seconds"]:.1f}s; no I/O errors, oracles passed', flush=True)

# Phase C: lower write errors while every thread writes and reads. Plain
# writes are not flushed, so even a write that reported success before the
# fault may not persist: any block or unit written in this phase may end old,
# new or (hidden, single slot) unavailable.
written_hidden = set()
outcome_lock = threading.Lock()
progress = [0] * THREADS
deadline = time.monotonic() + 900


def phase_c(views, thread):
    rng = random.Random(f'stress-c/{thread}')
    blocks_mine = [b for b in range(R) if b % THREADS == thread]
    errors = op = 0
    while errors < 3 and time.monotonic() < deadline:
        op += 1
        try:
            if blocks_mine and rng.random() < 0.3:
                index = rng.choice(blocks_mine)
                data = value('c-hidden', thread, op, size=BLOCK)
                with outcome_lock: written_hidden.add(index)
                hidden_write(views, index, data)
            else:
                # Some writes fsync: dm-integrity completes plain journal writes
                # before committing them, so lower errors surface at commits.
                start = rng.choice(stripes_of(thread))
                decoy_write(views, start, b''.join(value('c', thread, op, k) for k in range(STRIPE)),
                            sync=rng.random() < 0.2)
        except OSError as exc:
            assert exc.errno == errno.EIO, exc
            errors += 1
        progress[thread] = op
    return dict(ops=op, errors=errors)


with ThreadPoolExecutor(max_workers=THREADS) as pool:
    futures = [pool.submit(phase_c, views, t) for t in range(THREADS)]
    while min(progress) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    fault('writes')
    try:
        # Every request must return (EIO once the owner stopped); none may hang.
        outcomes = [f.result(timeout=600) for f in futures]
    finally:
        fault()
results['phase_c'] = outcomes
state = status()[0]
assert state['failed'], state
assert all(o['errors'] == 3 for o in outcomes), outcomes
for role in ('decoy', 'hidden'):
    try:
        io(views[role], 0, BLOCK)
    except OSError as exc:
        assert exc.errno == errno.EIO
    else:
        raise AssertionError('A fail-stopped owner served a read')
close_views()
assert absent()
views = open_views()
assert not status()[0]['failed']
# Journaled: every primary sector stays whole; failed writes may be partial.
# Stock persistent no-journal (direct mode): a lower write that landed while
# another (data or tag) failed leaves its sector torn (EIO). Torn sectors must
# lie in the region phase C wrote (decoy stripes and the striped hidden
# records, shaped to 4 KiB edges: their extents reach the last sectors of
# directory group 1 and the first of block R's record, whose fragments the
# refresh keeps); their plaintext is lost, so a full-sector decoy write of a fresh
# value replaces each (the failing-sector replacement path), which keeps the
# stored fragment.
torn = unreadable_units(views['decoy'], len(image) // UNIT)
results['phase_c_torn_primary_sectors'] = torn
if NO_JOURNAL:
    shaped = (shaped_extent(first_record // unit, GROUP, unit, len(image) // unit)[0] * unit,
              shaped_extent(striped[1] // unit - GROUP, GROUP, unit, len(image) // unit)[1] * unit)
    assert all(shaped[0] <= u * UNIT < shaped[1] for u in torn), torn
    for u in torn:
        decoy_write(views, u * UNIT, value('c-torn-repair', u), sync=True)
    assert not unreadable_units(views['decoy'], len(image) // UNIT)
else:
    assert not torn, torn
data = Path(views['decoy']).read_bytes()
check_decoy_read(0, data)
image[:] = data
repaired = []
for index in range(records):
    try:
        data = io(views['hidden'], index * BLOCK, BLOCK)
    except OSError as exc:
        assert exc.errno == errno.EIO and index in written_hidden, (index, exc)
        data = value('repair', index, size=BLOCK)
        hidden_write(views, index, data)
        repaired.append(index)
    else:
        check_hidden_read(index, data)
    hidden[index * BLOCK:(index + 1) * BLOCK] = data
results['phase_c_repaired_hidden_blocks'] = repaired
results['phase_c_written_hidden_blocks'] = sorted(written_hidden)
verify_all(views)
close_views()
views = open_views()
verify_all(views)
close_views()
dm('remove', '--retry', 'piv-test-fault')
assert absent()
print(f'Phase C: fail-stop under concurrency, {len(repaired)} hidden blocks repaired, recreation passed', flush=True)

subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
assert hashlib.sha256(Path('/dev/mapper/piv-stock').read_bytes()).digest() == hashlib.sha256(image).digest()
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
(W / 'expected-hidden-volume').write_bytes(hidden)
(W / 'expected-primary.sha256').write_text(hashlib.sha256(image).hexdigest() + '\n')
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'stress-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'stress-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Concurrent exact/history oracles, overlapping writes, fail-stop under concurrency, '
                              'recreation and stock verification passed\n')
