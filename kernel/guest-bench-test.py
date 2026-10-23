#!/usr/bin/env python3
"""Pinned disposable guest: configuration benchmark on a pristine stock fixture.

Times stock and native activation, decoy and hidden throughput (4096-byte
hidden blocks; random writes also at queue depth 16), A/B, RS parity and the
Argon2id passphrase cost tiers,
checking every byte read back. Destroys the fixture's decoy
contents (guest-owned copy only). Results: bench-results.json.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import mmap
import os
from pathlib import Path
import random
import subprocess
import time

import pivstore.blocks as blocks
from pivstore.kernel_owner import GuestOwner

W = Path('/mnt/piv-work')
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
MIB = 1024 * 1024
DECOY_BYTES, DECOY_CHUNK = 16 * MIB, MIB
HIDDEN_LIMIT, HIDDEN_CHUNK = MIB, 64 * 1024
RANDOM_DECOY, RANDOM_HIDDEN = 256, 64
DEPTH = 16
STOCK = '/dev/mapper/piv-stock-bench'
results = dict(activation=[], throughput=[], encryptions=[])


def crypt(*args):
    subprocess.run(['cryptsetup', *map(str, args)], check=True)


def size(path):
    return int(subprocess.check_output(['blockdev', '--getsize64', path]))


def timed(fn):
    start = time.monotonic()
    value = fn()
    return value, time.monotonic() - start


def transfer(path, offset, length, chunk, data=None):
    """Sequential O_DIRECT I/O; a write ends with fsync. Returns (bytes, seconds)."""
    out = bytearray()
    with mmap.mmap(-1, chunk) as buf:
        fd = os.open(path, (os.O_RDONLY if data is None else os.O_RDWR) | os.O_DIRECT)
        try:
            start = time.monotonic()
            for pos in range(0, length, chunk):
                count = min(chunk, length - pos)
                view = memoryview(buf)[:count]
                try:
                    if data is None:
                        assert os.preadv(fd, [view], offset + pos) == count
                        out += view
                    else:
                        view[:] = data[pos:pos + count]
                        assert os.pwritev(fd, [view], offset + pos) == count
                finally:
                    view.release()
            if data is not None:
                os.fsync(fd)
            return bytes(out), time.monotonic() - start
        finally:
            os.close(fd)


def scattered(path, offsets, unit, data=None):
    """Random O_DIRECT requests of @unit bytes; writes end with one fsync."""
    out = {}
    with mmap.mmap(-1, unit) as buf:
        fd = os.open(path, (os.O_RDONLY if data is None else os.O_RDWR) | os.O_DIRECT)
        try:
            start = time.monotonic()
            for offset in offsets:
                if data is None:
                    assert os.preadv(fd, [buf], offset) == unit
                    out[offset] = buf[:]
                else:
                    buf[:] = data[offset]
                    assert os.pwritev(fd, [buf], offset) == unit
            if data is not None:
                os.fsync(fd)
            return out, time.monotonic() - start
        finally:
            os.close(fd)


def concurrent(path, offsets, unit, data):
    """Random O_DIRECT writes of @unit bytes from DEPTH threads (one request
    in flight each, so queue depth DEPTH), then one fsync. Returns seconds."""
    parts = [offsets[i::DEPTH] for i in range(DEPTH)]
    fd = os.open(path, os.O_RDWR | os.O_DIRECT)

    def worker(part):
        with mmap.mmap(-1, unit) as buf:
            for offset in part:
                buf[:] = data[offset]
                assert os.pwritev(fd, [buf], offset) == unit

    try:
        start = time.monotonic()
        with ThreadPoolExecutor(DEPTH) as pool:
            list(pool.map(worker, parts))
        os.fsync(fd)
        return time.monotonic() - start
    finally:
        os.close(fd)


def encryptions():
    owner = GuestOwner('/dev/vdb', KEY)
    try:
        status = blocks.native_status(owner.device)
        assert not status['failed']
        return status['encryptions']
    finally:
        owner.close()


def record(config, role, pattern, nbytes, seconds, requests=None):
    results['throughput'].append(dict(config=config, role=role, pattern=pattern, bytes=nbytes,
                                      seconds=seconds, requests=requests,
                                      mib_per_s=nbytes / MIB / seconds,
                                      iops=None if requests is None else requests / seconds))


def workload(config, path, role, offset, length, chunk, unit, count, native=True):
    """Sequential write+read of @length at @offset, then @count random @unit writes+reads."""
    data = os.urandom(length)
    before = encryptions() if native else None
    _, seconds = transfer(path, offset, length, chunk, data)
    if native:
        results['encryptions'].append(dict(config=config, role=role, pattern='sequential-write',
                                           bytes=length, encryptions=encryptions() - before))
    record(config, role, 'sequential-write', length, seconds)
    back, seconds = transfer(path, offset, length, chunk)
    assert back == data, (config, role)
    record(config, role, 'sequential-read', length, seconds)
    rng = random.Random(f'{config}/{role}')
    offsets = sorted({offset + rng.randrange(length // unit) * unit for _ in range(count)})
    rng.shuffle(offsets)
    blocks_ = {o: os.urandom(unit) for o in offsets}
    _, seconds = scattered(path, offsets, unit, blocks_)
    record(config, role, f'random-write-{unit}', unit * len(offsets), seconds, len(offsets))
    back, seconds = scattered(path, offsets, unit)
    assert back == blocks_, (config, role)
    record(config, role, f'random-read-{unit}', unit * len(offsets), seconds, len(offsets))
    image = bytearray(data)
    for o, value in blocks_.items():
        image[o - offset:o - offset + unit] = value
    # Queue depth 16: the same number of random writes from 16 threads.
    rng = random.Random(f'{config}/{role}/qd{DEPTH}')
    offsets = sorted({offset + rng.randrange(length // unit) * unit for _ in range(count)})
    rng.shuffle(offsets)
    deep = {o: os.urandom(unit) for o in offsets}
    seconds = concurrent(path, offsets, unit, deep)
    record(config, role, f'random-write-{unit}-qd{DEPTH}', unit * len(offsets), seconds, len(offsets))
    back, _ = scattered(path, offsets, unit)
    assert back == deep, (config, role)
    for o, value in deep.items():
        image[o - offset:o - offset + unit] = value
    return hashlib.sha256(image).hexdigest()


def native_open(config, kind, **options):
    views, seconds = timed(lambda: blocks.open_blocks('/dev/vdb', KEY, options.pop('key', HKEY), **options))
    results['activation'].append(dict(config=config, kind=kind, seconds=seconds))
    subprocess.run(['udevadm', 'settle'], check=True)
    return views


def native_close(config):
    _, seconds = timed(lambda: blocks.close_blocks('/dev/vdb', KEY))
    results['activation'].append(dict(config=config, kind='close', seconds=seconds))


# Stock baseline over the same fixture: three timed opens; workload on the first.
for repeat in range(3):
    _, seconds = timed(lambda: crypt('open', '--key-file', KEY, '/dev/vdb', 'piv-stock-bench'))
    results['activation'].append(dict(config='stock', kind='open', seconds=seconds))
    if repeat == 0:
        unit = int(subprocess.check_output(['blockdev', '--getss', STOCK]))
        stock_bytes = size(STOCK)
        stock_hash = workload('stock', STOCK, 'decoy', 0, DECOY_BYTES, DECOY_CHUNK, 4096, RANDOM_DECOY,
                              native=False)
    _, seconds = timed(lambda: crypt('close', 'piv-stock-bench'))
    results['activation'].append(dict(config='stock', kind='close', seconds=seconds))

# Native, one record slot per block (the default).
views = native_open('single', 'initialize', initialize=True)
decoy_bytes, hidden_bytes = size(views['decoy']), size(views['hidden'])
hidden_len = min(hidden_bytes, HIDDEN_LIMIT) // HIDDEN_CHUNK * HIDDEN_CHUNK or hidden_bytes
decoy_hash = workload('single', views['decoy'], 'decoy', DECOY_BYTES, DECOY_BYTES, DECOY_CHUNK, 4096,
                      RANDOM_DECOY)
hidden_hash = workload('single', views['hidden'], 'hidden', 0, hidden_len, HIDDEN_CHUNK, 4096, RANDOM_HIDDEN)
native_close('single')
for repeat in range(3):
    views = native_open('single', 'open')
    native_close('single')
views = native_open('single', 'open-verify', verify=True)
# Persistence across reopen: stock region untouched, both native regions intact.
assert hashlib.sha256(transfer(views['decoy'], 0, DECOY_BYTES, DECOY_CHUNK)[0]).hexdigest() == stock_hash
assert hashlib.sha256(transfer(views['decoy'], DECOY_BYTES, DECOY_BYTES, DECOY_CHUNK)[0]).hexdigest() == decoy_hash
assert hashlib.sha256(transfer(views['hidden'], 0, hidden_len, HIDDEN_CHUNK)[0]).hexdigest() == hidden_hash
native_close('single')

# A/B: two record slots per block (reinitializes the hidden volume).
views = native_open('ab', 'initialize', initialize=True, ab=True)
ab_bytes = size(views['hidden'])
ab_len = min(ab_bytes, HIDDEN_LIMIT) // HIDDEN_CHUNK * HIDDEN_CHUNK or ab_bytes
ab_hash = workload('ab', views['hidden'], 'hidden', 0, ab_len, HIDDEN_CHUNK, 4096, RANDOM_HIDDEN)
native_close('ab')
views = native_open('ab', 'open')
assert hashlib.sha256(transfer(views['hidden'], 0, ab_len, HIDDEN_CHUNK)[0]).hexdigest() == ab_hash
native_close('ab')

# Reed-Solomon parity p = 8 (G = 711 sectors per record).
views = native_open('parity8', 'initialize', initialize=True, parity=8)
parity_bytes = size(views['hidden'])
parity_len = min(parity_bytes, HIDDEN_LIMIT) // HIDDEN_CHUNK * HIDDEN_CHUNK or parity_bytes
parity_hash = workload('parity8', views['hidden'], 'hidden', 0, parity_len, HIDDEN_CHUNK, 4096, RANDOM_HIDDEN)
native_close('parity8')
views = native_open('parity8', 'open')
assert hashlib.sha256(transfer(views['hidden'], 0, parity_len, HIDDEN_CHUNK)[0]).hexdigest() == parity_hash
native_close('parity8')

# Argon2id passphrase KEK cost tiers (synthetic random passphrase): initialize
# with tier 1, add tiers 2-4 as further keyslots, then time an open per tier
# (pivsetup's KDF plus the same keyslot-area setup as a key-file open).
passphrase = os.urandom(16).hex().encode()
native_open('argon2id-tier1', 'initialize', key=None, hidden_passphrase=passphrase, initialize=True, kdf_cost=1)
for tier in (2, 3, 4):
    # Authorized by the tier-1 passphrase of keyslot 0.
    blocks.keyslot('/dev/vdb', KEY, tier - 1, passphrase=passphrase, kdf_cost=tier,
                   hidden_passphrase=passphrase, hidden_kdf_cost=1)
native_close('argon2id-tier1')
for tier in (1, 2, 3, 4):
    native_open(f'argon2id-tier{tier}', 'open', key=None, hidden_passphrase=passphrase, kdf_cost=tier)
    native_close(f'argon2id-tier{tier}')

# Stock Linux still authenticates every primary sector and sees both decoy regions.
subprocess.run(['rmmod', 'dm_piv'], check=True)
crypt('open', '--readonly', '--key-file', KEY, '/dev/vdb', 'piv-stock-bench')
primary = Path(STOCK).read_bytes()
assert hashlib.sha256(primary[:DECOY_BYTES]).hexdigest() == stock_hash
assert hashlib.sha256(primary[DECOY_BYTES:2 * DECOY_BYTES]).hexdigest() == decoy_hash
crypt('close', 'piv-stock-bench')

results.update(primary_sector=unit, raw_bytes=size('/dev/vdb'), stock_bytes=stock_bytes,
               decoy_bytes=decoy_bytes, hidden_bytes=hidden_bytes, ab_hidden_bytes=ab_bytes,
               parity8_hidden_bytes=parity_bytes, format=5,
               cpu=next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                        if line.startswith('model name')),
               vcpus=os.cpu_count(), kernel=os.uname().release,
               cache_state='QEMU raw image on host page cache; O_DIRECT bypasses only the guest page cache')
(W / 'bench-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Configuration benchmark completed with byte-exact readback and stock verification\n')
print(json.dumps(results), flush=True)

