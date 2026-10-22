#!/usr/bin/env python3
"""Disposable 512 MiB fixture: high-offset geometry, tails and read faults."""
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import secrets
import subprocess
import time

from pivstore.blocks import open_blocks, close_blocks, native_status
from pivstore.kernel_api import dm
from pivstore.kernel_owner import GuestOwner

W = Path('/mnt/piv-work')
KEY = W / 'passphrase.key'
HKEY = secrets.token_bytes(32)
(W / 'hidden.key').write_bytes(HKEY)
PRIMARY = (W / 'expected.sha256').read_text().strip()
(W / 'expected-primary.sha256').write_text(PRIMARY + '\n')
SOURCE = '/dev/mapper/piv-test-fault'
RAW = 512 * 1024 * 1024
OLD_CAP = 256 * 1024 * 1024
results = dict(cases=[], faults=[])


def direct(path, offset, count=4096, write=None):   # 4096: hidden logical block
    with mmap.mmap(-1, count) as buf:
        fd = os.open(path, os.O_RDWR | os.O_DIRECT)
        try:
            if write is None:
                assert os.preadv(fd, [buf], offset) == count
                return buf[:]
            assert len(write) == count
            buf[:] = write
            assert os.pwritev(fd, [buf], offset) == count
            os.fsync(fd)
        finally:
            os.close(fd)


def open_views(source='/dev/vdb', initialize=False):
    value = open_blocks(source, KEY, HKEY, initialize=initialize, allow_test_stack=source == SOURCE)
    subprocess.run(['udevadm', 'settle'], check=True)
    return value


def close_views(source='/dev/vdb'):
    close_blocks(source, KEY, allow_test_stack=source == SOURCE)


def verify(views):
    assert subprocess.check_output(['sha256sum', views['decoy']], text=True).split()[0] == PRIMARY
    assert Path(views['hidden']).read_bytes() == expected


def rejected(action):
    try:
        action()
    except OSError as error:
        assert error.errno == errno.EIO, error
    else:
        raise AssertionError('Expected EIO')


start = time.monotonic()
v = open_views(initialize=True)
results['initialize_seconds'] = time.monotonic() - start
owner = GuestOwner('/dev/vdb', KEY)
unit, sectors, iv = owner.device.sector_size, owner.device.sectors, owner.device.iv_size
# Format v5 geometry: 112 keyslot sectors, two directory groups, 687-sector
# records (no parity) of 4096-byte hidden blocks.
group, size, BLOCK = 687, sectors * unit, 4096
records = (sectors - 112) // group - 2
capacity = v['hidden_bytes']
def first_sector(block): return 112 + group * (2 + block)
def blocks_in(offset, count):
    """Hidden blocks with a fragment in primary bytes [offset, offset + count)."""
    low, high = offset // unit, (offset + count - 1) // unit
    return range(max(0, (low - 112) // group - 2), min(records, max(0, (high - 112) // group - 1)))
old_cap_block = (OLD_CAP // unit - first_sector(0)) // group
assert size > OLD_CAP and capacity == records * BLOCK
assert owner.raw_bytes == RAW
# Keyslot 0 (2 x 14), the directory (687), then one 687-sector record per block.
assert native_status(owner.device)['encryptions'] == 28 + group + records * group
expected = bytearray(capacity)
assert Path(v['hidden']).read_bytes() == expected
for index in sorted({0, old_cap_block, capacity // BLOCK - 1}):
    value = hashlib.shake_256(b'large-hidden-' + index.to_bytes(8, 'little')).digest(BLOCK)
    direct(v['hidden'], index * BLOCK, write=value)
    expected[index * BLOCK:(index + 1) * BLOCK] = value
    assert direct(v['hidden'], index * BLOCK) == value
print(f'Initialized {size} primary / {capacity} hidden bytes, sector={unit}', flush=True)

boundary = (OLD_CAP // (32768 * 512) + 1) * 32768 * 512
record = first_sector(old_cap_block + 1) * unit
cases = [('old-cap-boundary', OLD_CAP - 512, 4096),
         ('high-unaligned', OLD_CAP + 32768 + 512, 16384),
         ('high-interleave', boundary - 512, 4096),
         ('high-record', record - 512, 4096),
         ('last-16k', size - 16384, 16384),
         ('last-sector', size - unit, unit)]
tail = first_sector(records) * unit
if tail < size:
    cases.append(('record-tail', tail - 512, min(4096, size - tail + 512)))
for label, offset, count in cases:
    assert offset >= OLD_CAP - 512 and offset + count <= size
    old = direct(v['decoy'], offset, count)
    value = hashlib.shake_256(label.encode()).digest(count)
    direct(v['decoy'], offset, count, value)
    assert direct(v['decoy'], offset, count) == value
    # Check every affected hidden block, including records preserved across a
    # partial primary-sector write and records near the unused tail.
    for index in blocks_in(offset, count):
        assert direct(v['hidden'], index * BLOCK) == expected[index * BLOCK:(index + 1) * BLOCK]
    direct(v['decoy'], offset, count, old)
    assert direct(v['decoy'], offset, count) == old
    results['cases'].append(dict(case=label, offset=offset, bytes=count))
    print(f'{label}: {count} bytes at {offset} passed', flush=True)

# End-of-device reads cannot wrap to low addresses or change shared health.
for role, end in (('decoy', size), ('hidden', capacity)):
    with mmap.mmap(-1, BLOCK) as buf:
        buf[:] = b'\xa5' * BLOCK
        fd = os.open(v[role], os.O_RDWR | os.O_DIRECT)
        try:
            assert os.preadv(fd, [buf], end) == 0
            assert buf[:] == b'\xa5' * BLOCK
            try:
                os.pwritev(fd, [buf], end)
            except OSError as error:
                assert error.errno in (errno.ENOSPC, errno.EINVAL), error
            else:
                raise AssertionError('Past-end write succeeded')
        finally:
            os.close(fd)
assert not native_status(owner.device)['failed']
layout = owner.layout
owner.close()
verify(v)
close_views()
start = time.monotonic()
v = open_views()
results['reopen_seconds'] = time.monotonic() - start
verify(v)
close_views()

raw_sectors = RAW // 512
healthy = f'0 {raw_sectors} linear /dev/vdb 0\n'
dm('create', 'piv-test-fault', input=healthy)


def reload(table):
    dm('suspend', '--noflush', 'piv-test-fault')
    dm('reload', 'piv-test-fault', input=table)
    dm('resume', 'piv-test-fault')


for fault in ('reads', 'corruption'):
    v = open_views(SOURCE)
    handle = GuestOwner(SOURCE, KEY, allow_test_stack=True)
    # Last sector of the last record, beyond the old limit and away from checkpoint0.
    last = first_sector(records) - 1
    assert last * unit > OLD_CAP
    physical = layout.offsets(last)[0]
    if fault == 'reads':
        reload(f'0 {raw_sectors} flakey /dev/vdb 0 0 3600 1 error_reads\n')
        rejected(lambda: direct(SOURCE, physical))
        offset = (last * unit // 16384) * 16384
        role, count = 'decoy', min(16384, size - offset)
    else:
        original = direct('/dev/vdb', physical)
        sector512, replacement = physical // 512, original[0] ^ 1
        reload(f'0 {sector512} linear /dev/vdb 0\n'
               f'{sector512} 1 flakey /dev/vdb {sector512} 0 3600 5 corrupt_bio_byte 1 r {replacement} 0\n'
               f'{sector512 + 1} {raw_sectors - sector512 - 1} linear /dev/vdb {sector512 + 1}\n')
        assert direct(SOURCE, physical) == bytes([replacement]) + original[1:]
        # Format v5: hidden reads take the raw stored IV of a carrier sector
        # failing authentication; corrupt data alone leaves the block
        # readable (the record's SIV tag decides), while the decoy work item
        # holding that sector is withheld.
        assert direct(v['hidden'], capacity - BLOCK) == expected[capacity - BLOCK:]
        offset = (last * unit // 16384) * 16384
        role, count = 'decoy', min(16384, size - offset)
    with mmap.mmap(-1, count) as buf:
        sentinel = b'\xa5' * count
        buf[:] = sentinel
        fd = os.open(v[role], os.O_RDONLY | os.O_DIRECT)
        try:
            rejected(lambda: os.preadv(fd, [buf], offset))
            assert buf[:] == sentinel
        finally:
            os.close(fd)
    # Scoped isolation (since 2026-10-20): a read or authentication failure
    # mutates nothing, so only the request fails; the same owner keeps serving
    # both views once the fault clears.
    assert not native_status(handle.device)['failed']
    reload(healthy)
    for peer in ('decoy', 'hidden'):
        direct(v[peer], 0)
    handle.close()
    close_views(SOURCE)
    v = open_views(SOURCE)
    verify(v)
    close_views(SOURCE)
    results['faults'].append(dict(fault=fault, primary_sector=last,
                                 beyond_old_cap=True, no_output=True, local_failure=True))
    print(f'High-address {fault}: withholding, local EIO, continuation and reopen passed', flush=True)
dm('remove', '--retry', 'piv-test-fault')
subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0] == PRIMARY
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
(W / 'expected-hidden-volume').write_bytes(expected)
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'large-final.img'), 'bs=1M', 'status=none'], check=True)
results.update(raw_bytes=RAW, primary_bytes=size, hidden_bytes=capacity,
               primary_sectors=sectors, sector_size=unit, iv_bytes=iv,
               format=5, unused_tail_sectors=sectors - first_sector(records))
(W / 'large-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Larger geometry, high addresses, record/tail boundaries, faults, full oracles and stock verification passed\n')
