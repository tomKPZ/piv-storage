#!/usr/bin/env python3
"""Measure bounded decoy I/O against complete closed-fixture oracles."""
import hashlib
import json
import mmap
import os
from pathlib import Path
import subprocess
import time

from pivstore.blocks import open_blocks, close_blocks, native_status
from pivstore.kernel_owner import GuestOwner

W = Path('/mnt/piv-work')
KEY = W / 'passphrase.key'
EXPECTED = (W / 'expected-hidden-volume').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
v = open_blocks('/dev/vdb', KEY, (W / 'hidden.key').read_bytes())
subprocess.run(['udevadm', 'settle'], check=True)
owner = GuestOwner('/dev/vdb', KEY)
unit = owner.device.sector_size
group = 576 // owner.device.iv_size
size = owner.device.sectors * unit
groups_end = owner.device.sectors // group * group * unit
# Current target contract; historical pre-batching runs retain frozen harnesses.
batched = True
quantum = 16384
results = []

def direct(offset, count, write=None):
    buf = mmap.mmap(-1, count)
    fd = os.open(v['decoy'], os.O_RDWR | os.O_DIRECT | os.O_DSYNC)
    try:
        if write is None:
            assert os.preadv(fd, [buf], offset) == count
            return buf[:]
        buf[:] = write
        assert os.pwritev(fd, [buf], offset) == count
        os.fsync(fd)
    finally:
        os.close(fd)
        buf.close()

def expected_count(offset, count):
    end, total = offset + count, 0
    while offset < end:
        stop = min(end, (offset // quantum + 1) * quantum)
        first, last = offset // unit, (stop - 1) // unit
        full = owner.device.sectors // group
        total += max(0, min(last // group, full - 1) - first // group + 1) * group
        total += max(0, last - max(first, full * group) + 1)
        offset = stop
    return total

cases = [('4k', 0, 4096), ('16k', 0, 16384),
         ('unaligned', 512, 16384),
         ('carrier-boundary', group * unit - 512, 4096),
         ('32k-split', 0, 32768),
         ('last-16k', size - 16384, 16384)]
if groups_end < size:
    cases.append(('carrier-tail', groups_end - 512, min(4096, size - groups_end + 512)))
for label, offset, count in cases:
    old = direct(offset, count)
    new = hashlib.shake_256(('batch-' + label).encode()).digest(count)
    before = native_status(owner.device)['encryptions']
    start = time.monotonic()
    direct(offset, count, new)
    elapsed = time.monotonic() - start
    spent = native_status(owner.device)['encryptions'] - before
    assert spent == expected_count(offset, count), (label, spent, expected_count(offset, count))
    assert direct(offset, count) == new
    direct(offset, count, old)
    assert direct(offset, count) == old
    results.append(dict(case=label, bytes=count, offset=offset,
                        encryptions=spent, seconds=elapsed, bytes_per_second=count / elapsed))
    print(f'{label}: {spent} primary encryptions, {elapsed:.3f}s', flush=True)
assert not native_status(owner.device)['failed']
owner.close()
# Full checks catch both out-of-range primary changes and hidden corruption.
assert subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0] == PRIMARY
assert Path(v['hidden']).read_bytes() == EXPECTED
close_blocks('/dev/vdb', KEY)
v = open_blocks('/dev/vdb', KEY, (W / 'hidden.key').read_bytes())
assert Path(v['hidden']).read_bytes() == EXPECTED
close_blocks('/dev/vdb', KEY)
subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0] == PRIMARY
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'batch-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'batch-results.json').write_text(json.dumps(dict(batched=batched, primary_sector=unit,
    group=group, cases=results), indent=2) + '\n')
(W / 'result.txt').write_text('Batch counts, direct read/write/restore, full oracles, reopen and stock verification passed\n')
