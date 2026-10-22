#!/usr/bin/env python3
"""Two sequential matched arms (stock, native) on guest-owned disposable /dev/vdb only."""
from dataclasses import asdict
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import subprocess
import time

from control_metrics import workload, payload
from pivstore.blocks import open_blocks, close_blocks
from pivstore.kernel_api import dm
from pivstore.kernel_owner import guest_guard, crypt
from pivstore.profile import validate_segment, parse_superblock

W = Path('/mnt/piv-work')
T = Path('/sys/kernel/tracing')
KEY = W / 'passphrase.key'
guest_guard('/dev/vdb')
metadata = json.loads(crypt('luksDump', '--dump-json-metadata', '/dev/vdb').stdout)
offset = validate_segment(metadata)
raw = os.open('/dev/vdb', os.O_RDONLY)
layout = parse_superblock(os.pread(raw, 4096, offset), offset, 128 * 1024 * 1024)
os.close(raw)
subprocess.run(['dd', 'if=/dev/vdb', 'of=/var/tmp/piv-control-original.img', 'bs=1M', 'status=none'], check=True)

def copy_disk(name):
    subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / name), 'bs=1M', 'status=none'], check=True)

def io(path, start, size, data=None):
    buf = mmap.mmap(-1, size)
    fd = os.open(path, os.O_RDWR | os.O_DIRECT)
    try:
        if data is None:
            assert os.preadv(fd, [buf], start) == size
            return buf[:]
        buf[:] = data
        assert os.pwritev(fd, [buf], start) == size
        os.fsync(fd)
    finally:
        os.close(fd); buf.close()

def opened(arm, initialize=False):
    if arm == 'native':
        return open_blocks('/dev/vdb', KEY, (W / 'hidden.key').read_bytes(), initialize=initialize)['decoy']
    crypt('open', '--disable-keyring', '--key-file', KEY, '/dev/vdb', 'piv-control')
    assert dm('table', 'piv-control').stdout.split()[2] == 'crypt'
    return '/dev/mapper/piv-control'

def closed(arm):
    if arm == 'native': close_blocks('/dev/vdb', KEY)
    else: crypt('close', 'piv-control')

def trace_value(name, value): (T / name).write_text(str(value))

results = []
original_primary = None
for arm in ('stock', 'native'):
    assert not list(Path('/sys/class/block/vdb/holders').iterdir())
    # Restore ONLY the guest's synthetic disk with ALL its mappings closed.
    subprocess.run(['dd', 'if=/var/tmp/piv-control-original.img', 'of=/dev/vdb', 'bs=1M', 'conv=fsync', 'status=none'], check=True)
    subprocess.run(['blockdev', '--flushbufs', '/dev/vdb'], check=True)
    if arm == 'native':
        subprocess.run(['insmod', str(W / 'experimental-dm-piv.ko')], check=True)
    path = opened(arm, initialize=arm == 'native')
    before_hash = subprocess.check_output(['sha256sum', path], text=True).split()[0]
    if original_primary is None: original_primary = before_hash
    assert before_hash == original_primary
    closed(arm)
    copy_disk(arm + '-before.img')
    path = opened(arm)
    subprocess.run(['udevadm', 'settle'], check=True)
    trace_value('current_tracer', 'nop')
    trace_value('tracing_on', 0)
    trace_value('trace_clock', 'global')
    trace_value('buffer_size_kb', 4096)
    device = Path('/dev/vdb').stat().st_rdev
    encoded_dev = (os.major(device) << 20) | os.minor(device)
    trace_value('events/block/block_bio_queue/filter', f'dev == {encoded_dev}')
    trace_value('events/block/block_bio_queue/enable', 1)
    trace_value('trace', '')
    trace_value('tracing_on', 1)
    start_time = time.monotonic()
    try:
        for label, start, size, same in workload(layout):
            value = io(path, start, size) if same else payload(label, size)
            io(path, start, size, value)
            assert io(path, start, size) == value
        elapsed = time.monotonic() - start_time
        # Sample after successful fsync. Journal background activity may race;
        # this is explicitly NOT an atomic journal snapshot or replay source.
        raw = os.open('/dev/vdb', os.O_RDONLY | os.O_DIRECT)
        size = layout.journal_sections * layout.journal_section_sectors * 512
        sample = mmap.mmap(-1, size)
        try:
            assert os.preadv(raw, [sample], offset + 4096) == size
            (W / (arm + '-journal.bin')).write_bytes(sample[:])
        finally: sample.close(); os.close(raw)
        time.sleep(1)  # same bounded post-fsync observation window in every arm
    finally:
        trace_value('tracing_on', 0)
        trace_value('events/block/block_bio_queue/enable', 0)
    (W / (arm + '.trace')).write_text((T / 'trace').read_text())
    stats = '\n'.join(p.read_text() for p in (T / 'per_cpu').glob('cpu*/stats'))
    assert not re.search(r'(?:overrun|dropped events):\s*[1-9]', stats), stats
    after_hash = subprocess.check_output(['sha256sum', path], text=True).split()[0]
    if arm == 'native':
        # Format v4: 112 keyslot sectors, two directory groups, 90-sector records.
        records = (layout.sectors - 112) // 90 - 2
        assert Path('/dev/mapper/piv-native-hidden').read_bytes() == bytes(records * 512)
    closed(arm)
    copy_disk(arm + '-after.img')
    if arm == 'native': subprocess.run(['rmmod', 'dm_piv'], check=True)
    # Unmodified stock target authenticates every arm's final primary.
    crypt('open', '--readonly', '--key-file', KEY, '/dev/vdb', 'piv-verify')
    assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-verify'], text=True).split()[0] == after_hash
    crypt('close', 'piv-verify')
    results.append(dict(arm=arm, before_primary=before_hash, after_primary=after_hash,
                        workload_seconds=elapsed, trace_device=f'{os.major(device)},{os.minor(device)}'))
    print(arm + ': matched workload, full stock authentication and closed snapshots passed', flush=True)
assert len({r['after_primary'] for r in results}) == 1
(W / 'control-results.json').write_text(json.dumps(dict(layout=asdict(layout), encryption=metadata['segments']['0']['encryption'],
    operations=workload(layout), arms=results, live_journal_atomic=False), indent=2) + '\n')
(W / 'result.txt').write_text('Matched stock and native arms, equal authenticated primary outputs and preserved native hidden zeros passed\n')
