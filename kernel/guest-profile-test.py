#!/usr/bin/env python3
"""Pinned disposable guest: uninstrumented timings and separate call-count probes."""
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
T = Path('/sys/kernel/tracing')
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
EXPECTED = (W / 'expected-hidden-volume').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
results = dict(activation=[], reads=[], counts=[])


def crypt(*args):
    subprocess.run(['cryptsetup', *map(str, args)], check=True)


def measure_reads(path, oracle, role, logical=512):
    # mmap provides page-aligned storage; all requests are direct, read-only I/O.
    length = min(len(oracle), 1024 * 1024 if role != 'hidden' else 65536)
    for chunk in (c for c in (512, 4096, 16384, 65536) if c >= logical):
        samples = []
        with mmap.mmap(-1, chunk) as buf:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
            try:
                for repeat in range(3):
                    start = time.monotonic()
                    for offset in range(0, length, chunk):
                        count = min(chunk, length - offset)
                        view = memoryview(buf)[:count]
                        try:
                            assert os.preadv(fd, [view], offset) == count
                        finally:
                            view.release()
                        assert buf[:count] == oracle[offset:offset + count]
                    samples.append(time.monotonic() - start)
            finally:
                os.close(fd)
        results['reads'].append(dict(role=role, pattern='sequential', chunk=chunk,
                                    bytes=length, seconds=samples))
    offsets = [random.Random(i).randrange(len(oracle) // logical) * logical for i in range(32)]
    with mmap.mmap(-1, logical) as buf:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
        try:
            start = time.monotonic()
            for offset in offsets:
                assert os.preadv(fd, [buf], offset) == logical
                assert buf[:] == oracle[offset:offset + logical]
            elapsed = time.monotonic() - start
        finally:
            os.close(fd)
    results['reads'].append(dict(role=role, pattern=f'random-{logical}', requests=len(offsets),
                                bytes=len(offsets) * logical, seconds=[elapsed]))


# Include complete stock authentication, and retain plaintext solely in guest RAM
# as the independent read oracle. These runs intentionally warm storage caches.
for repeat in range(3):
    start = time.monotonic()
    crypt('open', '--readonly', '--key-file', KEY, '/dev/vdb', 'piv-stock-profile')
    results['activation'].append(dict(kind='stock', repeat=repeat,
                                     seconds=time.monotonic() - start))
    if repeat == 0:
        primary = Path('/dev/mapper/piv-stock-profile').read_bytes()
        assert hashlib.sha256(primary).hexdigest() == PRIMARY
        logical = int(subprocess.check_output(['blockdev', '--getss', '/dev/mapper/piv-stock-profile']))
        measure_reads('/dev/mapper/piv-stock-profile', primary, 'stock-decoy', logical)
    crypt('close', 'piv-stock-profile')

# pivsetup's explicit test hook reports the SETUP ioctl time (PREFIX-setup.json).
# A pre-created gate means it never waits; timings stay uninstrumented.
GATE = '/run/piv-profile'
Path(GATE + '-gate').touch()


def hooked_open():
    Path(GATE + '-setup.json').unlink(missing_ok=True)
    views = blocks.open_blocks('/dev/vdb', KEY, HKEY, env=dict(PIVSETUP_TEST_GATE=GATE))
    return views, json.loads(Path(GATE + '-setup.json').read_text())


for repeat in range(3):
    start = time.monotonic()
    views, report = hooked_open()
    results['activation'].append(dict(kind='native', repeat=repeat,
        seconds=time.monotonic() - start, setup_ioctl_seconds=report['seconds']))
    subprocess.run(['udevadm', 'settle'], check=True)
    if repeat == 0:
        owner = GuestOwner('/dev/vdb', KEY)
        sectors, unit = owner.device.sectors, owner.device.sector_size
        before = blocks.native_status(owner.device)['encryptions']
        # The decoy view's logical block size is the primary sector size (as stock).
        logical = int(subprocess.check_output(['blockdev', '--getss', views['decoy']]))
        measure_reads(views['decoy'], primary, 'native-decoy', logical)
        measure_reads(views['hidden'], EXPECTED, 'hidden', 4096)   # 4096-byte hidden blocks
        assert blocks.native_status(owner.device)['encryptions'] == before == 0
        assert not blocks.native_status(owner.device)['failed']
        owner.close()
    blocks.close_blocks('/dev/vdb', KEY)

# Timings above are uninstrumented. Probe entry counts below have no payload/key
# fields and use tracing_on=0: no ring-buffer events need to be retained.
# Resolve compiler specializations in this module, never the stock copy.
symbols = [line.split()[2] for line in Path('/proc/kallsyms').read_text().splitlines()
           if len(line.split()) == 4 and line.split()[3] == '[dm_piv]']
def symbol(stem):
    matches = [name for name in symbols if (name == stem or name.startswith(stem + '.'))
               and '.cold' not in name]
    assert len(matches) == 1, (stem, matches)
    return 'dm_piv:' + matches[0]
probes = {event: symbol(function) for event, function in dict(
    range='piv_read_range', crypto='piv_aead',
    write='pn_write', checkpoint='piv_checkpoint', batch='piv_batch_read',
    submit='piv_batch_submit').items()}


def probe_command(value):
    fd = os.open(T / 'kprobe_events', os.O_WRONLY | os.O_APPEND)
    try:
        value = (value + '\n').encode()
        assert os.write(fd, value) == len(value)
    finally:
        os.close(fd)


def counters():
    values = {}
    for line in (T / 'kprobe_profile').read_text().splitlines():
        words = line.split()
        event = words[0].split('/')[-1]
        if event in probes:
            assert int(words[2]) == 0, line
            values[event] = int(words[1])
    assert set(values) == set(probes), values
    return values


def counted(label, action, expected):
    before = counters()
    action()
    after = counters()
    delta = {key: after[key] - before[key] for key in probes}
    assert delta == expected, (label, delta, expected)
    results['counts'].append(dict(case=label, **delta))


(T / 'tracing_on').write_text('0')
registered = []
try:
    for event, function in probes.items():
        probe_command(f'p:piv_profile/{event} {function}')
        registered.append(event)
    (T / 'events/piv_profile/enable').write_text('1')
    per_range = 1024                                  # PIV_READ_SECTORS: sectors per range read
    GROUP = 687                                       # format v5 record without parity
    record_ranges = (GROUP + per_range - 1) // per_range  # one 687-sector record
    keyslot_ranges = (112 + per_range - 1) // per_range
    # Default setup scans only the 112 keyslot sectors (the keyslot check runs
    # on their IVs); the directory (groups 0 and 1) is then read and
    # authenticated. --verify would scan every sector instead. Each range read
    # is one batch submission of a few concurrent bios.
    # The checkpoint reads, authenticates and rewrites one sector: one crypto
    # call and two submissions (read, write).
    setup_expected = dict(range=keyslot_ranges + 2 * record_ranges,
                          crypto=112 + 1 + 2 * GROUP, write=0, checkpoint=1, batch=0,
                          submit=keyslot_ranges + 2 * record_ranges + 2)
    # Bracket exactly the SETUP ioctl with pivsetup's gate (before) and hold
    # (after) hooks; the binary waits at each point for our marker file.
    counted_gate = '/run/piv-profile-counted'
    def counted_open():
        before = counters()
        with blocks.spawn_open('/dev/vdb', KEY, HKEY, env=dict(PIVSETUP_TEST_GATE=counted_gate,
                                                              PIVSETUP_TEST_HOLD='1')) as process:
            while not Path(counted_gate + '-ready.json').exists():
                assert process.poll() is None, process.communicate()
                time.sleep(0.005)
            before = counters()
            Path(counted_gate + '-gate').touch()
            while not Path(counted_gate + '-setup.json').exists():
                assert process.poll() is None, process.communicate()
                time.sleep(0.005)
            after = counters()
            Path(counted_gate + '-continue').touch()
            out, err = process.communicate(timeout=120)
            assert process.returncode == 0, err
        delta = {key: after[key] - before[key] for key in probes}
        assert delta == setup_expected, ('setup-ioctl', delta, setup_expected)
        results['counts'].append(dict(case='setup-ioctl', **delta))
        return json.loads(out)
    views = counted_open()
    subprocess.run(['udevadm', 'settle'], check=True)
    # Hidden reads authenticate each 4096-byte block's 687 sectors.
    hidden_cases = (('hidden', 4096, GROUP, record_ranges), ('hidden', 16384, 4 * GROUP, 4 * record_ranges))
    decoy_cases = (('decoy', unit, 1, 1), ('decoy', 16384, 16384 // unit, 1), ('decoy', 131072, 131072 // unit, 1))
    for role, count, loads, ranges in decoy_cases + hidden_cases:
        def read():
            with mmap.mmap(-1, count) as buf:
                fd = os.open(views[role], os.O_RDONLY | os.O_DIRECT)
                try:
                    assert os.preadv(fd, [buf], 0) == count
                    assert buf[:] == (primary if role == 'decoy' else EXPECTED)[:count]
                finally:
                    os.close(fd)
        counted(f'{role}-{count}', read, dict(range=ranges, crypto=loads, write=0, checkpoint=0,
                                              batch=0, submit=ranges))
    # Writes (same bytes, so the oracles hold): one authenticated batch read of
    # every touched sector, one encryption each, one write submission of a few
    # multi-sector bios. No per-sector reads, re-reads or self-decryption.
    status_owner = GuestOwner('/dev/vdb', KEY)
    for role, count, sectors in (('decoy', 16384, 16384 // unit), ('decoy', 131072, 131072 // unit),
                                 ('hidden', 4096, GROUP)):
        # Close outside the counted window: closing a written dm device makes
        # udev re-probe it (inotify watch), and those reads must not count.
        with mmap.mmap(-1, count) as buf:
            buf[:] = (primary if role == 'decoy' else EXPECTED)[:count]
            fd = os.open(views[role], os.O_WRONLY | os.O_DIRECT)
            try:
                before = blocks.native_status(status_owner.device)['encryptions']
                def write():
                    assert os.pwritev(fd, [buf], 0) == count
                counted(f'{role}-write-{count}', write,
                        dict(range=0, crypto=2 * sectors, write=1, checkpoint=0, batch=1, submit=2))
                assert blocks.native_status(status_owner.device)['encryptions'] - before == sectors
            finally:
                os.close(fd)
        time.sleep(0.5)
        subprocess.run(['udevadm', 'settle'], check=True)
    assert not blocks.native_status(status_owner.device)['failed']
    status_owner.close()
    (W / 'profile-kprobe-counts.txt').write_text((T / 'kprobe_profile').read_text())
finally:
    if registered:
        (T / 'events/piv_profile/enable').write_text('0')
    for event in reversed(registered):
        probe_command(f'-:piv_profile/{event}')

assert hashlib.sha256(Path(views['decoy']).read_bytes()).hexdigest() == PRIMARY
assert Path(views['hidden']).read_bytes() == EXPECTED
blocks.close_blocks('/dev/vdb', KEY)
subprocess.run(['rmmod', 'dm_piv'], check=True)
crypt('open', '--readonly', '--key-file', KEY, '/dev/vdb', 'piv-stock-profile')
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock-profile'], text=True).split()[0] == PRIMARY
crypt('close', 'piv-stock-profile')
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'profile-final.img'), 'bs=1M', 'status=none'], check=True)
results.update(primary_sector=unit, primary_sectors=sectors, group=687, format=5,
               cache_state='warm guest/host caches; O_DIRECT bypasses public page cache only',
               timings_include_python_comparison=True, probes_used_during_timing=False, bounded_range_reads=True)
(W / 'profile-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Read/setup profiling, exact probe counts, complete oracles and stock readback passed\n')
print(json.dumps(results), flush=True)
