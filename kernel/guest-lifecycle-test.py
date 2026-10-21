#!/usr/bin/env python3
"""Disposable guest: exact bio flags/traces and concurrent public-view lifecycle."""
from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import struct
import subprocess
import threading
import time

from lifecycle_trace import check_trace

from pivstore.blocks import open_blocks, close_blocks, native_status
from pivstore.kernel_api import dm, mapping_identity
from pivstore.kernel_owner import GuestOwner

W = Path('/mnt/piv-work')
T = Path('/sys/kernel/tracing')
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
EXPECTED = (W / 'expected-hidden-volume').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
results = {}

def direct(path, offset, count=512, write=None, sync=False):
    buf = mmap.mmap(-1, count)
    fd = os.open(path, os.O_RDWR | os.O_DIRECT | (os.O_DSYNC if sync else 0))
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
        buf.close()

def open_views():
    v = open_blocks('/dev/vdb', KEY, HKEY)
    subprocess.run(['udevadm', 'settle'], check=True)
    return v

def check_views(v):
    assert subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0] == PRIMARY
    assert Path(v['hidden']).read_bytes() == EXPECTED

def trace_control(path, value):
    (T / path).write_text(str(value))

def probe_command(value):
    # Python append streams seek to EOF; tracefs seq_files reject SEEK_END.
    fd = os.open(T / 'kprobe_events', os.O_WRONLY | os.O_APPEND)
    try:
        data = (value + '\n').encode()
        assert os.write(fd, data) == len(data)
    finally: os.close(fd)


v = open_views()
owner = GuestOwner('/dev/vdb', KEY)
unit, group = owner.device.sector_size, 90  # format v4 record size in primary sectors
generation = owner.device.generation
owner.close()

# Dynamic probes record only call metadata/results, never data or keys.
probes = [('worker', 'pn_worker', False), ('worker_done', 'pn_worker', True),
          ('write', 'pn_write', False), ('write_done', 'pn_write', True),
          ('flush', 'blkdev_issue_flush', False), ('flush_done', 'blkdev_issue_flush', True),
          ('endio', 'bio_endio', False)]
trace_control('current_tracer', 'nop')
trace_control('tracing_on', 0)
trace_control('trace_clock', 'global')
trace_control('buffer_size_kb', 1024)
for event, function, returning in probes:
    definition = f'{"r" if returning else "p"}:piv_lifecycle/{event} {function}'
    if returning and event != 'worker_done': definition += ' result=$retval:s32'
    probe_command(definition)
trace_control('events/piv_lifecycle/enable', 1)
traces = []
try:
    for role in (0, 1):
        for mode in range(4):
            label = f'{"hidden" if role else "decoy"}-{("plain", "fua", "preflush-fua", "flush")[mode]}'
            trace_control('trace', '')
            trace_control('tracing_on', 1)
            fd = os.open('/dev/piv-io-test', os.O_WRONLY)
            try:
                assert os.write(fd, struct.pack('=II', role, mode)) == 8
                # Upper bio completion can wake this CPU before pn_worker's
                # return probe runs on the other CPU. Drain that evidence.
                deadline = time.monotonic() + 5
                while True:
                    try: check_trace((T / 'trace').read_text(), mode)
                    except AssertionError:
                        if time.monotonic() >= deadline: raise
                        time.sleep(0.01)
                    else: break
            finally:
                os.close(fd)
                trace_control('tracing_on', 0)
                (W / (label + '.trace')).write_text((T / 'trace').read_text())
            text = (T / 'trace').read_text()
            stats = '\n'.join(p.read_text() for p in (T / 'per_cpu').glob('cpu*/stats'))
            assert not re.search(r'(?:overrun|dropped events):\s*[1-9]', stats), stats
            traces.append(dict(case=label, **check_trace(text, mode)))
    profile = (T / 'kprobe_profile').read_text()
    (W / 'kprobe-profile.txt').write_text(profile)
    seen = set()
    for line in profile.splitlines():
        fields = line.split()
        event = fields[0].split('/')[-1].split(':')[-1]
        if event in {p[0] for p in probes}:
            assert int(fields[-1]) == 0, line
            seen.add(event)
    assert seen == {p[0] for p in probes}, profile
finally:
    trace_control('events/piv_lifecycle/enable', 0)
    for event, _, _ in reversed(probes):
        probe_command(f'-:piv_lifecycle/{event}')
results['flag_traces'] = traces
subprocess.run(['rmmod', 'piv_io_test'], check=True)
print('Exact bio flags and native flush/completion traces passed', flush=True)

# Distinct logical writers deliberately share primary records. Each owns
# its logical region; preservation, rather than a guessed race winner, is tested.
barrier = threading.Barrier(5)
progress_lock = threading.Lock()
progress = 0
def writer(role, index):
    global progress
    path = v[role]
    offset = (index * 2 * group * unit if role == 'decoy' else index * 2 * 512)
    count = 16384 if role == 'decoy' else 512
    old = direct(path, offset, count)
    barrier.wait(timeout=30)
    for turn in range(8):
        value = hashlib.shake_256(f'lifecycle/{role}/{index}/{turn}'.encode()).digest(count)
        direct(path, offset, count, value, sync=bool(turn % 2))
        assert direct(path, offset, count) == value
        with progress_lock: progress += 1
    direct(path, offset, count, old)
    return dict(role=role, offset=offset, writes=9)
def suspender():
    observations = []
    barrier.wait(timeout=30)
    for _ in range(4):
        for role in ('decoy', 'hidden'):
            name = 'piv-native-' + role
            dm('suspend', '--noflush', name)
            dm('resume', name)
            with progress_lock: observations.append(progress)
    assert any(0 < done < 32 for done in observations), observations
    return observations
with ThreadPoolExecutor(max_workers=5) as pool:
    futures = [pool.submit(writer, role, index) for role in ('decoy', 'hidden') for index in range(2)]
    suspending = pool.submit(suspender)
    results['concurrent_writers'] = [f.result(timeout=180) for f in futures]
    results['concurrent_suspend_resume_progress'] = suspending.result(timeout=60)
check_views(v)
print('Concurrent overlapping-carrier writes, reads, fsync and full oracles passed', flush=True)

# An open descriptor must protect its target and shared owner from removal.
held = [os.open(v[role], os.O_RDWR | os.O_DIRECT) for role in ('decoy', 'hidden')]
before = {n: mapping_identity(n) for n in ('piv-native', 'piv-native_dif', 'piv-native-decoy', 'piv-native-hidden')}
for name in before:
    assert dm('remove', name, check=False).returncode != 0
assert subprocess.run(['rmmod', 'dm_piv'], capture_output=True).returncode != 0
assert before == {n: mapping_identity(n) for n in before}
# A real close attempt while both descriptors are held must report busy and
# preserve mappings; close retries are bounded by the frontend's dm retry policy.
try: close_blocks('/dev/vdb', KEY)
except ValueError as exc:
    # pivsetup reports the failed dmsetup remove, with its stderr as a note.
    assert 'resource busy' in ' '.join(getattr(exc, '__notes__', [])), exc
else: raise AssertionError('Busy close unexpectedly succeeded')
assert before == {n: mapping_identity(n) for n in before}
for fd in held: os.close(fd)

# Suspend each PUBLIC view and prove an arriving direct write remains queued
# until resume. The peer view remains usable through the shared owner.
for role in ('decoy', 'hidden'):
    name = 'piv-native-' + role
    old = direct(v[role], 0)
    peer = 'hidden' if role == 'decoy' else 'decoy'
    peer_before = direct(v[peer], 0)
    queued_fd = os.open(v[role], os.O_RDWR | os.O_DIRECT)
    queued_data = mmap.mmap(-1, 512)
    queued_data[:] = old
    dm('suspend', '--noflush', name)
    with ThreadPoolExecutor(max_workers=1) as pool:
        entered = threading.Event()
        task = {}
        def queued():
            task['tid'] = threading.get_native_id()
            entered.set()
            assert os.pwritev(queued_fd, [queued_data], 0) == 512
            os.fsync(queued_fd)
        future = pool.submit(queued)
        assert entered.wait(timeout=10)
        try:
            # Pinned x86_64: pwritev=296, pwritev2=328 (CPython may use either).
            # Witness the actual
            # blocked syscall instead of assuming a scheduled thread submitted.
            deadline = time.monotonic() + 5
            blocked = False
            call = 'not observed'
            while time.monotonic() < deadline and not future.done():
                call = Path(f'/proc/self/task/{task["tid"]}/syscall').read_text().split()[0]
                if call in ('296', '328'):
                    blocked = True
                    break
                time.sleep(0.01)
            if future.done(): future.result()
            assert blocked, f'Suspended request never reached pwritev/pwritev2 (last syscall={call})'
            assert not future.done()
            assert direct(v[peer], 0) == peer_before
        finally: dm('resume', name)
        future.result(timeout=30)
    os.close(queued_fd)
    queued_data.close()
    assert direct(v[role], 0) == old
results['busy_remove_close_unload'] = True
results['suspended_public_writes_waited_for_resume'] = True
check_views(v)
close_blocks('/dev/vdb', KEY)
v = open_views()
owner = GuestOwner('/dev/vdb', KEY)
assert owner.device.generation != generation and not native_status(owner.device)['failed']
owner.close()
check_views(v)
close_blocks('/dev/vdb', KEY)
assert not list(Path('/dev').glob('pivctl-*'))
subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0] == PRIMARY
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'lifecycle-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'lifecycle-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Exact flag traces, concurrent writes, busy lifecycle, suspension, reopen and stock verification passed\n')
