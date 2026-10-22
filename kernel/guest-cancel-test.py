#!/usr/bin/env python3
"""Witness setup/lock/init/fill cancellation in the kernel, not merely before
ioctl, and fill completing a cancelled initialization or fill."""
import errno
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

import pivstore.blocks as blocks
from pivstore.kernel_api import command, dm, mapping_identity
from pivstore.kernel_owner import GuestOwner

W = Path('/mnt/piv-work')
T = Path('/sys/kernel/tracing')
SOURCE = '/dev/mapper/piv-test-delay'
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
SETUP_CMD = command(12, blocks.SETUP.size, 3)
BLOCK, GROUP = 4096, 687         # format v5 hidden block and record (no parity)


def write_json(name, value):
    (W / name).write_text(json.dumps(value, indent=2) + '\n')


def wait_until(check, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check(): return
        time.sleep(0.005)
    raise AssertionError('Timed out waiting for kernel/child evidence')


def child(phase):
    signal.signal(signal.SIGINT, signal.default_int_handler)
    if phase == 'waiter':
        info = json.loads((W / 'scan-ready.json').read_text())
        identity = bytes.fromhex(info['context'])
        fd = os.open(info['control'], os.O_RDWR)
        data = bytearray(blocks.SETUP.pack(blocks.SETUP_VERSION, blocks.SETUP.size, info['generation'], 0,
                                         len(identity), HKEY, identity, 0, 0, 0, 0, 0))
        interrupted = False
        try:
            fcntl.ioctl(fd, SETUP_CMD, data, True)
        except KeyboardInterrupt:
            interrupted = True
        finally:
            data[:] = bytes(len(data))
        assert interrupted
        # release may wait for the first setup's mutex; report EINTR beforehand.
        write_json('waiter-interrupted.json', dict(interrupted=True))
        os.close(fd)
        return
    raise AssertionError('Only the raw waiter runs as a Python child')

if len(sys.argv) == 3 and sys.argv[1] == '--child':
    child(sys.argv[2])
    raise SystemExit(0)

PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
expected = bytearray((W / 'expected-hidden-volume').read_bytes())
raw_bytes = int(subprocess.check_output(['blockdev', '--getsize64', '/dev/vdb']))
raw_sectors = raw_bytes // 512
names = ('piv-native', 'piv-native_dif', 'piv-native-decoy', 'piv-native-hidden')
results = []


def absent():
    identities = {name: mapping_identity(name) for name in names}
    assert not any(identities.values()), identities
    settled = subprocess.run(['udevadm', 'settle', '--timeout=10'])
    if settled.returncode:
        subprocess.run(['ps', '-eo', 'pid,ppid,stat,wchan:32,comm'], check=True)
        subprocess.run(['dmsetup', 'info', '-c'], check=True)
    assert settled.returncode == 0
    assert not list(Path('/dev').glob('pivctl-*'))


def table(read_ms=0, write_ms=0):
    return f'0 {raw_sectors} delay /dev/vdb 0 {read_ms} /dev/vdb 0 {write_ms}\n'


def reload(read_ms=0, write_ms=0):
    dm('suspend', '--noflush', 'piv-test-delay')
    dm('reload', 'piv-test-delay', input=table(read_ms, write_ms))
    dm('resume', 'piv-test-delay')


def probe_command(value):
    fd = os.open(T / 'kprobe_events', os.O_WRONLY | os.O_APPEND)
    try:
        value = (value + '\n').encode()
        assert os.write(fd, value) == len(value)
    finally:
        os.close(fd)


def symbol(stem):
    matches = [line.split()[2] for line in Path('/proc/kallsyms').read_text().splitlines()
               if len(line.split()) == 4 and line.split()[3] == '[dm_piv]'
               and (line.split()[2] == stem or line.split()[2].startswith(stem + '.'))
               and '.cold' not in line.split()[2]]
    assert len(matches) == 1, (stem, matches)
    return 'dm_piv:' + matches[0]


def setup_state(process):
    """True/False if /proc shows the task in/out of the SETUP ioctl; None while
    it is on a CPU (/proc/PID/syscall then reads "running", even inside the
    ioctl, e.g. while the scan authenticates a range)."""
    try:
        fields = Path(f'/proc/{process.pid}/syscall').read_text().split()
    except FileNotFoundError:
        return False
    if fields == ['running']:
        return None
    try:
        return len(fields) >= 3 and int(fields[0], 0) == 16 and int(fields[2], 0) == SETUP_CMD
    except ValueError:
        return False


def in_setup(process):
    return setup_state(process) is True


def held(process, timeout=5):
    """Definitive in-SETUP check: resample while the task is merely on a CPU.
    A single sample can read "running" inside the ioctl (suite-076 flake)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = setup_state(process)
        if state is not None:
            return state
        time.sleep(0.001)
    raise AssertionError('Task stayed on a CPU; SETUP state not observable')


def spawn(phase):
    if phase == 'waiter':
        # Second raw SETUP caller (Python ioctl instrumentation) on the same control.
        return subprocess.Popen([sys.executable, __file__, '--child', phase],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # The real setup client: pivsetup with its explicit gate hook, default SIGINT
    # handling (cooperative cancellation), cleanup and exit status 130.
    # The scan phase cancels a --verify full audit: the default setup scans only
    # the keyslot area, too briefly to witness cancellation reliably.
    # The fill phase cancels a fill of a quick-initialized volume.
    args = blocks.open_args(SOURCE, KEY, W / 'hidden.key', initialize=phase == 'initialize',
                            verify=phase == 'scan', fill=phase == 'fill')
    return subprocess.Popen([blocks.binary(), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env={**os.environ, 'PIVSETUP_TEST_GATE': str(W / phase)})


def finished(process, interrupted=False):
    out, err = process.communicate(timeout=20)
    if interrupted:
        # Cancelled: exit 130 and no "cleanup incomplete" notes after unwinding.
        assert process.returncode == 130, (process.returncode, out, err)
        assert 'cleanup incomplete' not in err, err
    else:
        assert process.returncode == 0, (process.returncode, out, err)


def open_views(**options):
    v = blocks.open_blocks(SOURCE, KEY, HKEY, **options)
    subprocess.run(['udevadm', 'settle'], check=True)
    return v


def verify(v, unavailable_from=None):
    assert subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0] == PRIMARY
    if unavailable_from is None:
        assert Path(v['hidden']).read_bytes() == expected
        return
    # Interrupted v5 re-initialization: a new master key was written first, so
    # completed leading blocks are zeros and every later block is unavailable
    # (old records no longer authenticate) rather than retaining old content.
    # Exact O_DIRECT reads: buffered page reads would include unavailable neighbours.
    fd = os.open(v['hidden'], os.O_RDONLY | os.O_DIRECT)
    try:
        with mmap.mmap(-1, unavailable_from * BLOCK) as buf:
            assert os.preadv(fd, [buf], 0) == unavailable_from * BLOCK
            assert buf[:] == expected[:unavailable_from * BLOCK]
    finally:
        os.close(fd)
    for index in (unavailable_from, len(expected) // BLOCK - 1):
        fd = os.open(v['hidden'], os.O_RDONLY | os.O_DIRECT)
        try:
            with mmap.mmap(-1, BLOCK) as buf:
                try:
                    os.preadv(fd, [buf], index * BLOCK)
                except OSError as exc:
                    assert exc.errno == errno.EIO
                else:
                    raise AssertionError(f'Block {index} after interrupted v5 initialization was readable')
        finally:
            os.close(fd)


absent()
dm('create', 'piv-test-delay', input=table())
wrapper = mapping_identity('piv-test-delay')
(T / 'tracing_on').write_text('0')
(T / 'current_tracer').write_text('nop')
(T / 'buffer_size_kb').write_text('1024')
registered = []
try:
    for event, function in (('range', 'piv_read_range'), ('write', 'pn_write')):
        probe_command(f'p:piv_cancel/{event} {symbol(function)}')
        registered.append(event)
    for phase, event in (('scan', 'range'), ('initialize', 'write'), ('fill', 'write')):
        if phase == 'fill':
            # Quick initialization: keyslot and directory only, every block unavailable.
            v = open_views(initialize=True, quick=True)
            blocks.close_blocks(SOURCE, KEY)
        # A short lower write delay slows initialization records (each a few
        # multi-sector writes through the journal) without exceeding the
        # signal-to-exit timeout.
        reload(read_ms=25 if phase == 'scan' else 0,
               write_ms=2 if phase in ('initialize', 'fill') else 0)
        process = spawn(phase)
        wait_until(lambda: (W / (phase + '-ready.json')).exists())
        # Scan ranges run in the SETUP caller; initialization records run on
        # the module's workqueue (nothing else writes during this test).
        (T / f'events/piv_cancel/{event}/filter').write_text(
            f'common_pid == {process.pid}' if event == 'range' else '0')
        (T / 'trace').write_text('')
        (T / f'events/piv_cancel/{event}/enable').write_text('1')
        (T / 'tracing_on').write_text('1')
        (W / (phase + '-gate')).touch()
        needed = 3 if phase == 'scan' else 2
        wait_until(lambda: (T / 'trace').read_text().count(f'{event}:') >= needed and in_setup(process))
        waiter = None
        if phase == 'scan':
            waiter = spawn('waiter')
            wait_until(lambda: in_setup(waiter))
            start = time.monotonic()
            waiter.send_signal(signal.SIGINT)
            wait_until(lambda: (W / 'waiter-interrupted.json').exists(), timeout=10)
            assert held(process), 'First scan must still hold the setup mutex'
            results.append(dict(phase='contended-setup-lock', interrupted_seconds=time.monotonic() - start))
        start = time.monotonic()
        process.send_signal(signal.SIGINT)
        finished(process, interrupted=True)
        elapsed = time.monotonic() - start
        if waiter is not None: finished(waiter)
        (T / 'tracing_on').write_text('0')
        (T / f'events/piv_cancel/{event}/enable').write_text('0')
        text = (T / 'trace').read_text()
        (W / (phase + '.trace')).write_text(text)
        stats = '\n'.join(path.read_text() for path in (T / 'per_cpu').glob('cpu*/stats'))
        assert not re.search(r'(?:overrun|dropped events):\s*[1-9]', stats), stats
        report = json.loads((W / (phase + '-setup.json')).read_text())
        assert report['interrupted'] and report['errno'] == errno.EINTR, report
        status = report['status']
        assert not status['active'] and not status['views'] and not status['failed']
        assert status['hidden_bytes'] == 0
        reload()
        absent()
        assert mapping_identity('piv-test-delay') == wrapper
        v = open_views()
        handle = GuestOwner(SOURCE, KEY)
        handle.close()
        unavailable_from, total = None, len(expected) // BLOCK
        if phase == 'scan':
            assert status['encryptions'] == 0
        else:
            # Initialization: keyslot 0 (2 x 14 sectors) and the directory (687)
            # precede the 687-sector zero records. Fill writes records only.
            setup = 2 * 14 + GROUP if phase == 'initialize' else 0
            completed, remainder = divmod(status['encryptions'] - setup, GROUP)
            assert not remainder and 2 <= completed < min(64, total), status
            expected[:completed * BLOCK] = bytes(completed * BLOCK)
            unavailable_from = completed
        verify(v, unavailable_from)
        blocks.close_blocks(SOURCE, KEY)
        fill = None
        if phase != 'scan':
            # Resume: fill skips the records completed before the cancellation
            # (they authenticate) and writes zeros into every other block.
            v = open_views(fill=True)
            fill = v['fill']
            assert fill == dict(valid=completed, written=total - completed, failed=0), (fill, completed)
            expected[:] = bytes(len(expected))
            verify(v)
            blocks.close_blocks(SOURCE, KEY)
        results.append(dict(phase=phase, interrupted_seconds=elapsed,
                            encryptions=status['encryptions'], no_native_state=True,
                            cleanup=True, complete_oracles=True, resumed_by_fill=fill))
        print(f'{phase}: interrupted in {elapsed:.3f}s; cleanup, full oracles and reopen passed', flush=True)
    profile = (T / 'kprobe_profile').read_text()
    (W / 'kprobe-profile.txt').write_text(profile)
    seen = set()
    for line in profile.splitlines():
        fields = line.split()
        event = fields[0].split('/')[-1].split(':')[-1]
        if event in registered:
            assert int(fields[-1]) == 0, line
            seen.add(event)
    assert seen == set(registered)
finally:
    (T / 'tracing_on').write_text('0')
    for event in reversed(registered):
        (T / f'events/piv_cancel/{event}/enable').write_text('0')
        probe_command(f'-:piv_cancel/{event}')

# Exercise normal initialization completion too, on the smaller fixture. Large
# initialization was already verified in large-*; do not repeat an eight-minute run.
# Always complete it: an interrupted initialization leaves later blocks
# unavailable (the master key changed first) until a fill completes it.
v = open_views(initialize=True)
expected[:] = bytes(len(expected))
verify(v)
blocks.close_blocks(SOURCE, KEY)
results.append(dict(phase='normal-initialization', complete_oracles=True))
absent()
dm('remove', '--retry', 'piv-test-delay')
subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0] == PRIMARY
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
(W / 'expected-cancel-hidden').write_bytes(expected)
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'cancel-final.img'), 'bs=1M', 'status=none'], check=True)
write_json('cancel-results.json', results)
(W / 'result.txt').write_text('Witnessed scan, contended setup lock and record-boundary initialization and fill '
                              'cancellation, cleanup, fill resumption, reopen and stock verification passed\n')
