#!/usr/bin/env python3
"""Disposable guest: setup ownership, scoped lower EIO isolation, fail-stop and recreation."""
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pivstore.blocks as blocks
import pivstore.kernel_owner as owners
from pivstore.kernel_api import dm, mapping_identity

W = Path('/mnt/piv-work')
SOURCE = '/dev/mapper/piv-test-fault'
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
EXPECTED = (W / 'expected-hidden-volume').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
NAMES = ('piv-native-hidden', 'piv-native-decoy', 'piv-native', 'piv-native_dif')
results = []

# Format v4 geometry (docs/format-v4.md): 112 keyslot sectors, two directory
# groups, then 90-sector records (AEGIS-128 is the only supported profile).
def record_span(device, block):
    """First and last primary sector carrying hidden block @block."""
    first = 112 + 90 * (2 + block)
    return first, first + 89

def blocks_touched(device, first, last):
    """Hidden blocks with a fragment in primary sectors first..last."""
    low, high = (first - 112) // 90 - 2, (last - 112) // 90 - 2
    return range(max(0, low), high + 1) if last >= 112 + 180 else range(0)

def open_views():
    value = blocks.open_blocks(SOURCE, KEY, HKEY, allow_test_stack=True)
    subprocess.run(['udevadm', 'settle'], check=True)
    return value

def close_views():
    blocks.close_blocks(SOURCE, KEY, allow_test_stack=True)

def owner():
    return owners.GuestOwner(SOURCE, KEY, allow_test_stack=True)

def absent():
    assert all(mapping_identity(name) is None for name in NAMES)
    assert not list(Path('/dev').glob('pivctl-*'))

def rejected(fn, exception=OSError):
    try:
        fn()
    except exception as exc:
        return exc
    raise AssertionError('Operation unexpectedly succeeded')

def table(mode='linear'):
    line = ('linear /dev/vdb 0' if mode == 'linear' else
            f'flakey /dev/vdb 0 0 3600 1 error_{mode}')
    return '0 262144 ' + line + '\n'

def fault(mode='linear'):
    dm('suspend', '--noflush', 'piv-test-fault')
    dm('reload', 'piv-test-fault', input=table(mode))
    dm('resume', 'piv-test-fault')

def corrupt_read(sector512, value):
    # One raw data sector only; unchanged backing bytes and normal writes.
    lines = (f'0 {sector512} linear /dev/vdb 0\n'
             f'{sector512} 1 flakey /dev/vdb {sector512} 0 3600 5 corrupt_bio_byte 1 r {value} 0\n'
             f'{sector512 + 1} {262144 - sector512 - 1} linear /dev/vdb {sector512 + 1}\n')
    dm('suspend', '--noflush', 'piv-test-fault')
    dm('reload', 'piv-test-fault', input=lines)
    dm('resume', 'piv-test-fault')

def direct(path, *, write=None, offset=0, size=512):
    if write is not None: size = len(write)
    value = mmap.mmap(-1, size)
    fd = os.open(path, os.O_RDWR | os.O_DIRECT)
    try:
        if write is None:
            assert os.preadv(fd, [value], offset) == size
            return value[:]
        value[:] = write
        assert os.pwritev(fd, [value], offset) == size
        os.fsync(fd)
    finally:
        os.close(fd)
        value.close()

def verify(views, unavailable=()):
    assert subprocess.check_output(['sha256sum', views['decoy']], text=True).split()[0] == PRIMARY
    repaired = False
    for index in range(len(EXPECTED) // 512):
        expected = EXPECTED[index * 512:(index + 1) * 512]
        try:
            actual = direct(views['hidden'], offset=index * 512)
        except OSError as exc:
            assert index in unavailable and exc.errno == errno.EIO
            direct(views['hidden'], write=expected, offset=index * 512)
            actual = direct(views['hidden'], offset=index * 512)
            repaired = True
        assert actual == expected, index
    return repaired

absent()
dm('create', 'piv-test-fault', input=table())
# Name collisions must not remove any unrelated mapping.
for foreign in ('piv-native', 'piv-native_dif', 'piv-native-decoy', 'piv-native-hidden'):
    dm('create', foreign, '--uuid', 'FOREIGN-' + foreign, input='0 1 error\n')
    identity = mapping_identity(foreign)
    rejected(open_views, (FileExistsError, ValueError))
    assert mapping_identity(foreign) == identity
    for name in NAMES:
        if name != foreign: assert mapping_identity(name) is None
    dm('remove', '--retry', foreign)
    absent()
results.append('foreign setup names preserved')

# Inject failures at each setup phase through pivsetup's explicit test hook
# (PIVSETUP_TEST_FAIL); every attempt must remove exactly what it created.
for phase in ('after-cryptsetup-open', 'before-setup', 'after-setup', 'first-view', 'second-view'):
    rejected(lambda: blocks.open_blocks(SOURCE, KEY, HKEY, allow_test_stack=True,
                                        env=dict(PIVSETUP_TEST_FAIL=phase)))
    absent()
    results.append(phase + ' cleanup')

# Lower read failure during the kernel authentication scan: hold pivsetup at its
# gate, inject the fault for exactly the SETUP ioctl, then let it unwind.
gate = '/run/piv-fault-kernel-auth'
with blocks.spawn_open(SOURCE, KEY, HKEY, allow_test_stack=True,
                       env=dict(PIVSETUP_TEST_GATE=gate, PIVSETUP_TEST_HOLD='1')) as process:
    while not Path(gate + '-ready.json').exists():
        assert process.poll() is None, process.communicate()
    fault('reads')
    try:
        Path(gate + '-gate').touch()
        while not Path(gate + '-setup.json').exists():
            assert process.poll() is None, process.communicate()
    finally:
        fault()
    Path(gate + '-continue').touch()
    out, err = process.communicate(timeout=120)
    assert process.returncode == 1 and '[Errno 5]' in err, (process.returncode, err)
assert json.loads(Path(gate + '-setup.json').read_text())['errno'] == errno.EIO
absent()
results.append('kernel-auth cleanup')
print('Setup phase failures and unrelated-name protection passed', flush=True)

# Existing bare owners are not silently adopted or destroyed by a failed open.
existing = owner(); existing.close()
before = {n: mapping_identity(n) for n in NAMES}
rejected(open_views, FileExistsError)
assert before == {n: mapping_identity(n) for n in NAMES}
close_views(); absent()
# Validate both view names before deleting either on close.
v = open_views()
before = {n: mapping_identity(n) for n in NAMES}
rejected(open_views, FileExistsError)
assert before == {n: mapping_identity(n) for n in NAMES}
dm('remove', '--retry', 'piv-native-hidden')
dm('create', 'piv-native-hidden', '--uuid', 'FOREIGN-CLOSE', input='0 1 error\n')
before = {n: mapping_identity(n) for n in NAMES}
rejected(close_views, ValueError)
assert before == {n: mapping_identity(n) for n in NAMES}
dm('remove', '--retry', 'piv-native-hidden'); close_views(); absent()
results.append('existing owners and unrelated close names preserved')

for role in ('decoy', 'hidden'):
    for mode in ('reads', 'writes'):
        v = open_views()
        handle = owner()
        generation = handle.device.generation
        # Sector0 may be served from dm-integrity's cached setup checkpoint.
        # Choose record10, which setup did not write, and witness the raw fault.
        unit = handle.device.sector_size
        size = 512 if role == 'hidden' else 16384
        start = record_span(handle.device, 10)[0] * unit
        offset = 10 * 512 if role == 'hidden' else ((start + size - 1) // size) * size
        affected = (range(10, 11) if role == 'hidden' else
                    blocks_touched(handle.device, offset // unit, (offset + size - 1) // unit))
        old = direct(v[role], offset=offset, size=size)
        before_count = blocks.native_status(handle.device)['encryptions']
        print(f'Injecting lower {mode} through {role}, {size} bytes at offset {offset}', flush=True)
        fault(mode)
        if mode == 'reads': assert rejected(lambda: direct(SOURCE)).errno == errno.EIO
        failure = rejected(lambda: direct(v[role], write=old if mode == 'writes' else None, offset=offset, size=size))
        assert failure.errno == errno.EIO
        status = blocks.native_status(handle.device)
        spent = status['encryptions'] - before_count
        if mode == 'writes':
            # APPLY reached a failing lower write: storage may be partial, so the
            # shared owner still fails stop.
            assert status['failed'] and spent > 0
            fault()
            # Removing the fault does not clear the shared owner's fail-stop.
            for other in ('decoy', 'hidden'):
                assert rejected(lambda: direct(v[other])).errno == errno.EIO
                assert rejected(lambda: direct(v[other], write=old[:512])).errno == errno.EIO
            handle.close()
            close_views(); absent()
            v = open_views()
            handle = owner()
            assert handle.device.generation != generation and not blocks.native_status(handle.device)['failed']
            handle.close()
            repaired = verify(v, unavailable=affected)
        else:
            # Nothing was mutated: only the request fails. A write needing the
            # same carrier also fails while collecting it, before any encryption.
            assert not status['failed'] and spent == 0
            assert rejected(lambda: direct(v[role], write=old, offset=offset, size=size)).errno == errno.EIO
            status = blocks.native_status(handle.device)
            assert not status['failed'] and status['encryptions'] == before_count
            fault()
            # The SAME owner generation serves both views once the fault clears.
            assert direct(v[role], offset=offset, size=size) == old
            direct(v[role], write=old, offset=offset, size=size)
            status = blocks.native_status(handle.device)
            assert not status['failed'] and status['encryptions'] > before_count
            assert handle.device.generation == generation
            handle.close()
            repaired = verify(v)
            assert repaired is False
        close_views(); absent()
        results.append(dict(view=role, fault=mode, bytes=size, offset=offset,
                            failed_both_views=mode == 'writes', recreated=mode == 'writes',
                            same_owner_continued=mode == 'reads', repaired=repaired,
                            prepared_encryptions=spent))
        print(f'{role} lower {mode}: ' + ('fail-stop, teardown, replay and recreation passed' if mode == 'writes'
              else 'local EIO, no encryption, same-owner continuation passed'), flush=True)

# Corrupt the last authenticated sector of one read work item. Earlier sectors
# may have decrypted internally; none of that item's bytes may reach the caller.
# Authentication failure mutates nothing, so it is local to the request.
for role in ('decoy', 'hidden'):
    v = open_views()
    handle = owner()
    generation = handle.device.generation
    unit = handle.device.sector_size
    size = 16384 if role == 'decoy' else 512
    first10, last10 = record_span(handle.device, 10)
    offset = ((first10 * unit + size - 1) // size) * size if role == 'decoy' else 10 * 512
    last = ((offset + size - 1) // unit if role == 'decoy' else last10)
    physical = handle.layout.offsets(last)[0]
    original = direct('/dev/vdb', offset=physical, size=512)
    replacement = original[0] ^ 1
    corrupt_read(physical // 512, replacement)
    observed = direct(SOURCE, offset=physical, size=512)
    assert observed == bytes([replacement]) + original[1:]
    with mmap.mmap(-1, size) as buf:
        sentinel = b'\xa5' * size
        buf[:] = sentinel
        fd = os.open(v[role], os.O_RDONLY | os.O_DIRECT)
        try:
            assert rejected(lambda: os.preadv(fd, [buf], offset)).errno == errno.EIO
            assert buf[:] == sentinel, 'Failed authenticated work item exposed bytes'
        finally:
            os.close(fd)
    status = blocks.native_status(handle.device)
    assert not status['failed']
    before_count = status['encryptions']
    # A write overlapping the corrupt carrier authenticates first and must fail
    # before encrypting or changing anything.
    assert rejected(lambda: direct(v[role], write=b'\x5a' * size, offset=offset, size=size)).errno == errno.EIO
    status = blocks.native_status(handle.device)
    assert not status['failed'] and status['encryptions'] == before_count
    # Unrelated requests on both views continue during the fault.
    assert direct(v['hidden'], offset=0) == EXPECTED[:512]
    direct(v['decoy'], offset=0)
    fault()
    assert handle.device.generation == generation
    handle.close()
    assert verify(v) is False
    close_views(); absent()
    results.append(dict(corrupt_read=role, bytes=size, withheld_entire_work_item=True,
                        failed_both_views=False, overlapping_write_rejected_without_encryption=True,
                        same_owner_continued=True))
    print(f'{role} late primary corruption: no output, local EIO, unchanged storage and continuation passed', flush=True)

# The full setup scan must also reject a later corrupt sector, before views exist.
corrupt_read(physical // 512, replacement)
try:
    rejected(open_views)
    absent()
finally:
    fault()
v = open_views(); assert verify(v) is False
close_views(); absent()
results.append('late primary corruption rejected during setup, cleanup and reopen passed')

# A legitimate fresh-IV primary rewrite destroys one hidden record only.
handle = owner(); dev = handle.device
damaged = record_span(dev, 0)[0]  # sector 0 is a keyslot replica
handle.device.suspend(); dev.begin()
old = dev.read_iv(damaged, quiesced=True)
value = dev.prepare(damaged, old, os.urandom(dev.iv_size))
dev.apply(damaged, old, value); dev.end(); dev.resume(); handle.remove(); handle.close()
v = open_views()
assert rejected(lambda: direct(v['hidden'])).errno == errno.EIO
assert direct(v['hidden'], offset=512) == EXPECTED[512:1024]
handle = owner(); assert not blocks.native_status(handle.device)['failed']; handle.close()
# Rewrite the decoy bytes carrying that sector: re-randomizes only that sector,
# preserving the damage.
decoy_offset = damaged * dev.sector_size // 4096 * 4096
direct(v['decoy'], write=direct(v['decoy'], offset=decoy_offset), offset=decoy_offset)
assert rejected(lambda: direct(v['hidden'])).errno == errno.EIO
handle = owner(); assert not blocks.native_status(handle.device)['failed']; handle.close()
direct(v['hidden'], write=EXPECTED[:512]); assert verify(v) is False
close_views(); absent()
results.append('local hidden EIO, preserved damage and direct repair remain isolated')

# Leave a closed image and complete oracles for independent authentication.
dm('remove', '--retry', 'piv-test-fault')
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0] == PRIMARY
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'fault-final.img'), 'bs=1M', 'status=none'], check=True)
subprocess.run(['rmmod', 'dm_piv'], check=True)
assert Path('/sys/module/dm_crypt').is_dir()
(W / 'fault-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Setup cleanup, foreign-name protection, scoped lower read/auth isolation, write fail-stop and recreation passed\n')
