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

# Format v5 geometry (docs/format-v5.md): 112 keyslot sectors, two directory
# groups, then 687-sector records for 4096-byte hidden blocks (the native
# fixture has no parity; every supported profile has 16-byte IVs).
GROUP, BLOCK = 687, 4096
DECOY_ITEM = 131072   # one whole decoy work item (the DM split boundary, PN_DECOY_BYTES)

def record_span(device, block):
    """First and last primary sector carrying hidden block @block."""
    first = 112 + GROUP * (2 + block)
    return first, first + GROUP - 1

def blocks_touched(device, first, last):
    """Hidden blocks with a fragment in primary sectors first..last."""
    low, high = (first - 112) // GROUP - 2, (last - 112) // GROUP - 2
    return range(max(0, low), high + 1) if last >= 112 + 2 * GROUP else range(0)

# Fixture persists stock --integrity-no-journal (guest_code sets this).
NO_JOURNAL = os.environ.get('PIV_NO_JOURNAL') == '1'


def unreadable(path, unit, sectors, chunk=65536):
    """Primary sectors whose decoy reads fail (O_DIRECT, per-sector on error)."""
    bad, fd = [], os.open(path, os.O_RDONLY | os.O_DIRECT)
    try:
        with mmap.mmap(-1, chunk) as buf, mmap.mmap(-1, unit) as one:
            for start in range(0, sectors * unit, chunk):
                length = min(chunk, sectors * unit - start)
                try:
                    os.preadv(fd, [memoryview(buf)[:length]], start)
                    continue
                except OSError:
                    pass
                for sector in range(start // unit, (start + length) // unit):
                    try:
                        os.preadv(fd, [one], sector * unit)
                    except OSError as exc:
                        assert exc.errno == errno.EIO
                        bad.append(sector)
    finally:
        os.close(fd)
    return bad


def stock_rewrite(source, key, sector, unit):
    """One uncoordinated stock dm-crypt rewrite of primary @sector with its own
    plaintext: stock writes pick a fresh random IV, destroying that fragment."""
    subprocess.run(['cryptsetup', 'open', '--key-file', str(key), str(source), 'piv-stock-rw'], check=True)
    try:
        fd = os.open('/dev/mapper/piv-stock-rw', os.O_RDWR | os.O_DIRECT)
        with mmap.mmap(-1, unit) as buf:
            assert os.preadv(fd, [buf], sector * unit) == unit
            assert os.pwritev(fd, [buf], sector * unit) == unit
            os.fsync(fd)
        os.close(fd)
    finally:
        subprocess.run(['cryptsetup', 'close', 'piv-stock-rw'], check=True)


def open_views(**options):
    value = blocks.open_blocks(SOURCE, KEY, HKEY, **options)
    subprocess.run(['udevadm', 'settle'], check=True)
    return value

def close_views():
    blocks.close_blocks(SOURCE, KEY)

def owner():
    return owners.GuestOwner(SOURCE, KEY)

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

def corrupt_read(sector512, value, nth=1):
    # One raw 512-byte sector only (its @nth byte on reads); unchanged backing
    # bytes and normal writes.
    lines = (f'0 {sector512} linear /dev/vdb 0\n'
             f'{sector512} 1 flakey /dev/vdb {sector512} 0 3600 5 corrupt_bio_byte {nth} r {value} 0\n'
             f'{sector512 + 1} {262144 - sector512 - 1} linear /dev/vdb {sector512 + 1}\n')
    dm('suspend', '--noflush', 'piv-test-fault')
    dm('reload', 'piv-test-fault', input=lines)
    dm('resume', 'piv-test-fault')

def corrupt_reads(targets):
    """Several one-sector read corruptions at once: (sector512, value) pairs,
    first byte of each sector."""
    lines, at = [], 0
    for sector512, value in sorted(targets):
        if sector512 > at:
            lines.append(f'{at} {sector512 - at} linear /dev/vdb {at}')
        lines.append(f'{sector512} 1 flakey /dev/vdb {sector512} 0 3600 5 corrupt_bio_byte 1 r {value} 0')
        at = sector512 + 1
    lines.append(f'{at} {262144 - at} linear /dev/vdb {at}')
    dm('suspend', '--noflush', 'piv-test-fault')
    dm('reload', 'piv-test-fault', input='\n'.join(lines) + '\n')
    dm('resume', 'piv-test-fault')

def direct(path, *, write=None, offset=0, size=BLOCK):
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
    for index in range(len(EXPECTED) // BLOCK):
        expected = EXPECTED[index * BLOCK:(index + 1) * BLOCK]
        try:
            actual = direct(views['hidden'], offset=index * BLOCK)
        except OSError as exc:
            assert index in unavailable and exc.errno == errno.EIO
            direct(views['hidden'], write=expected, offset=index * BLOCK)
            actual = direct(views['hidden'], offset=index * BLOCK)
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
    rejected(lambda: blocks.open_blocks(SOURCE, KEY, HKEY,
                                        env=dict(PIVSETUP_TEST_FAIL=phase)))
    absent()
    results.append(phase + ' cleanup')

# Lower read failure during the kernel authentication scan: hold pivsetup at its
# gate, inject the fault for exactly the SETUP ioctl, then let it unwind.
gate = '/run/piv-fault-kernel-auth'
with blocks.spawn_open(SOURCE, KEY, HKEY,
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
        size = BLOCK if role == 'hidden' else DECOY_ITEM
        start = record_span(handle.device, 10)[0] * unit
        offset = 10 * BLOCK if role == 'hidden' else ((start + size - 1) // size) * size
        affected = (range(10, 11) if role == 'hidden' else
                    blocks_touched(handle.device, offset // unit, (offset + size - 1) // unit))
        old = direct(v[role], offset=offset, size=size)
        # Primary sectors this request may rewrite: the decoy range, or the
        # hidden record's whole carrier (hidden-only tuples).
        span = (range(offset // unit, (offset + size - 1) // unit + 1) if role == 'decoy'
                else range(record_span(handle.device, 10)[0], record_span(handle.device, 10)[1] + 1))
        saved = {sector: direct(v['decoy'], offset=sector * unit, size=unit) for sector in span}
        sectors = handle.device.sectors
        before_count = blocks.native_status(handle.device)['encryptions']
        print(f'Injecting lower {mode} through {role}, {size} bytes at offset {offset}', flush=True)
        fault(mode)
        if mode == 'reads': assert rejected(lambda: direct(SOURCE)).errno == errno.EIO
        failure = rejected(lambda: direct(v[role], write=old if mode == 'writes' else None, offset=offset, size=size))
        assert failure.errno == errno.EIO
        status = blocks.native_status(handle.device)
        spent = status['encryptions'] - before_count
        if mode == 'writes':
            # The write bios reached the failing device: storage may be partial, so the
            # shared owner still fails stop.
            assert status['failed'] and spent > 0
            fault()
            # Removing the fault does not clear the shared owner's fail-stop.
            for other in ('decoy', 'hidden'):
                assert rejected(lambda: direct(v[other])).errno == errno.EIO
                assert rejected(lambda: direct(v[other], write=old[:BLOCK])).errno == errno.EIO
            handle.close()
            close_views(); absent()
            v = open_views()
            handle = owner()
            assert handle.device.generation != generation and not blocks.native_status(handle.device)['failed']
            handle.close()
            torn = unreadable(v['decoy'], unit, sectors)
            if NO_JOURNAL:
                # Without the journal a failed lower write may leave sectors
                # torn (EIO). They must lie within the request's primary
                # sectors, and full-sector decoy writes of the saved plaintext
                # replace them (the failing-sector replacement path).
                assert set(torn) <= set(span), (torn, span)
                for sector in torn:
                    direct(v['decoy'], write=saved[sector], offset=sector * unit, size=unit)
                assert not unreadable(v['decoy'], unit, sectors)
            else:
                # The journal keeps every primary sector whole across the failed write.
                assert not torn, torn
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
                            torn_primary_sectors=torn if mode == 'writes' else [],
                            no_journal=NO_JOURNAL, prepared_encryptions=spent))
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
    layout = handle.layout
    size = DECOY_ITEM if role == 'decoy' else BLOCK
    first10, last10 = record_span(handle.device, 10)
    offset = ((first10 * unit + size - 1) // size) * size if role == 'decoy' else 10 * BLOCK
    last = ((offset + size - 1) // unit if role == 'decoy' else last10)
    physical = handle.layout.offsets(last)[0]
    plaintext = direct(v[role], offset=offset, size=size)  # authenticated, before the fault
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
            if role == 'decoy':
                assert rejected(lambda: os.preadv(fd, [buf], offset)).errno == errno.EIO
                assert buf[:] == sentinel, 'Failed authenticated work item exposed bytes'
            else:
                # Hidden reads use the raw stored IV of a carrier sector that
                # fails primary authentication; the fault hit only its data, so
                # the record's SIV tag still authenticates the intact fragment.
                assert os.preadv(fd, [buf], offset) == size
                assert buf[:] == EXPECTED[offset:offset + size]
        finally:
            os.close(fd)
    status = blocks.native_status(handle.device)
    assert not status['failed']
    before_count = status['encryptions']
    if role == 'hidden':
        # A write that does not cover the failing sector entirely (any hidden
        # write) needs its authenticated old data and must fail before
        # encrypting or changing anything.
        assert rejected(lambda: direct(v[role], write=b'\x5a' * BLOCK, offset=offset)).errno == errno.EIO
        status = blocks.native_status(handle.device)
        assert not status['failed'] and status['encryptions'] == before_count
    elif unit > 512:
        # The decoy's logical block size is the primary sector size (as stock
        # dm-crypt): a sub-sector direct write never reaches the module.
        assert rejected(lambda: direct(v[role], write=b'\x5a' * 512, offset=last * unit)).errno == errno.EINVAL
        status = blocks.native_status(handle.device)
        assert not status['failed'] and status['encryptions'] == before_count
    if role == 'decoy':
        # A decoy write covering the failing sector entirely replaces it
        # (user decision 2026-10-21): fresh IV, refreshed raw fragment. Writing
        # the same plaintext keeps the primary oracle; record 10's fragment
        # survives because the fault corrupts data, not the stored IV.
        direct(v[role], write=plaintext, offset=offset)
        status = blocks.native_status(handle.device)
        assert not status['failed'] and status['encryptions'] == before_count + size // unit, status
    # Unrelated requests on both views continue during the fault.
    assert direct(v['hidden'], offset=0) == EXPECTED[:BLOCK]
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

# --verify (full audit) rejects a later corrupt sector before views exist; the
# default setup scans only the keyslot area and opens, leaving that sector to
# fail authentication when accessed.
corrupt_read(physical // 512, replacement)
try:
    rejected(lambda: open_views(verify=True))
    absent()
    v = open_views()
    # Data-area damage: the decoy sector fails, its hidden block still reads.
    assert rejected(lambda: direct(v['decoy'], offset=last10 * unit,
                                   size=unit)).errno == errno.EIO
    assert direct(v['hidden'], offset=10 * BLOCK) == EXPECTED[10 * BLOCK:11 * BLOCK]
    assert direct(v['hidden'], offset=0) == EXPECTED[:BLOCK]
    handle = owner(); assert not blocks.native_status(handle.device)['failed']; handle.close()
    close_views(); absent()
finally:
    fault()
v = open_views(verify=True); assert verify(v) is False
close_views(); absent()
results.append('late corruption: --verify refuses, default setup opens with local EIO, reopen passed')

# IV damage: corrupt the first IV byte of a record-10 carrier sector whose tuple
# starts a 512-byte metadata sector (tuple = tag || IV16). The primary sector
# fails and its raw fragment is wrong, so the record's SIV tag rejects block 10.
# Applied before opening so no cached metadata masks it.
iv_sector = next(sector for sector in range(record_span(None, 10)[0], record_span(None, 10)[1] + 1)
                 if layout.offsets(sector)[1] % 512 == 0)
tag_physical = layout.offsets(iv_sector)[1]
iv_byte = direct('/dev/vdb', offset=tag_physical, size=512)[layout.tag_bytes] ^ 1
corrupt_read(tag_physical // 512, iv_byte, nth=layout.tag_bytes + 1)
try:
    v = open_views()
    assert rejected(lambda: direct(v['hidden'], offset=10 * BLOCK)).errno == errno.EIO
    assert rejected(lambda: direct(v['decoy'], offset=iv_sector * unit, size=unit)).errno == errno.EIO
    assert direct(v['hidden'], offset=11 * BLOCK) == EXPECTED[11 * BLOCK:12 * BLOCK]
    handle = owner(); assert not blocks.native_status(handle.device)['failed']; handle.close()
    close_views(); absent()
finally:
    fault()
results.append('IV damage: hidden block EIO (SIV), decoy sector EIO, neighbours intact')

# A keyslot sector failing authentication does not block the default setup:
# its raw stored IV is used and the keyslot SIV tag (or the other replica)
# decides; --verify still refuses.
ks_physical = layout.offsets(1)[0]
ks_byte = direct('/dev/vdb', offset=ks_physical, size=512)[0] ^ 1
corrupt_read(ks_physical // 512, ks_byte)
try:
    rejected(lambda: open_views(verify=True))
    absent()
    v = open_views()
    assert direct(v['hidden'], offset=0) == EXPECTED[:BLOCK]
    close_views(); absent()
finally:
    fault()
results.append('keyslot sector failing authentication: default setup unlocks, --verify refuses')

# An uncoordinated stock rewrite (same plaintext, fresh IV) destroys one hidden record only.
damaged = record_span(None, 0)[0]  # sector 0 is a keyslot replica
stock_rewrite(SOURCE, KEY, damaged, unit)
v = open_views()
assert rejected(lambda: direct(v['hidden'])).errno == errno.EIO
assert direct(v['hidden'], offset=BLOCK) == EXPECTED[BLOCK:2 * BLOCK]
handle = owner(); assert not blocks.native_status(handle.device)['failed']; handle.close()
# Rewrite the decoy bytes carrying that sector: re-randomizes only that sector,
# preserving the damage.
decoy_offset = damaged * unit // 4096 * 4096
direct(v['decoy'], write=direct(v['decoy'], offset=decoy_offset), offset=decoy_offset)
assert rejected(lambda: direct(v['hidden'])).errno == errno.EIO
handle = owner(); assert not blocks.native_status(handle.device)['failed']; handle.close()
direct(v['hidden'], write=EXPECTED[:BLOCK]); assert verify(v) is False
close_views(); absent()
results.append('local hidden EIO, preserved damage and direct repair remain isolated')

# A keyslot remove whose directory write fails before writing anything (the
# carrier of the target directory group fails authentication) changes neither
# disk nor memory: the owner stays healthy and a later decoy rewrite of the
# keyslot's sectors refreshes them as a listed keyslot, so it still opens.
second_hkey = os.urandom(32)
v = open_views()
blocks.keyslot(SOURCE, KEY, 1, second_hkey, hidden_key=HKEY)
handle = owner(); before_count = blocks.native_status(handle.device)['encryptions']; handle.close()
targets = [layout.offsets(112)[0], layout.offsets(112 + GROUP)[0]]       # first sector of both directory groups
corrupt_reads([(t // 512, direct('/dev/vdb', offset=t, size=512)[0] ^ 1) for t in targets])
try:
    failure = rejected(lambda: blocks.keyslot(SOURCE, KEY, 1, hidden_key=HKEY))
    assert failure.errno == errno.EBADMSG, (failure, getattr(failure, '__notes__', None))
    handle = owner(); status = blocks.native_status(handle.device); handle.close()
    assert not status['failed'] and status['encryptions'] == before_count, status
    area = direct(v['decoy'], offset=2 * 14 * unit, size=2 * 14 * unit)        # keyslot 1, both replicas
    direct(v['decoy'], write=area, offset=2 * 14 * unit)
finally:
    fault()
close_views(); absent()
v = blocks.open_blocks(SOURCE, KEY, second_hkey); subprocess.run(['udevadm', 'settle'], check=True)
assert verify(v) is False
blocks.keyslot(SOURCE, KEY, 1, hidden_key=second_hkey)                         # restore: slot 0 only
close_views(); absent()
assert rejected(lambda: blocks.open_blocks(SOURCE, KEY, second_hkey)).errno == errno.EKEYREJECTED
absent()
results.append('keyslot remove failing before its directory write: memory restored, slot still listed')

# Sector 0 (keyslot 0, replica 0) damaged: its fragment destroyed by an
# uncoordinated stock rewrite (persistent) and its data failing authentication
# (read corruption). Setup, END and DETACH checkpoint the first authenticating
# keyslot-area sector instead, and keyslot replica 1 unlocks.
stock_rewrite(SOURCE, KEY, 0, unit)
s0_physical = layout.offsets(0)[0]
corrupt_read(s0_physical // 512, direct('/dev/vdb', offset=s0_physical, size=512)[0] ^ 1)
try:
    rejected(lambda: open_views(verify=True))
    absent()
    v = open_views()
    assert rejected(lambda: direct(v['decoy'], offset=0, size=unit)).errno == errno.EIO
    assert direct(v['hidden'], offset=0) == EXPECTED[:BLOCK]
    handle = owner(); assert not blocks.native_status(handle.device)['failed']; handle.close()
    close_views(); absent()                                  # DETACH checkpoint
    # BEGIN/END on an idle private owner (END checkpoints too).
    idle = owner()
    try:
        idle.device.suspend(); idle.device.begin(); idle.device.end(); idle.device.resume()
        assert not blocks.native_status(idle.device)['failed']
    finally:
        idle.remove(); idle.close()
    absent()
finally:
    fault()
v = open_views(); assert verify(v) is False; close_views(); absent()
results.append('sector 0 damaged: setup, END and DETACH checkpoint another sector; replica 1 unlocks')
print('Sector-0 damage: setup, END, DETACH and replica-1 unlock passed', flush=True)


def gated_setup_fault(label, **options):
    """Hold pivsetup at its gate, fail all lower writes for exactly the SETUP
    ioctl, then let it unwind: the write error after writing began must
    fail-stop the owner (STATUS failed after the native state is gone)."""
    gate = f'/run/piv-fault-{label}'
    with blocks.spawn_open(SOURCE, KEY, HKEY, env=dict(PIVSETUP_TEST_GATE=gate, PIVSETUP_TEST_HOLD='1'),
                           **options) as process:
        while not Path(gate + '-ready.json').exists():
            assert process.poll() is None, process.communicate()
        fault('writes')
        try:
            Path(gate + '-gate').touch()
            while not Path(gate + '-setup.json').exists():
                assert process.poll() is None, process.communicate()
        finally:
            fault()
        Path(gate + '-continue').touch()
        out, err = process.communicate(timeout=120)
        assert process.returncode == 1 and '[Errno 5]' in err, (process.returncode, err)
    report = json.loads(Path(gate + '-setup.json').read_text())
    assert report['errno'] == errno.EIO and report['status']['failed'] and not report['status']['active'], report
    absent()
    return report


def setup_tears(v, scope):
    """No-journal: sectors a failed setup write left torn (EIO) must lie in
    @scope; restore them from the pre-fault decoy plaintext by full-sector
    decoy writes. Journaled: none may be torn."""
    unit = len(SAVED_DECOY) // SECTORS
    torn = unreadable(v['decoy'], unit, SECTORS)
    if NO_JOURNAL:
        assert set(torn) <= set(scope), (torn[:16], scope)
        for sector in torn:
            direct(v['decoy'], write=SAVED_DECOY[sector * unit:(sector + 1) * unit], offset=sector * unit, size=unit)
        assert not unreadable(v['decoy'], unit, SECTORS)
    else:
        assert not torn, torn[:16]
    return torn


# Decoy plaintext before the setup write faults (setup never changes it).
v = open_views()
SAVED_DECOY = Path(v['decoy']).read_bytes()
handle = owner()
SECTORS = handle.device.sectors
handle.close()
close_views(); absent()
# A lower write failure during --initialize (the first write revokes keyslot
# area 1) stops the owner; the volume keeps its previous keyslot, directory
# and records, so it reopens unchanged after recreation. Without the journal,
# tags buffered by dm-integrity can reach the disk after their data writes
# failed: only the revocation's sectors (keyslot areas 1-3, directory group 1)
# may tear.
report = gated_setup_fault('initialize', initialize=True)
v = open_views()
torn = setup_tears(v, range(28, 112 + 2 * GROUP))
assert verify(v) is False; close_views(); absent()
results.append(dict(setup_write_fault='initialize', owner_failed=True, encryptions=report['status']['encryptions'],
                    previous_volume_intact=True, torn_primary_sectors=len(torn)))
# A lower write failure during --fill (after a quick initialization) stops the
# owner; a later fill completes and the hidden contents are restored.
v = open_views(initialize=True, quick=True); close_views(); absent()
report = gated_setup_fault('fill', fill=True)
# Fill writes only hidden-block records.
v = open_views()
fill_torn = setup_tears(v, range(112 + 2 * GROUP, SECTORS))
close_views(); absent()
v = open_views(fill=True)
assert v['fill']['failed'] == 0 and v['fill']['valid'] + v['fill']['written'] == len(EXPECTED) // BLOCK, v['fill']
direct(v['hidden'], write=EXPECTED)
assert verify(v) is False
close_views(); absent()
results.append(dict(setup_write_fault='fill', owner_failed=True, encryptions=report['status']['encryptions'],
                    refill_and_restore=True, torn_primary_sectors=len(fill_torn)))
print('Setup write faults (initialize, fill): owner fail-stop, cleanup and recreation passed', flush=True)

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
