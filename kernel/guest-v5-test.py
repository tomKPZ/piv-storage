#!/usr/bin/env python3
"""Format v5 on a stock 16-byte-IV fixture: footprint, preservation, guard,
damage, repair, KDF tiers, quick initialization and fill, and Reed–Solomon
parity."""
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import random
import subprocess

from pivstore import rs
from pivstore.blocks import open_blocks, close_blocks, keyslot, native_status
from pivstore.kernel_api import dm
from pivstore.kernel_owner import GuestOwner
from pivstore.records import DATA_FRAGMENTS, FRAGMENT, correct_fragments, parity_fragments

W = Path('/mnt/piv-work')
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
BLOCK, KEYSLOT_AREA = 4096, 112
GROUP = 687                                  # sectors per record without parity
RESERVED = KEYSLOT_AREA + 2 * GROUP          # keyslots + directory (no parity)
STACK = '/dev/mapper/piv-test-fault'
results = {}


def direct(path, offset, size, write=None):
    buf = mmap.mmap(-1, size)
    fd = os.open(path, os.O_RDWR | os.O_DIRECT)
    try:
        if write is None:
            assert os.preadv(fd, [buf], offset) == size
            return buf[:]
        buf[:] = write
        assert os.pwritev(fd, [buf], offset) == size
        os.fsync(fd)
    finally:
        os.close(fd)
        buf.close()


def status(source='/dev/vdb', **kw):
    owner = GuestOwner(source, KEY, **kw)
    try:
        return native_status(owner.device), owner.device.sector_size, owner.device.sectors
    finally:
        owner.close()


def rejected(fn):
    try:
        fn()
    except OSError as exc:
        return exc
    raise AssertionError('Operation unexpectedly succeeded')


def opened(source='/dev/vdb', **kw):
    value = open_blocks(source, KEY, kw.pop('key', HKEY), **kw)
    subprocess.run(['udevadm', 'settle'], check=True)
    return value


def sector_size(source='/dev/vdb'):
    return json.loads(subprocess.check_output(['cryptsetup', 'luksDump', '--dump-json-metadata', source],
                                              text=True))['segments']['0']['sector_size']


def stock_rewrite(source, sectors):
    """Uncoordinated stock dm-crypt rewrites of primary @sectors with their own
    plaintext: stock writes pick fresh random IVs, destroying those fragments
    while the sectors still authenticate (RS errors, not erasures)."""
    unit = sector_size(source)
    subprocess.run(['cryptsetup', 'open', '--key-file', str(KEY), str(source), 'piv-stock-rw'], check=True)
    try:
        fd = os.open('/dev/mapper/piv-stock-rw', os.O_RDWR | os.O_DIRECT)
        with mmap.mmap(-1, unit) as buf:
            for sector in sectors:
                assert os.preadv(fd, [buf], sector * unit) == unit
                assert os.pwritev(fd, [buf], sector * unit) == unit
            os.fsync(fd)
        os.close(fd)
    finally:
        subprocess.run(['cryptsetup', 'close', 'piv-stock-rw'], check=True)


def damage(sector):
    stock_rewrite('/dev/vdb', [sector])


def readable(path, index):
    """Block @index of a hidden view, or None if it reads EIO (exact O_DIRECT)."""
    try:
        return direct(path, index * BLOCK, BLOCK)
    except OSError as exc:
        assert exc.errno == errno.EIO, exc
        return None


def setup_writes():
    """Primary encryptions of keyslot 0 (2 x 14 sectors) and one directory write."""
    return 2 * 14 + GROUP


def write_profile(count=48):
    """Direct 4 KiB O_DSYNC decoy writes at pseudo-random aligned offsets:
    elapsed time and exact primary encryptions (TCG timings are diagnostic)."""
    import time
    v = opened(initialize=True)
    st, unit, sectors = status()
    rng = random.Random(4)
    offsets = [rng.randrange(RESERVED * unit // 4096, (sectors * unit) // 4096 - 1) * 4096 for _ in range(count)]
    before = st['encryptions']
    fd = os.open(v['decoy'], os.O_RDWR | os.O_DIRECT | os.O_DSYNC)
    buf = mmap.mmap(-1, 4096)
    try:
        start = time.monotonic()
        for offset in offsets:
            assert os.preadv(fd, [buf], offset) == 4096
            assert os.pwritev(fd, [buf], offset) == 4096
        elapsed = time.monotonic() - start
    finally:
        os.close(fd); buf.close()
    spent = status()[0]['encryptions'] - before
    close_blocks('/dev/vdb', KEY)
    # A decoy write re-encrypts exactly the written sectors.
    assert spent == count * (4096 // unit), spent
    return dict(format='v5', writes=count, bytes_each=4096, seconds=round(elapsed, 3),
                encryptions=spent, encryptions_per_write=spent / count)


def rs_harness(trials=150):
    """Cross-check the kernel RS code (kernel/piv-rs.inc via the userspace
    harness kernel/piv-rs-test.c) against the independent Python reference:
    identical parity, and identical correction outcome and output for random
    erasure/error patterns inside and beyond the bound."""
    import ctypes
    subprocess.run(['gcc-14', '-O2', '-Wall', '-Werror', '-shared', '-fPIC', '-nostdlib', '-ffreestanding',
                    '-fno-tree-loop-distribute-patterns', '-I', str(W), '-o', '/root/piv-rs-test.so',
                    str(W / 'piv-rs-test.c')], check=True)
    library = ctypes.CDLL('/root/piv-rs-test.so')   # /run is mounted noexec
    library.piv_rs_test_parity.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p]
    library.piv_rs_test_correct.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p]
    rng = random.Random(11)
    counts = dict(encode=0, recovered=0, failed_both=0, agreed_beyond=0)
    for trial in range(trials):
        p = (4, 8, 16)[trial % 3]
        group = DATA_FRAGMENTS + 3 * p
        payload = rng.randbytes(DATA_FRAGMENTS * FRAGMENT)
        out = ctypes.create_string_buffer(3 * p * FRAGMENT)
        library.piv_rs_test_parity(payload, p, out)
        parity = out.raw
        assert parity == parity_fragments(payload, p), ('parity', p)
        counts['encode'] += 1
        fragments = bytearray(payload + parity)
        # Per lane: f erasures and e errors, sometimes beyond 2e + f <= p.
        erased, beyond = set(), False
        for lane in range(3):
            candidates = [j for j in range(group) if j % 3 == lane]
            f = rng.randrange(p + 2)
            e = rng.randrange(max(1, (p - min(f, p)) // 2 + 2))
            beyond |= 2 * e + f > p
            chosen = rng.sample(candidates, min(len(candidates), f + e))
            for j in chosen[:f]:
                erased.add(j)
                fragments[j * 6:j * 6 + 6] = bytes(6)
            for j in chosen[f:]:
                fragments[j * 6 + rng.randrange(6)] ^= rng.randrange(1, 256)
        flags = bytes(1 if j in erased else 0 for j in range(group))
        work = ctypes.create_string_buffer(bytes(fragments), len(fragments))
        code = library.piv_rs_test_correct(work, p, flags)
        try:
            reference = correct_fragments(bytes(fragments), p, sorted(erased))
        except rs.DecodeError:
            reference = None
        assert code in (0, -1), code
        kernel = work.raw[:DATA_FRAGMENTS * FRAGMENT] if code == 0 else None
        assert kernel == reference, ('correct', p, trial, beyond)
        if not beyond:
            assert kernel == payload, ('within bound', p, trial)
            counts['recovered'] += 1
        elif kernel is None:
            counts['failed_both'] += 1
        else:
            counts['agreed_beyond'] += 1
    return counts


# Kernel RS code equals the Python reference before any volume work.
results['rs_harness'] = rs_harness()
print('RS harness cross-check passed:', results['rs_harness'], flush=True)

# A stock carrier has no keyslot: refused unless initializing.
assert rejected(lambda: opened()).errno == errno.EKEYREJECTED
results['write_profile'] = [write_profile()]

# A/B slots: half capacity; a damaged newest slot falls back to the previous
# version, and the next write targets the damaged slot again.
v = opened(initialize=True, ab=True)
st, unit, sectors = status()
assert v['hidden_bytes'] == ((sectors - KEYSLOT_AREA) // GROUP - 2) // 2 * BLOCK
first, second = bytes([0xa1]) * BLOCK, bytes([0xb2]) * BLOCK
direct(v['hidden'], 0, BLOCK, first)     # initialization wrote gen1 to slot A: this is slot B gen2
direct(v['hidden'], 0, BLOCK, second)    # slot A gen3
assert direct(v['hidden'], 0, BLOCK) == second
close_blocks('/dev/vdb', KEY)
damage(RESERVED)                         # slot A (group 2) of block 0: the newest version
v = opened()                             # layout (A/B) comes from the keyslot
assert direct(v['hidden'], 0, BLOCK) == first, 'A/B did not fall back to the previous version'
before = status()[0]['encryptions']
direct(v['hidden'], 0, BLOCK, second)
assert status()[0]['encryptions'] - before == GROUP
assert direct(v['hidden'], 0, BLOCK) == second
close_blocks('/dev/vdb', KEY)
v = opened()
assert direct(v['hidden'], 0, BLOCK) == second
assert direct(v['hidden'], BLOCK, BLOCK) == bytes(BLOCK)

# Keyslots: add a key-file slot and passphrase slots (default tier 3 and tier
# 1) on the active owner, rewrite the whole keyslot/directory area through the
# decoy (fragment refresh must preserve every listed keyslot), then retire the
# original key.
second_key, passphrase = os.urandom(32), b'synthetic test passphrase'
third_passphrase = b'another synthetic test passphrase'
keyslot('/dev/vdb', KEY, 1, second_key)
keyslot('/dev/vdb', KEY, 2, passphrase=passphrase)            # pivsetup derives the tier-3 KEK
keyslot('/dev/vdb', KEY, 3, passphrase=third_passphrase, kdf_cost=1)
# Independent Python Argon2id KEKs must open the same slots: Rust/Python KDF
# parity on the real volume context, per tier.
from pivstore.blocks import base_identity, passphrase_kek
owner = GuestOwner('/dev/vdb', KEY)
identity = base_identity(owner)
owner.close()
pass_kek = passphrase_kek(passphrase, identity, 3)
third_kek = passphrase_kek(third_passphrase, identity, 1)
area = direct(v['decoy'], 0, RESERVED * unit)
direct(v['decoy'], 0, RESERVED * unit, area)
close_blocks('/dev/vdb', KEY)
for kw in (dict(), dict(key=second_key), dict(key=None, hidden_passphrase=passphrase), dict(key=pass_kek),
           dict(key=None, hidden_passphrase=third_passphrase, kdf_cost=1), dict(key=third_kek)):
    v = opened(**kw)
    assert direct(v['hidden'], 0, BLOCK) == second
    close_blocks('/dev/vdb', KEY)
# A wrong passphrase, or the right one at another cost tier, derives an
# unrelated KEK: indistinguishable rejections.
assert rejected(lambda: opened(key=None, hidden_passphrase=b'wrong synthetic passphrase')).errno == errno.EKEYREJECTED
assert rejected(lambda: opened(key=None, hidden_passphrase=third_passphrase)).errno == errno.EKEYREJECTED
assert rejected(lambda: opened(key=None, hidden_passphrase=passphrase, kdf_cost=1)).errno == errno.EKEYREJECTED
assert rejected(lambda: opened(key=None, hidden_passphrase=third_passphrase, kdf_cost=2)).errno == errno.EKEYREJECTED
v = opened(key=second_key)
keyslot('/dev/vdb', KEY, 3)
close_blocks('/dev/vdb', KEY)
assert rejected(lambda: opened(key=None, hidden_passphrase=third_passphrase, kdf_cost=1)).errno == errno.EKEYREJECTED
v = opened(key=second_key)
keyslot('/dev/vdb', KEY, 0)            # remove the original key file's slot
assert rejected(lambda: keyslot('/dev/vdb', KEY, 0)).errno == errno.ENOENT
close_blocks('/dev/vdb', KEY)
assert rejected(lambda: opened()).errno == errno.EKEYREJECTED
v = opened(key=second_key)
keyslot('/dev/vdb', KEY, 2)
assert rejected(lambda: keyslot('/dev/vdb', KEY, 1)).errno == errno.EBUSY   # last keyslot stays
close_blocks('/dev/vdb', KEY)
assert rejected(lambda: opened(key=None, hidden_passphrase=passphrase)).errno == errno.EKEYREJECTED
results['keyslots'] = dict(added=[1, 2, 3], removed=[3, 0, 2], last_slot_protected=True,
                           passphrase_slots={2: 'tier 3 (default)', 3: 'tier 1'}, python_kdf_cross_check=[1, 3],
                           wrong_passphrase_rejected=True, wrong_tier_rejected=True,
                           decoy_rewrite_of_keyslot_area_preserved=True)
results['ab'] = dict(fallback_after_damaged_newest_slot=True, rewrite_encryptions=GROUP)

# ---- Quick initialization and fill (no parity) ----
# --quick writes only keyslot 0 and the directory: every hidden block reads EIO
# until written. --fill skips authenticated blocks and writes zero records into
# the rest; a block with a destroyed fragment (stock rewrite) is rewritten as
# zeros (documented destructive behaviour). Encryption counts witness exactly
# which records were written.
v = opened(initialize=True, quick=True)
st, unit, sectors = status()
records = (sectors - KEYSLOT_AREA) // GROUP - 2
assert v['hidden_bytes'] == st['hidden_bytes'] == records * BLOCK, (v, records)
assert st['encryptions'] == setup_writes(), st
for index in (0, 1, records // 2, records - 1):
    assert readable(v['hidden'], index) is None, index
quick = {i: hashlib.shake_256(b'quick-%d' % i).digest(BLOCK) for i in (1, 3, records // 2)}
for index, value in quick.items():
    before = status()[0]['encryptions']
    direct(v['hidden'], index * BLOCK, BLOCK, value)
    assert status()[0]['encryptions'] - before == GROUP
for index, value in quick.items():
    assert direct(v['hidden'], index * BLOCK, BLOCK) == value
primary_quick = subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0]
close_blocks('/dev/vdb', KEY)
for kw in (dict(quick=True), dict(initialize=True, fill=True)):    # usage errors, nothing opened
    try:
        opened(**kw)
    except ValueError:
        pass
    else:
        raise AssertionError(kw)
v = opened()
assert readable(v['hidden'], 0) is None and readable(v['hidden'], records - 1) is None
assert direct(v['hidden'], BLOCK, BLOCK) == quick[1]
close_blocks('/dev/vdb', KEY)
damage(RESERVED + 3 * GROUP + 100)                   # one fragment of block 3's record
v = opened(fill=True)
assert v['fill'] == dict(valid=2, written=records - 2, failed=0), v['fill']
assert status()[0]['encryptions'] == (records - 2) * GROUP
expected_quick = bytearray(records * BLOCK)
for index in (1, records // 2):
    expected_quick[index * BLOCK:(index + 1) * BLOCK] = quick[index]
assert Path(v['hidden']).read_bytes() == expected_quick      # block 3 is now zeros
assert subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0] == primary_quick
close_blocks('/dev/vdb', KEY)
v = opened(fill=True)                                        # idempotent: nothing left to write
assert v['fill'] == dict(valid=records, written=0, failed=0), v['fill']
assert status()[0]['encryptions'] == 0
close_blocks('/dev/vdb', KEY)
results['quick_fill'] = dict(records=records, quick_encryptions=setup_writes(), unwritten='EIO',
                             fill_first=dict(valid=2, written=records - 2, failed=0),
                             damaged_block_rewritten_as_zeros=True, fill_again=dict(valid=records, written=0),
                             primary_preserved=True)

# A/B quick: unwritten blocks have no valid slot; a write goes to slot 0
# (generation 1) and fill completes the rest.
v = opened(initialize=True, quick=True, ab=True)
ab_records = ((sectors - KEYSLOT_AREA) // GROUP - 2) // 2
assert v['hidden_bytes'] == ab_records * BLOCK and status()[0]['encryptions'] == setup_writes()
assert readable(v['hidden'], 0) is None
direct(v['hidden'], BLOCK, BLOCK, quick[1])
close_blocks('/dev/vdb', KEY)
v = opened(fill=True)
assert v['fill'] == dict(valid=1, written=ab_records - 1, failed=0), v['fill']
assert status()[0]['encryptions'] == (ab_records - 1) * GROUP
direct(v['hidden'], BLOCK, BLOCK, quick[3])                 # second version: slot 1, generation 2
expected_ab = bytearray(ab_records * BLOCK)
expected_ab[BLOCK:2 * BLOCK] = quick[3]
assert Path(v['hidden']).read_bytes() == expected_ab
close_blocks('/dev/vdb', KEY)
results['quick_fill_ab'] = dict(records=ab_records, fill=dict(valid=1, written=ab_records - 1, failed=0))

v = opened(initialize=True)
st, unit, sectors = status()
assert v['hidden_bytes'] == st['hidden_bytes'] == records * BLOCK, (v, records)
assert Path(v['hidden']).read_bytes() == bytes(records * BLOCK)
results['records'] = records

# Hidden writes re-encode exactly one 687-fragment record per 4096-byte block.
pattern = {i: hashlib.shake_256(b'v5-%d' % i).digest(BLOCK) for i in (0, 1, records // 2, records - 1)}
for index, value in pattern.items():
    before = status()[0]['encryptions']
    direct(v['hidden'], index * BLOCK, BLOCK, value)
    assert status()[0]['encryptions'] - before == GROUP
for index, value in pattern.items():
    assert direct(v['hidden'], index * BLOCK, BLOCK) == value
# A multi-block direct write is split per block by DM: one record each.
before = status()[0]['encryptions']
pair = hashlib.shake_256(b'v5-pair').digest(2 * BLOCK)
direct(v['hidden'], 2 * BLOCK, 2 * BLOCK, pair)
assert status()[0]['encryptions'] - before == 2 * GROUP
assert direct(v['hidden'], 2 * BLOCK, 2 * BLOCK) == pair
hidden_before = Path(v['hidden']).read_bytes()

# Decoy writes re-randomize only the written primary sectors: one encryption per
# sector, independent of record groups.
footprint = []
for offset in (0, RESERVED * unit, (RESERVED + GROUP // 2) * unit, (RESERVED + GROUP) * unit - 4096,
               (sectors - 1) * unit - 4096 + unit):
    old = direct(v['decoy'], offset, 4096)
    new = hashlib.shake_256(b'decoy-%d' % offset).digest(4096)
    before = status()[0]['encryptions']
    direct(v['decoy'], offset, 4096, new)
    spent = status()[0]['encryptions'] - before
    assert spent == 4096 // unit, (offset, spent)
    assert direct(v['decoy'], offset, 4096) == new
    footprint.append(dict(offset=offset, bytes=4096, encryptions=spent))
    direct(v['decoy'], offset, 4096, old)
assert Path(v['hidden']).read_bytes() == hidden_before
results['decoy_footprint'] = footprint

# Larger decoy rewrite across many record groups preserves every hidden byte.
span = 2 * 1024 * 1024
region = direct(v['decoy'], RESERVED * unit, span)
direct(v['decoy'], RESERVED * unit, span, region)
assert Path(v['hidden']).read_bytes() == hidden_before
primary_after = subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0]
close_blocks('/dev/vdb', KEY)

# Wrong key: rejected before any view exists; correct key reopens without flags.
assert rejected(lambda: opened(key=bytes(32))).errno == errno.EKEYREJECTED
v = opened()
assert Path(v['hidden']).read_bytes() == hidden_before
close_blocks('/dev/vdb', KEY)

# Damage record 0 with one legitimate fresh-IV primary rewrite (as a stock write
# would). It becomes local EIO; a decoy write over it leaves it unavailable (no
# fabricated data); a full hidden write repairs it.
target = RESERVED
damage(target)
v = opened()
assert rejected(lambda: direct(v['hidden'], 0, BLOCK)).errno == errno.EIO
assert direct(v['hidden'], BLOCK, BLOCK) == pattern[1]
block = direct(v['decoy'], target * unit, unit)
direct(v['decoy'], target * unit, unit, block)
assert rejected(lambda: direct(v['hidden'], 0, BLOCK)).errno == errno.EIO
assert not status()[0]['failed']
direct(v['hidden'], 0, BLOCK, pattern[0])
assert Path(v['hidden']).read_bytes() == hidden_before
assert subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0] == primary_after
close_blocks('/dev/vdb', KEY)
results['damage'] = dict(local_eio=True, preserved_by_decoy_write=True, repaired_by_hidden_write=True)

# ---- Reed–Solomon parity (p = 8, G = 711) on a dm test stack over /dev/vdb ----
P = 8
G = DATA_FRAGMENTS + 3 * P
disk = int(subprocess.check_output(['blockdev', '--getsz', '/dev/vdb']))


def stack(errors=()):
    """Linear map of /dev/vdb, with dm error segments over the data of the
    primary sectors in @errors (they become unreadable: RS erasures)."""
    ranges = sorted((layout.offsets(s)[0] // 512, unit // 512) for s in errors) if errors else []
    lines, at = [], 0
    for start, length in ranges:
        if start > at:
            lines.append(f'{at} {start - at} linear /dev/vdb {at}')
        lines.append(f'{start} {length} error')
        at = start + length
    if at < disk:
        lines.append(f'{at} {disk - at} linear /dev/vdb {at}')
    return '\n'.join(lines) + '\n'


def restack(errors=()):
    dm('suspend', '--noflush', 'piv-test-fault')
    dm('reload', 'piv-test-fault', input=stack(errors))
    dm('resume', 'piv-test-fault')


def rs_open(**kw):
    return opened(STACK, **kw)


def rs_close():
    close_blocks(STACK, KEY)


def rs_status():
    return status(STACK)[0]


def raw_tuple_patch(sector, data, metadata):
    """Write raw primary @sector bytes (ciphertext and tag || IV) with the
    views closed (aligned O_DIRECT read-modify-write of the metadata)."""
    data_offset, tag_offset = layout.offsets(sector)
    direct(STACK, data_offset, unit, data)
    lo = tag_offset // 512 * 512
    hi = -(-(tag_offset + layout.tuple_bytes) // 512) * 512
    span = bytearray(direct(STACK, lo, hi - lo))
    span[tag_offset - lo:tag_offset - lo + layout.tuple_bytes] = metadata
    direct(STACK, lo, hi - lo, bytes(span))


def raw_tuple(sector):
    data_offset, tag_offset = layout.offsets(sector)
    lo = tag_offset // 512 * 512
    hi = -(-(tag_offset + layout.tuple_bytes) // 512) * 512
    span = direct(STACK, lo, hi - lo)
    return direct(STACK, data_offset, unit), span[tag_offset - lo:tag_offset - lo + layout.tuple_bytes]


def group_first(block):
    return KEYSLOT_AREA + G * (2 + block)


dm('create', 'piv-test-fault', input='0 %d linear /dev/vdb 0\n' % disk)
# Quick initialization with parity, then fill: the four written blocks are
# skipped, the rest receive zero records with parity.
v = rs_open(initialize=True, quick=True, parity=P)
handle = GuestOwner(STACK, KEY)
layout, unit, sectors = handle.layout, handle.device.sector_size, handle.device.sectors
handle.close()
rs_records = (sectors - KEYSLOT_AREA) // G - 2
assert v['hidden_bytes'] == rs_records * BLOCK, (v, rs_records)
assert rs_status()['encryptions'] == 2 * 14 + G
rs_pattern = {i: hashlib.shake_256(b'v5-rs-%d' % i).digest(BLOCK) for i in range(4)}
for index, value in rs_pattern.items():
    before = rs_status()['encryptions']
    direct(v['hidden'], index * BLOCK, BLOCK, value)
    assert rs_status()['encryptions'] - before == G
assert readable(v['hidden'], 4) is None
rs_close()
v = rs_open(fill=True)
assert v['fill'] == dict(valid=4, written=rs_records - 4, failed=0), v['fill']
assert rs_status()['encryptions'] == (rs_records - 4) * G
assert direct(v['hidden'], 4 * BLOCK, BLOCK) == bytes(BLOCK)
rs_close()
results['rs'] = dict(parity=P, group=G, blocks=rs_records, write_encryptions=G,
                     quick_fill=dict(valid=4, written=rs_records - 4, failed=0))

# Unreadable carrier sectors (erasures): p per lane recover, including parity
# sectors; p + 1 in one lane returns EIO, never wrong data; the decoy sector
# fails locally and a hidden write over the block refuses before encrypting.
rng = random.Random(7)
lost = []
for lane in range(3):
    lost += rng.sample([j for j in range(G) if j % 3 == lane], P)
assert any(j >= DATA_FRAGMENTS for j in lost)
restack([group_first(1) + j for j in lost])
v = rs_open()
assert direct(v['hidden'], BLOCK, BLOCK) == rs_pattern[1]
assert direct(v['hidden'], 0, BLOCK) == rs_pattern[0]
assert rejected(lambda: direct(v['decoy'], (group_first(1) + lost[0]) * unit, unit)).errno == errno.EIO
before = rs_status()
assert rejected(lambda: direct(v['hidden'], BLOCK, BLOCK, rs_pattern[1])).errno == errno.EIO
after = rs_status()
assert not after['failed'] and after['encryptions'] == before['encryptions']
rs_close()
# Fill counts an RS-recovered block as valid and writes nothing.
v = rs_open(fill=True)
assert v['fill'] == dict(valid=rs_records, written=0, failed=0), v['fill']
assert rs_status()['encryptions'] == 0
assert direct(v['hidden'], BLOCK, BLOCK) == rs_pattern[1]
rs_close()
too_many = [3 * i for i in range(P + 1)]          # p + 1 erasures in lane 0
restack([group_first(1) + j for j in too_many])
v = rs_open()
assert rejected(lambda: direct(v['hidden'], BLOCK, BLOCK)).errno == errno.EIO
assert direct(v['hidden'], 2 * BLOCK, BLOCK) == rs_pattern[2]
assert not rs_status()['failed']
rs_close()
# Fill cannot authenticate block 1's carrier (unreadable sectors): it is left
# as it was and counted as failed; nothing is written and the owner stays up.
v = rs_open(fill=True)
assert v['fill'] == dict(valid=rs_records - 1, written=0, failed=1), v['fill']
st = rs_status()
assert st['encryptions'] == 0 and not st['failed']
assert rejected(lambda: direct(v['hidden'], BLOCK, BLOCK)).errno == errno.EIO
rs_close()
restack()
v = rs_open()
assert direct(v['hidden'], BLOCK, BLOCK) == rs_pattern[1]    # untouched by the fill
rs_close()
results['rs']['erasures'] = dict(recovered_per_lane=P, total=len(lost), parity_sectors_included=True,
                                 beyond_bound='EIO', strict_write_refused_without_encryption=True,
                                 fill_counts_recovered_as_valid=True, fill_leaves_unreadable_block=True)

# Authenticating sectors with foreign fragments (errors, as from uncoordinated
# stock writes): p/2 per lane are corrected without erasure information.
errors = []
for lane in range(3):
    errors += rng.sample([j for j in range(DATA_FRAGMENTS) if j % 3 == lane], P // 2)
stock_rewrite(STACK, [group_first(2) + j for j in errors])
v = rs_open()
assert direct(v['hidden'], 2 * BLOCK, BLOCK) == rs_pattern[2]
# Repair: a hidden write re-encodes all G sectors (they all authenticate).
direct(v['hidden'], 2 * BLOCK, BLOCK, rs_pattern[2])
rs_close()
results['rs']['errors'] = dict(corrected_per_lane=P // 2, total=len(errors), repaired_by_hidden_write=True)

# Mixed versions (an interrupted rewrite): restore the raw old tuples of some
# carrier sectors after a hidden rewrite. They authenticate and carry the old
# fragments: 4 per lane (12 consecutive sectors) still decode the NEW version;
# 10 per lane return EIO (no A/B), never the old or a mixed block.
old_raw = {j: raw_tuple(group_first(3) + j) for j in range(300, 330)}
v = rs_open()
newer = hashlib.shake_256(b'v5-rs-newer').digest(BLOCK)
direct(v['hidden'], 3 * BLOCK, BLOCK, newer)
rs_close()
for j in range(300, 312):
    raw_tuple_patch(group_first(3) + j, *old_raw[j])
v = rs_open()
assert direct(v['hidden'], 3 * BLOCK, BLOCK) == newer
rs_close()
for j in range(312, 330):
    raw_tuple_patch(group_first(3) + j, *old_raw[j])
v = rs_open()
assert rejected(lambda: direct(v['hidden'], 3 * BLOCK, BLOCK)).errno == errno.EIO
assert not rs_status()['failed']
direct(v['hidden'], 3 * BLOCK, BLOCK, rs_pattern[3])
assert direct(v['hidden'], 3 * BLOCK, BLOCK) == rs_pattern[3]
results['rs']['mixed_versions'] = dict(new_version_recovered_with_errors_per_lane=4,
                                       ten_per_lane='EIO', repaired=True)

# Oracles, stock readback and a closed parity image for independent host
# decoding (strict: the host compares every stored parity fragment with the
# Python encoder).
rs_hidden = Path(v['hidden']).read_bytes()
for index, value in rs_pattern.items():
    assert rs_hidden[index * BLOCK:(index + 1) * BLOCK] == value
rs_primary = subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0]
assert rs_primary == primary_after
rs_close()
dm('remove', '--retry', 'piv-test-fault')
print('RS parity: erasures, errors, mixed versions and repair passed', flush=True)
(W / 'expected-hidden-volume').write_bytes(rs_hidden)
(W / 'expected-primary.sha256').write_text(rs_primary + '\n')
subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0] == rs_primary
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'v5-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'v5-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Format v5 footprint, preservation, guard, KDF tiers, local damage, repair, '
                              'quick initialization and fill, RS parity and stock readback passed\n')
