#!/usr/bin/env python3
"""Format v4 on a stock 16-byte-IV fixture: footprint, preservation, guard, damage, repair."""
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import subprocess

from pivstore.blocks import open_blocks, close_blocks, keyslot, native_status
from pivstore.kernel_owner import GuestOwner

W = Path('/mnt/piv-work')
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
GROUP, RESERVED = 90, 112 + 2 * 90
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


def status():
    owner = GuestOwner('/dev/vdb', KEY)
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


def opened(**kw):
    value = open_blocks('/dev/vdb', KEY, kw.pop('key', HKEY), **kw)
    subprocess.run(['udevadm', 'settle'], check=True)
    return value


def damage(sector):
    """One legitimate fresh-IV primary rewrite, as an uncoordinated stock write would."""
    owner = GuestOwner('/dev/vdb', KEY)
    owner.device.suspend(); owner.device.begin()
    old_iv = owner.device.read_iv(sector, quiesced=True)
    prepared = owner.device.prepare(sector, old_iv, os.urandom(owner.device.iv_size))
    owner.device.apply(sector, old_iv, prepared)
    owner.device.end(); owner.device.resume(); owner.remove(); owner.close()


def write_profile(label, count=48):
    """Direct 4 KiB O_DSYNC decoy writes at pseudo-random aligned offsets:
    elapsed time and exact primary encryptions (TCG timings are diagnostic)."""
    import random, time
    # Explicit format: initialization defaults to v4 on this 16-byte-IV profile.
    v = opened(initialize=True, format=3 if label == 'v3' else 4)
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
    # v4 re-encrypts exactly the written sectors; v3 refreshes >= one 36-sector group.
    if label == 'v4':
        assert spent == count * (4096 // unit), (label, spent)
    else:
        assert spent >= count * 36, (label, spent)
    return dict(format=label, writes=count, bytes_each=4096, seconds=round(elapsed, 3),
                encryptions=spent, encryptions_per_write=spent / count)


# A stock carrier has no keyslot (and no v3 record): refused unless initializing.
assert rejected(lambda: opened()).errno == errno.EKEYREJECTED
assert rejected(lambda: opened(format=4)).errno == errno.EKEYREJECTED
results['write_profile'] = [write_profile('v3'), write_profile('v4')]

# A/B slots: half capacity; a damaged newest slot falls back to the previous
# version, and the next write targets the damaged slot again.
v = opened(initialize=True, format=4, ab=True)
st, unit, sectors = status()
assert v['hidden_bytes'] == ((sectors - RESERVED) // GROUP // 2) * 512
first, second = bytes([0xa1]) * 512, bytes([0xb2]) * 512
direct(v['hidden'], 0, 512, first)     # initialization wrote gen1 to slot A: this is slot B gen2
direct(v['hidden'], 0, 512, second)    # slot A gen3
assert direct(v['hidden'], 0, 512) == second
close_blocks('/dev/vdb', KEY)
damage(RESERVED)                       # slot A (group 2) of block 0: the newest version
v = opened()                           # layout (A/B) comes from the keyslot
assert direct(v['hidden'], 0, 512) == first, 'A/B did not fall back to the previous version'
before = status()[0]['encryptions']
direct(v['hidden'], 0, 512, second)
assert status()[0]['encryptions'] - before == GROUP
assert direct(v['hidden'], 0, 512) == second
close_blocks('/dev/vdb', KEY)
v = opened()
assert direct(v['hidden'], 0, 512) == second
assert direct(v['hidden'], 512, 512) == bytes(512)

# Keyslots: add a key-file slot and a passphrase slot on the active owner,
# rewrite the whole keyslot/directory area through the decoy (fragment refresh
# must preserve every listed keyslot), then retire the original key.
second_key, passphrase = os.urandom(32), b'synthetic test passphrase'
scrypt_passphrase = b'synthetic scrypt passphrase'
keyslot('/dev/vdb', KEY, 1, second_key)
keyslot('/dev/vdb', KEY, 2, passphrase=passphrase)   # pivsetup derives the KEK (default Argon2id)
keyslot('/dev/vdb', KEY, 3, passphrase=scrypt_passphrase, kdf='scrypt')
# Independent Python KEKs (cryptography Argon2id, hashlib scrypt) must open the
# same slots: Rust/Python KDF parity on the real volume context.
from pivstore.blocks import base_identity, passphrase_kek
from pivstore.kernel_owner import GuestOwner as _Owner
owner = _Owner('/dev/vdb', KEY)
identity = base_identity(owner)
owner.close()
pass_kek = passphrase_kek(passphrase, identity)
scrypt_kek = passphrase_kek(scrypt_passphrase, identity, 'scrypt')
area = direct(v['decoy'], 0, RESERVED * unit)
direct(v['decoy'], 0, RESERVED * unit, area)
close_blocks('/dev/vdb', KEY)
for kw in (dict(), dict(key=second_key), dict(key=None, hidden_passphrase=passphrase), dict(key=pass_kek),
           dict(key=None, hidden_passphrase=scrypt_passphrase, kdf='scrypt'), dict(key=scrypt_kek)):
    v = opened(**kw)
    assert direct(v['hidden'], 0, 512) == second
    close_blocks('/dev/vdb', KEY)
# Nothing records the KDF: the wrong one derives an unrelated KEK.
assert rejected(lambda: opened(key=None, hidden_passphrase=scrypt_passphrase)).errno == errno.EKEYREJECTED
v = opened(key=second_key)
keyslot('/dev/vdb', KEY, 3)
close_blocks('/dev/vdb', KEY)
assert rejected(lambda: opened(key=None, hidden_passphrase=scrypt_passphrase, kdf='scrypt')).errno == errno.EKEYREJECTED
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
                           kdfs=dict(slot2='argon2id', slot3='scrypt'), python_kdf_cross_check=True,
                           wrong_kdf_rejected=True, decoy_rewrite_of_keyslot_area_preserved=True)
results['ab'] = dict(fallback_after_damaged_newest_slot=True, rewrite_encryptions=GROUP)

v = opened(initialize=True, format=4)
st, unit, sectors = status()
records = (sectors - RESERVED) // GROUP
assert v['hidden_bytes'] == st['hidden_bytes'] == records * 512, (v, records)
assert Path(v['hidden']).read_bytes() == bytes(records * 512)
results['records'] = records

# Hidden writes re-encode exactly one 90-fragment record.
pattern = {i: hashlib.shake_256(b'v4-%d' % i).digest(512) for i in (0, 1, records // 2, records - 1)}
for index, value in pattern.items():
    before = status()[0]['encryptions']
    direct(v['hidden'], index * 512, 512, value)
    assert status()[0]['encryptions'] - before == GROUP
for index, value in pattern.items():
    assert direct(v['hidden'], index * 512, 512) == value
hidden_before = Path(v['hidden']).read_bytes()

# Decoy writes re-randomize only the written primary sectors: one encryption per
# sector, independent of carrier groups (v3 refreshed 36/48-sector groups).
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
# invalid marker, no fabricated data); a full hidden write repairs it.
target = RESERVED
damage(target)
v = opened()
assert rejected(lambda: direct(v['hidden'], 0, 512)).errno == errno.EIO
assert direct(v['hidden'], 512, 512) == pattern[1]
block = direct(v['decoy'], target * unit, unit)
direct(v['decoy'], target * unit, unit, block)
assert rejected(lambda: direct(v['hidden'], 0, 512)).errno == errno.EIO
assert not status()[0]['failed'] and status()[0]['invalidations'] == 0
direct(v['hidden'], 0, 512, pattern[0])
assert Path(v['hidden']).read_bytes() == hidden_before
assert subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0] == primary_after

# Oracles, stock readback and a closed image for independent host decoding.
(W / 'expected-hidden-volume').write_bytes(hidden_before)
(W / 'expected-primary.sha256').write_text(primary_after + '\n')
close_blocks('/dev/vdb', KEY)
subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0] == primary_after
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'v4-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'v4-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Format v4 footprint, preservation, guard, local damage, repair and stock readback passed\n')
