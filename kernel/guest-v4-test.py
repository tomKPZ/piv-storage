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
    """One uncoordinated stock dm-crypt rewrite of @sector (same plaintext, fresh IV)."""
    unit = json.loads(subprocess.check_output(['cryptsetup', 'luksDump', '--dump-json-metadata', '/dev/vdb'],
                                              text=True))['segments']['0']['sector_size']
    stock_rewrite('/dev/vdb', KEY, sector, unit)

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



def write_profile(count=48):
    """Direct 4 KiB O_DSYNC decoy writes at pseudo-random aligned offsets:
    elapsed time and exact primary encryptions (TCG timings are diagnostic)."""
    import random, time
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
    return dict(format='v4', writes=count, bytes_each=4096, seconds=round(elapsed, 3),
                encryptions=spent, encryptions_per_write=spent / count)


# A stock carrier has no keyslot: refused unless initializing.
assert rejected(lambda: opened()).errno == errno.EKEYREJECTED
results['write_profile'] = [write_profile()]

# A/B slots: half capacity; a damaged newest slot falls back to the previous
# version, and the next write targets the damaged slot again.
v = opened(initialize=True, ab=True)
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

v = opened(initialize=True)
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
# invalid marker, no fabricated data); a full hidden write repairs it.
target = RESERVED
damage(target)
v = opened()
assert rejected(lambda: direct(v['hidden'], 0, 512)).errno == errno.EIO
assert direct(v['hidden'], 512, 512) == pattern[1]
block = direct(v['decoy'], target * unit, unit)
direct(v['decoy'], target * unit, unit, block)
assert rejected(lambda: direct(v['hidden'], 0, 512)).errno == errno.EIO
assert not status()[0]['failed']
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
