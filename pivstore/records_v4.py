"""Format v4 (docs/format-v4.md): fragment-local re-randomization for 16-byte IVs.

Independent userspace reference/decoder for fragments, records (optionally A/B),
keyslots and the keyslot directory.
"""
import os
from pathlib import Path
import secrets
import struct
import tempfile

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .format import context_v4
from .profile import Image, UnsupportedImage

IV_BYTES = 16
RANDOM_BYTES = 10
FRAGMENT = IV_BYTES - RANDOM_BYTES          # 6 payload bytes per sector
DATA = 512
RECORD_PLAIN = 8 + DATA                     # generation || data
PAYLOAD = 16 + RECORD_PLAIN                 # tag || ciphertext = 536
GROUP = -(-PAYLOAD // FRAGMENT)             # 90 sectors per record
KEYSLOT_SECTORS = 14
KEYSLOT_AREA = 4 * 2 * KEYSLOT_SECTORS      # 112 sectors reserved for keyslots
DIRECTORY_GROUPS = 2
KEYSLOTS = 4
KEYSLOT_PLAIN = 64                          # version, flags, master key, reserved
KEYSLOT_PAYLOAD = 16 + KEYSLOT_PLAIN        # 80 bytes in 14 fragments (84)
FLAG_AB = 1


context = context_v4


def derive(key, salt, label):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'pivstore/v4/' + label).derive(key)


class Fragments:
    """LRW-AES tweakable PRP over 16-byte IVs, tweak = primary sector index."""

    def __init__(self, tweak_key, prp_key):
        self.tweak = Cipher(algorithms.AES(tweak_key), modes.ECB())
        self.prp = Cipher(algorithms.AES(prp_key), modes.ECB())

    def mask(self, sector):
        encryptor = self.tweak.encryptor()
        return encryptor.update(sector.to_bytes(16, 'little')) + encryptor.finalize()

    @staticmethod
    def xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def encode(self, sector, value):
        if len(value) != IV_BYTES:
            raise ValueError('Fragment input must be 16 bytes')
        delta = self.mask(sector)
        encryptor = self.prp.encryptor()
        return self.xor(encryptor.update(self.xor(value, delta)) + encryptor.finalize(), delta)

    def decode(self, sector, iv):
        delta = self.mask(sector)
        decryptor = self.prp.decryptor()
        return self.xor(decryptor.update(self.xor(iv, delta)) + decryptor.finalize(), delta)

    def refresh(self, sector, iv):
        """Decoy-write rule: keep the 6 payload bytes, replace the random bytes."""
        payload = self.decode(sector, iv)[RANDOM_BYTES:]
        while True:
            fresh = self.encode(sector, secrets.token_bytes(RANDOM_BYTES) + payload)
            if fresh != iv:
                return fresh


class RecordsV4:
    """Records in groups of 90 fragments after the keyslot area. Groups 0-1 are
    the (phase 2) directory. Without A/B block i uses group 2+i; with A/B it
    uses groups 2+2i (slot 0) and 3+2i (slot 1) and readers return the valid
    slot with the larger generation.
    """

    def __init__(self, sectors, identity, master_key, ab=False):
        if len(master_key) != 32:
            raise ValueError('Expected a 32-byte master key')
        self.identity = identity
        self.ab = ab
        self.fragments = Fragments(derive(master_key, identity, b'tweak'), derive(master_key, identity, b'prp'))
        self.mac_key = derive(master_key, identity, b'mac')
        self.enc_key = derive(master_key, identity, b'enc')
        groups = (sectors - KEYSLOT_AREA) // GROUP if sectors > KEYSLOT_AREA else 0
        usable = max(0, groups - DIRECTORY_GROUPS)
        self.count = usable // 2 if ab else usable
        if not self.count:
            raise ValueError('Volume too small for format v4')
        self.capacity = self.count * DATA

    def group_of(self, index, slot=0):
        if not 0 <= index < self.count or slot not in ((0, 1) if self.ab else (0,)):
            raise ValueError('Record outside carrier')
        return DIRECTORY_GROUPS + (2 * index + slot if self.ab else index)

    def first_sector(self, group):
        return KEYSLOT_AREA + group * GROUP

    def tag(self, group, plain):
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(self.identity + b'/record/' + struct.pack('<Q', group) + plain)
        return h.finalize()[:16]

    def stream(self, tag, value):
        encryptor = Cipher(algorithms.ChaCha20(self.enc_key, bytes(4) + tag[:12]), None).encryptor()
        return encryptor.update(value) + encryptor.finalize()

    def seal(self, group, data, generation):
        if len(data) != DATA:
            raise ValueError('Hidden writes must contain exactly 512 bytes')
        plain = struct.pack('<Q', generation) + data
        tag = self.tag(group, plain)
        return tag + self.stream(tag, plain) + bytes(GROUP * FRAGMENT - PAYLOAD)

    def open_group(self, group, ivs):
        """(generation, data) of one record group, or UnsupportedImage."""
        if len(ivs) != GROUP:
            raise UnsupportedImage('Invalid v4 carrier length')
        first = self.first_sector(group)
        payload = b''.join(self.fragments.decode(first + j, iv)[RANDOM_BYTES:] for j, iv in enumerate(ivs))
        if any(payload[PAYLOAD:]):
            raise UnsupportedImage('Hidden block unavailable: malformed record')
        tag = payload[:16]
        plain = self.stream(tag, payload[16:PAYLOAD])
        if not hmac_equal(self.tag(group, plain), tag):
            raise UnsupportedImage('Hidden block unavailable: absent, wrong key or damaged')
        return struct.unpack_from('<Q', plain)[0], plain[8:]

    def encode_group(self, group, data, generation=0, randoms=None):
        """Fresh IVs for every fragment of one record group (a hidden write)."""
        first = self.first_sector(group)
        value = self.seal(group, data, generation)
        if randoms is None:
            randoms = [secrets.token_bytes(RANDOM_BYTES) for _ in range(GROUP)]
        return [self.fragments.encode(first + j, randoms[j] + value[j * FRAGMENT:(j + 1) * FRAGMENT])
                for j in range(GROUP)]

    def encode(self, index, data, generation=0, randoms=None, slot=0):
        return self.encode_group(self.group_of(index, slot), data, generation, randoms)

    def decode_directory(self, ivs):
        """Newest valid of directory groups 0 and 1 (always an A/B pair)."""
        best = None
        for group in (0, 1):
            first = self.first_sector(group)
            try:
                found = self.open_group(group, ivs[first:first + GROUP])
            except UnsupportedImage:
                continue
            if best is None or found[0] > best[0]:
                best = found
        if best is None:
            raise UnsupportedImage('Keyslot directory unavailable')
        return best[1]

    def decode(self, index, ivs, ivs_b=None):
        """Data of block i; with A/B give both slots' carriers."""
        if not self.ab:
            return self.open_group(self.group_of(index), ivs)[1]
        best = None
        for slot, carrier in enumerate((ivs, ivs_b)):
            try:
                found = self.open_group(self.group_of(index, slot), carrier)
            except UnsupportedImage:
                continue
            if best is None or found[0] > best[0]:
                best = found
        if best is None:
            raise UnsupportedImage('Hidden block unavailable: no valid A/B slot')
        return best[1]


def hmac_equal(a, b):
    return secrets.compare_digest(a, b)


def decode_image(image, key, ab=False, keyslots=True):
    """All-or-error v4 extraction without the primary key; journal must be clean.

    With keyslots, @key is a KEK and the layout comes from the keyslot; without,
    @key is the master key itself (phase-1 volumes) and @ab gives the layout.
    """
    if keyslots:
        records, _directory, _slot, ivs = open_volume(image, key)
        ab = records.ab
    else:
        if image.layout.iv_bytes != IV_BYTES:
            raise UnsupportedImage('Format v4 requires 16-byte primary IVs')
        records = RecordsV4(image.layout.sectors, context(image.uuid, image.layout.primary_bytes,
                                                          image.layout.sector_size, ab), key, ab=ab)
        ivs = list(image.iv_slots())

    def carrier(group):
        first = records.first_sector(group)
        return ivs[first:first + GROUP]
    out = []
    for index in range(records.count):
        if ab:
            out.append(records.decode(index, carrier(records.group_of(index, 0)),
                                      carrier(records.group_of(index, 1))))
        else:
            out.append(records.decode(index, carrier(records.group_of(index))))
    return b''.join(out)


class Keyslot:
    """Keyslot j: SIV of (version, flags, MK) under keys derived from a KEK, in
    two 14-sector replicas at sectors (2j + replica) * 14. Its outer keys
    (tweak, prp) are what the directory records for decoy refresh.
    """

    def __init__(self, identity, kek, slot):
        if len(kek) != 32 or not 0 <= slot < KEYSLOTS:
            raise ValueError('Invalid keyslot key or index')
        self.identity, self.slot = identity, slot
        self.outer = (derive(kek, identity, b'keyslot-tweak'), derive(kek, identity, b'keyslot-prp'))
        self.fragments = Fragments(*self.outer)
        self.mac_key = derive(kek, identity, b'keyslot-mac')
        self.enc_key = derive(kek, identity, b'keyslot-enc')

    def first_sector(self, replica):
        return (2 * self.slot + replica) * KEYSLOT_SECTORS

    def tag(self, replica, plain):
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(self.identity + b'/keyslot/' + struct.pack('<Q', 2 * self.slot + replica) + plain)
        return h.finalize()[:16]

    def stream(self, tag, value):
        encryptor = Cipher(algorithms.ChaCha20(self.enc_key, bytes(4) + tag[:12]), None).encryptor()
        return encryptor.update(value) + encryptor.finalize()

    def encode(self, master_key, flags, replica, randoms=None):
        plain = struct.pack('<II', 4, flags) + master_key + bytes(24)
        tag = self.tag(replica, plain)
        payload = tag + self.stream(tag, plain) + bytes(KEYSLOT_SECTORS * FRAGMENT - KEYSLOT_PAYLOAD)
        first = self.first_sector(replica)
        if randoms is None:
            randoms = [secrets.token_bytes(RANDOM_BYTES) for _ in range(KEYSLOT_SECTORS)]
        return [self.fragments.encode(first + j, randoms[j] + payload[j * FRAGMENT:(j + 1) * FRAGMENT])
                for j in range(KEYSLOT_SECTORS)]

    def open(self, ivs, replica):
        """(flags, master_key) or UnsupportedImage."""
        first = self.first_sector(replica)
        payload = b''.join(self.fragments.decode(first + j, iv)[RANDOM_BYTES:] for j, iv in enumerate(ivs))
        if any(payload[KEYSLOT_PAYLOAD:]):
            raise UnsupportedImage('Keyslot unavailable')
        tag = payload[:16]
        plain = self.stream(tag, payload[16:KEYSLOT_PAYLOAD])
        if not hmac_equal(self.tag(replica, plain), tag):
            raise UnsupportedImage('Keyslot unavailable')
        version, flags = struct.unpack_from('<II', plain)
        if version != 4 or flags & ~FLAG_AB or any(plain[40:]):
            raise UnsupportedImage('Unsupported keyslot contents')
        return flags, plain[8:40]


def unlock(ivs, identity, kek):
    """Try every keyslot replica: (slot, flags, master_key) or UnsupportedImage."""
    for slot in range(KEYSLOTS):
        keyslot = Keyslot(identity, kek, slot)
        for replica in (0, 1):
            first = keyslot.first_sector(replica)
            try:
                return (slot,) + keyslot.open(ivs[first:first + KEYSLOT_SECTORS], replica)
            except UnsupportedImage:
                pass
    raise UnsupportedImage('No keyslot authenticates under this key')


def directory_data(outer_keys):
    """512-byte directory: per keyslot j, present byte || tweak key || prp key."""
    data = bytearray(DATA)
    for slot, keys in outer_keys.items():
        data[slot * 65] = 1
        data[slot * 65 + 1:slot * 65 + 65] = keys[0] + keys[1]
    return bytes(data)


def parse_directory(data):
    if any(data[KEYSLOTS * 65:]):
        raise UnsupportedImage('Malformed keyslot directory')
    found = {}
    for slot in range(KEYSLOTS):
        present = data[slot * 65]
        if present not in (0, 1) or (not present and any(data[slot * 65 + 1:slot * 65 + 65])):
            raise UnsupportedImage('Malformed keyslot directory')
        if present:
            found[slot] = (data[slot * 65 + 1:slot * 65 + 33], data[slot * 65 + 33:slot * 65 + 65])
    return found


def open_volume(image, kek):
    """Unlock a v4 image with a KEK: (records, directory, slot, ivs)."""
    if image.layout.iv_bytes != IV_BYTES:
        raise UnsupportedImage('Format v4 requires 16-byte primary IVs')
    ivs = list(image.iv_slots())
    base = context(image.uuid, image.layout.primary_bytes, image.layout.sector_size)
    slot, flags, master = unlock(ivs, base, kek)
    ab = bool(flags & FLAG_AB)
    records = RecordsV4(image.layout.sectors, context(image.uuid, image.layout.primary_bytes,
                                                      image.layout.sector_size, ab), master, ab=ab)
    directory = parse_directory(records.decode_directory(ivs))
    return records, directory, slot, ivs


def unpack(source, output, kek):
    """Open a keyslot with @kek, authenticate every hidden block and publish
    a new private output file only after success; no primary key is needed."""
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('Output must not exist')
    with Image(source) as image:
        payload = decode_image(image, kek)
        image.check_unchanged()
        fd, name = tempfile.mkstemp(prefix='.pivstore-', suffix='.partial', dir=output.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, output)
            temporary.unlink()
            directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return {'extracted_payload_bytes': len(payload)}
