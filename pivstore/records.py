"""Format v5 (docs/format-v5.md): fragment-local re-randomization for 16-byte IVs.

Independent userspace reference/decoder for fragments, 4 KiB records
(optionally A/B, optionally with Reed–Solomon parity), keyslots and the keyslot
directory. The kernel module (kernel/piv-native.inc) is the only writer.
"""
import os
from pathlib import Path
import secrets
import struct
import tempfile

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import rs
from .format import BLOCK_LOG2, RS_PARITIES, base_context, layout_context
from .profile import Image, UnsupportedImage

IV_BYTES = 16
RANDOM_BYTES = 10
FRAGMENT = IV_BYTES - RANDOM_BYTES          # 6 payload bytes per sector
DATA = 1 << BLOCK_LOG2                      # 4096-byte hidden blocks
RECORD_PLAIN = 8 + DATA                     # generation || data
PAYLOAD = 16 + RECORD_PLAIN                 # tag || ciphertext = 4120
DATA_FRAGMENTS = -(-PAYLOAD // FRAGMENT)    # 687 (2 zero padding bytes)
LANES = 3                                   # RS lanes by fragment index mod 3
LANE_DATA = DATA_FRAGMENTS // LANES         # 229 data fragments per lane
KEYSLOT_SECTORS = 14
KEYSLOT_AREA = 4 * 2 * KEYSLOT_SECTORS      # 112 sectors reserved for keyslots
DIRECTORY_GROUPS = 2
KEYSLOTS = 4
KEYSLOT_PLAIN = 64                          # version, flags, MK, parameters, reserved
KEYSLOT_PAYLOAD = 16 + KEYSLOT_PLAIN        # 80 bytes in 14 fragments (84)
KEYSLOT_VERSION = 5
FLAG_AB = 1
DIRECTORY_ENTRY = 65                        # present || outer tweak key || outer prp key

assert DATA_FRAGMENTS == LANES * LANE_DATA == 687


def group_sectors(rs_parity=0):
    """G = 687 + 3p primary sectors per record."""
    if rs_parity not in RS_PARITIES:
        raise ValueError('Unsupported parity')
    return DATA_FRAGMENTS + LANES * rs_parity


def block_count(sectors, ab=False, rs_parity=0):
    """Hidden 4096-byte blocks: floor((N - 112) / G) - 2, halved with A/B."""
    groups = (sectors - KEYSLOT_AREA) // group_sectors(rs_parity) if sectors > KEYSLOT_AREA else 0
    usable = max(0, groups - DIRECTORY_GROUPS)
    return usable // 2 if ab else usable


def derive(key, salt, label):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'pivstore/v5/' + label).derive(key)


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


def parity_fragments(payload, rs_parity):
    """3p parity fragments for the 687 data fragments of @payload (4122 bytes).

    Lane l holds data fragments j = 3i + l (i < 229) and parity fragment i at
    fragment index 687 + 3i + l. Byte position b (0-5) of the lane's fragments
    is one systematic RS(229 + p, 229) codeword.
    """
    if len(payload) != DATA_FRAGMENTS * FRAGMENT:
        raise ValueError('Invalid record payload length')
    out = bytearray(LANES * rs_parity * FRAGMENT)
    for lane in range(LANES):
        for b in range(FRAGMENT):
            data = [payload[(LANES * i + lane) * FRAGMENT + b] for i in range(LANE_DATA)]
            for i, symbol in enumerate(rs.encode(data, rs_parity)):
                out[(LANES * i + lane) * FRAGMENT + b] = symbol
    return bytes(out)


def correct_fragments(fragments, rs_parity, erasures=()):
    """RS errors-and-erasures decoding of G fragments (687 data + 3p parity).

    @erasures are fragment indices (sectors failing primary authentication or
    unreadable). Returns the corrected 687 data fragments, or raises
    rs.DecodeError. Never authenticates: only the SIV tag accepts the result.
    """
    group = group_sectors(rs_parity)
    if len(fragments) != group * FRAGMENT or not rs_parity:
        raise ValueError('Invalid record fragments')
    out = bytearray(fragments[:DATA_FRAGMENTS * FRAGMENT])
    for lane in range(LANES):
        indices = ([LANES * i + lane for i in range(LANE_DATA)] +
                   [DATA_FRAGMENTS + LANES * i + lane for i in range(rs_parity)])
        lost = [position for position, j in enumerate(indices) if j in set(erasures)]
        for b in range(FRAGMENT):
            word = rs.decode([fragments[j * FRAGMENT + b] for j in indices], rs_parity, lost)
            for position in range(LANE_DATA):
                out[indices[position] * FRAGMENT + b] = word[position]
    return bytes(out)


class Records:
    """4 KiB records in groups of G = 687 + 3p fragments after the keyslot area.

    Groups 0-1 are the keyslot directory (an A/B pair). Without A/B block i
    uses group 2+i; with A/B it uses groups 2+2i (slot 0) and 3+2i (slot 1)
    and readers return the valid slot with the larger generation.
    """

    def __init__(self, sectors, base, master_key, ab=False, rs_parity=0):
        if len(master_key) != 32:
            raise ValueError('Expected a 32-byte master key')
        self.base = base
        self.identity = layout_context(base, ab, BLOCK_LOG2, rs_parity)
        self.ab = ab
        self.rs_parity = rs_parity
        self.group = group_sectors(rs_parity)
        self.fragments = Fragments(derive(master_key, self.identity, b'tweak'),
                                   derive(master_key, self.identity, b'prp'))
        self.mac_key = derive(master_key, self.identity, b'mac')
        self.enc_key = derive(master_key, self.identity, b'enc')
        self.count = block_count(sectors, ab, rs_parity)
        if not self.count:
            raise ValueError('Volume too small for format v5')
        self.capacity = self.count * DATA

    def group_of(self, index, slot=0):
        if not 0 <= index < self.count or slot not in ((0, 1) if self.ab else (0,)):
            raise ValueError('Record outside carrier')
        return DIRECTORY_GROUPS + (2 * index + slot if self.ab else index)

    def first_sector(self, group):
        return KEYSLOT_AREA + group * self.group

    def area_end(self):
        """First sector after the last record group (start of the tail)."""
        return self.first_sector(DIRECTORY_GROUPS + (2 * self.count if self.ab else self.count))

    def tag(self, group, plain):
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(self.identity + b'/record/' + struct.pack('<Q', group) + plain)
        return h.finalize()[:16]

    def stream(self, tag, value):
        encryptor = Cipher(algorithms.ChaCha20(self.enc_key, bytes(4) + tag[:12]), None).encryptor()
        return encryptor.update(value) + encryptor.finalize()

    def seal(self, group, data, generation):
        """G fragments' payload bytes: SIV payload, zero padding, then parity."""
        if len(data) != DATA:
            raise ValueError('Hidden writes must contain exactly 4096 bytes')
        plain = struct.pack('<Q', generation) + data
        tag = self.tag(group, plain)
        payload = tag + self.stream(tag, plain) + bytes(DATA_FRAGMENTS * FRAGMENT - PAYLOAD)
        if self.rs_parity:
            payload += parity_fragments(payload, self.rs_parity)
        return payload

    def _open_payload(self, group, payload):
        if any(payload[PAYLOAD:DATA_FRAGMENTS * FRAGMENT]):
            raise UnsupportedImage('Hidden block unavailable: malformed record')
        tag = payload[:16]
        plain = self.stream(tag, payload[16:PAYLOAD])
        if not hmac_equal(self.tag(group, plain), tag):
            raise UnsupportedImage('Hidden block unavailable: absent, wrong key or damaged')
        return struct.unpack_from('<Q', plain)[0], plain[8:]

    def open_group(self, group, ivs, erasures=(), strict=False):
        """(generation, data) of one record group, or UnsupportedImage.

        Fast path: SIV-open the data fragments. With parity, on failure the
        fragments are RS-corrected (@erasures: carrier offsets known to be bad;
        errors-only without) and SIV-opened again; only a valid tag accepts.
        @strict (host checks of writer output) additionally requires the
        stored parity fragments to equal the reference encoder's.
        """
        if len(ivs) != self.group:
            raise UnsupportedImage('Invalid v5 carrier length')
        first = self.first_sector(group)
        fragments = b''.join(self.fragments.decode(first + j, iv)[RANDOM_BYTES:] for j, iv in enumerate(ivs))
        try:
            found = self._open_payload(group, fragments[:DATA_FRAGMENTS * FRAGMENT])
        except UnsupportedImage:
            if not self.rs_parity or strict:
                raise
        else:
            if strict and self.rs_parity and (fragments[DATA_FRAGMENTS * FRAGMENT:] !=
                                              parity_fragments(fragments[:DATA_FRAGMENTS * FRAGMENT],
                                                               self.rs_parity)):
                raise UnsupportedImage('Stored parity differs from the reference encoder')
            return found
        try:
            corrected = correct_fragments(fragments, self.rs_parity, erasures)
        except rs.DecodeError:
            raise UnsupportedImage('Hidden block unavailable: beyond parity') from None
        return self._open_payload(group, corrected)

    def encode_group(self, group, data, generation=0, randoms=None):
        """Fresh IVs for every fragment of one record group (a hidden write)."""
        first = self.first_sector(group)
        value = self.seal(group, data, generation)
        if randoms is None:
            randoms = [secrets.token_bytes(RANDOM_BYTES) for _ in range(self.group)]
        return [self.fragments.encode(first + j, randoms[j] + value[j * FRAGMENT:(j + 1) * FRAGMENT])
                for j in range(self.group)]

    def encode(self, index, data, generation=0, randoms=None, slot=0):
        return self.encode_group(self.group_of(index, slot), data, generation, randoms)

    def decode_directory(self, ivs, strict=False):
        """Newest valid of directory groups 0 and 1 (always an A/B pair)."""
        best = None
        for group in (0, 1):
            first = self.first_sector(group)
            try:
                found = self.open_group(group, ivs[first:first + self.group], strict=strict)
            except UnsupportedImage:
                continue
            if best is None or found[0] > best[0]:
                best = found
        if best is None:
            raise UnsupportedImage('Keyslot directory unavailable')
        return best[1]

    def decode(self, index, ivs, ivs_b=None, strict=False):
        """Data of block i; with A/B give both slots' carriers."""
        if not self.ab:
            return self.open_group(self.group_of(index), ivs, strict=strict)[1]
        best = None
        for slot, carrier in enumerate((ivs, ivs_b)):
            try:
                found = self.open_group(self.group_of(index, slot), carrier, strict=strict)
            except UnsupportedImage:
                continue
            if best is None or found[0] > best[0]:
                best = found
        if best is None:
            raise UnsupportedImage('Hidden block unavailable: no valid A/B slot')
        return best[1]


def hmac_equal(a, b):
    return secrets.compare_digest(a, b)


def decode_image(image, kek, strict=False):
    """All-or-error v5 extraction with a keyslot KEK, without the primary key;
    the layout comes from the keyslot and the journal must be clean. @strict:
    see Records.open_group (also applied to the directory)."""
    records, _directory, _slot, ivs = open_volume(image, kek, strict)

    def carrier(group):
        first = records.first_sector(group)
        return ivs[first:first + records.group]
    out = []
    for index in range(records.count):
        if records.ab:
            out.append(records.decode(index, carrier(records.group_of(index, 0)),
                                      carrier(records.group_of(index, 1)), strict=strict))
        else:
            out.append(records.decode(index, carrier(records.group_of(index)), strict=strict))
    return b''.join(out)


class Keyslot:
    """Keyslot j: SIV of (version, flags, MK, layout parameters) under keys
    derived from a KEK, in two 14-sector replicas at sectors (2j + replica) * 14.
    Its outer keys (tweak, prp) are what the directory records for decoy refresh.
    """

    def __init__(self, base, kek, slot):
        if len(kek) != 32 or not 0 <= slot < KEYSLOTS:
            raise ValueError('Invalid keyslot key or index')
        self.identity, self.slot = base, slot
        self.outer = (derive(kek, base, b'keyslot-tweak'), derive(kek, base, b'keyslot-prp'))
        self.fragments = Fragments(*self.outer)
        self.mac_key = derive(kek, base, b'keyslot-mac')
        self.enc_key = derive(kek, base, b'keyslot-enc')

    def first_sector(self, replica):
        return (2 * self.slot + replica) * KEYSLOT_SECTORS

    def tag(self, replica, plain):
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(self.identity + b'/keyslot/' + struct.pack('<Q', 2 * self.slot + replica) + plain)
        return h.finalize()[:16]

    def stream(self, tag, value):
        encryptor = Cipher(algorithms.ChaCha20(self.enc_key, bytes(4) + tag[:12]), None).encryptor()
        return encryptor.update(value) + encryptor.finalize()

    @staticmethod
    def plain(master_key, flags, rs_parity=0, block_log2=BLOCK_LOG2):
        """LE32(5) || LE32(flags) || MK[32] || block_log2 || rs_parity || zero[22]."""
        return struct.pack('<II', KEYSLOT_VERSION, flags) + master_key + bytes([block_log2, rs_parity]) + bytes(22)

    def encode(self, master_key, flags, replica, randoms=None, rs_parity=0, plain=None):
        if plain is None:
            plain = self.plain(master_key, flags, rs_parity)
        tag = self.tag(replica, plain)
        payload = tag + self.stream(tag, plain) + bytes(KEYSLOT_SECTORS * FRAGMENT - KEYSLOT_PAYLOAD)
        first = self.first_sector(replica)
        if randoms is None:
            randoms = [secrets.token_bytes(RANDOM_BYTES) for _ in range(KEYSLOT_SECTORS)]
        return [self.fragments.encode(first + j, randoms[j] + payload[j * FRAGMENT:(j + 1) * FRAGMENT])
                for j in range(KEYSLOT_SECTORS)]

    def open(self, ivs, replica):
        """(flags, master_key, rs_parity) or UnsupportedImage."""
        first = self.first_sector(replica)
        payload = b''.join(self.fragments.decode(first + j, iv)[RANDOM_BYTES:] for j, iv in enumerate(ivs))
        if any(payload[KEYSLOT_PAYLOAD:]):
            raise UnsupportedImage('Keyslot unavailable')
        tag = payload[:16]
        plain = self.stream(tag, payload[16:KEYSLOT_PAYLOAD])
        if not hmac_equal(self.tag(replica, plain), tag):
            raise UnsupportedImage('Keyslot unavailable')
        version, flags = struct.unpack_from('<II', plain)
        block_log2, rs_parity = plain[40], plain[41]
        if (version != KEYSLOT_VERSION or flags & ~FLAG_AB or block_log2 != BLOCK_LOG2 or
                rs_parity not in RS_PARITIES or any(plain[42:])):
            raise UnsupportedImage('Unsupported keyslot contents')
        return flags, plain[8:40], rs_parity


def unlock(ivs, base, kek):
    """Try every keyslot replica: (slot, flags, master_key, rs_parity) or UnsupportedImage."""
    for slot in range(KEYSLOTS):
        keyslot = Keyslot(base, kek, slot)
        for replica in (0, 1):
            first = keyslot.first_sector(replica)
            try:
                return (slot,) + keyslot.open(ivs[first:first + KEYSLOT_SECTORS], replica)
            except UnsupportedImage:
                pass
    raise UnsupportedImage('No keyslot authenticates under this key')


def directory_data(outer_keys):
    """4096-byte directory: per keyslot j, present byte || tweak key || prp key."""
    data = bytearray(DATA)
    for slot, keys in outer_keys.items():
        data[slot * DIRECTORY_ENTRY] = 1
        data[slot * DIRECTORY_ENTRY + 1:(slot + 1) * DIRECTORY_ENTRY] = keys[0] + keys[1]
    return bytes(data)


def parse_directory(data):
    if len(data) != DATA or any(data[KEYSLOTS * DIRECTORY_ENTRY:]):
        raise UnsupportedImage('Malformed keyslot directory')
    found = {}
    for slot in range(KEYSLOTS):
        entry = data[slot * DIRECTORY_ENTRY:(slot + 1) * DIRECTORY_ENTRY]
        if entry[0] not in (0, 1) or (not entry[0] and any(entry[1:])):
            raise UnsupportedImage('Malformed keyslot directory')
        if entry[0]:
            found[slot] = (entry[1:33], entry[33:65])
    return found


def open_volume(image, kek, strict=False):
    """Unlock a v5 image with a KEK: (records, directory, slot, ivs)."""
    if image.layout.iv_bytes != IV_BYTES:
        raise UnsupportedImage('Format v5 requires 16-byte primary IVs')
    ivs = list(image.iv_slots())
    base = base_context(image.uuid, image.layout.primary_bytes, image.layout.sector_size)
    slot, flags, master, rs_parity = unlock(ivs, base, kek)
    records = Records(image.layout.sectors, base, master, ab=bool(flags & FLAG_AB), rs_parity=rs_parity)
    directory = parse_directory(records.decode_directory(ivs, strict))
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
