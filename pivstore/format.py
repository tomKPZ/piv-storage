"""Shared public volume context; no userspace crypto dependency at activation."""
import struct


# (LUKS encryption, LUKS integrity type) -> (exact dm-crypt cipher spec, tag bytes).
# The two supported stock profiles whose random 16-byte IVs live in
# dm-integrity metadata, as format v5 requires: AEGIS-128 (default) and AES-XTS
# + HMAC-SHA256 (user decision 2026-10-22).
PRIMARY_PROFILES = {
    ('aegis128-random', 'aead'): ('capi:aegis128-random', 16),
    ('aes-xts-random', 'hmac(sha256)'): ('capi:authenc(hmac(sha256),xts(aes))-random', 32),
}


BLOCK_LOG2 = 12                 # 4096-byte hidden blocks (the only v5 size)
RS_PARITIES = (0, 4, 8, 16)     # parity fragments per lane
KEYSLOT_VERSION = 5
FLAG_AB = 1


def base_context(uuid, primary_bytes, sector_size):
    """Format v5 base context (docs/format-v5.md); stdlib only. Salt of the
    keyslot keys and of the passphrase KEK. @uuid must already be the
    lower-case canonical 8-4-4-4-12 form (str(uuid.UUID(luksUUID)))."""
    return (b'pivstore/volume/v5\0' + uuid.encode('ascii') + b'\0' +
            struct.pack('<QQ', primary_bytes, sector_size))


def keyslot_parameters(ab=False, block_log2=BLOCK_LOG2, rs_parity=0):
    """The 32-byte keyslot parameter block (the keyslot plaintext without MK):
    LE32(version 5) || LE32(flags) || block_log2 || rs_parity || zero[22]."""
    return (struct.pack('<II', KEYSLOT_VERSION, FLAG_AB if ab else 0) +
            bytes([block_log2, rs_parity]) + bytes(22))


def layout_context(base, ab=False, block_log2=BLOCK_LOG2, rs_parity=0):
    """Record context: base || "/layout/" || the whole keyslot parameter block,
    so every record key differs between layouts, a volume opened with
    mismatched parameters fails the SIV check instead of returning another
    group's data, and any future record-affecting parameter is bound too.
    """
    if block_log2 != BLOCK_LOG2 or rs_parity not in RS_PARITIES:
        raise ValueError('Unsupported v5 layout')
    return base + b'/layout/' + keyslot_parameters(ab, block_log2, rs_parity)
