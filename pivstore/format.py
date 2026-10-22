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


def base_context(uuid, primary_bytes, sector_size):
    """Format v5 base context (docs/format-v5.md); stdlib only. Salt of the
    keyslot keys and of the passphrase KEK."""
    return (b'pivstore/volume/v5\0' + uuid.encode('ascii') + b'\0' +
            struct.pack('<QQ', primary_bytes, sector_size))


def layout_context(base, ab=False, block_log2=BLOCK_LOG2, rs_parity=0):
    """Record context: the layout parameters are part of it, so every record
    key differs between layouts and a volume opened with mismatched
    parameters fails the SIV check instead of returning another group's data.
    """
    if block_log2 != BLOCK_LOG2 or rs_parity not in RS_PARITIES:
        raise ValueError('Unsupported v5 layout')
    return base + b'/layout/' + bytes([int(bool(ab)), block_log2, rs_parity])
