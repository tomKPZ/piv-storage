"""Shared public volume context; no userspace crypto dependency at activation."""
import struct


# (LUKS encryption, LUKS integrity type) -> (exact dm-crypt cipher spec, tag bytes).
# The two supported stock profiles whose random 16-byte IVs live in
# dm-integrity metadata, as format v4 requires: AEGIS-128 (default) and AES-XTS
# + HMAC-SHA256 (user decision 2026-10-22).
PRIMARY_PROFILES = {
    ('aegis128-random', 'aead'): ('capi:aegis128-random', 16),
    ('aes-xts-random', 'hmac(sha256)'): ('capi:authenc(hmac(sha256),xts(aes))-random', 32),
}


def context_v4(uuid, primary_bytes, sector_size, ab=False):
    """Format v4 public context (docs/format-v4.md); stdlib only.

    The A/B layout is part of the context, so every key differs between modes
    and opening a volume in the wrong mode fails the key guard instead of
    returning another group's data.
    """
    return (b'pivstore/volume/v4\0' + uuid.encode('ascii') + b'\0' +
            struct.pack('<QQ', primary_bytes, sector_size) + (b'/ab' if ab else b''))
