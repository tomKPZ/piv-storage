"""Shared public volume context; no userspace crypto dependency at activation."""
import struct


# LUKS encryption name -> (LUKS integrity type, exact dm-crypt cipher spec).
# AEGIS-128 only: format v4 needs 16-byte IVs (the 12-byte-IV AES-GCM and
# ChaCha20-Poly1305 profiles were removed with format v3 on 2026-10-21).
PRIMARY_PROFILES = {
    'aegis128-random': ('aead', 'capi:aegis128-random'),
}


def context_v4(uuid, primary_bytes, sector_size, ab=False):
    """Format v4 public context (docs/format-v4.md); stdlib only.

    The A/B layout is part of the context, so every key differs between modes
    and opening a volume in the wrong mode fails the key guard instead of
    returning another group's data.
    """
    return (b'pivstore/volume/v4\0' + uuid.encode('ascii') + b'\0' +
            struct.pack('<QQ', primary_bytes, sector_size) + (b'/ab' if ab else b''))
