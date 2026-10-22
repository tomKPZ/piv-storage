"""Shared public volume context; no userspace crypto dependency at activation."""
import struct


# (LUKS encryption, LUKS integrity type) -> (exact dm-crypt cipher spec, tag bytes).
# Stock profiles whose random 16-byte IVs live in dm-integrity metadata, as
# format v4 requires: AEGIS-128 (default) and XTS + HMAC authenc (user decision
# 2026-10-22). 12-byte-IV AES-GCM/ChaCha20-Poly1305 cannot carry format v4.
PRIMARY_PROFILES = {('aegis128-random', 'aead'): ('capi:aegis128-random', 16)}
for _cipher in ('aes', 'serpent', 'twofish'):
    for _hash, _tag in (('sha1', 20), ('sha256', 32), ('sha512', 64)):
        PRIMARY_PROFILES[(f'{_cipher}-xts-random', f'hmac({_hash})')] = (
            f'capi:authenc(hmac({_hash}),xts({_cipher}))-random', _tag)


def context_v4(uuid, primary_bytes, sector_size, ab=False):
    """Format v4 public context (docs/format-v4.md); stdlib only.

    The A/B layout is part of the context, so every key differs between modes
    and opening a volume in the wrong mode fails the key guard instead of
    returning another group's data.
    """
    return (b'pivstore/volume/v4\0' + uuid.encode('ascii') + b'\0' +
            struct.pack('<QQ', primary_bytes, sector_size) + (b'/ab' if ab else b''))
