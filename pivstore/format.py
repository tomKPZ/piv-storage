"""Shared public volume context; no userspace crypto dependency at activation."""
import struct


# LUKS encryption name -> (LUKS integrity type, exact dm-crypt cipher spec).
PRIMARY_PROFILES = {
    'aes-gcm-random': ('aead', 'capi:gcm(aes)-random'),
    'aegis128-random': ('aead', 'capi:aegis128-random'),
    'chacha20-random': ('poly1305', 'capi:rfc7539(chacha20,poly1305)-random'),
}


def context(image):
    return (b'pivstore/volume/v3\0' + image.uuid.encode('ascii') + b'\0' +
            struct.pack('<QQ', image.layout.primary_bytes, image.layout.sector_size))


def context_v4(uuid, primary_bytes, sector_size, ab=False):
    """Format v4 public context (docs/format-v4.md); stdlib only for setup.

    The A/B layout is part of the context, so every key differs between modes
    and opening a volume in the wrong mode fails the key guard instead of
    returning another group's data.
    """
    return (b'pivstore/volume/v4\0' + uuid.encode('ascii') + b'\0' +
            struct.pack('<QQ', primary_bytes, sector_size) + (b'/ab' if ab else b''))
