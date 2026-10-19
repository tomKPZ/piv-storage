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
