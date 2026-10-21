"""The supported Linux primary-sector codec, retained for independent kernel verification."""

import struct

from cryptography.exceptions import InvalidTag


class SectorCodec:
    """Original AEGIS-128 (the only supported profile) via the pinned reference."""

    def __init__(self, key, sector_size=4096, encryption='aegis128-random'):
        if encryption != 'aegis128-random':
            raise ValueError('Unsupported primary cipher')
        self.iv_size = 16
        if len(key) != 16:
            raise ValueError('This profile requires a 16-byte primary volume key')
        if sector_size not in (512, 4096):
            raise ValueError('Unsupported primary sector size')
        self.sector_size = sector_size
        from .aegis_reference import AEGIS128Reference
        self.cipher = AEGIS128Reference(key)

    def decrypt(self, index, ciphertext, metadata):
        if len(ciphertext) != self.sector_size or len(metadata) != 16 + self.iv_size:
            raise ValueError('Invalid primary sector tuple size')
        iv = metadata[16:]
        try:
            return self.cipher.decrypt(iv, ciphertext + metadata[:16],
                                       struct.pack('<Q', index * (self.sector_size // 512)) + iv)
        except InvalidTag:
            # Import lazily to keep this codec independent of image ownership.
            from .profile import UnsupportedImage
            raise UnsupportedImage(f'Primary authentication failed at sector {index}') from None

    def encrypt(self, index, plaintext, iv):
        if len(plaintext) != self.sector_size or len(iv) != self.iv_size:
            raise ValueError('Invalid primary plaintext/IV size')
        encrypted = self.cipher.encrypt(iv, plaintext, struct.pack('<Q', index * (self.sector_size // 512)) + iv)
        return encrypted[:self.sector_size], encrypted[self.sector_size:] + iv
