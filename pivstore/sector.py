"""The supported Linux primary-sector codec, retained for independent kernel verification."""

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


class SectorCodec:
    def __init__(self, key, sector_size=4096, encryption='aes-gcm-random'):
        if len(key) != 32:
            raise ValueError('This profile requires a 32-byte primary volume key')
        if sector_size not in (512, 4096):
            raise ValueError('Unsupported primary sector size')
        self.sector_size = sector_size
        algorithms = {'aes-gcm-random': AESGCM, 'chacha20-random': ChaCha20Poly1305}
        if encryption not in algorithms:
            raise ValueError('Unsupported primary cipher')
        self.cipher = algorithms[encryption](key)

    def decrypt(self, index, ciphertext, metadata):
        if len(ciphertext) != self.sector_size or len(metadata) != 28:
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
        if len(plaintext) != self.sector_size or len(iv) != 12:
            raise ValueError('Invalid primary plaintext/IV size')
        encrypted = self.cipher.encrypt(iv, plaintext, struct.pack('<Q', index * (self.sector_size // 512)) + iv)
        return encrypted[:self.sector_size], encrypted[self.sector_size:] + iv
