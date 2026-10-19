"""The supported Linux primary-sector codec, retained for independent kernel verification."""

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SectorCodec:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError('This profile requires a 32-byte primary volume key')
        self.cipher = AESGCM(key)

    def decrypt(self, index, ciphertext, metadata):
        if len(ciphertext) != 4096 or len(metadata) != 28:
            raise ValueError('Invalid primary sector tuple size')
        iv = metadata[16:]
        try:
            return self.cipher.decrypt(iv, ciphertext + metadata[:16],
                                       struct.pack('<Q', index * 8) + iv)
        except InvalidTag:
            # Import lazily to keep this codec independent of image ownership.
            from .profile import UnsupportedImage
            raise UnsupportedImage(f'Primary authentication failed at sector {index}') from None

    def encrypt(self, index, plaintext, iv):
        if len(plaintext) != 4096 or len(iv) != 12:
            raise ValueError('Invalid primary plaintext/IV size')
        encrypted = self.cipher.encrypt(iv, plaintext, struct.pack('<Q', index * 8) + iv)
        return encrypted[:4096], encrypted[4096:] + iv
