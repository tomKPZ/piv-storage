"""The supported Linux primary-sector codecs, retained for independent kernel verification.

AEGIS-128 (via the pinned reference) and dm-crypt's XTS + HMAC authenc
profiles: tag = HMAC(mac_key, LE64(sector512) || IV || ciphertext) truncated to
the digest size, ciphertext = XTS(enc_key, tweak = IV). The LUKS volume key is
enc_key || mac_key (dm-crypt's default MAC key size is the digest size).
AES-XTS decrypts through cryptography; Serpent/Twofish-XTS have no maintained
Python implementation here, so those profiles are authenticated (HMAC) but not
decrypted on the host; their plaintext is checked by stock dm-crypt in guests.
"""

import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidTag

HASHES = {'hmac(sha1)': ('sha1', 20), 'hmac(sha256)': ('sha256', 32), 'hmac(sha512)': ('sha512', 64)}
XTS_CIPHERS = ('aes-xts-random', 'serpent-xts-random', 'twofish-xts-random')


def _failed(index):
    # Import lazily to keep this codec independent of image ownership.
    from .profile import UnsupportedImage
    return UnsupportedImage(f'Primary authentication failed at sector {index}')


class SectorCodec:
    def __init__(self, key, sector_size=4096, encryption='aegis128-random', integrity='aead'):
        if sector_size not in (512, 4096):
            raise ValueError('Unsupported primary sector size')
        self.sector_size = sector_size
        self.iv_size = 16
        self.encryption = encryption
        if encryption == 'aegis128-random' and integrity == 'aead':
            if len(key) != 16:
                raise ValueError('This profile requires a 16-byte primary volume key')
            from .aegis_reference import AEGIS128Reference
            self.tag_size = 16
            self.cipher = AEGIS128Reference(key)
        elif encryption in XTS_CIPHERS and integrity in HASHES:
            self.hash, self.tag_size = HASHES[integrity]
            if len(key) - self.tag_size not in (32, 64):
                raise ValueError('Unexpected XTS + HMAC volume key size')
            self.enc_key, self.mac_key = key[:-self.tag_size], key[-self.tag_size:]
        else:
            raise ValueError('Unsupported primary cipher')

    @property
    def decrypts(self):
        """False for profiles authenticated but not decrypted on the host."""
        return self.encryption in ('aegis128-random', 'aes-xts-random')

    def _aad(self, index, iv):
        return struct.pack('<Q', index * (self.sector_size // 512)) + iv

    def _xts(self, iv, data, encrypt):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        if self.encryption != 'aes-xts-random':
            raise NotImplementedError(f'{self.encryption} has no host implementation')
        cipher = Cipher(algorithms.AES(self.enc_key), modes.XTS(iv))
        op = cipher.encryptor() if encrypt else cipher.decryptor()
        return op.update(data) + op.finalize()

    def authenticate(self, index, ciphertext, metadata):
        """Check the tag only; returns the IV. Raises UnsupportedImage on failure."""
        if len(ciphertext) != self.sector_size or len(metadata) != self.tag_size + self.iv_size:
            raise ValueError('Invalid primary sector tuple size')
        tag, iv = metadata[:self.tag_size], metadata[self.tag_size:]
        if self.tag_size == 16 and self.encryption == 'aegis128-random':
            self.decrypt(index, ciphertext, metadata)
            return iv
        expected = hmac.new(self.mac_key, self._aad(index, iv) + ciphertext, self.hash).digest()
        if not hmac.compare_digest(expected[:self.tag_size], tag):
            raise _failed(index)
        return iv

    def decrypt(self, index, ciphertext, metadata):
        if len(ciphertext) != self.sector_size or len(metadata) != self.tag_size + self.iv_size:
            raise ValueError('Invalid primary sector tuple size')
        tag, iv = metadata[:self.tag_size], metadata[self.tag_size:]
        if self.encryption == 'aegis128-random':
            try:
                return self.cipher.decrypt(iv, ciphertext + tag, self._aad(index, iv))
            except InvalidTag:
                raise _failed(index) from None
        self.authenticate(index, ciphertext, metadata)
        return self._xts(iv, ciphertext, False)

    def encrypt(self, index, plaintext, iv):
        if len(plaintext) != self.sector_size or len(iv) != self.iv_size:
            raise ValueError('Invalid primary plaintext/IV size')
        if self.encryption == 'aegis128-random':
            encrypted = self.cipher.encrypt(iv, plaintext, self._aad(index, iv))
            return encrypted[:self.sector_size], encrypted[self.sector_size:] + iv
        ciphertext = self._xts(iv, plaintext, True)
        tag = hmac.new(self.mac_key, self._aad(index, iv) + ciphertext, self.hash).digest()[:self.tag_size]
        return ciphertext, tag + iv
