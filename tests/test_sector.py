"""Primary AEAD selection and Linux address/IV authentication."""
import os
import unittest
from pivstore.profile import UnsupportedImage
from pivstore.sector import SectorCodec


class SectorTests(unittest.TestCase):
    def test_both_ciphers_sector_sizes_and_authenticated_inputs(self):
        key = bytes(range(32))
        iv = bytes(range(12))
        for size in (512, 4096):
            for cipher, other in (('aes-gcm-random', 'chacha20-random'),
                                   ('chacha20-random', 'aes-gcm-random')):
                with self.subTest(size=size, cipher=cipher):
                    codec = SectorCodec(key, size, cipher)
                    plaintext = bytes(range(256)) * (size // 256)
                    ciphertext, metadata = codec.encrypt(17, plaintext, iv)
                    self.assertEqual((len(ciphertext), len(metadata)), (size, 28))
                    self.assertEqual(codec.decrypt(17, ciphertext, metadata), plaintext)
                    for selected, index, ct, tag in (
                            (codec, 18, ciphertext, metadata),
                            (SectorCodec(bytes(32), size, cipher), 17, ciphertext, metadata),
                            (SectorCodec(key, size, other), 17, ciphertext, metadata),
                            (codec, 17, bytes([ciphertext[0] ^ 1]) + ciphertext[1:], metadata),
                            (codec, 17, ciphertext, bytes([metadata[0] ^ 1]) + metadata[1:]),
                            (codec, 17, ciphertext, metadata[:-1] + bytes([metadata[-1] ^ 1]))):
                        with self.assertRaises(UnsupportedImage):
                            selected.decrypt(index, ct, tag)

    def test_unknown_primary_cipher_has_no_fallback(self):
        with self.assertRaises(ValueError):
            SectorCodec(bytes(32), 512, 'unknown')

    @unittest.skipUnless(os.environ.get('PIV_AEGIS_REFERENCE'), 'build pinned AEGIS-128 diagnostic reference')
    def test_original_aegis128_authenticated_inputs(self):
        for size in (512, 4096):
            codec = SectorCodec(bytes(range(16)), size, 'aegis128-random')
            iv = bytes(range(16))
            plain = bytes(size)
            ct, metadata = codec.encrypt(17, plain, iv)
            self.assertEqual((len(ct), len(metadata)), (size, 32))
            self.assertEqual(codec.decrypt(17, ct, metadata), plain)
            for index, ciphertext, tag in ((18, ct, metadata),
                    (17, bytes([ct[0] ^ 1]) + ct[1:], metadata),
                    (17, ct, bytes([metadata[0] ^ 1]) + metadata[1:]),
                    (17, ct, metadata[:-1] + bytes([metadata[-1] ^ 1]))):
                with self.assertRaises(UnsupportedImage): codec.decrypt(index, ciphertext, tag)
            with self.assertRaises(UnsupportedImage):
                SectorCodec(bytes(16), size, 'aegis128-random').decrypt(17, ct, metadata)
        with self.assertRaises(ValueError): SectorCodec(bytes(32), 512, 'aegis128-random')
