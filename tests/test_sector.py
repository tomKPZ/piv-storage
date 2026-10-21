"""Primary AEGIS-128 selection and Linux address/IV authentication."""
import os
import unittest
from pivstore.profile import UnsupportedImage
from pivstore.sector import SectorCodec


class SectorTests(unittest.TestCase):
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
