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


class XtsHmacTests(unittest.TestCase):
    def test_authenc_layout_round_trip_and_rejections(self):
        import hashlib, hmac, struct
        for integrity, tag in (('hmac(sha256)', 32),):
            for enc in (32, 64):
                for size in (512, 4096):
                    key = bytes(range(enc + tag))
                    codec = SectorCodec(key, size, 'aes-xts-random', integrity)
                    iv, plain = bytes(range(16, 32)), bytes(range(256)) * (size // 256)
                    ct, metadata = codec.encrypt(9, plain, iv)
                    # dm-crypt authenc: HMAC(mac key, LE64(sector512) || IV || ciphertext).
                    mac = hmac.new(key[enc:], struct.pack('<Q', 9 * (size // 512)) + iv + ct,
                                   integrity[5:-1]).digest()
                    self.assertEqual(metadata, mac[:tag] + iv)
                    self.assertEqual(codec.decrypt(9, ct, metadata), plain)
                    for index, c, m in ((10, ct, metadata), (9, bytes([ct[0] ^ 1]) + ct[1:], metadata),
                                        (9, ct, bytes([metadata[0] ^ 1]) + metadata[1:]),
                                        (9, ct, metadata[:-1] + bytes([metadata[-1] ^ 1]))):
                        with self.subTest(integrity=integrity, enc=enc, size=size, index=index), \
                                self.assertRaises(UnsupportedImage):
                            codec.decrypt(index, c, m)

    def test_dropped_profiles_and_bad_keys_rejected(self):
        for cipher, integrity in (('serpent-xts-random', 'hmac(sha256)'), ('twofish-xts-random', 'hmac(sha256)'),
                                  ('aes-xts-random', 'hmac(sha1)'), ('aes-xts-random', 'hmac(sha512)')):
            with self.subTest(cipher=cipher, integrity=integrity), self.assertRaises(ValueError):
                SectorCodec(bytes(96), 512, cipher, integrity)
        with self.assertRaises(ValueError):
            SectorCodec(bytes(70), 512, 'aes-xts-random', 'hmac(sha256)')
        with self.assertRaises(ValueError):
            SectorCodec(bytes(96), 512, 'aes-xts-random', 'aead')
