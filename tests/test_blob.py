import os
import unittest

from pivstore.blob import decode, encode
from pivstore.profile import UnsupportedImage


class BlobCodecTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.aad = b'test-context'

    def test_empty_maximum_and_repeated_payload(self):
        for payload in (b'', os.urandom(320), b'repeated'):
            with self.subTest(size=len(payload)):
                first = encode(payload, self.key, 384, self.aad)
                second = encode(payload, self.key, 384, self.aad)
                self.assertEqual(len(first), 384)
                self.assertNotEqual(first, second)
                self.assertEqual(decode(first, self.key, self.aad), payload)
                self.assertEqual(decode(second, self.key, self.aad), payload)

    def test_reject_wrong_key_context_and_tampering(self):
        encoded = encode(b'payload', self.key, 384, self.aad)
        for key, aad in ((os.urandom(32), self.aad), (self.key, b'other-volume')):
            with self.assertRaises(UnsupportedImage):
                decode(encoded, key, aad)
        for position in (0, 31, 32, 100, len(encoded) - 1):
            changed = bytearray(encoded)
            changed[position] ^= 1
            with self.subTest(position=position), self.assertRaises(UnsupportedImage):
                decode(bytes(changed), self.key, self.aad)

    def test_reject_oversize_and_invalid_keys(self):
        with self.assertRaises(ValueError):
            encode(b'x' * 321, self.key, 384, self.aad)
        with self.assertRaises(ValueError):
            encode(b'', self.key, 63, self.aad)
        with self.assertRaises(ValueError):
            encode(b'', self.key[:31], 384, self.aad)


if __name__ == '__main__':
    unittest.main()
