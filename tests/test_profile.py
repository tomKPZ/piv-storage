import copy
import struct
import unittest

from pivstore.profile import UnsupportedImage, parse_superblock, validate_segment


def header(**changes):
    values = dict(magic=b'integrt\0', version=4, interleave=15, tuple_size=28,
                  sections=7, provided=225952, flags=8, block=3)
    values.update(changes)
    return struct.pack('<8sBBHIQIB', *values.values()).ljust(4096, b'\0')


class LayoutTests(unittest.TestCase):
    def test_interleave_boundary_and_last_sector(self):
        layout = parse_superblock(header(), 16777216, 134217728)
        data0, tag0 = layout.offsets(0)
        data_before, tag_before = layout.offsets(4095)
        data_after, tag_after = layout.offsets(4096)
        self.assertEqual(data0, 16777216 + (1856 + 224) * 512)
        self.assertEqual(tag0, 16777216 + 1856 * 512)
        self.assertEqual(data_before, data0 + 4095 * 4096)
        self.assertEqual(data_after - data_before, 4096 + 224 * 512)
        self.assertEqual(tag_before, tag0 + 4095 * 28)
        self.assertEqual(tag_after, tag0 + (32768 + 224) * 512)
        self.assertLessEqual(layout.offsets(28243)[0] + 4096, 134217728)
        for value in (-1, 28244):
            with self.assertRaises(IndexError):
                layout.offsets(value)

    def test_reject_unsupported_or_invalid_superblocks(self):
        for change in ({'magic': b'badmagic'}, {'version': 6}, {'flags': 10},
                       {'flags': 9}, {'tuple_size': 32}, {'block': 0},
                       {'interleave': 14}, {'sections': 0}, {'sections': 4097},
                       {'provided': 0}, {'provided': 9}, {'provided': 2**63}):
            with self.subTest(change=change), self.assertRaises(UnsupportedImage):
                parse_superblock(header(**change), 16777216, 134217728)
        for data, offset, size in ((header()[:40], 16777216, 134217728),
                                   (header(), 16777217, 134217728),
                                   (header(), 16777216, 20000000)):
            with self.assertRaises(UnsupportedImage):
                parse_superblock(data, offset, size)


class SegmentTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {'config': {}, 'segments': {'0': {
            'type': 'crypt', 'offset': '16777216', 'size': 'dynamic',
            'iv_tweak': '0', 'encryption': 'aes-gcm-random', 'sector_size': 4096,
            'integrity': {'type': 'aead', 'journal_encryption': 'none',
                          'journal_integrity': 'none'}}}}

    def test_supported_segment(self):
        self.assertEqual(validate_segment(self.metadata), 16777216)

    def test_reject_alternative_layouts(self):
        for key, value in (('iv_tweak', '8'), ('sector_size', 512),
                           ('offset', '-1'), ('offset', '١'), ('offset', 1),
                           ('encryption', 'aes-xts-plain64'), ('size', '4096'),
                           ('flags', ['in-reencryption']),
                           ('integrity', {'type': 'aead'})):
            metadata = copy.deepcopy(self.metadata)
            metadata['segments']['0'][key] = value
            with self.subTest(key=key), self.assertRaises(UnsupportedImage):
                validate_segment(metadata)
        self.metadata['config']['requirements'] = {'mandatory': ['online-reencrypt']}
        with self.assertRaises(UnsupportedImage):
            validate_segment(self.metadata)


if __name__ == '__main__':
    unittest.main()
