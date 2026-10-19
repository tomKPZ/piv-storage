import copy
import os
import struct
import unittest

from pivstore.kernel_api import validate_integrity_table
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

    def test_512_interleave_and_journal_geometry(self):
        layout = parse_superblock(header(block=0, sections=23, provided=214800),
                                  16777216, 134217728)
        self.assertEqual((layout.sector_size, layout.journal_entry_bytes,
                          layout.journal_section_sectors, layout.metadata_run_sectors),
                         (512, 48, 88, 1792))
        data, tag = layout.offsets(0)
        self.assertEqual(layout.offsets(32767), (data + 32767 * 512, tag + 32767 * 28))
        self.assertEqual(layout.offsets(32768),
                         (data + (32768 + 1792) * 512, tag + (32768 + 1792) * 512))
        self.assertLessEqual(layout.offsets(layout.sectors - 1)[0] + 512, 134217728)

    def test_reject_unsupported_or_invalid_superblocks(self):
        for change in ({'magic': b'badmagic'}, {'version': 6}, {'flags': 10},
                       {'flags': 9}, {'tuple_size': 32}, {'block': 1},
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
        for size in (512, 4096):
            self.metadata['segments']['0']['sector_size'] = size
            self.assertEqual(validate_segment(self.metadata), 16777216)

    def test_reject_alternative_layouts(self):
        for key, value in (('iv_tweak', '8'), ('sector_size', 2048),
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


class IntegrityTableTests(unittest.TestCase):
    def test_both_stock_geometries_and_reject_mixed_options(self):
        for size, count, journal, buffer in ((512, 214800, 2024, 128),
                                             (4096, 28244, 1848, 32)):
            options = [f'journal_sectors:{journal}', 'interleave_sectors:32768',
                       f'buffer_sectors:{buffer}', 'journal_watermark:50',
                       'commit_time:10000', 'fix_padding']
            if size == 4096:
                options.insert(0, 'block_size:4096')
            table = f'0 {count * (size // 512)} integrity 254:16 32768 28 J {len(options)} ' + ' '.join(options)
            validate_integrity_table(table, count, os.makedev(254, 16), 16777216, size, journal)
            for changed in (table.replace('28 J', '32 J'),
                            table.replace('fix_padding', 'fix_hmac'),
                            table.replace(f'buffer_sectors:{buffer}', 'buffer_sectors:1'),
                            table.replace(f'journal_sectors:{journal}', 'journal_sectors:1')):
                with self.subTest(size=size, table=changed), self.assertRaises(ValueError):
                    validate_integrity_table(changed, count, os.makedev(254, 16), 16777216, size, journal)


if __name__ == '__main__':
    unittest.main()
