import unittest

from kernel.shape_trace import check_shaped, write_extents
from pivstore.records import shaped_count, shaped_extent


def line(device, rwbs, sector, count):
    return f' kworker/u4:1-42 [000] ..... 1.0: block_bio_queue: {device} {rwbs} {sector} + {count} [kworker/u4:1]'


class ShapedExtentTest(unittest.TestCase):
    def test_512_byte_sectors_round_to_4k_edges(self):
        # Block 0's record (group 2) starts at 112 + 2 * 687 = 1486.
        self.assertEqual(shaped_extent(1486, 687, 512, 1 << 18), (1480, 2176))
        self.assertEqual(shaped_count(1486, 687, 512, 1 << 18), 696)
        # Aligned start: only the end extends.
        self.assertEqual(shaped_extent(112, 687, 512, 1 << 18), (112, 800))
        # Keyslot replicas (14 sectors).
        self.assertEqual(shaped_extent(14, 14, 512, 1 << 18), (8, 32))
        self.assertEqual(shaped_extent(98, 14, 512, 1 << 18), (96, 112))

    def test_4096_byte_sectors_unchanged(self):
        self.assertEqual(shaped_extent(1486, 687, 4096, 1 << 15), (1486, 2173))

    def test_device_end_clamps(self):
        self.assertEqual(shaped_extent(1000, 5, 512, 1003), (1000, 1003))

    def test_larger_alignment(self):
        self.assertEqual(shaped_extent(1486, 687, 512, 1 << 18, align=65536), (1408, 2176))
        self.assertEqual(shaped_extent(1486, 687, 4096, 1 << 18, align=65536), (1472, 2176))


class ShapeTraceTest(unittest.TestCase):
    def test_runs_merge_and_filter(self):
        text = '\n'.join([
            line('253,2', 'WS', 1480, 256), line('253,2', 'WS', 1736, 440),
            line('253,2', 'R', 0, 8), line('253,1', 'WS', 7, 1), line('253,2', 'FWS', 0, 0)])
        self.assertEqual(write_extents(text, '253,2', 512), [(1480, 2176)])
        self.assertEqual(check_shaped(text, '253,2', 512, [(1480, 2176)], 1 << 18), [(1480, 2176)])

    def test_4096_byte_sectors_convert(self):
        text = line('253,2', 'WS', 1486 * 8, 687 * 8)
        self.assertEqual(write_extents(text, '253,2', 4096), [(1486, 2173)])

    def test_unaligned_or_unexpected_runs_fail(self):
        text = line('253,2', 'WS', 1486, 687)
        with self.assertRaises(AssertionError):
            check_shaped(text, '253,2', 512, [(1480, 2176)], 1 << 18)
        with self.assertRaises(AssertionError):
            check_shaped(text, '253,2', 512, [(1486, 2173)], 1 << 18)
        # Unaligned run allowed only at the device end.
        self.assertEqual(check_shaped(line('253,2', 'W', 1480, 13), '253,2', 512, [(1480, 1493)], 1493),
                         [(1480, 1493)])

    def test_overlapping_rewrites_union(self):
        text = '\n'.join([line('253,2', 'WS', 0, 16), line('253,2', 'WS', 8, 16)])
        self.assertEqual(write_extents(text, '253,2', 512), [(0, 24)])


if __name__ == '__main__':
    unittest.main()
