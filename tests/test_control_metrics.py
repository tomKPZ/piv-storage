import unittest
from pivstore.profile import Layout
from scripts.control_metrics import byte_statistics, trace_summary, journal_sample, workload


class ControlMetricsTests(unittest.TestCase):
    def setUp(self):
        self.layout = Layout(32768, 48 * 4096 * 8, 1, 264, 272, 224)

    def test_statistics_are_descriptive(self):
        self.assertEqual(byte_statistics(bytes(100))['entropy_bits_per_byte'], 0)
        self.assertEqual(byte_statistics(bytes(range(256)))['entropy_bits_per_byte'], 8)
        self.assertEqual(byte_statistics(bytes(range(256)))['byte_chi_square'], 0)
        with self.assertRaises(ValueError): byte_statistics(b'')

    def test_trace_filters_device_and_classifies_crossing(self):
        offset = self.layout.integrity_offset + self.layout.initial_sectors * 512
        text = f'block_bio_queue: 252,16 W {offset // 512 - 1} + 2 [test]\nblock_bio_queue: 252,0 W 0 + 99 [other]'
        result = trace_summary(text, self.layout, '252,16', 4 * 1024 * 1024)
        self.assertEqual(result['total_queued_write_bytes'], 1024)
        self.assertEqual(result['queued_write_bytes'], {'journal': 512, 'metadata_area': 512})
        with self.assertRaises(ValueError): trace_summary('', self.layout, '252,16', 4096)

    def test_live_journal_rejects_inconsistent_section(self):
        data = bytearray(self.layout.journal_section_sectors * 512)
        for index in range(self.layout.journal_section_sectors):
            data[index * 512 + 504:(index + 1) * 512] = (0x1111111111111111 ^ index).to_bytes(8, 'little')
        for header in range(8):
            for entry in range(504 // self.layout.journal_entry_bytes):
                at = header * 512 + entry * self.layout.journal_entry_bytes
                data[at + 4:at + 8] = b'\xff' * 4
        data[:8] = (16).to_bytes(8, 'little')
        result = journal_sample(data, self.layout)
        self.assertEqual(result['primary_sectors'], [2])
        self.assertFalse(result['atomic_snapshot'])
        data[-1] ^= 1
        self.assertEqual(journal_sample(data, self.layout)['rejected_sections'], 1)
        with self.assertRaises(ValueError): journal_sample(data[:-1], self.layout)

    def test_workload_respects_stock_primary_alignment(self):
        for _, offset, size, _ in workload(self.layout):
            self.assertEqual(offset % self.layout.sector_size, 0)
            self.assertEqual(size % self.layout.sector_size, 0)
