import unittest
from unittest.mock import patch
from pivstore.records import Records, BYTES, PAYLOAD
from pivstore.profile import UnsupportedImage
from pivstore.blocks import SETUP, STATUS
from pivstore.kernel_api import READ, UPDATE


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.records = Records(28244, b'test volume context', bytes(range(32)))
        self.value = bytes(range(256)) * 2

    def test_geometry_and_abi(self):
        self.assertEqual((self.records.count, self.records.capacity), (588, 301056))
        self.assertEqual((SETUP.size, STATUS.size, BYTES, PAYLOAD), (192, 48, 576, 512))
        self.assertEqual((READ.size, UPDATE.size), (48, 4176))
        wide = Records(28244, b'test', bytes(32), 16)
        self.assertEqual((wide.sectors_per_record, wide.count), (36, 784))
        for i in (-1, 588):
            with self.assertRaises(ValueError): self.records.aad(i)
        with self.assertRaises(ValueError): self.records.encode(0, b'short')

    def test_round_trip_fresh_encoding(self):
        first = self.records.encode(0, self.value)
        second = self.records.encode(0, self.value)
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), BYTES)
        self.assertEqual(self.records.decode(0, first), self.value)
        self.assertEqual(self.records.decode(0, second), self.value)

    def test_address_key_and_context_binding(self):
        encoded = self.records.encode(0, self.value)
        for records, index in ((self.records, 1), (Records(28244, b'other', bytes(range(32))), 0),
                               (Records(28244, b'test volume context', bytes(32)), 0)):
            with self.assertRaises(UnsupportedImage): records.decode(index, encoded)

    def test_invalid_marker_never_becomes_zeros(self):
        encoded = self.records.encode(0, self.value, invalid=True)
        with self.assertRaises(UnsupportedImage): self.records.decode(0, encoded)
        self.assertEqual(self.records.decode(0, self.records.encode(0, bytes(512))), bytes(512))

    def test_corruption_and_every_sector_torn_boundary(self):
        old = self.records.encode(0, b'A' * 512)
        new = self.records.encode(0, b'B' * 512)
        for boundary in sorted(set(range(12, BYTES, 12)) | set(range(16, BYTES, 16))):
            with self.assertRaises(UnsupportedImage):
                self.records.decode(0, new[:boundary] + old[boundary:])
        for at in (0, 31, 32, 575):
            damaged = bytearray(old); damaged[at] ^= 1
            with self.assertRaises(UnsupportedImage): self.records.decode(0, bytes(damaged))
        with self.assertRaises(UnsupportedImage): self.records.decode(0, old[:-1])

    def test_deterministic_reference(self):
        # Fixed entropy here only: ensures codec changes cannot silently change format.
        with patch('pivstore.records.secrets.token_bytes', return_value=bytes(range(32))):
            value = self.records.encode(2, self.value)
        import hashlib
        self.assertEqual(hashlib.sha256(value).hexdigest(), 'fe44a9147f3af52340fa7d9d092ddba71df4b01ee261b3576e13661d53b41860')


class ExtractionTests(unittest.TestCase):
    def image(self, corrupt=False):
        from types import SimpleNamespace
        from pivstore.records import context
        image = SimpleNamespace(uuid='00000000-0000-0000-0000-000000000000',
                                layout=SimpleNamespace(sectors=97, primary_bytes=97 * 4096, sector_size=4096, iv_bytes=12))
        records = Records(97, context(image), bytes(32))
        carrier = records.encode(0, b'A' * 512) + records.encode(1, b'B' * 512) + b'tail ignored'
        if corrupt:
            carrier = carrier[:600] + bytes([carrier[600] ^ 1]) + carrier[601:]
        image.iv_slots = lambda: (carrier[i:i + 12] for i in range(0, len(carrier), 12))
        image.check_unchanged = lambda: None
        return image

    def test_geometry_derived_volume_without_header_record(self):
        from pivstore.records import decode_image
        self.assertEqual(decode_image(self.image(), bytes(32)), b'A' * 512 + b'B' * 512)
        with self.assertRaises(UnsupportedImage): decode_image(self.image(True), bytes(32))

    def test_unpack_all_or_error_and_no_overwrite(self):
        from contextlib import nullcontext
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from pivstore.records import unpack
        with TemporaryDirectory() as directory:
            output = Path(directory) / 'hidden.raw'
            with patch('pivstore.records.Image', return_value=nullcontext(self.image(True))):
                with self.assertRaises(UnsupportedImage): unpack('fake', output, bytes(32))
            self.assertEqual(list(Path(directory).iterdir()), [])
            with patch('pivstore.records.Image', return_value=nullcontext(self.image())):
                self.assertEqual(unpack('fake', output, bytes(32)), {'extracted_payload_bytes': 1024})
            self.assertEqual(output.read_bytes(), b'A' * 512 + b'B' * 512)
            with self.assertRaises(FileExistsError): unpack('fake', output, bytes(32))
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)


class BootstrapDependencyTests(unittest.TestCase):
    def test_native_setup_and_cli_need_only_standard_library(self):
        import subprocess
        import sys
        subprocess.run([sys.executable, '-S', '-c',
            "import sys; import pivstore.blocks; import pivstore.__main__; "
            "assert not any(n.startswith('cryptography') for n in sys.modules)"], check=True)
