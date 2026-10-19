"""Independent kernel fixture checks; set PIV_FIXTURE to a successful VM run."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from pivstore.profile import Image, UnsupportedImage


@unittest.skipUnless(os.environ.get('PIV_FIXTURE'), 'set PIV_FIXTURE to a successful VM run')
class FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = Path(os.environ['PIV_FIXTURE'])
        if not (cls.fixture / 'share/result.txt').is_file():
            raise RuntimeError('Fixture must have completed stock-kernel readback')
        cls.key = (cls.fixture / 'share/volume.key').read_bytes()
        cls.expected = (cls.fixture / 'share/expected.sha256').read_text().strip()
        actual = (cls.fixture / 'share/actual.sha256').read_text().strip()
        if cls.expected != actual:
            raise RuntimeError('Fixture stock-kernel hash mismatch')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.path = Path(cls.temporary.name) / 'test.img'
        shutil.copyfile(cls.fixture / 'control.img', cls.path)
        os.chmod(cls.path, 0o600)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @contextmanager
    def changed(self, offset):
        with self.path.open('r+b') as stream:
            stream.seek(offset)
            original = stream.read(1)
            stream.seek(offset)
            stream.write(bytes([original[0] ^ 1]))
        try:
            yield
        finally:
            with self.path.open('r+b') as stream:
                stream.seek(offset)
                stream.write(original)


class KernelFixtureTests(FixtureCase):
    def test_entire_primary_matches_kernel_and_image_unchanged(self):
        with self.path.open('rb') as stream:
            before = hashlib.file_digest(stream, 'sha256').digest()
        with Image(self.path) as image:
            self.assertEqual(image.verify(self.key), self.expected)
            self.assertEqual(image.layout.primary_bytes, int((self.fixture / 'share/primary-size.txt').read_text()))
        with self.path.open('rb') as stream:
            after = hashlib.file_digest(stream, 'sha256').digest()
        self.assertEqual(before, after)

    def test_carrier_extraction_order(self):
        with Image(self.path) as image:
            carrier = b''.join(image.iv_slots())
            self.assertEqual(len(carrier), image.layout.sectors * image.layout.iv_bytes)
            self.assertEqual(image.summary()['gross_carrier_bytes'], len(carrier))
            for index in (0, 32768 // (image.layout.sector_size // 512) - 1,
                              32768 // (image.layout.sector_size // 512), image.layout.sectors - 1):
                _, offset = image.layout.offsets(index)
                self.assertEqual(carrier[index * image.layout.iv_bytes:(index + 1) * image.layout.iv_bytes],
                                 image.read(image.layout.iv_bytes, offset + 16))

    def test_cli_carrier_bytes_match_written_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'carrier.raw'
            response = subprocess.check_output([sys.executable, '-m', 'pivstore',
                'extract-ivs', str(self.path), '--output', str(output)], text=True)
            with Image(self.path) as image:
                carrier = b''.join(image.iv_slots())
                self.assertEqual(json.loads(response)['extracted_bytes'], len(carrier))
                self.assertEqual(output.read_bytes(), carrier)

    def test_wrong_key_rejected(self):
        wrong = bytes([self.key[0] ^ 1]) + self.key[1:]
        with Image(self.path) as image, self.assertRaisesRegex(UnsupportedImage, 'authentication failed'):
            image.verify(wrong)

    def test_ciphertext_tag_and_iv_corruption_at_boundaries(self):
        with Image(self.path) as image:
            positions = [(index, image.layout.offsets(index))
                         for index in (0, 32768 // (image.layout.sector_size // 512) - 1,
                              32768 // (image.layout.sector_size // 512), image.layout.sectors - 1)]
        for index, (data, metadata) in positions:
            for kind, offset in [('ciphertext', data), ('tag', metadata), ('IV', metadata + 16)]:
                with self.subTest(index=index, kind=kind), self.changed(offset):
                    with Image(self.path) as image, self.assertRaisesRegex(
                            UnsupportedImage, f'authentication failed at sector {index}$'):
                        image.verify(self.key)

    def test_torn_and_nonempty_journals_rejected(self):
        with Image(self.path) as image:
            journal = image.layout.integrity_offset + 4096
            last_entry = (504 // image.layout.journal_entry_bytes - 1) * image.layout.journal_entry_bytes
        for kind, offset in [('nonempty entry', journal + 4),
                             ('last header entry', journal + last_entry + 4),
                             ('commit ID', journal + 504)]:
            with self.subTest(kind=kind), self.changed(offset):
                with self.assertRaises(UnsupportedImage):
                    Image(self.path)

    def test_truncated_image_rejected(self):
        shortened = self.path.with_name('short.img')
        with self.path.open('rb') as source, shortened.open('wb') as out:
            out.write(source.read(20 * 1024 * 1024))
        with self.assertRaises(UnsupportedImage):
            Image(shortened)
