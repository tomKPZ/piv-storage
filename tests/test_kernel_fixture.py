"""Independent kernel fixture checks; set PIV_FIXTURE to a successful VM run."""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from pivstore.profile import Image, UnsupportedImage
from pivstore.writer import randomize_copy, rewrite_copy, write_exact
from pivstore.blob import pack, unpack


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
            self.assertEqual(image.layout.sectors, 28244)
        with self.path.open('rb') as stream:
            after = hashlib.file_digest(stream, 'sha256').digest()
        self.assertEqual(before, after)

    def test_carrier_extraction_order(self):
        with Image(self.path) as image:
            carrier = b''.join(image.iv_slots())
            self.assertEqual(len(carrier), 338928)
            for index in (0, 4095, 4096, image.layout.sectors - 1):
                _, offset = image.layout.offsets(index)
                self.assertEqual(carrier[index * 12:(index + 1) * 12],
                                 image.read(12, offset + 16))

    def test_wrong_key_rejected(self):
        wrong = bytes([self.key[0] ^ 1]) + self.key[1:]
        with Image(self.path) as image, self.assertRaisesRegex(UnsupportedImage, 'authentication failed'):
            image.verify(wrong)

    def test_ciphertext_tag_and_iv_corruption_at_boundaries(self):
        with Image(self.path) as image:
            positions = [(index, image.layout.offsets(index))
                         for index in (0, 4095, 4096, image.layout.sectors - 1)]
        for index, (data, metadata) in positions:
            for kind, offset in [('ciphertext', data), ('tag', metadata), ('IV', metadata + 16)]:
                with self.subTest(index=index, kind=kind), self.changed(offset):
                    with Image(self.path) as image, self.assertRaisesRegex(
                            UnsupportedImage, f'authentication failed at sector {index}$'):
                        image.verify(self.key)

    def test_torn_and_nonempty_journals_rejected(self):
        with Image(self.path) as image:
            journal = image.layout.integrity_offset + 4096
        for kind, offset in [('nonempty entry', journal + 4), ('commit ID', journal + 504)]:
            with self.subTest(kind=kind), self.changed(offset):
                with self.assertRaises(UnsupportedImage):
                    Image(self.path)

    def test_truncated_image_rejected(self):
        shortened = self.path.with_name('short.img')
        with self.path.open('rb') as source, shortened.open('wb') as out:
            out.write(source.read(20 * 1024 * 1024))
        with self.assertRaises(UnsupportedImage):
            Image(shortened)


class CopyWriterTests(FixtureCase):
    def test_randomized_copy_changes_only_selected_extents(self):
        output = self.path.with_name('randomized.img')
        indices = [0, 4095, 4096, 28243]
        randomize_copy(self.path, output, self.key, indices)
        with Image(self.path) as source, Image(output) as candidate:
            self.assertEqual(source.verify(self.key), self.expected)
            self.assertEqual(candidate.verify(self.key), self.expected)
            allowed = []
            for index in indices:
                data, metadata = source.layout.offsets(index)
                allowed.extend([(data, data + 4096), (metadata, metadata + 28)])
                self.assertNotEqual(source.read(12, metadata + 16), candidate.read(12, metadata + 16))
            position = 0
            for start, end in sorted(allowed) + [(source.size, source.size)]:
                self.assertEqual(source.read(start - position, position),
                                 candidate.read(start - position, position))
                position = end
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_refuse_overwrite_and_out_of_range(self):
        with self.assertRaises(FileExistsError):
            randomize_copy(self.path, self.path, self.key, [0])
        for value in (-1, 28244):
            output = self.path.with_name(f'invalid-{value}.img')
            with self.assertRaises(ValueError):
                randomize_copy(self.path, output, self.key, [value])
            self.assertFalse(output.exists())

    def test_repeated_primary_iv_plan_rejected(self):
        output = self.path.with_name('reused-iv.img')
        with self.assertRaises(ValueError):
            rewrite_copy(self.path, output, self.key,
                         lambda image, used: {0: next(iter(used))})
        self.assertFalse(output.exists())

    def test_write_failure_cleans_unpublished_output(self):
        output = self.path.with_name('failed.img')
        with mock.patch('pivstore.writer.write_exact', side_effect=OSError('injected write failure')):
            with self.assertRaises(OSError):
                randomize_copy(self.path, output, self.key, [0])
        self.assertFalse(output.exists())
        self.assertEqual(list(self.path.parent.glob('.pivstore-*.partial')), [])
        with Image(self.path) as source:
            self.assertEqual(source.verify(self.key), self.expected)

    def test_publication_failure_leaves_input_and_no_output(self):
        output = self.path.with_name('unpublished.img')
        with mock.patch('pivstore.writer.os.link', side_effect=OSError('injected link failure')):
            with self.assertRaises(OSError):
                randomize_copy(self.path, output, self.key, [0])
        self.assertFalse(output.exists())
        self.assertEqual(list(self.path.parent.glob('.pivstore-*.partial')), [])

    def test_partial_writes_are_completed(self):
        output = self.path.with_name('partial-write.bin')
        with output.open('wb') as stream:
            real = os.pwrite
            with mock.patch('pivstore.writer.os.pwrite', side_effect=lambda fd, data, offset: real(fd, data[:1], offset)):
                write_exact(stream.fileno(), b'abcdef', 0)
        self.assertEqual(output.read_bytes(), b'abcdef')

    def test_process_crashes_before_and_after_publication(self):
        script = '''
import os, signal, sys
from pivstore import writer
phase = sys.argv[4]
if phase == 'copy':
    real_write = writer.write_exact
    def interrupted(fd, data, offset):
        real_write(fd, data, offset)
        os.kill(os.getpid(), signal.SIGKILL)
    writer.write_exact = interrupted
elif phase == 'fsync':
    writer.os.fsync = lambda fd: os.kill(os.getpid(), signal.SIGKILL)
else:
    real_link = writer.os.link
    def interrupted_link(source, destination):
        real_link(source, destination)
        os.kill(os.getpid(), signal.SIGKILL)
    writer.os.link = interrupted_link
with open(sys.argv[3], 'rb') as stream:
    key = stream.read()
writer.randomize_copy(sys.argv[1], sys.argv[2], key, [0])
'''
        for phase in ('copy', 'fsync', 'published'):
            directory = self.path.parent / f'crash-{phase}'
            directory.mkdir()
            output = directory / 'output.img'
            result = subprocess.run([sys.executable, '-c', script, str(self.path),
                                     str(output), str(self.fixture / 'share/volume.key'), phase],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, -signal.SIGKILL)
            if phase == 'published':
                with Image(output) as image:
                    self.assertEqual(image.verify(self.key), self.expected)
            else:
                self.assertFalse(output.exists())
            self.assertEqual(len(list(directory.glob('.pivstore-*.partial'))), 1)
        with Image(self.path) as source:
            self.assertEqual(source.verify(self.key), self.expected)


class HiddenBlobTests(FixtureCase):
    def test_pack_update_and_unpack_without_primary_key(self):
        hidden_key = os.urandom(32)
        payload = os.urandom(1500)
        first = self.path.with_name('packed.img')
        second = self.path.with_name('updated.img')
        extracted = self.path.with_name('payload.out')
        pack(self.path, first, self.key, hidden_key, payload)
        unpack(first, extracted, hidden_key)
        self.assertEqual(extracted.read_bytes(), payload)
        self.assertEqual(extracted.stat().st_mode & 0o777, 0o600)
        pack(first, second, self.key, hidden_key, payload)
        with Image(first) as old, Image(second) as new:
            self.assertTrue(set(old.iv_slots()).isdisjoint(new.iv_slots()))
            self.assertEqual(old.verify(self.key), self.expected)
            self.assertEqual(new.verify(self.key), self.expected)
        with self.assertRaises(FileExistsError):
            unpack(second, extracted, hidden_key)
        with self.assertRaises(UnsupportedImage):
            unpack(first, self.path.with_name('wrong-key.out'), os.urandom(32))
        self.assertFalse(self.path.with_name('wrong-key.out').exists())
        damaged = self.path.with_name('hidden-damaged.img')
        randomize_copy(second, damaged, self.key, [0])
        with Image(damaged) as image:
            self.assertEqual(image.verify(self.key), self.expected)
        with self.assertRaises(UnsupportedImage):
            unpack(damaged, self.path.with_name('damaged.out'), hidden_key)

    def test_empty_and_maximum_blob(self):
        hidden_key = os.urandom(32)
        with Image(self.path) as image:
            maximum = image.layout.sectors * 12 - 64
        for name, payload in [('empty', b''), ('maximum', os.urandom(maximum))]:
            output = self.path.with_name(name + '.img')
            extracted = self.path.with_name(name + '.out')
            pack(self.path, output, self.key, hidden_key, payload)
            unpack(output, extracted, hidden_key)
            self.assertEqual(extracted.read_bytes(), payload)
        oversized = self.path.with_name('oversized.img')
        with self.assertRaises(ValueError):
            pack(self.path, oversized, self.key, hidden_key, b'X' * (maximum + 1))
        self.assertFalse(oversized.exists())


if __name__ == '__main__':
    unittest.main()
