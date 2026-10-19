"""History-preserving publication, error boundaries and process-death checks."""
import errno
import hashlib
import multiprocessing
import os
from pathlib import Path
import secrets
import signal
import struct
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pivstore import compaction
from pivstore.native_log import HEADER, ENTRY, LOG_DOMAIN, inspect_log
from pivstore.profile import UnsupportedImage
from pivstore.recovery import derive


class CompactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'native.log'
        self.path.touch(mode=0o600)
        self.key = secrets.token_bytes(32)
        self.identity = b'native test identity'
        self.used = [secrets.token_bytes(12) for _ in range(96)]
        self.frames = []
        self.append(1, struct.pack('<I', 64) + b''.join(self.used[:64]))
        self.append(4)
        self.append(2, struct.pack('<I', 32) + b''.join(
            ENTRY.pack(32 + i, 0, self.used[i], bytes(4112) + self.used[32 + i]) for i in range(32)))
        self.append(3)
        # Reservations from an abandoned transaction MUST survive compaction.
        self.append(1, struct.pack('<I', 32) + b''.join(self.used[64:]))
        self.original = self.path.read_bytes()

    def append(self, kind, payload=b''):
        salt = secrets.token_bytes(32)
        previous = hashlib.sha256(self.frames[-1]).digest() if self.frames else bytes(32)
        header = HEADER.pack(b'PIVNLOG1', len(self.frames), kind, len(payload), salt, previous)
        self.frames.append(header + AESGCM(derive(self.key, salt, LOG_DOMAIN + self.identity)).encrypt(
            bytes(12), payload, header + self.identity))
        self.path.write_bytes(b''.join(self.frames))

    def compact(self):
        return compaction._compact_file(self.path, self.key, self.identity, 100)

    def verify(self):
        state = inspect_log(self.path, self.key, self.identity, 100)
        self.assertEqual(state.used, set(self.used))
        self.assertTrue(state.ready)
        self.assertIsNone(state.pending)
        self.assertEqual(state.trailing_bytes, 0)
        return state

    def test_compaction_keeps_abandoned_history_and_repeated_compaction_uses_fresh_salts(self):
        result = self.compact()
        self.assertEqual(result['nonces'], 96)
        self.assertLess(result['compacted_bytes'], result['previous_bytes'])
        self.assertEqual(self.verify().frames, 2)
        first = self.path.read_bytes()
        self.compact()
        self.verify()
        self.assertNotEqual(first, self.path.read_bytes())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_history_spanning_multiple_nonce_batches(self):
        extra = [secrets.token_bytes(12) for _ in range(512)]
        self.used.extend(extra)
        self.append(1, struct.pack('<I', 512) + b''.join(extra))
        self.compact()
        self.assertEqual(self.verify().frames, 3)

    def test_pending_incomplete_corrupt_and_wrong_key_refused_without_changes(self):
        for value in (b''.join(self.frames[:3]), self.original + b'partial',
                      self.original[:-1] + bytes([self.original[-1] ^ 1])):
            with self.subTest(length=len(value)):
                self.path.write_bytes(value)
                with self.assertRaises(UnsupportedImage): self.compact()
                self.assertEqual(self.path.read_bytes(), value)
        self.path.write_bytes(self.original)
        with self.assertRaises(UnsupportedImage):
            compaction._compact_file(self.path, secrets.token_bytes(32), self.identity, 100)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertFalse(list(self.path.parent.glob('.piv-compacting-*')))

    def test_write_fsync_rename_and_directory_fsync_errors_preserve_a_complete_history(self):
        for point in ('write', 'fsync', 'rename', 'directory'):
            self.path.write_bytes(self.original)
            with self.subTest(point=point):
                if point == 'write':
                    def fail(phase):
                        if phase == 'frame': raise OSError(errno.ENOSPC, 'test append failure')
                    patch = mock.patch.object(compaction, '_checkpoint', fail)
                else:
                    name = {'fsync': 'os.fsync', 'rename': 'os.replace', 'directory': 'fsync_dir'}[point]
                    patch = mock.patch('pivstore.compaction.' + name,
                                       side_effect=OSError(errno.EIO, 'test persistence failure'))
                with patch, self.assertRaises(OSError): self.compact()
                self.verify()
                if point != 'directory': self.assertEqual(self.path.read_bytes(), self.original)
                self.assertFalse(list(self.path.parent.glob('.piv-compacting-*')))

    def test_process_death_at_each_publication_boundary_keeps_old_or_complete_new_log(self):
        for point in ('frame', 'prepared', 'published', 'durable'):
            with self.subTest(point=point):
                self.path.write_bytes(self.original)
                def child():
                    def die(phase):
                        if phase == point: os.kill(os.getpid(), signal.SIGKILL)
                    compaction._checkpoint = die
                    self.compact()
                process = multiprocessing.get_context('fork').Process(target=child)
                process.start()
                process.join(10)
                if process.is_alive():
                    process.kill(); process.join()
                    self.fail('Compaction child hung')
                self.assertEqual(process.exitcode, -signal.SIGKILL)
                self.verify()
                if point in ('frame', 'prepared'):
                    self.assertEqual(self.path.read_bytes(), self.original)
                else:
                    self.assertNotEqual(self.path.read_bytes(), self.original)

    def test_active_native_owner_refused_without_detach_or_removal(self):
        owner = mock.Mock()
        with mock.patch('pivstore.kernel_owner.GuestOwner', return_value=owner), \
             mock.patch('pivstore.blocks.native_status', return_value={'active': True}), \
             mock.patch('pivstore.blocks.native_detach') as detach:
            with self.assertRaises(BlockingIOError):
                compaction.compact_state('/dev/vdb', '/test/credential', self.key)
        detach.assert_not_called()
        owner.remove.assert_not_called()
        owner.close.assert_called_once()
