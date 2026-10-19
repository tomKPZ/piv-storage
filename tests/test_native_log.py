"""Independent native-log authentication, ordering and reservation checks."""
import hashlib
from pathlib import Path
import secrets
import struct
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pivstore.native_log import HEADER, ENTRY, LOG_DOMAIN, inspect_log
from pivstore.profile import UnsupportedImage
from pivstore.recovery import derive
from pivstore.blocks import SETUP, STATUS, _phase


class NativeLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'native.log'
        self.path.touch(mode=0o600)
        self.key = secrets.token_bytes(32)
        self.context = b'test native context'
        self.frames = []

    def append(self, kind, body=b''):
        salt = secrets.token_bytes(32)
        previous = hashlib.sha256(self.frames[-1]).digest() if self.frames else bytes(32)
        header = HEADER.pack(b'PIVNLOG1', len(self.frames), kind, len(body), salt, previous)
        encrypted = AESGCM(derive(self.key, salt, LOG_DOMAIN + self.context)).encrypt(
            bytes(12), body, header + self.context)
        self.frames.append(header + encrypted)
        self.path.write_bytes(b''.join(self.frames))

    def inspect(self, key=None):
        return inspect_log(self.path, key or self.key, self.context, 100)

    def test_abi_sizes(self):
        self.assertEqual((SETUP.size, STATUS.size, HEADER.size, ENTRY.size), (464, 48, 88, 4148))

    def test_adoption_marker_forbids_missing_or_empty_native_history(self):
        root = Path(self.temp.name)
        self.assertEqual(_phase(root, self.path), b'importing\n')
        marker = root / 'native.phase'
        marker.write_bytes(b'ready\n')
        with self.assertRaises(ValueError): _phase(root, self.path)
        self.path.unlink()
        with self.assertRaises(ValueError): _phase(root, self.path)
        self.path.write_bytes(b'existing encrypted log')
        self.assertEqual(_phase(root, self.path), b'ready\n')
        marker.unlink()
        self.assertEqual(_phase(root, self.path), b'ready\n')
        marker.write_bytes(b'corrupt')
        with self.assertRaises(ValueError): _phase(root, self.path)

    def test_valid_native_reservation_wal_and_completion(self):
        old = [secrets.token_bytes(12) for _ in range(32)]
        new = [secrets.token_bytes(12) for _ in range(32)]
        self.append(1, struct.pack('<I', 64) + b''.join(old + new))
        self.append(4)
        self.append(2, struct.pack('<I', 32) + b''.join(
            ENTRY.pack(32 + i, int(i == 1), old[i], bytes(4112) + new[i]) for i in range(32)))
        self.assertEqual(len(self.inspect().pending), 32)
        self.append(3)
        state = self.inspect()
        self.assertIsNone(state.pending)
        self.assertTrue(state.ready)
        self.assertEqual(len(state.used), 64)
        self.assertEqual(state.trailing_bytes, 0)

    def test_wrong_key_corruption_chain_and_partial_tail(self):
        iv = secrets.token_bytes(12)
        self.append(1, struct.pack('<I', 1) + iv)
        with self.assertRaises(UnsupportedImage): self.inspect(secrets.token_bytes(32))
        original = self.path.read_bytes()
        raw = bytearray(original); raw[-1] ^= 1
        self.path.write_bytes(raw)
        with self.assertRaises(UnsupportedImage): self.inspect()
        self.path.write_bytes(original + b'partial')
        self.assertEqual(self.inspect().trailing_bytes, 7)
        self.path.write_bytes(original)
        self.append(4)
        self.path.write_bytes(self.frames[1] + self.frames[0])
        with self.assertRaises(UnsupportedImage): self.inspect()

    def test_repeated_reservations_and_incomplete_record_wal_rejected(self):
        old, new = secrets.token_bytes(12), secrets.token_bytes(12)
        self.append(1, struct.pack('<I', 2) + old + new)
        self.append(4)
        self.append(2, struct.pack('<I', 1) + ENTRY.pack(32, 0, old, bytes(4112) + new))
        with self.assertRaises(UnsupportedImage): self.inspect()
        self.frames = self.frames[:2]
        self.append(1, struct.pack('<I', 1) + old)
        with self.assertRaises(UnsupportedImage): self.inspect()
