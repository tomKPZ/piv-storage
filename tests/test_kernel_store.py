"""Recovery semantics tested without requiring kernel privileges."""
import errno
import os
from pathlib import Path
import secrets
import struct
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pivstore.kernel_store import KernelStore
from pivstore.profile import UnsupportedImage


class FakeDevice:
    def __init__(self, state=None, sectors=8):
        self.sectors = sectors
        self.primary_key = secrets.token_bytes(32)
        self.suspended = False
        self.transaction = False
        self.preparations = 0
        self.plain = [bytes([i]) * 4096 for i in range(self.sectors)]
        self.state = state or [self.encrypt(i, self.plain[i], secrets.token_bytes(12)) for i in range(self.sectors)]

    def encrypt(self, index, value, iv):
        return AESGCM(self.primary_key).encrypt(iv, value, struct.pack('<Q', index * 8) + iv) + iv

    def decrypt(self, index, value):
        return AESGCM(self.primary_key).decrypt(value[-12:], value[:-12], struct.pack('<Q', index * 8) + value[-12:])

    def check(self):
        pass

    validate = check

    def suspend(self):
        self.suspended = True

    def resume(self):
        if self.transaction:
            raise OSError(errno.EBUSY, 'Pending transaction')
        self.suspended = False

    def begin(self):
        assert self.suspended
        self.transaction = True

    def end(self):
        assert self.suspended and self.transaction
        self.transaction = False

    def read_iv(self, index, quiesced=False):
        assert self.suspended == quiesced
        self.decrypt(index, self.state[index])
        return self.state[index][-12:]

    def prepare(self, index, old, iv):
        assert self.transaction and self.suspended and old == self.state[index][-12:]
        self.preparations += 1
        return self.encrypt(index, self.decrypt(index, self.state[index]), iv)

    def apply(self, index, old, value, *, defer_flush=False):
        assert self.transaction and self.suspended
        if value == self.state[index]:
            return
        if self.state[index][-12:] != old:
            raise OSError(errno.ESTALE, 'Old IV mismatch')
        assert self.decrypt(index, self.state[index]) == self.decrypt(index, value)
        self.state[index] = value

    def sync(self):
        assert self.suspended and self.transaction

    def close(self):
        pass


class KernelRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'state'
        self.key = secrets.token_bytes(32)
        self.uuid = 'd0be2e2c-93dd-4af8-aac7-d212d81f9355'
        self.device = FakeDevice()

    def store(self, initialize=False, key=None):
        return KernelStore(self.device, self.directory, key or self.key, self.uuid, initialize=initialize)

    def test_roundtrip_restart_and_nonce_reservations(self):
        with self.store(True) as store:
            store.write_hidden(0, b'first')
            store.flush()
            used = set(store.ledger.used)
            store.write_hidden(0, b'first')
            store.flush()
            self.assertGreater(len(store.ledger.used), len(used))
        with self.store() as store:
            self.assertEqual(store.read_hidden(0, 100), b'first')
        self.assertEqual([self.device.decrypt(i, t) for i, t in enumerate(self.device.state)], self.device.plain)

    def test_crash_boundaries_recover_complete_payload_without_reencryption(self):
        for phase in ('reserved', 'journaled', 'applied:0', 'applied:4', 'ended', 'forgotten', 'resumed'):
            with self.subTest(phase=phase):
                self.directory = Path(self.tmp.name) / phase.replace(':', '-')
                self.device = FakeDevice()
                with self.store(True) as store:
                    store.write_hidden(0, b'old')
                    store.flush()
                    store.truncate_hidden(0)
                    store.write_hidden(0, b'new')
                    def crash(current):
                        if current == phase:
                            raise RuntimeError('simulated controller death')
                    store._checkpoint = crash
                    with self.assertRaises(RuntimeError):
                        store.flush()
                preparations = self.device.preparations
                with self.store() as recovered:
                    self.assertEqual(recovered.read_hidden(0, 10), b'old' if phase == 'reserved' else b'new')
                    self.assertEqual(preparations, self.device.preparations)
                self.assertFalse(self.device.suspended)
                self.assertFalse((self.directory / 'pending').exists())

    def test_journal_corruption_rejected_before_any_apply(self):
        with self.store(True) as store:
            store.flush()
            store.write_hidden(0, b'next')
            store._checkpoint = lambda phase: (_ for _ in ()).throw(RuntimeError()) if phase == 'journaled' else None
            with self.assertRaises(RuntimeError):
                store.flush()
        before = list(self.device.state)
        path = self.directory / 'pending'
        raw = bytearray(path.read_bytes()); raw[-25] ^= 1
        path.write_bytes(raw)
        with self.assertRaises(UnsupportedImage):
            self.store()
        self.assertEqual(self.device.state, before)
        self.assertTrue(self.device.suspended)

    def test_wrong_key_missing_lineage_and_double_owner_fail_closed(self):
        with self.assertRaises(ValueError):
            self.store()
        with self.store(True) as store:
            store.flush()
            with self.assertRaises(BlockingIOError):
                self.store()
        with self.assertRaises(UnsupportedImage):
            self.store(key=secrets.token_bytes(32))
        self.assertTrue(self.device.suspended)

    def test_abandoned_preparation_nonces_stay_reserved(self):
        with self.store(True) as store:
            store.flush()
            store.write_hidden(0, b'changed')
            store._checkpoint = lambda phase: (_ for _ in ()).throw(RuntimeError()) if phase == 'reserved' else None
            with self.assertRaises(RuntimeError):
                store.flush()
            reserved = set(store.ledger.used)
        with self.store() as store:
            self.assertTrue(reserved.issubset(store.ledger.used))
            store.write_hidden(0, b'retry')
            store.flush()
            self.assertEqual(len(store.ledger.used), len(reserved) + self.device.sectors)

    def test_budget_reservation_precedes_any_primary_encryption(self):
        with KernelStore(self.device, self.directory, self.key, self.uuid,
                         initialize=True, max_sector_encryptions=self.device.sectors) as store:
            before = list(self.device.state)
            with self.assertRaises(OSError) as caught:
                store.flush()
            self.assertEqual(caught.exception.errno, errno.EDQUOT)
            self.assertEqual(self.device.preparations, 0)
            self.assertEqual(self.device.state, before)

    def test_ledger_rollback_alone_is_detected_by_current_nonce_membership(self):
        with self.store(True) as store:
            initial = (self.directory / 'ledger').read_bytes()
            store.flush()
        (self.directory / 'ledger').write_bytes(initial)
        with self.assertRaises(UnsupportedImage):
            self.store()

    def test_lower_journal_policy_rejects_other_modes_and_geometry(self):
        from pivstore.kernel_api import validate_integrity_table
        table = ('0 64 integrity 254:16 32768 28 J 7 block_size:4096 '
                 'journal_sectors:1848 interleave_sectors:32768 buffer_sectors:32 '
                 'journal_watermark:50 commit_time:10000 fix_padding')
        validate_integrity_table(table, 8, os.makedev(254, 16), 16777216)
        for bad in (table.replace('28 J', '28 D'), table.replace('1848', '500'),
                    table.replace('fix_padding', 'internal_hash:sha256'),
                    table.replace('0 64', '0 72'), table.replace('254:16', '254:32')):
            with self.subTest(table=bad), self.assertRaises(ValueError):
                validate_integrity_table(bad, 8, os.makedev(254, 16), 16777216)

    def test_multichunk_journal_authenticates_before_metadata_parsing(self):
        self.device = FakeDevice(sectors=40)
        with self.store(True) as store:
            store.write_hidden(0, b'multiple encrypted journal chunks')
            store._checkpoint = lambda phase: (_ for _ in ()).throw(RuntimeError()) if phase == 'journaled' else None
            with self.assertRaises(RuntimeError):
                store.flush()
        path = self.directory / 'pending'
        original = path.read_bytes()
        raw = bytearray(original); raw[-1] ^= 1
        path.write_bytes(raw)
        from pivstore.recovery import Journal
        from unittest.mock import patch
        journal = Journal(path, self.key, store.identity, self.device.sectors)
        with patch.object(journal, 'entries', side_effect=AssertionError('parsed before authentication')):
            with self.assertRaises(UnsupportedImage):
                journal.load()
        path.write_bytes(original)
        with self.store() as recovered:
            self.assertEqual(recovered.read_hidden(0, 100), b'multiple encrypted journal chunks')

    def test_state_policy_rejects_different_mount_before_using_it(self):
        from pivstore.kernel_api import KernelDevice
        from unittest.mock import patch
        from types import SimpleNamespace
        with patch('pivstore.kernel_api.os.stat', side_effect=[
                SimpleNamespace(st_dev=2), SimpleNamespace(st_dev=1)]):
            with self.assertRaises(ValueError):
                KernelDevice.validate_state(None, self.directory)
