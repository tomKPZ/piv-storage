"""Native adoption, including recovery of persisted pre-cleanup bootstrap state."""
from pathlib import Path
import secrets
import tempfile
import unittest

from pivstore.bootstrap import NativeBootstrap
from pivstore.profile import UnsupportedImage
from tests.fake_device import FakeDevice


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'bootstrap'
        self.key = secrets.token_bytes(32)
        self.uuid = 'd0be2e2c-93dd-4af8-aac7-d212d81f9355'
        self.device = FakeDevice(sectors=100)
        self.capacity = 512

    def run_bootstrap(self, initialize=False, cls=NativeBootstrap, key=None):
        return cls(self.device, self.path, key or self.key, self.uuid, self.capacity,
                   initialize=initialize)

    def test_initialization_preserves_primary_and_tail_and_reopen_spends_nothing(self):
        before = list(self.device.state)
        with self.run_bootstrap(True) as bootstrap:
            self.assertTrue(bootstrap.ledger.initialized)
            spent = set(bootstrap.ledger.used)
            self.assertEqual(len(spent), 100 + 96)
            carrier = b''.join(value[-12:] for value in self.device.state)
            values = [bootstrap.records.decode(i, carrier[i * 384:(i + 1) * 384]) for i in range(3)]
            self.assertEqual(bootstrap.records.payload(values), bytes(512))
        self.assertFalse(self.device.suspended)
        self.assertEqual(self.device.state[96:], before[96:])
        self.assertEqual([self.device.decrypt(i, value) for i, value in enumerate(self.device.state)],
                         self.device.plain)
        preparations = self.device.preparations
        with self.run_bootstrap() as bootstrap:
            self.assertEqual(bootstrap.ledger.used, spent)
        self.assertEqual(self.device.preparations, preparations)
        with self.assertRaises(FileExistsError):
            self.run_bootstrap(True)

    def test_crash_recovery_replays_without_encryption(self):
        for phase in ('reserved', 'journaled', 'applied:0', 'applied:31', 'ended', 'forgotten', 'resumed'):
            with self.subTest(phase=phase):
                self.path = Path(self.tmp.name) / phase.replace(':', '-')
                self.device = FakeDevice(sectors=100)

                class Interrupted(NativeBootstrap):
                    def _checkpoint(self, current):
                        if current == phase:
                            raise RuntimeError('simulated crash')

                with self.assertRaises(RuntimeError):
                    self.run_bootstrap(True, Interrupted)
                prepared = self.device.preparations
                with self.run_bootstrap() as bootstrap:
                    self.assertTrue(bootstrap.ledger.initialized)
                    self.assertFalse(bootstrap.journal.path.exists())
                    if phase != 'reserved':
                        self.assertEqual(self.device.preparations, prepared)
                    else:
                        self.assertEqual(len(bootstrap.ledger.used), 100 + 96 * 2)
                self.assertEqual([self.device.decrypt(i, v) for i, v in enumerate(self.device.state)],
                                 self.device.plain)

    def interrupted(self):
        class Interrupted(NativeBootstrap):
            def _checkpoint(self, phase):
                if phase == 'journaled':
                    raise RuntimeError('simulated crash')
        with self.assertRaises(RuntimeError):
            self.run_bootstrap(True, Interrupted)

    def test_corrupt_pending_and_wrong_key_rejected_before_apply(self):
        self.interrupted()
        before = list(self.device.state)
        with self.assertRaises(UnsupportedImage):
            self.run_bootstrap(key=secrets.token_bytes(32))
        journal = self.path / 'pending-v2'
        raw = journal.read_bytes()
        journal.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaises(UnsupportedImage):
            self.run_bootstrap()
        self.assertEqual(self.device.state, before)

    def test_authenticated_incomplete_record_refused_before_apply(self):
        self.interrupted()
        before = list(self.device.state)
        from pivstore.recovery import SparseJournal
        from pivstore.blob import context
        from types import SimpleNamespace
        identity = context(SimpleNamespace(uuid=self.uuid, layout=SimpleNamespace(
            primary_bytes=100 * 4096, sector_size=4096))) + b'/incremental/v2'
        journal = SparseJournal(self.path / 'pending-v2', self.key,
                                identity + b'/incremental/v2', 100).load()
        entry = next(journal.entries())
        journal.remove()
        journal.create(entry[2][-12:], [entry])
        with self.assertRaisesRegex(UnsupportedImage, 'Incomplete incremental record'):
            self.run_bootstrap()
        self.assertEqual(self.device.state, before)

    def test_missing_ledger_and_unrecognized_current_iv_refused(self):
        with self.assertRaisesRegex(ValueError, 'Missing nonce lineage'):
            self.run_bootstrap()
        with self.run_bootstrap(True):
            pass
        self.device.state[0] = self.device.encrypt(0, self.device.plain[0], secrets.token_bytes(12))
        before = list(self.device.state)
        with self.assertRaisesRegex(UnsupportedImage, 'trusted nonce lineage'):
            self.run_bootstrap()
        self.assertEqual(self.device.state, before)


class RecordTests(unittest.TestCase):
    def test_record_binding_size_and_padding(self):
        from pivstore.records import Records, PAYLOAD
        records = Records(100, b'volume context', secrets.token_bytes(32))
        encoded = records.encode(1, bytes(PAYLOAD))
        self.assertEqual(records.decode(1, encoded), bytes(PAYLOAD))
        with self.assertRaises(UnsupportedImage):
            records.decode(2, encoded)
        with self.assertRaises(UnsupportedImage):
            records.decode(1, records.encode(1, b'short'))
        values = records.values(b'abc')
        self.assertEqual(records.payload(values), b'abc')
        values[-1] = values[-1][:-1] + b'x'
        with self.assertRaises(UnsupportedImage):
            records.payload(values)
