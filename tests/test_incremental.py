"""v2 record isolation, primary preservation, sparse recovery and NBD writes."""
import errno
from pathlib import Path
import secrets
import socket
import struct
import tempfile
import threading
import unittest

from pivstore.incremental_store import IncrementalStore
from pivstore.profile import UnsupportedImage
from pivstore.records import Records, PAYLOAD, decode_image
from pivstore import nbd
from pivstore.recovery import SparseJournal
from tests.test_kernel_store import FakeDevice


class WritableDevice(FakeDevice):
    flags = 15

    def read_primary_sector(self, index):
        assert not self.suspended
        return self.decrypt(index, self.state[index])

    def prepare_primary(self, index, old, iv, plaintext):
        assert self.suspended and self.transaction and old == self.state[index][-12:]
        self.decrypt(index, self.state[index])
        self.preparations += 1
        return self.encrypt(index, plaintext, iv)

    def apply_primary(self, index, old, value, *, defer_flush=False):
        assert self.suspended and self.transaction
        if value == self.state[index]:
            return
        if old != self.state[index][-12:]:
            raise OSError(errno.ESTALE, 'Stale old IV')
        self.decrypt(index, self.state[index])
        self.decrypt(index, value)
        self.state[index] = value


class IncrementalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'state'
        self.key = secrets.token_bytes(32)
        self.device = WritableDevice(sectors=100)
        self.uuid = 'd0be2e2c-93dd-4af8-aac7-d212d81f9355'

    def store(self, initialize=False):
        return IncrementalStore(self.device, self.state, self.key, self.uuid, initialize=initialize)

    def plain(self):
        return b''.join(self.device.decrypt(i, v) for i, v in enumerate(self.device.state))

    def test_incremental_hidden_record_isolation_and_size(self):
        before = self.plain()
        with self.store(True) as store:
            store.write_hidden(0, b'x' * 500)
            store.flush()
            initial = list(self.device.state)
            store.write_hidden(325, b'new')
            store.flush()
            changed = {i for i in range(100) if initial[i] != self.device.state[i]}
            self.assertEqual(changed, set(range(64, 96)))
            initial = list(self.device.state)
            store.flush()
            self.assertEqual(initial, self.device.state)
            store.truncate_hidden(100)
            store.flush()
        with self.store() as store:
            self.assertEqual(store.read_hidden(0, 1000), b'x' * 100)
        self.assertEqual(self.plain(), before)

    def test_partial_primary_cross_record_and_tail_preserves_hidden(self):
        with self.store(True) as store:
            hidden = secrets.token_bytes(500)
            store.write_hidden(0, hidden)
            store.flush()
            before = bytearray(self.plain())
            initial = list(self.device.state)
            offset = 32 * 4096 - 17
            value = secrets.token_bytes(43)
            self.assertEqual(store.write_primary(offset, value), len(value))
            before[offset:offset + len(value)] = value
            self.assertEqual(self.plain(), bytes(before))
            self.assertEqual(store.read_primary(offset - 2, len(value) + 4), bytes(before[offset - 2:offset + len(value) + 2]))
            self.assertEqual({i for i in range(100) if initial[i] != self.device.state[i]}, set(range(64)))
            self.assertEqual(store.read_hidden(0, 1000), hidden)
            # Rewriting identical primary data MUST still refresh carrier IVs.
            initial = list(self.device.state)
            store.write_primary(offset, value)
            self.assertTrue(all(initial[i][-12:] != self.device.state[i][-12:] for i in range(64)))
            # Tail sectors contain no hidden records, but still need fresh IVs.
            tail = 99 * 4096 + 100
            store.write_primary(tail, b'tail')
            before[tail:tail + 4] = b'tail'
            self.assertEqual(self.plain(), bytes(before))
            store.truncate_hidden(0)
            store.flush()
        with self.store() as store:
            self.assertEqual(store.hidden_size(), 0)
        self.assertEqual(self.plain(), bytes(before))

    def test_crash_rollforward_no_reencryption_or_hidden_loss(self):
        for phase in ('reserved', 'journaled', 'applied:0', 'applied:31', 'ended', 'forgotten', 'resumed'):
            with self.subTest(phase=phase):
                self.device = WritableDevice(sectors=100)
                self.state = Path(self.temp.name) / phase.replace(':', '-')
                with self.store(True) as store:
                    store.write_hidden(0, b'hidden stays')
                    store.flush()
                    before = self.plain()
                    def crash(current):
                        if phase == current:
                            raise RuntimeError('simulated controller death')
                    store._checkpoint = crash
                    with self.assertRaises(RuntimeError):
                        store.write_primary(40 * 4096 + 3, b'primary changes')
                preparations = self.device.preparations
                with self.store() as recovered:
                    self.assertEqual(recovered.read_hidden(0, 100), b'hidden stays')
                    expected = bytearray(before)
                    if phase != 'reserved':
                        expected[40 * 4096 + 3:40 * 4096 + 18] = b'primary changes'
                    self.assertEqual(self.plain(), bytes(expected))
                self.assertEqual(self.device.preparations, preparations)

    def test_corrupt_sparse_journal_refused_before_any_apply(self):
        with self.store(True) as store:
            store.flush()
            def crash(phase):
                if phase == 'journaled':
                    raise RuntimeError('stop')
            store._checkpoint = crash
            with self.assertRaises(RuntimeError):
                store.write_primary(4096, b'new')
        before = list(self.device.state)
        path = self.state / 'pending-v2'
        raw = bytearray(path.read_bytes()); raw[-1] ^= 1
        path.write_bytes(raw)
        with self.assertRaises(UnsupportedImage):
            self.store()
        self.assertEqual(before, self.device.state)

    def test_record_address_binding_wrong_key_and_corruption(self):
        records = Records(100, b'context', self.key)
        value = records.encode(1, bytes(PAYLOAD))
        self.assertEqual(records.decode(1, value), bytes(PAYLOAD))
        for index, encoded in ((2, value), (1, value[:-1] + bytes([value[-1] ^ 1]))):
            with self.assertRaises(UnsupportedImage):
                records.decode(index, encoded)
        with self.assertRaises(UnsupportedImage):
            Records(100, b'context', secrets.token_bytes(32)).decode(1, value)

    def test_hidden_only_decode_independent_of_primary_key(self):
        with self.store(True) as store:
            store.write_hidden(0, b'extracted without primary key')
            store.flush()
            image = store.description
            image.iv_slots = lambda: (value[-12:] for value in self.device.state)
            self.assertEqual(decode_image(image, self.key), b'extracted without primary key')
            with self.assertRaises(UnsupportedImage):
                decode_image(image, secrets.token_bytes(32))

    def test_sparse_missing_record_coverage_rejected_before_apply(self):
        with self.store(True) as store:
            store.flush()
            old = self.device.state[32][-12:]
            iv = secrets.token_bytes(12)
            store.ledger.reserve([iv])
            store.device.suspend(); store.device.begin()
            candidate = store.device.prepare(32, old, iv)
            store.journal.create(iv, [(32, old, candidate)])
        before = list(self.device.state)
        with self.assertRaises(UnsupportedImage):
            self.store()
        self.assertEqual(before, self.device.state)

    def test_sparse_address_order_and_wrong_key_rejected(self):
        path = Path(self.temp.name) / 'journal'
        journal = SparseJournal(path, self.key, b'context', 100)
        ivs = [secrets.token_bytes(12) for _ in range(2)]
        old = secrets.token_bytes(12)
        with self.assertRaises(ValueError):
            journal.create(b''.join(ivs), [(32, old, bytes(4112) + ivs[0]),
                                          (31, old, bytes(4112) + ivs[1])])
        self.assertFalse(path.exists())
        journal.create(ivs[0], [(99, old, bytes(4112) + ivs[0])])
        journal.load()
        self.assertEqual(next(journal.entries())[0], 99)
        with self.assertRaises(UnsupportedImage):
            SparseJournal(path, secrets.token_bytes(32), b'context', 100).load()

    def test_nbd_writes_fua_flush_and_rejections(self):
        with self.store(True) as store:
            left, right = socket.socketpair()
            thread = threading.Thread(target=nbd.session, args=(left, store))
            thread.start()
            try:
                nbd.receive(right, 18)
                right.sendall(struct.pack('>I', 3))
                right.sendall(struct.pack('>QII', nbd.OPTION_MAGIC, 1, 0))
                size, flags = struct.unpack('>QH', nbd.receive(right, 10))
                self.assertEqual(flags, 13)
                def request(cmd, off=0, value=b'', flags=0, length=None):
                    right.sendall(struct.pack('>IHHQQI', nbd.REQUEST_MAGIC, flags, cmd, 42, off,
                                              len(value) if length is None else length) + value)
                    magic, error, handle = struct.unpack('>IIQ', nbd.receive(right, 16))
                    self.assertEqual((magic, handle), (nbd.REPLY_MAGIC, 42))
                    return error
                self.assertEqual(request(1, 511, b'nbd-primary', flags=1), 0)
                self.assertEqual(request(3), 0)
                self.assertEqual(request(0, 511, length=11), 0)
                self.assertEqual(nbd.receive(right, 11), b'nbd-primary')
                self.assertEqual(request(1, 0, b'x', flags=2), errno.EINVAL)
                self.assertEqual(request(4), errno.EPERM)
                right.sendall(struct.pack('>IHHQQI', nbd.REQUEST_MAGIC, 0, 2, 0, 0, 0))
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
            finally:
                right.close(); left.close()
