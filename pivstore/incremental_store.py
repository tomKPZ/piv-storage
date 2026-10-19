"""Opt-in v2 record store and coordinated, write-through primary I/O.

Direct native primary mappings remain private/read-only. Writable access must
pass through this owner (NBD) so each touched record is freshly randomized.
"""
import errno
import os

from .kernel_store import KernelStore
from .profile import UnsupportedImage
from .records import Records, SECTORS
from .recovery import SparseJournal


class IncrementalStore(KernelStore):
    primary_writable = True

    def __init__(self, device, state_directory, hidden_key, uuid, *, initialize=False,
                 max_sector_encryptions=1 << 20):
        # Reuse ownership/adoption/recovery ordering from KernelStore, but replace
        # only its format-dependent hooks through a deliberately explicit flag.
        self.incremental = True
        super().__init__(device, state_directory, hidden_key, uuid,
                         initialize=initialize, max_sector_encryptions=max_sector_encryptions)

    def _format_setup(self):
        if getattr(self.device, 'flags', 15) != 15:
            raise ValueError('Kernel does not support coordinated primary I/O')
        self.records = Records(self.device.sectors, self.identity, self.hidden_key)
        self.capacity = self.records.capacity
        self.journal = SparseJournal(self.state / 'pending-v2', self.hidden_key,
                                     self.identity + b'/incremental/v2', self.device.sectors)

    def _decode_carrier(self, carrier):
        self.committed = [self.records.decode(i, carrier[i * SECTORS * 12:(i + 1) * SECTORS * 12])
                          for i in range(self.records.count)]
        return self.records.payload(self.committed)

    def _read_indices(self, indices):
        return {i: self.device.read_iv(i, quiesced=True) for i in indices}

    def _replay(self):
        self.journal.load()
        planned = set()
        touched = set()
        for index, old, value in self.journal.entries():
            iv = value[-12:]
            if iv not in self.ledger.used or old not in self.ledger.used or iv in planned:
                raise UnsupportedImage('Unreserved/repeated sparse recovery nonce')
            planned.add(iv)
            if index // SECTORS < self.records.count:
                touched.add(index // SECTORS)
        # Every touched hidden record must be wholly represented, never a partial
        # refresh. Validate coverage before any primary write, including recovery.
        indices = {i for i, _, _ in self.journal.entries()}
        if any(not set(range(r * SECTORS, (r + 1) * SECTORS)) <= indices for r in touched):
            raise UnsupportedImage('Incomplete incremental record transaction')
        for ordinal, (index, old, value) in enumerate(self.journal.entries()):
            self.device.apply_primary(index, old, value, defer_flush=True)
            if (ordinal + 1) % 32 == 0:
                self.device.sync()
            self._checkpoint(f'applied:{ordinal}')
        # Compare all resulting tuples' IVs against the authenticated plan, then
        # authenticate every touched hidden record before acknowledging durability.
        for index, _, value in self.journal.entries():
            if self.device.read_iv(index, quiesced=True) != value[-12:]:
                raise UnsupportedImage('Sparse replay did not install planned IV')
        for r in touched:
            carrier = b''.join(self.device.read_iv(i, quiesced=True)
                               for i in range(r * SECTORS, (r + 1) * SECTORS))
            self.records.decode(r, carrier)
        self.device.end()
        self._checkpoint('ended')
        self.ledger.initialized = True
        self.ledger.save()
        self.journal.remove()
        self._checkpoint('forgotten')
        self.device.begin()

    def _commit(self, changed, primary):
        try:
            self.device.validate()
            self.device.suspend()
            self.device.begin()
            indices = sorted(set(primary) | {i for r in changed for i in range(r * SECTORS, (r + 1) * SECTORS)})
            old = self._read_indices(indices)
            if any(iv not in self.ledger.used for iv in old.values()):
                raise UnsupportedImage('Unrecognized current IV lineage')
            for _ in range(16):
                ivs = {}
                for r, value in changed.items():
                    carrier = self.records.encode(r, value)
                    ivs.update({r * SECTORS + j: carrier[j * 12:(j + 1) * 12] for j in range(SECTORS)})
                for i in primary.keys() - ivs.keys():
                    ivs[i] = os.urandom(12)  # Unused tail sectors carry no records.
                values = list(ivs.values())
                if len(set(values)) == len(values) and not self.ledger.used.intersection(values):
                    break
            else:
                raise ValueError('Unable to generate fresh incremental IVs')
            self.ledger.reserve(values)
            self._checkpoint('reserved')

            def prepared():
                for index in indices:
                    if index in primary:
                        value = self.device.prepare_primary(index, old[index], ivs[index], primary[index])
                    else:
                        value = self.device.prepare(index, old[index], ivs[index])
                    yield index, old[index], value
            self.journal.create(b''.join(ivs[i] for i in indices), prepared())
            self._checkpoint('journaled')
            self._replay()
            self.device.end()
            self.device.resume()
            self._checkpoint('resumed')
        except BaseException:
            self.failed = True
            raise

    def flush(self):
        with self.lock:
            self._check()
            if not self.dirty:
                return
            values = self.records.values(bytes(self.payload))
            changed = {i: value for i, value in enumerate(values)
                       if not self.ledger.initialized or value != self.committed[i]}
            if changed:
                self._commit(changed, {})
            self.committed = values
            self.dirty = False

    def read_primary(self, offset, length):
        with self.lock:
            self._check()
            if offset < 0 or length < 0 or offset + length > self.primary_bytes:
                raise OSError(errno.EINVAL, 'Primary read outside export')
            if not length:
                return b''
            result = b''.join(self.device.read_primary_sector(i)
                              for i in range(offset // 4096, (offset + length + 4095) // 4096))
            return result[offset % 4096:offset % 4096 + length]

    def write_primary(self, offset, data):
        with self.lock:
            self._check()
            if offset < 0 or offset + len(data) > self.primary_bytes or len(data) > 1024 * 1024:
                raise OSError(errno.EINVAL, 'Primary write outside export/request limit')
            if not data:
                return 0
            # Durably commit buffered hidden edits before primary refreshes, so
            # recovery always preserves one unambiguous committed hidden state.
            self.flush()
            first = offset // 4096
            end = (offset + len(data) + 4095) // 4096
            primary = {}
            for i in range(first, end):
                lo, hi = max(offset, i * 4096), min(offset + len(data), (i + 1) * 4096)
                value = bytearray(self.device.read_primary_sector(i))
                value[lo - i * 4096:hi - i * 4096] = data[lo - offset:hi - offset]
                primary[i] = bytes(value)
            touched = {i // SECTORS for i in primary if i // SECTORS < self.records.count}
            self._commit({r: self.committed[r] for r in touched}, primary)
            return len(data)
