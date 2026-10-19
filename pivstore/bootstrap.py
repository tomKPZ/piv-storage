"""One-time, recoverable adoption of the fixed native hidden block volume.

No serving interface or primary-data writes. Existing bootstrap ledger/pending-v2
bytes remain compatible; the kernel owns all I/O after native READY adoption.
"""
from contextlib import AbstractContextManager
import fcntl
import os
from pathlib import Path
import stat
from types import SimpleNamespace

from .blob import context
from .profile import UnsupportedImage
from .records import Records, SECTORS
from .recovery import Ledger, SparseJournal


class NativeBootstrap(AbstractContextManager):
    def __init__(self, device, state_directory, hidden_key, uuid, capacity, *, initialize=False):
        self.device = device
        self.lock_fd = None
        self.state = Path(state_directory).absolute()
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.capacity = capacity
        self.identity = context(SimpleNamespace(uuid=uuid, layout=SimpleNamespace(
            primary_bytes=device.sectors * 4096, sector_size=4096))) + b'/incremental/v2'
        self.records = Records(device.sectors, self.identity, hidden_key)
        self.journal = SparseJournal(self.state / 'pending-v2', hidden_key,
                                     self.identity + b'/incremental/v2', device.sectors)
        try:
            if (capacity != self.records.capacity // 512 * 512 or
                    getattr(device, 'flags', 15) != 15):
                raise ValueError('Unsupported native bootstrap geometry/profile')
            info = self.state.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
                raise ValueError('Recovery directory must be a private real directory')
            if hasattr(device, 'validate_state'):
                device.validate_state(self.state)
            self.lock_fd = os.open(self.state / 'owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Invalid bootstrap lock')
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            device.validate()
            device.suspend()
            device.begin()  # Recover an orphan before ever resuming the owner.
            ledger = self.state / 'ledger'
            if ledger.exists():
                if initialize:
                    raise FileExistsError('Cannot reinitialize an existing nonce lineage')
                self.ledger = Ledger(ledger, hidden_key, self.identity)
            else:
                if not initialize or self.journal.path.exists():
                    raise ValueError('Missing nonce lineage: explicit fresh initialization required')
                self.ledger = Ledger(ledger, hidden_key, self.identity, current=self._carrier())
            if self.journal.path.exists():
                self._replay()
            current = self._carrier()
            if not set(current) <= self.ledger.used:
                raise UnsupportedImage('Current IVs do not belong to the trusted nonce lineage')
            if not self.ledger.initialized:
                self._initialize(current)
            self._verify_volume()
            device.end()
            device.resume()
            self._checkpoint('resumed')
        except BaseException:
            self.close()
            raise

    def _carrier(self):
        values = [self.device.read_iv(i, quiesced=True) for i in range(self.device.sectors)]
        if len(set(values)) != len(values):
            raise UnsupportedImage('Repeated current primary nonce')
        return values

    def _verify_volume(self):
        carrier = b''.join(self._carrier())
        values = [self.records.decode(i, carrier[i * 384:(i + 1) * 384])
                  for i in range(self.records.count)]
        if len(self.records.payload(values)) != self.capacity:
            raise UnsupportedImage('Native block mode requires the fixed-capacity record format')

    def _initialize(self, old):
        values = self.records.values(bytes(self.capacity))
        for _ in range(16):
            encoded = b''.join(self.records.encode(i, value) for i, value in enumerate(values))
            ivs = [encoded[i:i + 12] for i in range(0, len(encoded), 12)]
            if len(set(ivs)) == len(ivs) and not self.ledger.used.intersection(ivs):
                break
        else:
            raise ValueError('Unable to generate fresh bootstrap IVs')
        self.ledger.reserve(ivs)
        self._checkpoint('reserved')

        def prepared():
            for i, iv in enumerate(ivs):
                yield i, old[i], self.device.prepare(i, old[i], iv)
        self.journal.create(encoded, prepared())
        self._checkpoint('journaled')
        self._replay()

    def _checkpoint(self, phase):
        """Test hook at persistent boundaries; never changes production ordering."""

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
            self.device.apply(index, old, value, defer_flush=True)
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

    def close(self):
        try:
            self.device.close()
        finally:
            if self.lock_fd is not None:
                os.close(self.lock_fd)
                self.lock_fd = None

    def __exit__(self, *args):
        self.close()
