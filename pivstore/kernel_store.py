"""Whole-carrier commits through native prepared tuples and an external journal."""
import errno
import fcntl
import os
from pathlib import Path
import stat
import threading
from types import SimpleNamespace

from . import blob
from .online import OnlineStore
from .profile import UnsupportedImage
from .recovery import Journal, Ledger


class KernelStore(OnlineStore):
    def __init__(self, device, state_directory, hidden_key, uuid, *, initialize=False,
                 max_sector_encryptions=1 << 20):
        self.lock = threading.RLock()
        self.closed = False
        self.failed = False
        self.lock_fd = None
        self.device = device
        self.hidden_key = hidden_key
        self.state = Path(state_directory).absolute()
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise ValueError('Recovery directory must be a private real directory')
        if hasattr(device, 'validate_state'):
            device.validate_state(self.state)
        self.primary_bytes = device.sectors * 4096
        self.capacity = device.sectors * 12 - 64
        self.description = SimpleNamespace(uuid=uuid,
            layout=SimpleNamespace(primary_bytes=self.primary_bytes, sector_size=4096,
                                   sectors=device.sectors))
        self.identity = blob.context(self.description)
        if getattr(self, 'incremental', False):
            self.identity += b'/incremental/v2'
        self.journal = Journal(self.state / 'pending', hidden_key, self.identity, device.sectors)
        if getattr(self, 'incremental', False):
            self._format_setup()
        try:
            self.lock_fd = os.open(self.state / 'owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            lock_info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1:
                raise ValueError('Invalid kernel owner lock')
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.device.validate()
            self.device.suspend()
            self.device.begin()  # Adopt an orphaned transaction; never resume before recovery.
            if (self.state / 'ledger').exists():
                if initialize:
                    raise FileExistsError('Cannot reinitialize an existing nonce lineage')
                self.ledger = Ledger(self.state / 'ledger', hidden_key, self.identity,
                                     limit=max_sector_encryptions)
            else:
                if not initialize or self.journal.path.exists():
                    raise ValueError('Missing nonce lineage: explicit fresh initialization required')
                current = self._carrier()
                self.ledger = Ledger(self.state / 'ledger', hidden_key, self.identity,
                                     current=[current[i:i + 12] for i in range(0, len(current), 12)],
                                     limit=max_sector_encryptions)
            if self.journal.path.exists():
                self._replay()
            carrier = self._carrier()
            if any(carrier[i:i + 12] not in self.ledger.used for i in range(0, len(carrier), 12)):
                raise UnsupportedImage('Current IVs do not belong to the trusted nonce lineage')
            if self.ledger.initialized:
                self.payload = bytearray(self._decode_carrier(carrier) if getattr(self, 'incremental', False)
                                         else blob.decode(carrier, hidden_key, self.identity))
                self.dirty = False
            else:
                self.payload = bytearray()
                self.dirty = True
                if getattr(self, 'incremental', False):
                    self.committed = []
            self.device.end()
            self.device.resume()
        except BaseException:
            self.failed = True
            self.close()
            raise

    def _carrier(self):
        values = [self.device.read_iv(i, quiesced=True) for i in range(self.device.sectors)]
        if len(set(values)) != len(values):
            raise UnsupportedImage('Repeated current primary nonce')
        return b''.join(values)

    def _check(self):
        if self.failed or self.closed:
            raise OSError(errno.EIO, 'Kernel store failed/closed; recover before access')
        try:
            self.device.check()
        except BaseException:
            self.failed = True
            raise

    def read_primary(self, offset, length):
        raise OSError(errno.ENOTSUP, 'Use the native read-only primary presentation')

    def _replay(self):
        self.journal.load()  # No writes until all journal bytes authenticate.
        planned = set()
        for _, old, value in self.journal.entries():
            iv = value[-12:]
            if iv not in self.ledger.used or old not in self.ledger.used or iv in planned:
                raise UnsupportedImage('Unreserved or repeated recovery nonce')
            planned.add(iv)
        for index, old, value in self.journal.entries():
            self.device.apply(index, old, value, defer_flush=True)
            if (index + 1) % 32 == 0:
                self.device.sync()
            self._checkpoint(f'applied:{index}')
        carrier = self._carrier()
        blob.decode(carrier, self.hidden_key, self.identity)
        self.device.end()
        self._checkpoint('ended')
        self.ledger.initialized = True
        self.ledger.save()
        self.journal.remove()
        self._checkpoint('forgotten')
        self.device.begin()

    def flush(self):
        with self.lock:
            self._check()
            if not self.dirty:
                return
            try:
                self.device.validate()
                self.device.suspend()
                self.device.begin()
                old_carrier = self._carrier()
                for _ in range(16):
                    new = blob.encode(bytes(self.payload), self.hidden_key,
                                      self.device.sectors * 12, self.identity)
                    ivs = [new[i:i + 12] for i in range(0, len(new), 12)]
                    if len(set(ivs)) == len(ivs) and not self.ledger.used.intersection(ivs):
                        break
                else:
                    raise ValueError('Unable to encode without nonce collisions')
                self.ledger.reserve(ivs)
                self._checkpoint('reserved')

                def prepared():
                    for index, iv in enumerate(ivs):
                        old = old_carrier[index * 12:(index + 1) * 12]
                        yield index, old, self.device.prepare(index, old, iv)
                self.journal.create(new, prepared())
                self._checkpoint('journaled')
                self._replay()
                self.device.end()
                self.device.resume()
                self.dirty = False
                self._checkpoint('resumed')
            except BaseException:
                self.failed = True
                # Never resume after an uncertain transaction. The kernel also
                # blocks resume while its controller-owned transaction is pending.
                raise

    def close(self):
        with self.lock:
            self.device.close()
            if self.lock_fd is not None:
                os.close(self.lock_fd)
                self.lock_fd = None
            self.closed = True
