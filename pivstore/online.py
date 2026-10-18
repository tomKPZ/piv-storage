"""Single-owner regular-file service with serialized, whole-image commits.

The canonical path always names a complete old/new image. This deliberately
does not support direct block devices or independent backing-file mappings.
"""

from contextlib import AbstractContextManager
import errno
import fcntl
import os
from pathlib import Path
import stat
import tempfile
import threading

from . import blob
from .profile import Image, UnsupportedImage
from .sector import SectorCodec
from .writer import rewrite_open_image


class OnlineStore(AbstractContextManager):
    def __init__(self, path, primary_key, hidden_key, *, initialize=False,
                 max_sector_encryptions=1 << 20):
        self.path = Path(path).absolute()
        self.lock = threading.RLock()
        self.image = None
        self.lock_fd = None
        self.failed = False
        self.closed = False
        self.codec = SectorCodec(primary_key)
        if len(hidden_key) != 32:
            raise ValueError('Hidden key must contain exactly 32 bytes')
        self.primary_key = primary_key
        self.hidden_key = hidden_key
        self.encrypted_sectors = 0
        self.max_sector_encryptions = max_sector_encryptions
        try:
            # Stable lock survives replacement of the backing inode. Never
            # unlink it on close: doing so would permit two different lock inodes.
            self.lock_fd = os.open(str(self.path) + '.pivstore.lock',
                                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Invalid owner lock file')
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.image = Image(self.path, exclusive=True)
            self.primary_hash = self.image.verify(primary_key)
            self.primary_bytes = self.image.layout.primary_bytes
            self.capacity = self.image.layout.sectors * 12 - 64
            self.used_ivs = set(self.image.iv_slots())
            if len(self.used_ivs) != self.image.layout.sectors:
                raise UnsupportedImage('Repeated current primary IV; refusing online access')
            self.payload = bytearray() if initialize else bytearray(blob.decode(
                b''.join(self.image.iv_slots()), hidden_key, blob.context(self.image)))
            self.dirty = initialize
        except BaseException:
            self.close()
            raise

    def _check(self):
        if self.closed or self.failed:
            raise OSError(errno.EIO, 'Online store is closed or failed; restart required')
        try:
            self.image.check_unchanged()
            current = os.stat(self.path, follow_symlinks=False)
            held = os.fstat(self.image.fd)
            if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                raise UnsupportedImage('Backing path replaced outside owner')
        except (OSError, UnsupportedImage):
            self.failed = True
            raise

    def read_primary(self, offset, length):
        with self.lock:
            self._check()
            if offset < 0 or length < 0 or offset + length > self.primary_bytes:
                raise OSError(errno.EINVAL, 'Primary read outside export')
            if not length:
                return b''
            result = bytearray()
            try:
                for index in range(offset // 4096, (offset + length + 4095) // 4096):
                    data, tag = self.image.layout.offsets(index)
                    result.extend(self.codec.decrypt(index, self.image.read(4096, data),
                                                     self.image.read(28, tag)))
                self._check()
            except (OSError, UnsupportedImage):
                self.failed = True
                raise
            start = offset % 4096
            return bytes(result[start:start + length])

    def write_primary(self, offset, data):
        raise OSError(errno.EROFS, 'Primary view is read-only')

    def hidden_size(self):
        with self.lock:
            self._check()
            return len(self.payload)

    def read_hidden(self, offset, length):
        with self.lock:
            self._check()
            if offset < 0 or length < 0:
                raise OSError(errno.EINVAL, 'Invalid hidden read')
            return bytes(self.payload[offset:offset + length])

    def write_hidden(self, offset, data):
        with self.lock:
            self._check()
            end = offset + len(data)
            if offset < 0:
                raise OSError(errno.EINVAL, 'Invalid hidden write')
            if end > self.capacity:
                raise OSError(errno.ENOSPC, 'Hidden carrier capacity exceeded')
            if not data:
                return 0
            if end > len(self.payload):
                self.payload.extend(b'\0' * (end - len(self.payload)))
            self.payload[offset:end] = data
            self.dirty = True
            return len(data)

    def truncate_hidden(self, size):
        with self.lock:
            self._check()
            if size < 0 or size > self.capacity:
                raise OSError(errno.EINVAL if size < 0 else errno.ENOSPC, 'Invalid hidden size')
            if size < len(self.payload):
                del self.payload[size:]
            else:
                self.payload.extend(b'\0' * (size - len(self.payload)))
            self.dirty = True

    def _checkpoint(self, phase):
        """No-op boundary hook for process-crash/concurrency tests."""

    def flush(self):
        with self.lock:
            self._check()
            if not self.dirty:
                return
            count = self.image.layout.sectors
            if self.encrypted_sectors + count > self.max_sector_encryptions:
                raise OSError(errno.EDQUOT, 'Session encryption budget exhausted')
            # Reserve conservatively even if a later stage fails. This is not a
            # lifetime counter; trusted disposable lineage remains required.
            self.encrypted_sectors += count
            def plan(image, current):
                result = blob.make_plan(image, self.hidden_key, bytes(self.payload),
                                        self.used_ivs | current)
                self.used_ivs.update(result.values())
                return result

            replacement = None
            try:
                with tempfile.TemporaryDirectory(prefix='.pivstore-commit-',
                                                 dir=self.path.parent) as directory:
                    candidate_path = Path(directory) / 'image.img'
                    rewrite_open_image(self.image, candidate_path, self.primary_key, plan)
                    replacement = Image(candidate_path, exclusive=True)
                    self._checkpoint('prepared')
                    self._check()
                    os.replace(candidate_path, self.path)
                    self._checkpoint('published')
                    # Rename changes ctime. Refresh only after our own authorized
                    # replacement, while both inode locks and the path lock are held.
                    replacement.initial_stat = os.fstat(replacement.fd)
                    old = self.image
                    self.image = replacement
                    replacement = None
                    old.close()
                    fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    self._checkpoint('durable')
                    self.dirty = False
            except BaseException:
                self.failed = True
                raise
            finally:
                if replacement is not None:
                    replacement.close()

    def close(self):
        with self.lock:
            if self.image is not None:
                self.image.close()
            if self.lock_fd is not None:
                os.close(self.lock_fd)
                self.lock_fd = None
            self.closed = True

    def __exit__(self, *args):
        self.close()
