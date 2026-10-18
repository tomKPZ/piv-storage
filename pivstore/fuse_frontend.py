"""One direct-I/O FUSE file. Optional guest-only dependencies are imported here."""

import errno
import os
import stat
import time

import pyfuse3
import trio

from .profile import UnsupportedImage


class HiddenFile(pyfuse3.Operations):
    enable_writeback_cache = False

    def __init__(self, store):
        super().__init__()
        self.store = store
        self.stamp = time.time_ns()

    def call(self, function, *args):
        try:
            return function(*args)
        except UnsupportedImage:
            raise pyfuse3.FUSEError(errno.EIO) from None
        except OSError as exc:
            raise pyfuse3.FUSEError(exc.errno or errno.EIO) from None

    async def getattr(self, inode, ctx=None):
        if inode not in (pyfuse3.ROOT_INODE, 2):
            raise pyfuse3.FUSEError(errno.ENOENT)
        entry = pyfuse3.EntryAttributes()
        entry.st_ino = inode
        entry.st_mode = (stat.S_IFDIR | 0o700) if inode == 1 else (stat.S_IFREG | 0o600)
        entry.st_nlink = 2 if inode == 1 else 1
        entry.st_uid = os.getuid()
        entry.st_gid = os.getgid()
        entry.st_size = 0 if inode == 1 else self.call(self.store.hidden_size)
        entry.st_blksize = 4096
        entry.st_blocks = (entry.st_size + 511) // 512
        entry.st_atime_ns = self.stamp
        entry.st_mtime_ns = self.stamp
        entry.st_ctime_ns = self.stamp
        entry.attr_timeout = 0
        entry.entry_timeout = 0
        return entry

    async def lookup(self, parent_inode, name, ctx=None):
        if parent_inode != 1 or name != b'payload':
            raise pyfuse3.FUSEError(errno.ENOENT)
        return await self.getattr(2, ctx)

    async def opendir(self, inode, ctx):
        if inode != 1:
            raise pyfuse3.FUSEError(errno.ENOTDIR)
        return 1

    async def readdir(self, fh, start_id, token):
        if not start_id:
            pyfuse3.readdir_reply(token, b'payload', await self.getattr(2), 1)

    async def open(self, inode, flags, ctx):
        if inode != 2:
            raise pyfuse3.FUSEError(errno.ENOENT)
        if flags & os.O_TRUNC:
            self.call(self.store.truncate_hidden, 0)
        result = pyfuse3.FileInfo(fh=2)
        result.direct_io = True
        result.keep_cache = False
        return result

    async def read(self, fh, off, size):
        return self.call(self.store.read_hidden, off, size)

    async def write(self, fh, off, buf):
        result = self.call(self.store.write_hidden, off, bytes(buf))
        self.stamp = time.time_ns()
        return result

    async def setattr(self, inode, attr, fields, fh, ctx):
        if inode != 2:
            raise pyfuse3.FUSEError(errno.EPERM)
        if fields.update_mode or fields.update_uid or fields.update_gid:
            raise pyfuse3.FUSEError(errno.EOPNOTSUPP)
        if fields.update_size:
            self.call(self.store.truncate_hidden, attr.st_size)
        self.stamp = time.time_ns()
        return await self.getattr(inode, ctx)

    async def flush(self, fh):
        self.call(self.store.flush)

    async def fsync(self, fh, datasync):
        self.call(self.store.flush)

    async def release(self, fh):
        return None


def mount(store, mountpoint, *, fsname='pivstore'):
    options = set(pyfuse3.default_options)
    options.add('fsname=' + fsname)
    pyfuse3.init(HiddenFile(store), str(mountpoint), options)
    try:
        trio.run(pyfuse3.main)
        store.flush()
    finally:
        pyfuse3.close()
