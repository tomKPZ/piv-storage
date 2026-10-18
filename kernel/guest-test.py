#!/usr/bin/env python3
"""Guest-only K0 test. DM tables containing test keys stay in process memory."""
import errno
import fcntl
import glob
import hashlib
import mmap
import os
import struct
import stat
import subprocess


def run(*args, **kw):
    return subprocess.run(args, check=True, **kw)


def digest():
    h = hashlib.sha256()
    with open('/dev/mapper/piv-kernel', 'rb', buffering=0) as src:
        while block := src.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def rejected(fn, expected):
    try:
        fn()
    except OSError as exc:
        assert exc.errno in expected, exc.errno
    else:
        raise AssertionError('operation unexpectedly accepted')


assert os.geteuid() == 0
assert os.uname().release == '6.12.113+deb13-amd64'
assert subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '/mnt/piv-work']).strip() == b'9p'
path = '/dev/mapper/piv-kernel'
assert not glob.glob('/dev/pivctl-*')
# Feature disabled: stock writes still work (rewrite the same synthetic plaintext).
fd = os.open(path, os.O_RDWR)
first = os.pread(fd, 4096, 0)
assert os.pwrite(fd, first, 0) == 4096
os.fsync(fd)
os.close(fd)
before = digest()
assert before == open('/mnt/piv-work/expected.sha256').read().strip()
table = subprocess.check_output(['dmsetup', 'table', '--showkeys', 'piv-kernel'], text=True).split()
assert table[2] == 'crypt' and len(table) == 9 + int(table[8])
table[8] = str(int(table[8]) + 1)
table.append('piv_control')
# Read-only owner mode cannot supply the required lower write access.
p = subprocess.run(['dmsetup', 'create', '--readonly', 'piv-unsupported'],
                   input=' '.join(table) + '\n', text=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
assert p.returncode != 0 and 'Invalid argument' in p.stderr
run('dmsetup', 'suspend', 'piv-kernel')
run('dmsetup', 'reload', 'piv-kernel', input=' '.join(table) + '\n', text=True)
run('dmsetup', 'resume', 'piv-kernel')
del table
run('udevadm', 'settle')
controls = glob.glob('/dev/pivctl-*')
assert len(controls) == 1
assert stat.S_IMODE(os.stat(controls[0]).st_mode) == 0o600
assert subprocess.check_output(['blockdev', '--getro', path]).strip() == b'0'
assert subprocess.check_output(['blockdev', '--getro', path + '_dif']).strip() == b'0'
ctl = os.open(controls[0], os.O_RDONLY)
fmt = '=IIQQIIIIII'
size = struct.calcsize(fmt)
query = (2 << 30) | (size << 16) | (ord('P') << 8)
buf = bytearray(size)
fcntl.ioctl(ctl, query, buf, True)
version, length, generation, sectors, sector_size, iv, tag, tup, flags, reserved = struct.unpack(fmt, buf)
assert (version, length, sector_size, iv, tag, tup, flags, reserved) == (1, size, 4096, 12, 16, 28, 3, 0)
assert sectors * 4096 == int(subprocess.check_output(['blockdev', '--getsize64', path]))
assert generation > 0
rejected(lambda: fcntl.ioctl(ctl, query + 1, buf), {errno.ENOTTY})
rejected(lambda: fcntl.ioctl(ctl, query, 0), {errno.EFAULT})
pid = os.fork()
if pid == 0:
    try:
        os.setgid(65534)
        os.setuid(65534)
        rejected(lambda: fcntl.ioctl(ctl, query, buf), {errno.EPERM})
        os._exit(0)
    except BaseException:
        os._exit(1)
assert os.waitpid(pid, 0)[1] == 0
# Bypass the writable owner's page cache to exercise its bio mutation filter.
fd = os.open(path, os.O_RDWR | os.O_DIRECT)
with mmap.mmap(-1, 4096) as block:
    rejected(lambda: os.pwrite(fd, block, 0), {errno.EIO, errno.EROFS})
# BLKDISCARD and BLKZEROOUT: must not modify primary even if rejected above map.
for operation in (0x1277, 0x127f):
    rejected(lambda: fcntl.ioctl(fd, operation, struct.pack('=QQ', 0, 4096)),
             {errno.EIO, errno.EROFS, errno.EOPNOTSUPP, errno.ENOTTY})
os.fsync(fd)
os.close(fd)
assert digest() == before
# The presentation also rejects buffered writes before they can dirty page cache.
run('dmsetup', 'create', '--readonly', 'piv-view',
    input=f'0 {sectors * 8} linear {path} 0\n', text=True)
assert subprocess.check_output(['blockdev', '--getro', '/dev/mapper/piv-view']).strip() == b'1'
view = os.open('/dev/mapper/piv-view', os.O_WRONLY)
rejected(lambda: os.pwrite(view, first, 0), {errno.EROFS, errno.EPERM})
os.close(view)
run('dmsetup', 'remove', '--retry', 'piv-view')
# Existing fd must not keep the target alive or dereference its freed cc.
# Stock cryptsetup's table parser does not recognize the opt-in token.
run('dmsetup', 'remove', '--retry', 'piv-kernel')
run('dmsetup', 'remove', '--retry', 'piv-kernel_dif')
rejected(lambda: fcntl.ioctl(ctl, query, buf), {errno.ENODEV})
assert not glob.glob('/dev/pivctl-*')
# The open control pins the module until release.
p = subprocess.run(['rmmod', 'dm_crypt'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
assert p.returncode != 0
os.close(ctl)
run('rmmod', 'dm_crypt')
run('modprobe', 'dm_crypt')
run('cryptsetup', 'open', '--readonly', '--key-file', '/mnt/piv-work/passphrase.key', '/dev/vdb', 'piv-kernel')
assert digest() == before
run('cryptsetup', 'close', 'piv-kernel')
open('/mnt/piv-work/result.txt', 'w').write('K0 query/filter/lifetime and stock readback passed\n')
