"""Experimental native control ABI. Setup/ownership remains guest-controller policy."""
import errno
import fcntl
import os
from pathlib import Path
import re
import stat
import struct
import subprocess

READ = struct.Struct('=IIQQ12sIII')
UPDATE = struct.Struct('=IIQQ12sI4124sI')
QUERY = struct.Struct('=IIQQIIIIII')


def command(number, size, direction=3):
    return direction << 30 | size << 16 | ord('P') << 8 | number


def dm(*args, input=None, check=True):
    # Never pass keys or tuple data as command arguments.
    return subprocess.run(['dmsetup', *args], input=input, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def validate_integrity_table(table, sectors, raw_device, offset):
    words = table.split()
    if (len(words) < 8 or words[:3] != ['0', str(sectors * 8), 'integrity'] or
            words[3:7] != [f'{os.major(raw_device)}:{os.minor(raw_device)}',
                           str(offset // 512), '28', 'J'] or
            int(words[7]) != len(words) - 8):
        raise ValueError('Unsupported lower integrity mapping')
    options = words[8:]
    required = {'block_size:4096', 'interleave_sectors:32768', 'buffer_sectors:32',
                'journal_watermark:50', 'commit_time:10000', 'fix_padding'}
    if len(options) != 7 or not required.issubset(options):
        raise ValueError('Unsupported lower integrity options')
    extra = set(options) - required
    if len(extra) != 1 or not next(iter(extra)).startswith('journal_sectors:'):
        raise ValueError('Unsupported lower integrity journal')
    journal = int(next(iter(extra)).split(':')[1])
    if journal != 1848:
        raise ValueError('Unsupported lower integrity journal size')


class KernelDevice:
    def __init__(self, control, owner):
        self.fd = None
        self.owner = Path(owner)
        self.name = self.owner.name
        if not re.fullmatch(r'piv-[a-zA-Z0-9_-]+', self.name):
            raise ValueError('Experimental owner must have a piv- name')
        try:
            self.fd = os.open(control, os.O_RDWR | os.O_NOFOLLOW)
            if not stat.S_ISCHR(os.fstat(self.fd).st_mode):
                raise ValueError('Control must be a character device')
            data = bytearray(QUERY.size)
            fcntl.ioctl(self.fd, command(0, QUERY.size, 2), data, True)
            v, size, self.generation, self.sectors, sector, iv, tag, tup, flags, reserved = QUERY.unpack(data)
            if (v, size, sector, iv, tag, tup, flags, reserved) != (1, 48, 4096, 12, 16, 28, 7, 0):
                raise ValueError('Unsupported kernel control/profile')
            devices = bytearray(16)
            fcntl.ioctl(self.fd, command(7, 16, 2), devices, True)
            major, minor, low_major, low_minor = struct.unpack('=IIII', devices)
            info = self.owner.stat()
            if not stat.S_ISBLK(info.st_mode) or info.st_rdev != os.makedev(major, minor):
                raise ValueError('Control is bound to a different owner')
            self.lower_device = os.makedev(low_major, low_minor)
            self.validate_callback = None
        except BaseException:
            self.close()
            raise

    def validate_state(self, directory):
        if os.stat(directory).st_dev != os.stat('/').st_dev:
            raise ValueError('Recovery state must be on the guest root filesystem')
        filesystem = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(directory)],
                                            text=True).strip()
        if filesystem != 'ext4':
            raise ValueError('Recovery state requires the pinned local ext4 root')

    def check(self):
        data = bytearray(QUERY.size)
        fcntl.ioctl(self.fd, command(0, QUERY.size, 2), data, True)
        value = QUERY.unpack(data)
        if value[2:4] != (self.generation, self.sectors) or value[8] != 7:
            raise OSError(errno.ESTALE, 'Kernel owner changed')

    def validate(self):
        self.check()
        if self.validate_callback is None:
            raise ValueError('Missing lower-journal validation policy')
        self.validate_callback()

    def request(self, index=0):
        return bytearray(READ.pack(1, READ.size, self.generation, index, bytes(12), 0, 0, 0))

    def read_iv(self, index, *, quiesced=False):
        data = self.request(index)
        fcntl.ioctl(self.fd, command(2 if quiesced else 1, READ.size), data, True)
        return READ.unpack(data)[4]

    def begin(self):
        fcntl.ioctl(self.fd, command(5, READ.size, 1), self.request(), True)

    def end(self):
        fcntl.ioctl(self.fd, command(6, READ.size, 1), self.request(), True)

    def sync(self):
        fcntl.ioctl(self.fd, command(8, READ.size, 1), self.request(), True)

    def prepare(self, index, old_iv, new_iv):
        if len(old_iv) != 12 or len(new_iv) != 12:
            raise ValueError('Invalid IV size')
        data = bytearray(UPDATE.pack(1, UPDATE.size, self.generation, index,
                                    old_iv, 0, bytes(4112) + new_iv, 0))
        fcntl.ioctl(self.fd, command(3, UPDATE.size), data, True)
        result = UPDATE.unpack(data)
        if result[:6] != (1, UPDATE.size, self.generation, index, old_iv, 0) or result[7] or result[6][-12:] != new_iv:
            raise OSError(errno.EIO, 'Invalid prepare response')
        return result[6]

    def apply(self, index, old_iv, prepared, *, defer_flush=False):
        if len(old_iv) != 12 or len(prepared) != 4124:
            raise ValueError('Invalid tuple size')
        data = bytearray(UPDATE.pack(1, UPDATE.size, self.generation, index,
                                    old_iv, int(defer_flush), prepared, 0))
        fcntl.ioctl(self.fd, command(4, UPDATE.size, 1), data, True)

    def suspend(self):
        dm('suspend', self.name)

    def resume(self):
        dm('resume', self.name)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
