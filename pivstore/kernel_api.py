"""Experimental native control ABI. Setup/ownership remains guest-controller policy."""
import errno
import fcntl
import os
from pathlib import Path
import re
import stat
import struct
import subprocess

READ = struct.Struct('=IIQQ16sII')
UPDATE = struct.Struct('=IIQQ16sI4128sI')
QUERY = struct.Struct('=IIQQIIIIII')


def command(number, size, direction=3):
    return direction << 30 | size << 16 | ord('P') << 8 | number


def dm(*args, input=None, check=True):
    # Never pass keys or tuple data as command arguments.
    result = subprocess.run(['dmsetup', '--noudevsync', *args], input=input, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)
    if result.returncode == 0 and args and args[0] in ('create', 'resume'):
        subprocess.run(['dmsetup', '--noudevsync', 'mknodes', args[1]], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result


def mapping_identity(name):
    """DM UUID plus device number, without reading any key-containing table."""
    result = dm('info', '-c', '--noheadings', '--separator', ',',
                '-o', 'major,minor,uuid', name, check=False)
    if result.returncode:
        return None
    fields = tuple(word.strip() for word in result.stdout.strip().split(','))
    if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
        raise ValueError('Invalid mapping identity')
    return fields


def remove_mapping(name, identity):
    current = mapping_identity(name)
    if current is None:
        return
    if current != identity:
        raise ValueError(f'Refusing to remove changed mapping {name}')
    dm('remove', '--retry', name)


def validate_integrity_table(table, sectors, raw_device, offset, sector_size=4096, journal_sectors=1848, tuple_size=28):
    if tuple_size not in (28, 32):
        raise ValueError('Unsupported lower tuple size')
    words = table.split()
    if (len(words) < 8 or words[:3] != ['0', str(sectors * (sector_size // 512)), 'integrity'] or
            words[3:7] != [f'{os.major(raw_device)}:{os.minor(raw_device)}',
                           str(offset // 512), str(tuple_size), 'J'] or
            int(words[7]) != len(words) - 8):
        raise ValueError('Unsupported lower integrity mapping')
    options = words[8:]
    required = {'interleave_sectors:32768', f'buffer_sectors:{128 if sector_size == 512 or tuple_size == 32 else 32}',
                'journal_watermark:50', 'commit_time:10000', 'fix_padding'}
    if sector_size == 4096:
        required.add('block_size:4096')
    elif sector_size != 512:
        raise ValueError('Unsupported lower sector size')
    if len(options) != len(required) + 1 or not required.issubset(options):
        raise ValueError('Unsupported lower integrity options')
    extra = set(options) - required
    if len(extra) != 1 or not next(iter(extra)).startswith('journal_sectors:'):
        raise ValueError('Unsupported lower integrity journal')
    journal = int(next(iter(extra)).split(':')[1])
    if journal != journal_sectors:
        raise ValueError('Unsupported lower integrity journal size')


class KernelDevice:
    def __init__(self, control, owner):
        self.fd = None
        self.control_path = str(control)
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
            if (v, size, tag, reserved) != (2, 48, 16, 0) or iv not in (12, 16) or tup != 16 + iv or sector not in (512, 4096) or flags not in (7, 15):
                raise ValueError('Unsupported kernel control/profile')
            devices = bytearray(16)
            fcntl.ioctl(self.fd, command(7, 16, 2), devices, True)
            major, minor, low_major, low_minor = struct.unpack('=IIII', devices)
            info = self.owner.stat()
            if not stat.S_ISBLK(info.st_mode) or info.st_rdev != os.makedev(major, minor):
                raise ValueError('Control is bound to a different owner')
            self.lower_device = os.makedev(low_major, low_minor)
            self.iv_size = iv
            self.tuple_size = tup
            self.sector_size = sector
            self.flags = flags
            self.validate_callback = None
        except BaseException:
            self.close()
            raise

    def check(self):
        data = bytearray(QUERY.size)
        fcntl.ioctl(self.fd, command(0, QUERY.size, 2), data, True)
        value = QUERY.unpack(data)
        if value[2:4] != (self.generation, self.sectors) or value[8] != self.flags:
            raise OSError(errno.ESTALE, 'Kernel owner changed')

    def validate(self):
        self.check()
        if self.validate_callback is None:
            raise ValueError('Missing lower-journal validation policy')
        self.validate_callback()

    def request(self, index=0):
        return bytearray(READ.pack(2, READ.size, self.generation, index, bytes(16), 0, 0))

    def read_iv(self, index, *, quiesced=False):
        data = self.request(index)
        fcntl.ioctl(self.fd, command(2 if quiesced else 1, READ.size), data, True)
        return READ.unpack(data)[4][:self.iv_size]

    def begin(self):
        fcntl.ioctl(self.fd, command(5, READ.size, 1), self.request(), True)

    def end(self):
        fcntl.ioctl(self.fd, command(6, READ.size, 1), self.request(), True)

    def sync(self):
        fcntl.ioctl(self.fd, command(8, READ.size, 1), self.request(), True)

    def prepare(self, index, old_iv, new_iv):
        if len(old_iv) != self.iv_size or len(new_iv) != self.iv_size:
            raise ValueError('Invalid IV size')
        data = bytearray(UPDATE.pack(2, UPDATE.size, self.generation, index,
                                    old_iv, 0, bytes(4112) + new_iv.ljust(16, b'\0'), 0))
        fcntl.ioctl(self.fd, command(3, UPDATE.size), data, True)
        result = UPDATE.unpack(data)
        if result[:6] != (2, UPDATE.size, self.generation, index, old_iv.ljust(16, b'\0'), 0) or result[7] or result[6][4112:4112 + self.iv_size] != new_iv:
            raise OSError(errno.EIO, 'Invalid prepare response')
        return result[6]

    def apply(self, index, old_iv, prepared, *, defer_flush=False):
        if len(old_iv) != self.iv_size or len(prepared) != 4128:
            raise ValueError('Invalid tuple size')
        data = bytearray(UPDATE.pack(2, UPDATE.size, self.generation, index,
                                    old_iv, int(defer_flush), prepared, 0))
        fcntl.ioctl(self.fd, command(4, UPDATE.size, 1), data, True)

    def read_primary_sector(self, index):
        data = bytearray(UPDATE.pack(2, UPDATE.size, self.generation, index,
                                    bytes(16), 0, bytes(4128), 0))
        fcntl.ioctl(self.fd, command(9, UPDATE.size), data, True)
        return UPDATE.unpack(data)[6][:self.sector_size]

    def prepare_primary(self, index, old_iv, new_iv, plaintext):
        if len(plaintext) != self.sector_size or len(old_iv) != self.iv_size or len(new_iv) != self.iv_size:
            raise ValueError('Invalid primary preparation')
        data = bytearray(UPDATE.pack(2, UPDATE.size, self.generation, index,
                                    old_iv, 0, plaintext.ljust(4096, b'\0') + bytes(16) + new_iv.ljust(16, b'\0'), 0))
        fcntl.ioctl(self.fd, command(10, UPDATE.size), data, True)
        value = UPDATE.unpack(data)[6]
        if value[4112:4112 + self.iv_size] != new_iv:
            raise OSError(errno.EIO, 'Invalid primary prepare response')
        return value

    def apply_primary(self, index, old_iv, prepared, *, defer_flush=False):
        if len(old_iv) != self.iv_size or len(prepared) != 4128:
            raise ValueError('Invalid primary tuple')
        data = bytearray(UPDATE.pack(2, UPDATE.size, self.generation, index,
                                    old_iv, int(defer_flush), prepared, 0))
        fcntl.ioctl(self.fd, command(11, UPDATE.size, 1), data, True)

    def suspend(self):
        dm('suspend', self.name)

    def resume(self):
        dm('resume', self.name)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
