"""Strict setup/lifecycle policy for the disposable pinned QEMU guest only."""
import fcntl
import glob
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

from .kernel_api import KernelDevice, dm, validate_integrity_table
from .profile import parse_superblock, validate_segment
from .recovery import fsync_dir


def guest_guard(source, allow_test_stack=False):
    if (os.geteuid() != 0 or os.uname().release != '6.12.113+deb13-amd64' or
            Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'):
        raise ValueError('Kernel setup is restricted to the pinned disposable QEMU guest')
    allowed = ['/dev/vdb']
    if allow_test_stack:
        allowed += ['/dev/mapper/piv-test-delay', '/dev/mapper/piv-test-fault']
    if str(source) not in allowed or not stat.S_ISBLK(Path(source).stat().st_mode):
        raise ValueError('Unsupported disposable test device')
    size = subprocess.check_output(['blockdev', '--getsize64', str(source)], text=True)
    if int(size) != 128 * 1024 * 1024:
        raise ValueError('Expected a 128 MiB disposable guest disk')


def crypt(*args):
    return subprocess.run(['cryptsetup', *map(str, args)], check=True,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class GuestOwner:
    def __init__(self, source, passphrase_file, name='piv-native', *, allow_test_stack=False):
        self.lock_fd = None
        self.device = None
        self.name = name
        self.view_name = name + '-view'  # Cleanup of retired RO wrappers only.
        self.lower_name = name + '_dif'
        self.source = Path(source)
        if not re.fullmatch(r'piv-[a-zA-Z0-9_-]{1,40}', name):
            raise ValueError('Invalid experimental mapping name')
        guest_guard(self.source, allow_test_stack)
        metadata = json.loads(crypt('luksDump', '--dump-json-metadata', self.source).stdout)
        self.offset = validate_segment(metadata)
        self.uuid = str(uuid.UUID(crypt('luksUUID', self.source).stdout.strip()))
        self.raw_device = self.source.stat().st_rdev
        directory = Path('/run/pivstore')
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('Invalid global owner-lock directory')
        created = False
        try:
            self.lock_fd = os.open(directory / (self.uuid + '.lock'),
                                   os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Invalid global owner lock')
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Only static format fields: live journal recovery belongs to Linux.
            raw = os.open(self.source, os.O_RDONLY)
            try:
                self.layout = parse_superblock(os.pread(raw, 4096, self.offset),
                                               self.offset, 128 * 1024 * 1024)
            finally:
                os.close(raw)
            existing = dm('info', name, check=False).returncode == 0
            if not existing:
                holders = Path(f'/sys/dev/block/{os.major(self.raw_device)}:{os.minor(self.raw_device)}/holders')
                if list(holders.iterdir()):
                    raise ValueError('Disposable device already has an independent mapping')
                crypt('open', '--disable-keyring', '--key-file', passphrase_file, self.source, name)
                created = True
                owner_size = int(subprocess.check_output(['blockdev', '--getsize64', '/dev/mapper/' + name]))
                validate_integrity_table(dm('table', self.lower_name).stdout, owner_size // 4096,
                                         self.raw_device, self.offset)
                # Key-containing table is kept in memory and sent only through stdin.
                fields = dm('table', '--showkeys', name).stdout.split()
                if fields[2:4] != ['crypt', 'capi:gcm(aes)-random']:
                    raise ValueError('Unexpected primary mapping cipher')
                fields[8] = str(int(fields[8]) + 1)
                fields.append('piv_control')
                dm('suspend', name)
                dm('reload', name, input=' '.join(fields) + '\n')
                dm('resume', name)
                del fields
            expected_uuid = 'CRYPT-LUKS2-' + self.uuid.replace('-', '') + '-' + name
            if dm('info', '-c', '--noheadings', '-o', 'uuid', name).stdout.strip() != expected_uuid:
                raise ValueError('Mapping does not belong to this disposable LUKS volume')
            subprocess.run(['udevadm', 'settle'], check=True)
            owner_path = '/dev/mapper/' + name
            matches = []
            for path in glob.glob('/dev/pivctl-*'):
                try:
                    matches.append(KernelDevice(path, owner_path))
                except ValueError:
                    pass
            if len(matches) != 1:
                for device in matches:
                    device.close()
                raise ValueError('Expected exactly one native control for owner')
            self.device = matches[0]
            self.lower_table = dm('table', self.lower_name).stdout
            self.device.validate_callback = self.validate
            self.validate()
        except BaseException:
            if created:
                dm('remove', '--retry', name, check=False)
                dm('remove', '--retry', self.lower_name, check=False)
            self.close()
            raise

    def validate(self):
        if self.device.sectors != self.layout.sectors:
            raise ValueError('Native geometry differs from supported superblock')
        table = dm('table', self.lower_name).stdout
        if table != self.lower_table:
            raise ValueError('Lower integrity mapping changed outside owner')
        validate_integrity_table(table, self.device.sectors, self.raw_device, self.offset)
        lower = Path('/dev/mapper/' + self.lower_name).stat().st_rdev
        if lower != self.device.lower_device:
            raise ValueError('Native control bound to unexpected lower device')
        raw_holders = Path(f'/sys/dev/block/{os.major(self.raw_device)}:{os.minor(self.raw_device)}/holders')
        lower_sys = Path(f'/sys/dev/block/{os.major(lower)}:{os.minor(lower)}').resolve().name
        if {p.name for p in raw_holders.iterdir()} != {lower_sys}:
            raise ValueError('Unexpected independent holder of backing storage')

    def remove(self):
        if self.device is not None:
            self.device.close()
        for name in (self.view_name, self.name, self.lower_name):
            if dm('info', name, check=False).returncode == 0:
                dm('remove', '--retry', name)

    def close(self):
        if self.device is not None:
            self.device.close()
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
