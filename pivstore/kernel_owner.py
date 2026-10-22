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

from .format import PRIMARY_PROFILES
from .kernel_api import KernelDevice, dm, check_activation_flags, mapping_identity, remove_mapping, validate_integrity_table
from .profile import parse_superblock, validate_segment


PINNED_KERNEL = '6.12.113+deb13-amd64'
# Sanitizer (KASAN/UBSAN/lockdep) build of the same source, accepted only on a
# guest image explicitly marked by scripts/build_debug_kernel.py.
DEBUG_KERNEL = PINNED_KERNEL + '-pivdbg'
# Newer-kernel port target (Debian trixie-backports), accepted only on a guest
# image explicitly marked by scripts/build_port_image.py.
PORT_KERNEL = '7.2.9+deb13-amd64'


def pinned_release():
    release = os.uname().release
    return (release == PINNED_KERNEL or
            (release == DEBUG_KERNEL and Path('/etc/piv-debug-kernel').exists()) or
            (release == PORT_KERNEL and Path('/etc/piv-port-kernel').exists()))


def guest_guard(source, allow_test_stack=False, allow_second_disk=False):
    if (os.geteuid() != 0 or not pinned_release() or
            Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'):
        raise ValueError('Kernel setup is restricted to the pinned disposable QEMU guest')
    allowed = ['/dev/vdb']
    if allow_test_stack:
        allowed += ['/dev/mapper/piv-test-delay', '/dev/mapper/piv-test-fault']
    if allow_second_disk:
        # Explicit opt-in for migration tests: the pinned guest's second disposable disk.
        allowed += ['/dev/vdc']
    if str(source) not in allowed or not stat.S_ISBLK(Path(source).stat().st_mode):
        raise ValueError('Unsupported disposable test device')
    size = subprocess.check_output(['blockdev', '--getsize64', str(source)], text=True)
    size = int(size)
    if size not in (128 * 1024 * 1024, 512 * 1024 * 1024):
        raise ValueError('Expected an explicitly supported 128 or 512 MiB disposable guest disk')
    return size


def crypt(*args):
    return subprocess.run(['cryptsetup', *map(str, args)], check=True,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class GuestOwner:
    def __init__(self, source, passphrase_file, name='piv-native', *, allow_test_stack=False,
                 allow_second_disk=False):
        self.lock_fd = None
        self.device = None
        self.created = False
        self.mappings = {}
        self.name = name
        self.lower_name = name + '_dif'
        self.source = Path(source)
        if not re.fullmatch(r'piv-[a-zA-Z0-9_-]{1,40}', name):
            raise ValueError('Invalid experimental mapping name')
        self.raw_bytes = guest_guard(self.source, allow_test_stack, allow_second_disk)
        metadata = json.loads(crypt('luksDump', '--dump-json-metadata', self.source).stdout)
        self.offset = validate_segment(metadata)
        check_activation_flags(metadata)
        self.encryption = metadata['segments']['0']['encryption']
        self.integrity = metadata['segments']['0']['integrity']['type']
        self.mapping_cipher, self.profile_tag = PRIMARY_PROFILES[(self.encryption, self.integrity)]
        self.uuid = str(uuid.UUID(crypt('luksUUID', self.source).stdout.strip()))
        self.raw_device = self.source.stat().st_rdev
        directory = Path('/run/pivstore')
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('Invalid global owner-lock directory')
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
                                               self.offset, self.raw_bytes)
            finally:
                os.close(raw)
            if self.layout.iv_bytes != 16 or self.layout.tag_bytes != self.profile_tag:
                raise ValueError('LUKS profile and integrity tuple size disagree')
            if self.layout.sector_size != metadata['segments']['0']['sector_size']:
                raise ValueError('LUKS and integrity sector sizes disagree')
            existing = dm('info', name, check=False).returncode == 0
            if not existing:
                if mapping_identity(self.lower_name) is not None:
                    raise FileExistsError('Lower mapping name is already in use')
                holders = Path(f'/sys/dev/block/{os.major(self.raw_device)}:{os.minor(self.raw_device)}/holders')
                if list(holders.iterdir()):
                    raise ValueError('Disposable device already has an independent mapping')
                self.created = True
                try:
                    crypt('open', '--disable-keyring', '--key-file', passphrase_file, self.source, name)
                finally:
                    # A command can fail after the kernel created a mapping.
                    self.capture_created()
                if len(self.mappings) != 2:
                    raise ValueError('Created mapping identity is missing')
                owner_size = int(subprocess.check_output(['blockdev', '--getsize64', '/dev/mapper/' + name]))
                validate_integrity_table(dm('table', self.lower_name).stdout, owner_size // self.layout.sector_size,
                                         self.raw_device, self.offset, self.layout.sector_size,
                                         self.layout.journal_sections * self.layout.journal_section_sectors,
                                 self.layout.tuple_bytes)
                # Key-containing table is kept in memory and sent only through stdin.
                fields = dm('table', '--showkeys', name).stdout.split()
                if fields[2:4] != ['crypt', self.mapping_cipher]:
                    raise ValueError('Unexpected primary mapping cipher')
                fields[2] = 'piv-crypt'
                fields[8] = str(int(fields[8]) + 1)
                fields.append('piv_control')
                dm('suspend', name)
                dm('reload', name, input=' '.join(fields) + '\n')
                dm('resume', name)
                del fields
            expected_uuid = 'CRYPT-LUKS2-' + self.uuid.replace('-', '') + '-' + name
            if dm('info', '-c', '--noheadings', '-o', 'uuid', name).stdout.strip() != expected_uuid:
                raise ValueError('Mapping does not belong to this disposable LUKS volume')
            if not self.mappings:
                self.mappings = {mapping: mapping_identity(mapping)
                                 for mapping in (self.name, self.lower_name)}
            dm('mknodes', name)
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
        except BaseException as error:
            if self.created:
                try:
                    self.remove(abort=True)
                except BaseException as cleanup:
                    error.add_note(f'Private mapping cleanup incomplete: {cleanup}')
            self.close()
            raise

    def capture_created(self):
        expected = 'CRYPT-LUKS2-' + self.uuid.replace('-', '') + '-' + self.name
        for mapping in (self.name, self.lower_name):
            identity = mapping_identity(mapping)
            if identity is None:
                continue
            if mapping == self.name:
                if identity[2] != expected:
                    continue
            else:
                words = dm('table', mapping).stdout.split()
                if (not identity[2].startswith('CRYPT-INTEGRITY-') or
                        not identity[2].endswith('-' + self.lower_name) or len(words) < 7 or
                        words[2:5] != ['integrity',
                            f'{os.major(self.raw_device)}:{os.minor(self.raw_device)}',
                            str(self.offset // 512)]):
                    continue
            self.mappings[mapping] = identity

    def validate(self):
        if dm('table', self.name).stdout.split()[2:4] != ['piv-crypt', self.mapping_cipher]:
            raise ValueError('Primary mapping cipher differs from LUKS metadata')
        if (self.device.sectors, self.device.sector_size, self.device.iv_size, self.device.tuple_size) != (self.layout.sectors, self.layout.sector_size, self.layout.iv_bytes, self.layout.tuple_bytes):
            raise ValueError('Native geometry differs from supported superblock')
        table = dm('table', self.lower_name).stdout
        if table != self.lower_table:
            raise ValueError('Lower integrity mapping changed outside owner')
        validate_integrity_table(table, self.device.sectors, self.raw_device, self.offset,
                                 self.layout.sector_size,
                                 self.layout.journal_sections * self.layout.journal_section_sectors,
                                 self.layout.tuple_bytes)
        lower = Path('/dev/mapper/' + self.lower_name).stat().st_rdev
        if lower != self.device.lower_device:
            raise ValueError('Native control bound to unexpected lower device')
        raw_holders = Path(f'/sys/dev/block/{os.major(self.raw_device)}:{os.minor(self.raw_device)}/holders')
        lower_sys = Path(f'/sys/dev/block/{os.major(lower)}:{os.minor(lower)}').resolve().name
        if {p.name for p in raw_holders.iterdir()} != {lower_sys}:
            raise ValueError('Unexpected independent holder of backing storage')

    def remove(self, *, abort=False):
        if abort and not self.created:
            raise ValueError('Cannot discard an owner created by another attempt')
        if self.device is not None:
            self.device.close()
        for name in (self.name, self.lower_name):
            if name in self.mappings:
                remove_mapping(name, self.mappings[name], discard=abort and name == self.name)

    def close(self):
        if self.device is not None:
            self.device.close()
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
