"""Python mirror of pivsetup's owner lifecycle (owner.rs), kept as guest test
instrumentation: device checks, LUKS/integrity validation, exclusive /run lock,
ordinary cryptsetup open, reload as piv-crypt, control binding, identity checks."""
import errno
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


def has_partitions(rdev):
    """A whole disk whose kernel partition table lists partitions (they can be
    in use without appearing as holders of the disk itself)."""
    base = Path(f'/sys/dev/block/{os.major(rdev)}:{os.minor(rdev)}')
    if (base / 'partition').exists():
        return False
    return any((entry / 'partition').exists() for entry in base.iterdir())


def check_device(source):
    """Activation preconditions that protect the caller (no test confinement):
    root, an existing block device (symlinks followed) of a nonzero whole
    number of 512-byte sectors that is not a partitioned whole disk. Mirrors
    pivsetup's owner::check_device."""
    if os.geteuid() != 0:
        raise PermissionError('Kernel setup requires root')
    info = Path(source).stat()
    if not stat.S_ISBLK(info.st_mode):
        raise ValueError(f'{source} is not a block device')
    size = int(subprocess.check_output(['blockdev', '--getsize64', str(source)], text=True))
    if size <= 0 or size % 512:
        raise ValueError(f'Unsupported block device size {size}')
    if has_partitions(info.st_rdev):
        raise ValueError(f'{source} has a partition table in use; give the partition that holds the LUKS volume')
    return size


def check_unclaimed(source):
    """Exclusive-open probe of an unowned device (EBUSY while mounted, mapped
    or otherwise opened exclusively)."""
    try:
        os.close(os.open(source, os.O_RDONLY | os.O_EXCL | os.O_CLOEXEC))
    except OSError as error:
        if error.errno == errno.EBUSY:
            raise OSError(errno.EBUSY, f'{source} is in use (mounted, mapped or open exclusively)') from None
        raise


def crypt(*args):
    return subprocess.run(['cryptsetup', *map(str, args)], check=True,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class GuestOwner:
    def __init__(self, source, passphrase_file, name='piv-native'):
        self.lock_fd = None
        self.device = None
        self.created = False
        self.mappings = {}
        self.name = name
        self.lower_name = name + '_dif'
        self.source = Path(source)
        if not re.fullmatch(r'piv-[a-zA-Z0-9_-]{1,40}', name):
            raise ValueError('Invalid experimental mapping name')
        self.raw_bytes = check_device(self.source)
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
            existing = dm('info', name, check=False).returncode == 0
            if not existing:
                # Busy-device protection before reading anything from the device.
                if mapping_identity(self.lower_name) is not None:
                    raise FileExistsError('Lower mapping name is already in use')
                holders = Path(f'/sys/dev/block/{os.major(self.raw_device)}:{os.minor(self.raw_device)}/holders')
                if list(holders.iterdir()):
                    raise OSError(errno.EBUSY, 'Device already has an independent mapping')
                check_unclaimed(self.source)
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
            if not existing:
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
                raise ValueError('Mapping does not belong to this LUKS volume')
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
