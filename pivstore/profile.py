"""Read-only LUKS2/dm-integrity profile, cross-checked with stock Linux fixtures.

LUKS2 header checksums and redundant-header selection are delegated to cryptsetup.
Only no-journal-crypto, fixed-padding, 512/4096-byte profiles with 16-byte random IVs
(original AEGIS-128, or aes/serpent/twofish-xts-random with hmac-sha1/256/512) are accepted.
"""

from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import uuid

from .format import PRIMARY_PROFILES



class UnsupportedImage(ValueError):
    pass


@dataclass(frozen=True)
class Layout:
    integrity_offset: int
    primary_bytes: int
    journal_sections: int
    journal_section_sectors: int
    initial_sectors: int
    metadata_run_sectors: int
    interleave_sectors: int = 32768
    sector_size: int = 4096
    tag_bytes: int = 16
    iv_bytes: int = 12

    @property
    def sectors(self):
        return self.primary_bytes // self.sector_size

    @property
    def tuple_bytes(self):
        return self.tag_bytes + self.iv_bytes

    @property
    def journal_entry_bytes(self):
        return ((8 + 8 * (self.sector_size // 512) + self.tuple_bytes + 7) // 8) * 8

    def offsets(self, index):
        if not 0 <= index < self.sectors:
            raise IndexError('Primary sector out of range')
        factor = self.sector_size // 512
        sector512 = index * factor
        area, offset = divmod(sector512, self.interleave_sectors)
        base = self.integrity_offset + (self.initial_sectors + area * (
            self.interleave_sectors + self.metadata_run_sectors)) * 512
        return (base + (self.metadata_run_sectors + offset) * 512,
                base + (offset // factor) * self.tuple_bytes)


def read_exact(fd, length, offset, limit):
    if length < 0 or offset < 0 or offset + length > limit:
        raise UnsupportedImage('Image extent outside file')
    value = os.pread(fd, length, offset)
    if len(value) != length:
        raise UnsupportedImage('Short image read')
    return value


def parse_superblock(header, offset, file_size):
    if len(header) != 4096:
        raise UnsupportedImage('Incomplete integrity superblock')
    magic, version, interleave, tuple_size, sections, provided, flags, block = (
        struct.unpack_from('<8sBBHIQIB', header))
    if (magic, version, interleave, flags) != (
            b'integrt\0', 4, 15, 8) or tuple_size not in (32, 36, 48, 80) or block not in (0, 3):
        raise UnsupportedImage('Unsupported integrity superblock profile')
    if offset < 32768 or offset % 4096 or offset + 4096 > file_size:
        raise UnsupportedImage('Invalid integrity offset')
    factor = 1 << block
    if not 1 <= sections <= 4096 or provided <= 0 or provided % factor:
        raise UnsupportedImage('Invalid integrity dimensions')
    # Pinned Linux: header address8 + saved data-sector tails8*factor + tuple[28|32].
    entry_bytes = ((8 + 8 * factor + tuple_size + 7) // 8) * 8
    section_sectors = (504 // entry_bytes) * 8 * factor + 8
    initial = 8 + section_sectors * sections
    metadata_run = ((tuple_size * (32768 // factor) + 4095) // 4096) * 8
    layout = Layout(offset, provided * 512, sections, section_sectors,
                    initial, metadata_run, sector_size=512 * factor, tag_bytes=tuple_size - 16, iv_bytes=16)
    data, tag = layout.offsets(layout.sectors - 1)
    if data + layout.sector_size > file_size or tag + tuple_size > file_size:
        raise UnsupportedImage('Primary extents exceed image size')
    return layout


def validate_segment(metadata):
    if not isinstance(metadata, dict) or not isinstance(metadata.get('config'), dict):
        raise UnsupportedImage('Invalid LUKS2 metadata')
    if metadata['config'].get('requirements'):
        raise UnsupportedImage('Unsupported LUKS2 requirements')
    segments = metadata.get('segments')
    if not isinstance(segments, dict) or set(segments) != {'0'}:
        raise UnsupportedImage('Exactly one ordinary segment is supported')
    segment = segments['0']
    expected = {'type', 'offset', 'size', 'iv_tweak', 'encryption',
                'sector_size', 'integrity'}
    if not isinstance(segment, dict) or set(segment) != expected:
        raise UnsupportedImage('Unsupported segment fields')
    encryption, integrity = segment['encryption'], segment['integrity']
    kind = integrity.get('type') if isinstance(integrity, dict) else None
    if (not isinstance(encryption, str) or not isinstance(kind, str) or
            (encryption, kind) not in PRIMARY_PROFILES or
            (segment['type'], segment['size'], segment['iv_tweak']) !=
            ('crypt', 'dynamic', '0') or segment['sector_size'] not in (512, 4096)):
        raise UnsupportedImage('Unsupported primary encryption profile')
    if integrity != {'type': kind, 'journal_encryption': 'none', 'journal_integrity': 'none'}:
        raise UnsupportedImage('Unsupported integrity/journal algorithms')
    value = segment['offset']
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise UnsupportedImage('Invalid segment offset')
    return int(value)


class Image(AbstractContextManager):
    def __init__(self, path, *, exclusive=False):
        self.fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode):
                raise UnsupportedImage('Only regular-file images are supported')
            fcntl.flock(self.fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            self.initial_stat = info
            self.size = info.st_size
            # Use the held descriptor so path replacement cannot make cryptsetup
            # inspect a different file. No activation or keyslot unlock occurs.
            # In exclusive mode we already hold the lock. Suppress cryptsetup's
            # second, incompatible shared lock through a separately opened fd.
            options = ['--disable-locks'] if exclusive else []
            result = subprocess.run([
                'cryptsetup', *options, 'luksDump', '--dump-json-metadata',
                f'/proc/self/fd/{self.fd}'], pass_fds=(self.fd,),
                capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise UnsupportedImage('cryptsetup rejected LUKS2 metadata')
            uuid_result = subprocess.run([
                'cryptsetup', *options, 'luksUUID', f'/proc/self/fd/{self.fd}'],
                pass_fds=(self.fd,), capture_output=True, text=True, timeout=30)
            if uuid_result.returncode:
                raise UnsupportedImage('cryptsetup rejected LUKS UUID')
            self.uuid = str(uuid.UUID(uuid_result.stdout.strip()))
            try:
                metadata = json.loads(result.stdout)
                offset = validate_segment(metadata)
            except (json.JSONDecodeError, TypeError, KeyError) as exc:
                raise UnsupportedImage('Invalid LUKS2 segment metadata') from exc
            self.encryption = metadata['segments']['0']['encryption']
            self.integrity = metadata['segments']['0']['integrity']['type']
            self.layout = parse_superblock(self.read(4096, offset), offset, self.size)
            if (self.layout.iv_bytes != 16 or
                    self.layout.tag_bytes != PRIMARY_PROFILES[(self.encryption, self.integrity)][1]):
                raise UnsupportedImage('LUKS profile and integrity tuple size disagree')
            if self.layout.sector_size != metadata['segments']['0']['sector_size']:
                raise UnsupportedImage('LUKS and integrity sector sizes disagree')
            self.check_empty_journal()
        except BaseException:
            os.close(self.fd)
            raise

    def read(self, length, offset):
        return read_exact(self.fd, length, offset, self.size)

    def check_empty_journal(self):
        layout = self.layout
        known = {0x1111111111111111, 0x2222222222222222,
                 0x3333333333333333, 0x4444444444444444}
        for section in range(layout.journal_sections):
            base_id = None
            for index in range(layout.journal_section_sectors):
                offset = layout.integrity_offset + (8 + section *
                    layout.journal_section_sectors + index) * 512
                data = self.read(512, offset)
                current = int.from_bytes(data[504:], 'little') ^ (section << 32) ^ index
                if current not in known or (base_id is not None and base_id != current):
                    raise UnsupportedImage('Invalid/torn or unsupported journal section')
                base_id = current
                if index < 8:
                    stride = layout.journal_entry_bytes
                    for entry in range(504 // stride):
                        if data[entry * stride + 4:entry * stride + 8] != b'\xff' * 4:
                            raise UnsupportedImage('Nonempty journal: recover with stock Linux first')

    def summary(self):
        return {**asdict(self.layout), 'uuid': self.uuid, 'encryption': self.encryption, 'primary_sectors': self.layout.sectors,
                'gross_carrier_bytes': self.layout.sectors * self.layout.iv_bytes,
                'journal': 'validated empty; no replay implemented'}

    def iv_slots(self):
        """Yield carrier bytes in logical-sector order; does not authenticate them."""
        for index in range(self.layout.sectors):
            _, tag_offset = self.layout.offsets(index)
            yield self.read(self.layout.iv_bytes, tag_offset + self.layout.tag_bytes)

    def verify(self, key):
        """Authenticate every primary sector; return the plaintext SHA-256, or
        None for profiles authenticated but not decrypted on the host."""
        from .sector import SectorCodec
        codec = SectorCodec(key, self.layout.sector_size, self.encryption, self.integrity)
        digest = hashlib.sha256()
        for index in range(self.layout.sectors):
            data_offset, tag_offset = self.layout.offsets(index)
            ciphertext = self.read(self.layout.sector_size, data_offset)
            metadata = self.read(self.layout.tuple_bytes, tag_offset)
            if codec.decrypts:
                digest.update(codec.decrypt(index, ciphertext, metadata))
            else:
                codec.authenticate(index, ciphertext, metadata)
        return digest.hexdigest() if codec.decrypts else None

    def check_unchanged(self):
        current = os.fstat(self.fd)
        if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
                self.initial_stat.st_size, self.initial_stat.st_mtime_ns,
                self.initial_stat.st_ctime_ns):
            raise UnsupportedImage('Image changed during inspection')

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                self.check_unchanged()
        finally:
            self.close()

    def close(self):
        """Release ownership; callers that mutate/replace an image manage checks."""
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
