"""Private external recovery artifacts for the experimental kernel backend.

These files are NOT deniable volume metadata. Their storage must be trusted,
local, persistent and exclusive; rollback/clones remain outside the guarantee.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import struct
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .profile import UnsupportedImage

ENTRY = struct.Struct('<Q12s4124s')
HEADER = struct.Struct('<8sQ32s')
MAGIC = b'PIVJNL01'
CHUNK = 65536


def derive(key, salt, context):
    if len(key) != 32:
        raise ValueError('Hidden key must contain exactly 32 bytes')
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=context).derive(key)


def fsync_dir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_mode & 0o077 or info.st_uid != os.geteuid() or info.st_size > maximum):
            raise ValueError('Invalid private state file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            value = stream.read(maximum + 1)
        if len(value) != info.st_size:
            raise ValueError('Private state changed or truncated')
        return value
    finally:
        os.close(fd)


def atomic_stream(path, producer, *, exclusive=False):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.piv-preparing-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            producer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        # The controller holds the private directory's stable exclusive lock.
        # Rename avoids a crash window leaving two links to the canonical file.
        if exclusive and os.path.lexists(path):
            raise FileExistsError('Private transaction file already exists')
        os.replace(name, path)
        fsync_dir(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


class Ledger:
    def __init__(self, path, key, identity, *, current=None, limit=1 << 20):
        self.path = Path(path)
        self.key = key
        self.aad = b'pivstore/kernel/ledger/v1\0' + identity
        self.limit = limit
        if current is not None:
            if self.path.exists():
                raise FileExistsError('Nonce ledger already exists')
            self.used = set(current)
            if len(self.used) != len(current) or any(len(iv) != 12 for iv in current):
                raise UnsupportedImage('Invalid or repeated current IV')
            self.spent = len(current)
            self.initialized = False
            self.save(exclusive=True)
        else:
            raw = private_read(self.path, 40_000_000)
            if len(raw) < 48:
                raise UnsupportedImage('Truncated nonce ledger')
            try:
                value = AESGCM(derive(key, raw[:32], self.aad)).decrypt(bytes(12), raw[32:], self.aad)
                body = json.loads(value)
                packed = base64.b64decode(body['used'], validate=True)
                self.used = {packed[i:i + 12] for i in range(0, len(packed), 12)}
                self.spent = body['spent']
                self.initialized = body['initialized']
                if (body['version'] != 1 or body['limit'] != limit or
                        type(self.spent) is not int or type(self.initialized) is not bool or
                        len(packed) % 12 or len(self.used) * 12 != len(packed) or
                        self.spent != len(self.used) or not 0 < self.spent <= limit):
                    raise ValueError('Invalid ledger fields')
            except (InvalidTag, KeyError, TypeError, ValueError) as exc:
                raise UnsupportedImage('Invalid or unauthenticated nonce ledger') from exc

    def save(self, *, exclusive=False):
        if not 0 < self.spent <= self.limit:
            raise OSError(122, 'Primary encryption budget exhausted')
        value = json.dumps(dict(version=1, limit=self.limit, spent=self.spent,
                                initialized=self.initialized,
                                used=base64.b64encode(b''.join(sorted(self.used))).decode()),
                           separators=(',', ':')).encode()
        salt = secrets.token_bytes(32)
        raw = salt + AESGCM(derive(self.key, salt, self.aad)).encrypt(bytes(12), value, self.aad)
        atomic_stream(self.path, lambda stream: stream.write(raw), exclusive=exclusive)

    def reserve(self, ivs):
        if len(set(ivs)) != len(ivs) or self.used.intersection(ivs) or any(len(v) != 12 for v in ivs):
            raise ValueError('Primary IV reuse/collision')
        if self.spent + len(ivs) > self.limit:
            raise OSError(122, 'Primary encryption budget exhausted')
        # Persist BEFORE any GCM encryption. Failed/abandoned plans stay spent.
        self.used.update(ivs)
        self.spent += len(ivs)
        self.save()


class _AuthenticatedJournal:
    def __init__(self, path, key, identity, sectors):
        if not 1 <= sectors <= 65536:
            raise ValueError('Unsupported recovery geometry')
        self.path = Path(path)
        self.key = key
        self.aad = b'pivstore/kernel/journal/v1\0' + identity
        self.sectors = sectors
        self.raw = None
        self.expected_size = 40 + HEADER.size + sectors * ENTRY.size + 16

    def load(self):
        self.raw = private_read(self.path, self.expected_size)
        if len(self.raw) != self.expected_size or self.raw[:8] != MAGIC:
            raise UnsupportedImage('Invalid recovery journal framing')
        # Verify the tag BEFORE inspecting any decrypted metadata. Then validate
        # all records before exposing an iterator that can drive native writes.
        try:
            raw = self.raw
            decryptor = Cipher(algorithms.AES(derive(self.key, raw[8:40], self.aad)),
                               modes.GCM(bytes(12), raw[-16:])).decryptor()
            decryptor.authenticate_additional_data(raw[:40] + self.aad)
            for offset in range(40, len(raw) - 16, CHUNK):
                decryptor.update(raw[offset:min(offset + CHUNK, len(raw) - 16)])
            decryptor.finalize()
            for _ in self.entries():
                pass
        except (InvalidTag, ValueError) as exc:
            self.raw = None
            raise UnsupportedImage('Invalid or unauthenticated recovery journal') from exc
        return self

    def remove(self):
        self.path.unlink()
        fsync_dir(self.path.parent)
        self.raw = None


class SparseJournal(_AuthenticatedJournal):
    """v2 sparse transactions; indices remain logical primary-sector indices.

    The count is derived from the bounded ciphertext length before decryption;
    address ordering and the IV digest are checked after complete authentication.
    """
    def create(self, carrier, entries):
        count = len(carrier) // 12
        if len(carrier) % 12 or not 1 <= count <= self.sectors:
            raise ValueError('Invalid sparse carrier size')
        salt = secrets.token_bytes(32)
        header = MAGIC + salt
        encryptor = Cipher(algorithms.AES(derive(self.key, salt, self.aad)), modes.GCM(bytes(12))).encryptor()
        encryptor.authenticate_additional_data(header + self.aad)

        def produce(stream):
            stream.write(header)
            stream.write(encryptor.update(HEADER.pack(b'PIVTXN02', count, hashlib.sha256(carrier).digest())))
            previous = -1
            seen = 0
            for index, old, value in entries:
                if (not previous < index < self.sectors or len(old) != 12 or len(value) != 4124 or
                        value[-12:] != carrier[seen * 12:(seen + 1) * 12]):
                    raise ValueError('Invalid sparse transaction entry')
                stream.write(encryptor.update(ENTRY.pack(index, old, value)))
                previous = index
                seen += 1
            if seen != count:
                raise ValueError('Incomplete sparse transaction')
            stream.write(encryptor.finalize())
            stream.write(encryptor.tag)
        atomic_stream(self.path, produce, exclusive=True)

    def load(self):
        # Reuse the full authentication prepass with an exact size inferred from
        # the bounded file length, never decrypted untrusted metadata.
        info = self.path.lstat()
        minimum = 40 + HEADER.size + 16
        if not minimum < info.st_size <= self.expected_size or (info.st_size - minimum) % ENTRY.size:
            raise UnsupportedImage('Invalid sparse journal length')
        maximum = self.expected_size
        self.expected_size = info.st_size
        try:
            return super().load()
        finally:
            self.expected_size = maximum

    def entries(self):
        if self.raw is None:
            raise ValueError('Journal must be authenticated before replay')
        raw = self.raw
        expected_count = (len(raw) - 40 - HEADER.size - 16) // ENTRY.size
        decryptor = Cipher(algorithms.AES(derive(self.key, raw[8:40], self.aad)),
                           modes.GCM(bytes(12), raw[-16:])).decryptor()
        decryptor.authenticate_additional_data(raw[:40] + self.aad)
        buffer = bytearray()
        count = 0
        previous = -1
        expected_hash = None
        digest = hashlib.sha256()
        for offset in range(40, len(raw) - 16, CHUNK):
            buffer.extend(decryptor.update(raw[offset:min(offset + CHUNK, len(raw) - 16)]))
            if expected_hash is None and len(buffer) >= HEADER.size:
                magic, sectors, expected_hash = HEADER.unpack(buffer[:HEADER.size])
                del buffer[:HEADER.size]
                if magic != b'PIVTXN02' or sectors != expected_count:
                    raise ValueError('Invalid sparse journal header')
            while expected_hash is not None and len(buffer) >= ENTRY.size:
                index, old, value = ENTRY.unpack(buffer[:ENTRY.size])
                del buffer[:ENTRY.size]
                if not previous < index < self.sectors or count >= expected_count or old == value[-12:]:
                    raise ValueError('Invalid sparse entry address/IV')
                digest.update(value[-12:])
                previous = index
                count += 1
                yield index, old, value
        decryptor.finalize()
        if buffer or count != expected_count or digest.digest() != expected_hash:
            raise ValueError('Incomplete sparse transaction')
