"""Stateless v3: one independently authenticated 512-byte logical block per record."""
import os
from pathlib import Path
import secrets
import struct
import tempfile
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .profile import Image, UnsupportedImage
from .format import context

BYTES = 576
PAYLOAD = 512
MAGIC = b'PIVBLK03'


class Records:
    def __init__(self, sectors, identity, key, iv_size=12):
        if iv_size not in (12, 16):
            raise ValueError('Unsupported carrier IV size')
        self.sectors_per_record = BYTES // iv_size
        if len(key) != 32 or sectors < self.sectors_per_record:
            raise ValueError('Expected a 32-byte key and at least one complete carrier group')
        self.count = sectors // self.sectors_per_record
        self.capacity = self.count * PAYLOAD
        self.identity = identity + b'/block/'
        self.key = key

    def aad(self, index):
        if not 0 <= index < self.count:
            raise ValueError('Record outside carrier')
        return self.identity + struct.pack('<Q', index)

    def cipher(self, salt, aad):
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=aad).derive(self.key)
        return ChaCha20Poly1305(derived)

    def encode(self, index, value, *, invalid=False):
        if len(value) != PAYLOAD:
            raise ValueError('Hidden writes must contain exactly 512 bytes')
        aad = self.aad(index)
        salt = secrets.token_bytes(32)
        plain = MAGIC + struct.pack('<Q', int(invalid)) + (bytes(PAYLOAD) if invalid else value)
        return salt + self.cipher(salt, aad).encrypt(bytes(12), plain, aad)

    def decode(self, index, carrier):
        if len(carrier) != BYTES:
            raise UnsupportedImage('Invalid hidden carrier length')
        aad = self.aad(index)
        try:
            plain = self.cipher(carrier[:32], aad).decrypt(bytes(12), carrier[32:], aad)
        except InvalidTag:
            raise UnsupportedImage('Hidden block unavailable: absent, wrong key or damaged') from None
        if plain[:8] != MAGIC or struct.unpack_from('<Q', plain, 8)[0] != 0:
            raise UnsupportedImage('Hidden block unavailable: invalid record')
        return plain[16:]


def decode_image(image, key):
    """All-or-error extraction without the primary key; stock journal must be clean."""
    records = Records(image.layout.sectors, context(image), key, image.layout.iv_bytes)
    carrier = b''.join(image.iv_slots())
    return b''.join(records.decode(i, carrier[i * BYTES:(i + 1) * BYTES])
                    for i in range(records.count))


def unpack(source, output, hidden_key, format=3):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('Output must not exist')
    with Image(source) as image:
        if format == 4:
            from .records_v4 import decode_image as decode_v4
            payload = decode_v4(image, hidden_key)
        else:
            payload = decode_image(image, hidden_key)
        image.check_unchanged()
        fd, name = tempfile.mkstemp(prefix='.pivstore-', suffix='.partial', dir=output.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, output)
            temporary.unlink()
            directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return {'extracted_payload_bytes': len(payload)}
