"""One randomized, authenticated auxiliary record; see docs/hidden-format.md."""

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
from .writer import rewrite_copy

MAGIC = b'PIVBLB01'


def context(image):
    return (b'pivstore/blob/v1\0' + image.uuid.encode('ascii') + b'\0' +
            struct.pack('<QQ', image.layout.primary_bytes, image.layout.sector_size))


def cipher(key, salt, aad):
    if len(key) != 32:
        raise ValueError('Hidden key must contain exactly 32 bytes')
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=aad).derive(key)
    return ChaCha20Poly1305(derived)


def encode(payload, key, carrier_size, aad):
    if carrier_size < 64 or len(payload) > carrier_size - 64:
        raise ValueError('Payload exceeds carrier capacity')
    plaintext = MAGIC + struct.pack('<Q', len(payload)) + payload
    plaintext = plaintext.ljust(carrier_size - 48, b'\0')
    salt = secrets.token_bytes(32)
    return salt + cipher(key, salt, aad).encrypt(b'\0' * 12, plaintext, aad)


def decode(carrier, key, aad):
    if len(carrier) < 64:
        raise ValueError('Carrier too small')
    try:
        plaintext = cipher(key, carrier[:32], aad).decrypt(b'\0' * 12, carrier[32:], aad)
    except InvalidTag:
        raise UnsupportedImage('No authenticated blob: wrong key, absent payload, or corruption') from None
    length = struct.unpack_from('<Q', plaintext, 8)[0]
    if plaintext[:8] != MAGIC or length > len(plaintext) - 16 or any(plaintext[16 + length:]):
        raise UnsupportedImage('Invalid authenticated blob format')
    return plaintext[16:16 + length]


def pack(source, output, primary_key, hidden_key, payload):
    def plan(image, used):
        for _ in range(16):
            encoded = encode(payload, hidden_key, image.layout.sectors * 12, context(image))
            ivs = [encoded[i:i + 12] for i in range(0, len(encoded), 12)]
            if len(set(ivs)) == len(ivs) and not used.intersection(ivs):
                return dict(enumerate(ivs))
        raise RuntimeError('Unable to encode carrier without primary IV collisions')
    return rewrite_copy(source, output, primary_key, plan)


def unpack(source, output, hidden_key):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('Output must not exist')
    with Image(source) as image:
        payload = decode(b''.join(image.iv_slots()), hidden_key, context(image))
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
