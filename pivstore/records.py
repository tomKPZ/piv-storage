"""Opt-in v2: independently randomized, address-bound 32-sector records.

No public format marker is stored in the carrier. v1 is deliberately unchanged.
"""
import struct

from . import blob
from .profile import UnsupportedImage

SECTORS = 32
BYTES = SECTORS * 12
PAYLOAD = BYTES - 64


class Records:
    def __init__(self, sectors, identity, key):
        self.count = sectors // SECTORS
        if self.count < 2:
            raise ValueError('Incremental format requires at least 64 sectors')
        self.capacity = (self.count - 1) * PAYLOAD
        self.identity = identity + b'/records/v2/'
        self.key = key

    def aad(self, index):
        if not 0 <= index < self.count:
            raise ValueError('Record outside carrier')
        return self.identity + struct.pack('<Q', index)

    def encode(self, index, value):
        return blob.encode(value, self.key, BYTES, self.aad(index))

    def decode(self, index, carrier):
        if len(carrier) != BYTES:
            raise UnsupportedImage('Invalid incremental carrier length')
        value = blob.decode(carrier, self.key, self.aad(index))
        if len(value) != (8 if index == 0 else PAYLOAD):
            raise UnsupportedImage('Invalid incremental record length')
        return value

    def values(self, payload):
        if len(payload) > self.capacity:
            raise ValueError('Incremental capacity exceeded')
        return [struct.pack('<Q', len(payload))] + [
            payload[i:i + PAYLOAD].ljust(PAYLOAD, b'\0')
            for i in range(0, self.capacity, PAYLOAD)]

    def payload(self, values):
        size, = struct.unpack('<Q', values[0])
        if size > self.capacity:
            raise UnsupportedImage('Invalid incremental hidden size')
        data = b''.join(values[1:])
        if any(data[size:]):
            raise UnsupportedImage('Noncanonical incremental hidden padding')
        return data[:size]


def decode_image(image, key):
    """Hidden-only extraction: no primary key or recovery state is required."""
    records = Records(image.layout.sectors, blob.context(image) + b'/incremental/v2', key)
    carrier = b''.join(image.iv_slots())
    values = [records.decode(i, carrier[i * BYTES:(i + 1) * BYTES])
              for i in range(records.count)]
    return records.payload(values)
