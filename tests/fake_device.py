"""Independent authenticated sector device for native-bootstrap recovery tests."""
import errno
import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM



class FakeDevice:
    def __init__(self, state=None, sectors=8):
        self.sectors = sectors
        self.primary_key = secrets.token_bytes(32)
        self.suspended = False
        self.transaction = False
        self.preparations = 0
        self.plain = [bytes([i]) * 4096 for i in range(self.sectors)]
        self.state = state or [self.encrypt(i, self.plain[i], secrets.token_bytes(12)) for i in range(self.sectors)]

    def encrypt(self, index, value, iv):
        return AESGCM(self.primary_key).encrypt(iv, value, struct.pack('<Q', index * 8) + iv) + iv

    def decrypt(self, index, value):
        return AESGCM(self.primary_key).decrypt(value[-12:], value[:-12], struct.pack('<Q', index * 8) + value[-12:])

    def check(self):
        pass

    validate = check

    def suspend(self):
        self.suspended = True

    def resume(self):
        if self.transaction:
            raise OSError(errno.EBUSY, 'Pending transaction')
        self.suspended = False

    def begin(self):
        assert self.suspended
        self.transaction = True

    def end(self):
        assert self.suspended and self.transaction
        self.transaction = False

    def read_iv(self, index, quiesced=False):
        assert self.suspended == quiesced
        self.decrypt(index, self.state[index])
        return self.state[index][-12:]

    def prepare(self, index, old, iv):
        assert self.transaction and self.suspended and old == self.state[index][-12:]
        self.preparations += 1
        return self.encrypt(index, self.decrypt(index, self.state[index]), iv)

    def apply(self, index, old, value, *, defer_flush=False):
        assert self.transaction and self.suspended
        if value == self.state[index]:
            return
        if self.state[index][-12:] != old:
            raise OSError(errno.ESTALE, 'Old IV mismatch')
        assert self.decrypt(index, self.state[index]) == self.decrypt(index, value)
        self.state[index] = value

    def sync(self):
        assert self.suspended and self.transaction

    def close(self):
        pass
