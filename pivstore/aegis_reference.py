"""Optional independent SUPERCOP oracle; never used by native activation or I/O.

The kernel supplies production-path AEGIS-128. cryptography/libaegis do not
supply this original variant. Build the pinned diagnostic library separately;
never substitute AEGIS-128L. This adapter exposes only sector-sized operations.
"""
import ctypes
import os
from cryptography.exceptions import InvalidTag


class AEGIS128Reference:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError('AEGIS-128 requires a 16-byte key')
        path = os.environ.get('PIV_AEGIS_REFERENCE')
        if not path or not os.path.isabs(path):
            raise ValueError('Set PIV_AEGIS_REFERENCE to the absolute pinned diagnostic library path')
        self.library = ctypes.CDLL(path)
        self.key = key
        ptr, size = ctypes.c_void_p, ctypes.c_ulonglong
        self.library.crypto_aead_encrypt.argtypes = [ptr, ctypes.POINTER(size), ptr, size,
                                                     ptr, size, ptr, ptr, ptr]
        self.library.crypto_aead_decrypt.argtypes = [ptr, ctypes.POINTER(size), ptr, ptr, size,
                                                     ptr, size, ptr, ptr]
        self.library.crypto_aead_encrypt.restype = ctypes.c_int
        self.library.crypto_aead_decrypt.restype = ctypes.c_int

    def _run(self, nonce, value, aad, encrypt):
        if len(nonce) != 16 or len(value) not in ((512, 4096) if encrypt else (528, 4112)):
            raise ValueError('Invalid AEGIS-128 sector/nonce size')
        output = ctypes.create_string_buffer(len(value) + 16)
        length = ctypes.c_ulonglong()
        try:
            if encrypt:
                result = self.library.crypto_aead_encrypt(output, ctypes.byref(length), value, len(value),
                                                          aad, len(aad), None, nonce, self.key)
            else:
                result = self.library.crypto_aead_decrypt(output, ctypes.byref(length), None, value, len(value),
                                                          aad, len(aad), nonce, self.key)
            if result:
                raise InvalidTag
            expected = len(value) + (16 if encrypt else -16)
            if length.value != expected:
                raise RuntimeError('Invalid reference response length')
            return output.raw[:expected]
        finally:
            # The historical reference does not wipe failed plaintext itself.
            ctypes.memset(output, 0, len(output))

    def encrypt(self, nonce, data, aad):
        return self._run(nonce, data, aad, True)

    def decrypt(self, nonce, data, aad):
        return self._run(nonce, data, aad, False)
