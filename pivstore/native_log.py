"""Independent, read-only decoder for the native kernel recovery log.

Used to cross-check kernel crypto/persistence in disposable experiments. Never
repairs/truncates a log or changes primary storage.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .profile import UnsupportedImage
from .recovery import derive

HEADER = struct.Struct('<8sQII32s32s')
ENTRY = struct.Struct('<QI12s4124s')
MAX_ENTRIES = 96
MAX_FRAME = MAX_ENTRIES * ENTRY.size + 4
MAX_LOG = 512 * 1024 * 1024
# Native wire format uses exactly these 21 bytes (the header carries version 1).
LOG_DOMAIN = b'pivstore/native/log/v'


@dataclass
class State:
    used: set
    ready: bool = False
    pending: list | None = None
    frames: int = 0
    valid_bytes: int = 0
    trailing_bytes: int = 0


def inspect_log(path, key, context, sectors):
    fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW)
    state = State(set())
    previous = bytes(32)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077 or
                info.st_size > MAX_LOG):
            raise UnsupportedImage('Invalid native state file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            while state.valid_bytes < info.st_size:
                raw_header = stream.read(HEADER.size)
                if len(raw_header) < HEADER.size:
                    break
                magic, sequence, kind, length, salt, chain = HEADER.unpack(raw_header)
                if magic != b'PIVNLOG1' or sequence != state.frames or chain != previous or length > MAX_FRAME:
                    raise UnsupportedImage('Invalid native log header/chain')
                ciphertext = stream.read(length + 16)
                if len(ciphertext) != length + 16:
                    break
                try:
                    body = AESGCM(derive(key, salt, LOG_DOMAIN + context)).decrypt(
                        bytes(12), ciphertext, raw_header + context)
                except InvalidTag as exc:
                    raise UnsupportedImage('Unauthenticated native log frame') from exc
                # Interpret payload only AFTER full frame authentication.
                if kind == 1:
                    if state.pending is not None or len(body) < 4:
                        raise UnsupportedImage('Invalid native reservation state')
                    count, = struct.unpack_from('<I', body)
                    if not 1 <= count <= 512 or len(body) != 4 + count * 12:
                        raise UnsupportedImage('Invalid native reservation length')
                    values = [body[4 + i * 12:4 + (i + 1) * 12] for i in range(count)]
                    if len(set(values)) != count or state.used.intersection(values):
                        raise UnsupportedImage('Native nonce reuse')
                    state.used.update(values)
                    if len(state.used) > 1 << 20:
                        raise UnsupportedImage('Native nonce budget exceeded')
                elif kind == 2:
                    if not state.ready or state.pending is not None or len(body) < 4:
                        raise UnsupportedImage('Invalid native WAL state')
                    count, = struct.unpack_from('<I', body)
                    if not 1 <= count <= MAX_ENTRIES or len(body) != 4 + count * ENTRY.size:
                        raise UnsupportedImage('Invalid native WAL size')
                    entries = [ENTRY.unpack_from(body, 4 + i * ENTRY.size) for i in range(count)]
                    indices = [item[0] for item in entries]
                    planned = [item[3][-12:] for item in entries]
                    if indices != sorted(set(indices)) or len(set(planned)) != count:
                        raise UnsupportedImage('Invalid native WAL ordering/nonces')
                    selected = set(indices)
                    for index, primary, old, value in entries:
                        if (index >= sectors or primary not in (0, 1) or old == value[-12:] or
                                old not in state.used or value[-12:] not in state.used):
                            raise UnsupportedImage('Invalid native WAL entry')
                        group = index // 32
                        if group < sectors // 32:
                            if not set(range(group * 32, (group + 1) * 32)) <= selected:
                                raise UnsupportedImage('Incomplete native record coverage')
                        elif not primary:
                            raise UnsupportedImage('Invalid native tail entry')
                    state.pending = entries
                elif kind == 3:
                    if body or state.pending is None:
                        raise UnsupportedImage('Invalid native completion')
                    state.pending = None
                elif kind == 4:
                    if body or state.ready or state.pending is not None:
                        raise UnsupportedImage('Invalid native activation')
                    state.ready = True
                else:
                    raise UnsupportedImage('Unknown native frame type')
                previous = hashlib.sha256(raw_header + ciphertext).digest()
                state.frames += 1
                state.valid_bytes += HEADER.size + length + 16
            state.trailing_bytes = info.st_size - state.valid_bytes
        if os.fstat(fd).st_size != info.st_size:
            raise UnsupportedImage('Native log changed during inspection')
        return state
    finally:
        os.close(fd)
