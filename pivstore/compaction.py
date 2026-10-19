"""Closed-volume native-log maintenance; never drops historical reservations."""
import hashlib
import os
from pathlib import Path
import secrets
import tempfile
from types import SimpleNamespace

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import blob
from .native_log import HEADER, LOG_DOMAIN, inspect_log
from .profile import UnsupportedImage
from .recovery import derive, fsync_dir


def _checkpoint(phase):
    """Persistence boundary hook for crash/error experiments."""


def _compact_file(path, key, identity, sectors):
    """Caller holds volume ownership and has detached the native kernel log fd.

    This helper is NOT a live-log editor. The full log must already have been
    replayed/verified by the kernel. Both old/new files preserve the same history.
    """
    path = Path(path)
    state = inspect_log(path, key, identity, sectors)
    if not state.ready or not state.used or state.pending is not None or state.trailing_bytes:
        raise UnsupportedImage('Compaction requires recovered, complete native history')
    values = sorted(state.used)
    fd, name = tempfile.mkstemp(prefix='.piv-compacting-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            sequence, previous = 0, bytes(32)

            def append(kind, payload=b''):
                nonlocal sequence, previous
                salt = secrets.token_bytes(32)
                header = HEADER.pack(b'PIVNLOG1', sequence, kind, len(payload), salt, previous)
                frame = header + AESGCM(derive(key, salt, LOG_DOMAIN + identity)).encrypt(
                    bytes(12), payload, header + identity)
                stream.write(frame)
                previous = hashlib.sha256(frame).digest()
                sequence += 1
                _checkpoint('frame')
            for start in range(0, len(values), 512):
                batch = values[start:start + 512]
                append(1, len(batch).to_bytes(4, 'little') + b''.join(batch))
            append(4)
            stream.flush()
            os.fsync(stream.fileno())
        # Authenticate the actual candidate before publishing it. This also
        # rejects accidentally incomplete snapshots, without editing the source.
        candidate = inspect_log(name, key, identity, sectors)
        if (candidate.used != state.used or not candidate.ready or candidate.pending is not None
                or candidate.trailing_bytes):
            raise UnsupportedImage('Compaction candidate lost native history')
        _checkpoint('prepared')
        os.replace(name, path)
        _checkpoint('published')
        fsync_dir(path.parent)
        _checkpoint('durable')
        return dict(nonces=len(state.used), previous_bytes=state.valid_bytes,
                    compacted_bytes=candidate.valid_bytes)
    finally:
        Path(name).unlink(missing_ok=True)


def compact_state(source, key_file, hidden_key, *, state_directory=None, name='piv-native',
                  allow_test_stack=False):
    from .blocks import _private_directory, _phase, native_status, native_setup, native_detach
    from .kernel_owner import GuestOwner
    if len(hidden_key) != 32:
        raise ValueError('Hidden key must contain exactly 32 bytes')
    owner = GuestOwner(source, key_file, name, allow_test_stack=allow_test_stack)
    owned = False
    try:
        if native_status(owner.device)['active']:
            raise BlockingIOError('Close both native block devices before compaction')
        owned = True
        state = _private_directory(state_directory or Path('/var/lib/pivstore') / owner.uuid,
                                   owner.device)
        log = state / 'native.log'
        if not log.is_file() or _phase(state, log) != b'ready\n':
            raise ValueError('Compaction requires adopted native history')
        identity = blob.context(SimpleNamespace(uuid=owner.uuid, layout=owner.layout)) + b'/incremental/v2'
        owner.device.validate()
        owner.device.suspend(); owner.device.begin()
        native_setup(owner.device, hidden_key, identity, log, b'')
        native_detach(owner.device)  # No public views; close the kernel fd BEFORE rename.
        _checkpoint('detached')
        result = _compact_file(log, hidden_key, identity, owner.device.sectors)
        # New kernel context authenticates every primary sector/record and all
        # history from the published file before reporting successful maintenance.
        owner.device.begin()
        native_setup(owner.device, hidden_key, identity, log, b'')
        native_detach(owner.device)
        return result
    finally:
        try:
            if owned:
                if native_status(owner.device)['active']:
                    native_detach(owner.device)
                owner.remove()
        finally:
            owner.close()
