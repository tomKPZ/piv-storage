"""Configure two native DM block views; no userspace data-path service."""
import ctypes
import fcntl
import os
from pathlib import Path
import stat
import struct
from types import SimpleNamespace

from . import blob
from .incremental_store import IncrementalStore
from .kernel_api import KernelDevice, command, dm
from .kernel_owner import GuestOwner
from .recovery import Ledger, fsync_dir, private_read, atomic_stream

SETUP = struct.Struct('=IIQQII32s128s256s4I')
STATUS = struct.Struct('=QQQQIIII')


def native_status(device):
    data = bytearray(STATUS.size)
    fcntl.ioctl(device.fd, command(14, STATUS.size, 2), data, True)
    generation, hidden, nonces, log_bytes, active, views, failed, reserved = STATUS.unpack(data)
    if generation != device.generation or reserved:
        raise ValueError('Invalid native status')
    return dict(active=bool(active), views=views, failed=bool(failed),
                hidden_bytes=hidden, nonces=nonces, log_bytes=log_bytes)


def native_setup(device, hidden_key, context, path, nonces):
    encoded = os.fsencode(Path(path).absolute())
    if len(hidden_key) != 32 or len(context) > 120 or len(encoded) > 255:
        raise ValueError('Invalid native key/context/path size')
    if len(nonces) % 12 or len(nonces) > (1 << 20) * 12:
        raise ValueError('Invalid native nonce seed')
    seeds = ctypes.create_string_buffer(nonces)
    data = bytearray(SETUP.pack(1, SETUP.size, device.generation, ctypes.addressof(seeds),
                              len(nonces) // 12, len(context), hidden_key, context,
                              encoded, 0, 0, 0, 0))
    try:
        fcntl.ioctl(device.fd, command(12, SETUP.size, 1), data, True)
    finally:
        data[:] = bytes(len(data))
        ctypes.memset(ctypes.addressof(seeds), 0, len(seeds))


def native_detach(device):
    fcntl.ioctl(device.fd, command(13, 48, 1), device.request(), True)


def _private_directory(path, device):
    path = Path(path).absolute()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Native state must be a private real directory')
    device.validate_state(path)
    return path


def _phase(state, log):
    marker = state / 'native.phase'
    if marker.exists() or marker.is_symlink():
        phase = private_read(marker, 16)
        if phase not in (b'importing\n', b'ready\n'):
            raise ValueError('Invalid native adoption marker')
    else:
        # Existing complete native logs predate the marker; never seed them anew.
        phase = b'ready\n' if log.exists() and log.stat().st_size else b'importing\n'
        atomic_stream(marker, lambda stream: stream.write(phase), exclusive=True)
    if phase == b'ready\n' and (not log.exists() or log.stat().st_size == 0):
        raise ValueError('Missing native history after adoption; refusing bootstrap reset')
    return phase


def open_blocks(source, key_file, hidden_key, *, state_directory=None, name='piv-native', initialize=False, allow_test_stack=False):
    if len(hidden_key) != 32:
        raise ValueError('Hidden key must contain exactly 32 bytes')
    owner = GuestOwner(source, key_file, name, allow_test_stack=allow_test_stack)
    created = []
    try:
        if native_status(owner.device)['active']:
            raise FileExistsError('Native block views are already active')
        if dm('info', owner.view_name, check=False).returncode == 0:
            dm('remove', owner.view_name)  # Never force removal of an in-use view.
        state = _private_directory(state_directory or Path('/var/lib/pivstore') / owner.uuid, owner.device)
        log = state / 'native.log'
        bootstrap = state / 'bootstrap'
        identity = blob.context(SimpleNamespace(uuid=owner.uuid, layout=SimpleNamespace(
            primary_bytes=owner.device.sectors * 4096, sector_size=4096))) + b'/incremental/v2'
        capacity = ((owner.device.sectors // 32 - 1) * 320 // 512) * 512
        phase = _phase(state, log)
        if initialize and log.exists():
            raise FileExistsError('Cannot reinitialize native recovery state')
        if not log.exists():
            if not initialize and not (bootstrap / 'ledger').exists():
                raise ValueError('Fresh adoption requires --initialize and a new state directory')
            control = owner.device.control_path
            with IncrementalStore(owner.device, bootstrap, hidden_key, owner.uuid,
                                  initialize=not (bootstrap / 'ledger').exists()) as store:
                if not store.ledger.initialized:
                    store.truncate_hidden(capacity)
                    store.flush()
                if store.hidden_size() != capacity:
                    raise ValueError('Native block mode requires the fixed-capacity record format')
            owner.device = KernelDevice(control, '/dev/mapper/' + owner.name)
            owner.device.validate_callback = owner.validate
            fd = os.open(log, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fsync(fd); os.close(fd); fsync_dir(state)
        # Bootstrap history is read only to resume an interrupted initial import.
        # Native READY logs ignore this seed and own all subsequent reservations.
        seeds = b''
        if phase == b'importing\n' and (bootstrap / 'ledger').exists():
            ledger = Ledger(bootstrap / 'ledger', hidden_key, identity)
            seeds = b''.join(sorted(ledger.used))
        owner.device.validate()
        owner.device.suspend(); owner.device.begin()
        native_setup(owner.device, hidden_key, identity, log, seeds)
        atomic_stream(state / 'native.phase', lambda stream: stream.write(b'ready\n'))
        owner.device.resume()
        status = native_status(owner.device)
        for role, sectors in (('decoy', owner.device.sectors * 8), ('hidden', status['hidden_bytes'] // 512)):
            mapping = name + '-' + role
            dm('create', mapping, input=f'0 {sectors} piv-view /dev/mapper/{name} {owner.device.generation} {role}\n')
            created.append(mapping)
        return dict(decoy='/dev/mapper/' + name + '-decoy', hidden='/dev/mapper/' + name + '-hidden',
                    hidden_bytes=status['hidden_bytes'], state_directory=str(state))
    except BaseException:
        for mapping in reversed(created):
            dm('remove', mapping)
        if created:
            native_detach(owner.device)
        raise
    finally:
        owner.close()  # The kernel owns keys, views and recovery log after return.


def close_blocks(source, key_file, *, name='piv-native', allow_test_stack=False):
    if dm('info', name, check=False).returncode:
        raise FileNotFoundError('Native owner is not active')
    owner = GuestOwner(source, key_file, name, allow_test_stack=allow_test_stack)
    try:
        if not native_status(owner.device)['active']:
            raise ValueError('Owner has no native block backend')
        for role in ('hidden', 'decoy'):
            mapping = name + '-' + role
            if dm('info', mapping, check=False).returncode == 0:
                dm('remove', '--retry', mapping)
        native_detach(owner.device)
        owner.remove()
    finally:
        owner.close()
