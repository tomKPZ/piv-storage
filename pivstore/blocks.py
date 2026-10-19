"""Configure stateless paired native DM views; no persistent userspace state."""
import fcntl
import struct
from types import SimpleNamespace
from .format import context
from .kernel_api import command, dm
from .kernel_owner import GuestOwner

SETUP = struct.Struct('=IIQII32s128s2I')
STATUS = struct.Struct('=QQQQIIII')


def native_status(device):
    data = bytearray(STATUS.size)
    fcntl.ioctl(device.fd, command(14, STATUS.size, 2), data, True)
    generation, hidden, encryptions, invalidations, active, views, failed, version = STATUS.unpack(data)
    if generation != device.generation or version != 3:
        raise ValueError('Unsupported native status ABI')
    return dict(active=bool(active), views=views, failed=bool(failed),
                hidden_bytes=hidden, encryptions=encryptions, invalidations=invalidations)


def native_setup(device, hidden_key, identity, *, initialize=False):
    if len(hidden_key) != 32 or not 0 < len(identity) <= 120:
        raise ValueError('Invalid native key/context size')
    data = bytearray(SETUP.pack(3, SETUP.size, device.generation, int(initialize),
                              len(identity), hidden_key, identity, 0, 0))
    try:
        fcntl.ioctl(device.fd, command(12, SETUP.size, 1), data, True)
    finally:
        data[:] = bytes(len(data))


def native_detach(device):
    fcntl.ioctl(device.fd, command(13, 48, 1), device.request(), True)


def open_blocks(source, key_file, hidden_key, *, name='piv-native', initialize=False, allow_test_stack=False):
    if len(hidden_key) != 32:
        raise ValueError('Hidden key must contain exactly 32 bytes')
    owner = GuestOwner(source, key_file, name, allow_test_stack=allow_test_stack)
    created = []
    adopted = False
    try:
        if native_status(owner.device)['active']:
            raise FileExistsError('Native block views are already active')
        identity = context(SimpleNamespace(uuid=owner.uuid, layout=SimpleNamespace(
            primary_bytes=owner.device.sectors * owner.device.sector_size, sector_size=owner.device.sector_size)))
        owner.device.validate()
        owner.device.suspend(); owner.device.begin()
        native_setup(owner.device, hidden_key, identity, initialize=initialize)
        adopted = True
        owner.device.resume()
        status = native_status(owner.device)
        for role, sectors in (('decoy', owner.device.sectors * (owner.device.sector_size // 512)), ('hidden', status['hidden_bytes'] // 512)):
            mapping = name + '-' + role
            dm('create', mapping, input=f'0 {sectors} piv-view /dev/mapper/{name} {owner.device.generation} {role}\n')
            created.append(mapping)
        return dict(decoy='/dev/mapper/' + name + '-decoy', hidden='/dev/mapper/' + name + '-hidden',
                    hidden_bytes=status['hidden_bytes'])
    except BaseException:
        for mapping in reversed(created):
            dm('remove', mapping)
        if adopted:
            native_detach(owner.device)
        raise
    finally:
        owner.close()


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
