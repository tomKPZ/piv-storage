"""Configure stateless paired native DM views; no persistent userspace state."""
import fcntl
import os
import struct
import secrets
from types import SimpleNamespace
from .format import context
from .kernel_api import command, dm, mapping_identity, remove_mapping
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
    try:
        if native_status(owner.device)['active']:
            raise FileExistsError('Native block views are already active')
        if not owner.created:
            raise FileExistsError('Close the existing idle private owner before opening')
        for role in ('decoy', 'hidden'):
            if mapping_identity(name + '-' + role) is not None:
                raise FileExistsError('Public view name is already in use')
        identity = context(SimpleNamespace(uuid=owner.uuid, layout=SimpleNamespace(
            primary_bytes=owner.device.sectors * owner.device.sector_size, sector_size=owner.device.sector_size)))
        owner.device.validate()
        owner.device.suspend(); owner.device.begin()
        native_setup(owner.device, hidden_key, identity, initialize=initialize)
        owner.device.resume()
        status = native_status(owner.device)
        for role, sectors in (('decoy', owner.device.sectors * (owner.device.sector_size // 512)), ('hidden', status['hidden_bytes'] // 512)):
            mapping = name + '-' + role
            token = 'PIVVIEW-' + secrets.token_hex(16)
            created.append((mapping, token))
            dm('create', mapping, '--uuid', token, input=f'0 {sectors} piv-view /dev/mapper/{name} {owner.device.generation} {role}\n')
        return dict(decoy='/dev/mapper/' + name + '-decoy', hidden='/dev/mapper/' + name + '-hidden',
                    hidden_bytes=status['hidden_bytes'])
    except BaseException as error:
        try:
            for mapping, token in reversed(created):
                identity = mapping_identity(mapping)
                if identity is not None and identity[2] == token:
                    remove_mapping(mapping, identity)
            if owner.created:
                # Removing the exclusive attempt's owner frees its native state;
                # do not issue an extra native checkpoint on failure.
                owner.remove()
        except BaseException as cleanup:
            error.add_note(f'Private mapping cleanup incomplete: {cleanup}')
        raise
    finally:
        owner.close()


def close_blocks(source, key_file, *, name='piv-native', allow_test_stack=False):
    if dm('info', name, check=False).returncode:
        raise FileNotFoundError('Native owner is not active')
    owner = GuestOwner(source, key_file, name, allow_test_stack=allow_test_stack)
    try:
        status = native_status(owner.device)
        views = []
        device = owner.device.owner.stat().st_rdev
        owner_names = {str(owner.device.owner), f'{os.major(device)}:{os.minor(device)}'}
        for role in ('hidden', 'decoy'):
            mapping = name + '-' + role
            identity = mapping_identity(mapping)
            if identity is None:
                continue
            words = dm('table', mapping).stdout.split()
            sectors = (status['hidden_bytes'] // 512 if role == 'hidden' else
                       owner.device.sectors * (owner.device.sector_size // 512))
            if (not status['active'] or len(words) != 6 or
                    words[:3] != ['0', str(sectors), 'piv-view'] or
                    words[3] not in owner_names or
                    words[4:] != [str(owner.device.generation), role]):
                raise ValueError(f'Refusing to remove unrelated view {mapping}')
            views.append((mapping, identity))
        # Validate BOTH names before removing either one.
        for mapping, identity in views:
            remove_mapping(mapping, identity)
        if status['active']:
            native_detach(owner.device)
        owner.remove()
    finally:
        owner.close()
