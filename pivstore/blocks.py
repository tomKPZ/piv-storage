"""Configure stateless paired native DM views; no persistent userspace state."""
import errno
import fcntl
import os
import struct
import secrets
from types import SimpleNamespace
from .format import context, context_v4
from .kernel_api import command, dm, mapping_identity, remove_mapping
from .kernel_owner import GuestOwner

SETUP = struct.Struct('=IIQII32s128s2I')
SETUP_INITIALIZE = 1
# Accept a carrier with no record authenticating under the hidden key. Without
# this (or initialize) the kernel rejects setup with EKEYREJECTED, because decoy
# writes under a wrong hidden key would destroy valid hidden records.
SETUP_UNINITIALIZED = 2
# Format v4 fragment-local records; 16-byte IV (AEGIS-128) profiles only.
SETUP_FORMAT_V4 = 4
# v4 A/B record slots: interrupted hidden writes keep the previous version.
SETUP_AB = 8
STATUS = struct.Struct('=QQQQIIII')
KEYSLOT = struct.Struct('=IIQII32s2I')
KEYSLOT_ADD, KEYSLOT_REMOVE = 1, 2
# scrypt parameters for passphrase KEKs (32 bytes); nothing is stored in clear,
# so they must be the same on every open.
SCRYPT = dict(n=2 ** 17, r=8, p=1, maxmem=256 * 1024 * 1024, dklen=32)


def passphrase_kek(passphrase, base_context):
    """KEK for a v4 keyslot from a passphrase; salt = v4 base context."""
    import hashlib
    if not passphrase:
        raise ValueError('Empty passphrase')
    return hashlib.scrypt(passphrase, salt=base_context + b'/kek', **SCRYPT)


def native_status(device):
    data = bytearray(STATUS.size)
    fcntl.ioctl(device.fd, command(14, STATUS.size, 2), data, True)
    generation, hidden, encryptions, invalidations, active, views, failed, version = STATUS.unpack(data)
    if generation != device.generation or version != 3:
        raise ValueError('Unsupported native status ABI')
    return dict(active=bool(active), views=views, failed=bool(failed),
                hidden_bytes=hidden, encryptions=encryptions, invalidations=invalidations)


def native_setup(device, hidden_key, identity, *, initialize=False, uninitialized=False, format=None, ab=False):
    """format None (auto at open), 3 or 4; ab only when initializing format 4."""
    if len(hidden_key) != 32 or not 0 < len(identity) <= 120:
        raise ValueError('Invalid native key/context size')
    if format not in (None, 3, 4) or (ab and not (format == 4 and initialize)):
        raise ValueError('Unsupported hidden format')
    flags = ((SETUP_INITIALIZE if initialize else 0) | (SETUP_UNINITIALIZED if uninitialized else 0) |
             (SETUP_FORMAT_V4 if format == 4 else 0) | (SETUP_AB if ab else 0))
    data = bytearray(SETUP.pack(3, SETUP.size, device.generation, flags,
                              len(identity), hidden_key, identity, 0, 0))
    try:
        fcntl.ioctl(device.fd, command(12, SETUP.size, 1), data, True)
    finally:
        data[:] = bytes(len(data))


def native_keyslot(device, slot, kek=None):
    """Add (kek given) or remove keyslot @slot on an active v4 owner."""
    if not 0 <= slot < 4 or (kek is not None and len(kek) != 32):
        raise ValueError('Invalid keyslot request')
    data = bytearray(KEYSLOT.pack(1, KEYSLOT.size, device.generation, slot,
                                  KEYSLOT_ADD if kek is not None else KEYSLOT_REMOVE,
                                  kek or bytes(32), 0, 0))
    try:
        fcntl.ioctl(device.fd, command(15, KEYSLOT.size, 1), data, True)
    finally:
        data[:] = bytes(len(data))


def base_identity(owner):
    primary_bytes = owner.device.sectors * owner.device.sector_size
    if owner.device.iv_size == 16:
        return context_v4(owner.uuid, primary_bytes, owner.device.sector_size)
    return context(SimpleNamespace(uuid=owner.uuid, layout=SimpleNamespace(
        primary_bytes=primary_bytes, sector_size=owner.device.sector_size)))


def keyslot(source, key_file, slot, kek=None, *, name='piv-native', allow_test_stack=False):
    owner = GuestOwner(source, key_file, name, allow_test_stack=allow_test_stack)
    try:
        if owner.created or not native_status(owner.device)['active']:
            raise FileNotFoundError('Native views must be active to manage keyslots')
        native_keyslot(owner.device, slot, kek)
    finally:
        if owner.created:
            owner.remove(abort=True)
        owner.close()


def native_detach(device):
    fcntl.ioctl(device.fd, command(13, 48, 1), device.request(), True)


def open_blocks(source, key_file, hidden_key, *, name='piv-native', initialize=False,
                uninitialized=False, format=None, ab=False, allow_test_stack=False,
                hidden_passphrase=None, allow_second_disk=False):
    """Open paired views. On 16-byte-IV profiles the hidden key is a format v4
    keyslot KEK (or derived from @hidden_passphrase) and the format is detected:
    a v4 keyslot, else a v3 record. format=4 requires v4; initialization uses
    format (default 3) and ab.
    """
    if hidden_passphrase is None and len(hidden_key) != 32:
        raise ValueError('Hidden key must contain exactly 32 bytes')
    owner = GuestOwner(source, key_file, name, allow_test_stack=allow_test_stack,
                       allow_second_disk=allow_second_disk)
    created = []
    try:
        if native_status(owner.device)['active']:
            raise FileExistsError('Native block views are already active')
        if not owner.created:
            raise FileExistsError('Close the existing idle private owner before opening')
        for role in ('decoy', 'hidden'):
            if mapping_identity(name + '-' + role) is not None:
                raise FileExistsError('Public view name is already in use')
        if format == 4 and owner.device.iv_size != 16:
            raise ValueError('Format v4 requires a 16-byte IV (AEGIS-128) primary profile')
        identity = base_identity(owner)
        if hidden_passphrase is not None:
            if owner.device.iv_size != 16:
                raise ValueError('Passphrases are supported only for format v4 keyslots')
            hidden_key = passphrase_kek(hidden_passphrase, identity)
        owner.device.validate()
        owner.device.suspend(); owner.device.begin()
        try:
            native_setup(owner.device, hidden_key, identity, initialize=initialize,
                         uninitialized=uninitialized, format=format, ab=ab)
        except OSError as error:
            if error.errno == errno.EKEYREJECTED:
                error.add_note('No hidden record authenticated: wrong hidden key, or an '
                               'uninitialized carrier (use --initialize or --uninitialized)')
            raise
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
                owner.remove(abort=True)
        except BaseException as cleanup:
            error.add_note(f'Private mapping cleanup incomplete: {cleanup}')
        raise
    finally:
        owner.close()


def close_blocks(source, key_file, *, name='piv-native', allow_test_stack=False, allow_second_disk=False):
    if dm('info', name, check=False).returncode:
        raise FileNotFoundError('Native owner is not active')
    owner = GuestOwner(source, key_file, name, allow_test_stack=allow_test_stack,
                       allow_second_disk=allow_second_disk)
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


def _copy(source, target, length, chunk=1 << 20):
    import hashlib
    digest = hashlib.sha256()
    with open(source, 'rb', buffering=0) as src, open(target, 'r+b', buffering=0) as dst:
        done = 0
        while done < length:
            data = src.read(min(chunk, length - done))
            if not data:
                raise OSError('Short read during migration')
            dst.write(data)
            digest.update(data)
            done += len(data)
        os.fsync(dst.fileno())
    return digest.hexdigest()


def _digest(path, length, chunk=1 << 20):
    import hashlib
    digest = hashlib.sha256()
    with open(path, 'rb', buffering=0) as src:
        done = 0
        while done < length:
            data = src.read(min(chunk, length - done))
            if not data:
                raise OSError('Short read during verification')
            digest.update(data)
            done += len(data)
    return digest.hexdigest()


def migrate(source, source_key_file, source_hidden_key, target, target_key_file, target_hidden_key, *,
            target_format=None, target_ab=False, allow_second_disk=False):
    """Copy decoy and hidden contents into a freshly formatted, initialized target.

    This one offline workflow provides primary rekey (a new LUKS volume key),
    cipher/sector-size change and offline resize. The target hidden volume is
    destructively initialized first; both views of both volumes are compared by
    SHA-256 after copying. Source contents are only read (activation still writes
    ordinary journal metadata); retire the source yourself.
    """
    src = open_blocks(source, source_key_file, source_hidden_key, name='piv-src',
                      allow_second_disk=allow_second_disk)
    try:
        dst = open_blocks(target, target_key_file, target_hidden_key, name='piv-dst', initialize=True,
                          format=target_format, ab=target_ab, allow_second_disk=allow_second_disk)
        try:
            sizes = {role: int(command_output(['blockdev', '--getsize64', src[role]])) for role in ('decoy', 'hidden')}
            room = {role: int(command_output(['blockdev', '--getsize64', dst[role]])) for role in ('decoy', 'hidden')}
            for role in ('decoy', 'hidden'):
                if room[role] < sizes[role]:
                    raise ValueError(f'Target {role} view is smaller than the source')
            result = {}
            for role in ('decoy', 'hidden'):
                copied = _copy(src[role], dst[role], sizes[role])
                if _digest(src[role], sizes[role]) != copied or _digest(dst[role], sizes[role]) != copied:
                    raise OSError(f'{role} verification failed after migration')
                result[role] = dict(bytes=sizes[role], target_bytes=room[role], sha256=copied)
            return result
        finally:
            close_blocks(target, target_key_file, name='piv-dst', allow_second_disk=allow_second_disk)
    finally:
        close_blocks(source, source_key_file, name='piv-src', allow_second_disk=allow_second_disk)


def command_output(args):
    import subprocess
    return subprocess.check_output(args, text=True)
