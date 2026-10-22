"""Client for the Rust `pivsetup` setup frontend, plus test instrumentation.

The supported setup path (open-blocks, close-blocks, keyslot) is the static
pivsetup binary (rust/). These wrappers keep the former Python API for guest
tests and automation: keys are passed through private 0600 files under /run,
never argv, and pivsetup errors become OSError (with errno), ValueError or
KeyboardInterrupt (exit 130) again. native_status and the raw ABI structs are
test instrumentation for the kernel control device; passphrase_kek and
base_identity are independent cross-check implementations.
"""
from contextlib import contextmanager
import errno
import fcntl
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile

from .format import base_context
from .kernel_api import command

SETUP = struct.Struct('=IIQII32s128sIIQQQ')
# SETUP ABI 6 (format v5 only, read/write ioctl): flags INITIALIZE, AB, VERIFY,
# QUICK (with INITIALIZE) and FILL (without); then the RS parity (0, 4, 8 or
# 16; non-zero only with INITIALIZE), a reserved word and the FILL output
# counts (valid, written, failed; zero on input).
SETUP_VERSION = 6
SETUP_INITIALIZE, SETUP_AB, SETUP_VERIFY, SETUP_QUICK, SETUP_FILL = 1, 8, 16, 32, 64
STATUS = struct.Struct('=QQQIIII')  # STATUS version 4
KEYSLOT = struct.Struct('=IIQII32s32s2I')  # KEYSLOT version 2: slot, op, new KEK, authorizing KEK
# Passphrase KEK cost tiers (--kdf-cost, docs/format-v5.md); must equal
# rust/src/blocks.rs. Argon2id v1.3, 4 lanes, 32-byte output: tier ->
# (memory KiB, passes). The tier is recorded nowhere and is part of the salt.
ARGON2ID_TIERS = {1: (64 * 1024, 3), 2: (256 * 1024, 3), 3: (1024 * 1024, 3), 4: (2048 * 1024, 6)}
DEFAULT_KDF_COST = 3
ERROR = re.compile(r'^pivsetup: (?:\[Errno (\d+)\] )?(.*)$')


def binary():
    """pivsetup from $PIVSETUP, PATH, the guest share or the test initramfs."""
    candidates = [os.environ.get('PIVSETUP'), shutil.which('pivsetup'), '/mnt/piv-work/pivsetup', '/piv/pivsetup']
    for candidate in candidates:
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(errno.ENOENT, 'pivsetup binary not found (set PIVSETUP)')


@contextmanager
def secret_file(data):
    """A private /run file holding @data for the duration of one call."""
    fd, path = tempfile.mkstemp(prefix='pivsetup-secret-', dir='/run')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        yield path
    finally:
        os.unlink(path)


def error_from(returncode, stderr):
    """Rebuild the Python exception a pivsetup failure corresponds to."""
    lines = [line for line in stderr.splitlines() if line.startswith('pivsetup: ')]
    match = ERROR.match(lines[0]) if lines else None
    if returncode == 130:
        error = KeyboardInterrupt()
    elif match and match.group(1):
        error = OSError(int(match.group(1)), match.group(2))
    else:
        error = ValueError(match.group(2) if match else stderr.strip() or 'pivsetup failed')
    for line in lines[1:]:
        error.add_note(line[len('pivsetup: '):])
    return error


def run(args, env=None):
    result = subprocess.run([binary(), *map(str, args)], capture_output=True, text=True,
                            env=None if env is None else {**os.environ, **env})
    if result.returncode:
        raise error_from(result.returncode, result.stderr)
    return result.stdout


def open_args(source, key_file, secret_path, *, passphrase=False, name='piv-native', initialize=False,
              quick=False, fill=False, ab=False, verify=False, parity=0, kdf_cost=None):
    args = ['open-blocks', '--device', source, '--key-file', key_file, '--name', name,
            '--hidden-passphrase-file' if passphrase else '--hidden-key-file', secret_path]
    if initialize: args.append('--initialize')
    if quick: args.append('--quick')
    if fill: args.append('--fill')
    if ab: args.append('--ab')
    if parity: args += ['--parity', str(parity)]
    if kdf_cost is not None: args += ['--kdf-cost', str(kdf_cost)]
    if verify: args.append('--verify')
    return [str(a) for a in args]


def open_blocks(source, key_file, hidden_key=None, *, hidden_passphrase=None, env=None, **options):
    """Open paired views through pivsetup; returns decoy/hidden paths and
    hidden_bytes (with fill=True also 'fill': valid/written/failed counts)."""
    passphrase = hidden_passphrase is not None
    with secret_file(hidden_passphrase if passphrase else hidden_key) as path:
        return json.loads(run(open_args(source, key_file, path, passphrase=passphrase, **options), env))


@contextmanager
def spawn_open(source, key_file, hidden_key, *, env, **options):
    """Start pivsetup open-blocks asynchronously (gate/hold/signal tests).

    Yields the Popen object; the caller waits for it. The key file lives until
    the context exits, which also reaps (or kills) the process.
    """
    with secret_file(hidden_key) as path:
        process = subprocess.Popen([binary(), *open_args(source, key_file, path, **options)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env={**os.environ, **env})
        try:
            yield process
        finally:
            if process.poll() is None:
                process.kill()
            if process.stdout and not process.stdout.closed:
                process.communicate()


def close_blocks(source, key_file, *, name='piv-native'):
    run(['close-blocks', '--device', source, '--key-file', key_file, '--name', name])


def migrate(source, source_key_file, source_hidden_key, target, target_key_file, target_hidden_key, *,
            ab=False, parity=0):
    """pivsetup migrate: copy both views into a freshly formatted target that it
    initializes, then re-read and compare both (rekey/resize/sector-size change).
    Returns byte counts per view. Hidden keys are passed in private files."""
    with secret_file(source_hidden_key) as source_path, secret_file(target_hidden_key) as target_path:
        args = ['migrate', '--source', source, '--source-key-file', source_key_file,
                '--source-hidden-key-file', source_path, '--target', target,
                '--target-key-file', target_key_file, '--target-hidden-key-file', target_path]
        if ab: args.append('--ab')
        if parity: args += ['--parity', str(parity)]
        return json.loads(run(args))


def keyslot(source, key_file, slot, kek=None, *, hidden_key=None, hidden_passphrase=None, hidden_kdf_cost=None,
            name='piv-native', passphrase=None, kdf_cost=None):
    """Add (kek or passphrase given; @kdf_cost: the new passphrase's tier) or
    remove keyslot @slot on active v5 views, authorized by the current hidden
    key or passphrase (@hidden_kdf_cost: its tier) of a listed keyslot."""
    adding = kek is not None or passphrase is not None
    if (hidden_key is None) == (hidden_passphrase is None):
        raise ValueError('Give exactly one of hidden_key or hidden_passphrase')
    args = ['keyslot', 'add' if adding else 'remove', '--device', source, '--key-file', key_file,
            '--name', name, '--slot', slot]
    if hidden_kdf_cost is not None: args += ['--kdf-cost', str(hidden_kdf_cost)]
    if kdf_cost is not None: args += ['--new-kdf-cost', str(kdf_cost)]
    auth_option = '--hidden-key-file' if hidden_key is not None else '--hidden-passphrase-file'
    with secret_file(hidden_key if hidden_key is not None else hidden_passphrase) as auth:
        args += [auth_option, auth]
        if not adding:
            run(args)
            return
        option = '--new-key-file' if kek is not None else '--new-passphrase-file'
        with secret_file(kek if kek is not None else passphrase) as path:
            run(args + [option, path])


def native_status(device):
    """Test instrumentation: volatile kernel status of a bound control."""
    data = bytearray(STATUS.size)
    fcntl.ioctl(device.fd, command(14, STATUS.size, 2), data, True)
    generation, hidden, encryptions, active, views, failed, version = STATUS.unpack(data)
    if generation != device.generation or version != 4:
        raise ValueError('Unsupported native status ABI')
    return dict(active=bool(active), views=views, failed=bool(failed),
                hidden_bytes=hidden, encryptions=encryptions)


def base_identity(owner):
    """Cross-check of pivsetup's public (v5 base) context for an owner."""
    return base_context(owner.uuid, owner.device.sectors * owner.device.sector_size, owner.device.sector_size)


def passphrase_kek(passphrase, base_context, tier=DEFAULT_KDF_COST):
    """Independent cross-check of pivsetup's v5 passphrase KEK: Argon2id at
    cost @tier with salt = base context || "/kek/argon2id/" || ASCII tier."""
    if not passphrase:
        raise ValueError('Empty passphrase')
    if tier not in ARGON2ID_TIERS:
        raise ValueError('Unsupported KDF cost tier')
    memory, passes = ARGON2ID_TIERS[tier]
    salt = base_context + b'/kek/argon2id/' + str(tier).encode('ascii')
    try:  # cryptography >= 44 (OpenSSL Argon2)
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError:  # e.g. Debian 13 guests: argon2-cffi (reference C implementation)
        from argon2.low_level import Type, hash_secret_raw
        return hash_secret_raw(passphrase, salt, time_cost=passes, memory_cost=memory, parallelism=4,
                               hash_len=32, type=Type.ID, version=19)
    return Argon2id(salt=salt, length=32, iterations=passes, lanes=4, memory_cost=memory).derive(passphrase)
