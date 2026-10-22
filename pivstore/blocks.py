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

from .format import context_v4
from .kernel_api import command

SETUP = struct.Struct('=IIQII32s128s2I')
# SETUP ABI 4 (format v4 only): flags INITIALIZE and AB.
SETUP_VERSION = 4
SETUP_INITIALIZE, SETUP_AB, SETUP_VERIFY = 1, 8, 16
STATUS = struct.Struct('=QQQQIIII')
KEYSLOT = struct.Struct('=IIQII32s2I')
# Passphrase KEK parameters; must equal rust/src/blocks.rs. Argon2id (default):
# RFC 9106 second recommendation; scrypt kept as an explicit alternative.
SCRYPT = dict(n=2 ** 17, r=8, p=1, maxmem=256 * 1024 * 1024, dklen=32)
ARGON2ID = dict(length=32, iterations=3, lanes=4, memory_cost=64 * 1024)
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
              ab=False, verify=False, allow_no_journal=None, allow_test_stack=False, allow_second_disk=False,
              kdf=None):
    # Guest instrumentation: guest_code exports PIV_ALLOW_NO_JOURNAL=1 when the
    # fixture persists stock no-journal, so every suite opens it unchanged.
    if allow_no_journal is None:
        allow_no_journal = os.environ.get('PIV_ALLOW_NO_JOURNAL') == '1'
    args = ['open-blocks', '--device', source, '--key-file', key_file, '--name', name,
            '--hidden-passphrase-file' if passphrase else '--hidden-key-file', secret_path]
    if initialize: args.append('--initialize')
    if ab: args.append('--ab')
    if verify: args.append('--verify')
    if allow_no_journal: args.append('--allow-no-journal')
    if allow_test_stack: args.append('--allow-test-stack')
    if allow_second_disk: args.append('--allow-second-disk')
    if kdf is not None: args += ['--kdf', kdf]
    return [str(a) for a in args]


def open_blocks(source, key_file, hidden_key=None, *, hidden_passphrase=None, env=None, **options):
    """Open paired views through pivsetup; returns decoy/hidden paths and hidden_bytes."""
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


def close_blocks(source, key_file, *, name='piv-native', allow_test_stack=False, allow_second_disk=False):
    run(['close-blocks', '--device', source, '--key-file', key_file, '--name', name]
        + (['--allow-test-stack'] if allow_test_stack else [])
        + (['--allow-second-disk'] if allow_second_disk else []))


def migrate(source, source_key_file, source_hidden_key, target, target_key_file, target_hidden_key, *,
            ab=False, allow_second_disk=False):
    """pivsetup migrate: copy both views into a freshly formatted target that it
    initializes, then re-read and compare both (rekey/resize/sector-size change).
    Returns byte counts per view. Hidden keys are passed in private files."""
    with secret_file(source_hidden_key) as source_path, secret_file(target_hidden_key) as target_path:
        args = ['migrate', '--source', source, '--source-key-file', source_key_file,
                '--source-hidden-key-file', source_path, '--target', target,
                '--target-key-file', target_key_file, '--target-hidden-key-file', target_path]
        if ab: args.append('--ab')
        if os.environ.get('PIV_ALLOW_NO_JOURNAL') == '1': args.append('--allow-no-journal')
        if allow_second_disk: args.append('--allow-second-disk')
        return json.loads(run(args))


def keyslot(source, key_file, slot, kek=None, *, name='piv-native', allow_test_stack=False, passphrase=None,
            kdf=None):
    """Add (kek or passphrase given) or remove keyslot @slot on active v4 views."""
    adding = kek is not None or passphrase is not None
    args = ['keyslot', 'add' if adding else 'remove', '--device', source, '--key-file', key_file,
            '--name', name, '--slot', slot] + (['--allow-test-stack'] if allow_test_stack else [])
    if not adding:
        run(args)
        return
    option = '--new-key-file' if kek is not None else '--new-passphrase-file'
    if kdf is not None: args += ['--kdf', kdf]
    with secret_file(kek if kek is not None else passphrase) as path:
        run(args + [option, path])


def native_status(device):
    """Test instrumentation: volatile kernel status of a bound control."""
    data = bytearray(STATUS.size)
    fcntl.ioctl(device.fd, command(14, STATUS.size, 2), data, True)
    generation, hidden, encryptions, invalidations, active, views, failed, version = STATUS.unpack(data)
    if generation != device.generation or version != 3:
        raise ValueError('Unsupported native status ABI')
    return dict(active=bool(active), views=views, failed=bool(failed),
                hidden_bytes=hidden, encryptions=encryptions, invalidations=invalidations)


def base_identity(owner):
    """Cross-check of pivsetup's public (v4 base) context for an owner."""
    return context_v4(owner.uuid, owner.device.sectors * owner.device.sector_size, owner.device.sector_size)


def passphrase_kek(passphrase, base_context, kdf='argon2id'):
    """Independent cross-check of pivsetup's v4 passphrase KEK.

    argon2id: salt = context || "/kek/argon2id" (Python cryptography);
    scrypt: salt = context || "/kek" (hashlib).
    """
    if not passphrase:
        raise ValueError('Empty passphrase')
    if kdf == 'scrypt':
        import hashlib
        return hashlib.scrypt(passphrase, salt=base_context + b'/kek', **SCRYPT)
    if kdf != 'argon2id':
        raise ValueError('Unsupported KDF')
    salt = base_context + b'/kek/argon2id'
    try:  # cryptography >= 44 (OpenSSL Argon2)
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError:  # e.g. Debian 13 guests: argon2-cffi (reference C implementation)
        from argon2.low_level import Type, hash_secret_raw
        return hash_secret_raw(passphrase, salt, time_cost=ARGON2ID['iterations'],
                               memory_cost=ARGON2ID['memory_cost'], parallelism=ARGON2ID['lanes'],
                               hash_len=ARGON2ID['length'], type=Type.ID, version=19)
    return Argon2id(salt=salt, **ARGON2ID).derive(passphrase)
