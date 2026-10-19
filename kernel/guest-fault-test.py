#!/usr/bin/env python3
"""Disposable guest: setup ownership, direct lower EIO, fail-stop and recreation."""
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pivstore.blocks as blocks
import pivstore.kernel_owner as owners
from pivstore.kernel_api import dm, mapping_identity

W = Path('/mnt/piv-work')
SOURCE = '/dev/mapper/piv-test-fault'
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
EXPECTED = (W / 'expected-hidden-volume').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
NAMES = ('piv-native-hidden', 'piv-native-decoy', 'piv-native', 'piv-native_dif')
results = []

def open_views():
    value = blocks.open_blocks(SOURCE, KEY, HKEY, allow_test_stack=True)
    subprocess.run(['udevadm', 'settle'], check=True)
    return value

def close_views():
    blocks.close_blocks(SOURCE, KEY, allow_test_stack=True)

def owner():
    return owners.GuestOwner(SOURCE, KEY, allow_test_stack=True)

def absent():
    assert all(mapping_identity(name) is None for name in NAMES)
    assert not list(Path('/dev').glob('pivctl-*'))

def rejected(fn, exception=OSError):
    try:
        fn()
    except exception as exc:
        return exc
    raise AssertionError('Operation unexpectedly succeeded')

def table(mode='linear'):
    line = ('linear /dev/vdb 0' if mode == 'linear' else
            f'flakey /dev/vdb 0 0 3600 1 error_{mode}')
    return '0 262144 ' + line + '\n'

def fault(mode='linear'):
    dm('suspend', '--noflush', 'piv-test-fault')
    dm('reload', 'piv-test-fault', input=table(mode))
    dm('resume', 'piv-test-fault')

def direct(path, *, write=None, offset=0):
    value = mmap.mmap(-1, 512)
    fd = os.open(path, os.O_RDWR | os.O_DIRECT)
    try:
        if write is None:
            assert os.preadv(fd, [value], offset) == 512
            return value[:]
        assert len(write) == 512
        value[:] = write
        assert os.pwritev(fd, [value], offset) == 512
        os.fsync(fd)
    finally:
        os.close(fd)
        value.close()

def verify(views, unavailable=None):
    assert subprocess.check_output(['sha256sum', views['decoy']], text=True).split()[0] == PRIMARY
    repaired = False
    for index in range(len(EXPECTED) // 512):
        expected = EXPECTED[index * 512:(index + 1) * 512]
        try:
            actual = direct(views['hidden'], offset=index * 512)
        except OSError as exc:
            assert index == unavailable and exc.errno == errno.EIO
            direct(views['hidden'], write=expected, offset=index * 512)
            actual = direct(views['hidden'], offset=index * 512)
            repaired = True
        assert actual == expected, index
    return repaired

absent()
dm('create', 'piv-test-fault', input=table())
# Name collisions must not remove any unrelated mapping.
for foreign in ('piv-native', 'piv-native_dif', 'piv-native-decoy', 'piv-native-hidden'):
    dm('create', foreign, '--uuid', 'FOREIGN-' + foreign, input='0 1 error\n')
    identity = mapping_identity(foreign)
    rejected(open_views, (FileExistsError, ValueError))
    assert mapping_identity(foreign) == identity
    for name in NAMES:
        if name != foreign: assert mapping_identity(name) is None
    dm('remove', '--retry', foreign)
    absent()
results.append('foreign setup names preserved')

# Inject failure immediately after cryptsetup created both mappings.
real_crypt = owners.crypt
def crypt_after(*args):
    result = real_crypt(*args)
    if args[0] == 'open': raise OSError(errno.EIO, 'after cryptsetup creation')
    return result
with patch.object(owners, 'crypt', side_effect=crypt_after):
    rejected(open_views)
absent()
results.append('post-cryptsetup failure cleanup')

real_setup, real_dm = blocks.native_setup, blocks.dm
for phase in ('before-setup', 'kernel-auth', 'after-setup', 'first-view', 'second-view'):
    def setup(*args, **kw):
        if phase == 'before-setup': raise OSError(errno.EIO, 'before native setup')
        if phase == 'kernel-auth':
            fault('reads')
            try: return real_setup(*args, **kw)
            finally: fault()
        result = real_setup(*args, **kw)
        if phase == 'after-setup': raise OSError(errno.EIO, 'after native setup')
        return result
    def create(*args, **kw):
        result = real_dm(*args, **kw)
        if args[0] == 'create' and phase == ('first-view' if args[1].endswith('decoy') else 'second-view'):
            raise OSError(errno.EIO, 'after view creation')
        return result
    with patch.object(blocks, 'native_setup', side_effect=setup), patch.object(blocks, 'dm', side_effect=create):
        rejected(open_views)
    absent()
    results.append(phase + ' cleanup')
print('Setup phase failures and unrelated-name protection passed', flush=True)

# Existing bare owners are not silently adopted or destroyed by a failed open.
existing = owner(); existing.close()
before = {n: mapping_identity(n) for n in NAMES}
rejected(open_views, FileExistsError)
assert before == {n: mapping_identity(n) for n in NAMES}
close_views(); absent()
# Validate both view names before deleting either on close.
v = open_views()
before = {n: mapping_identity(n) for n in NAMES}
rejected(open_views, FileExistsError)
assert before == {n: mapping_identity(n) for n in NAMES}
dm('remove', '--retry', 'piv-native-hidden')
dm('create', 'piv-native-hidden', '--uuid', 'FOREIGN-CLOSE', input='0 1 error\n')
before = {n: mapping_identity(n) for n in NAMES}
rejected(close_views, ValueError)
assert before == {n: mapping_identity(n) for n in NAMES}
dm('remove', '--retry', 'piv-native-hidden'); close_views(); absent()
results.append('existing owners and unrelated close names preserved')

for role in ('decoy', 'hidden'):
    for mode in ('reads', 'writes'):
        v = open_views()
        handle = owner()
        generation = handle.device.generation
        # Sector0 may be served from dm-integrity's cached setup checkpoint.
        # Choose record10, which setup did not write, and witness the raw fault.
        offset = 10 * (512 if role == 'hidden' else
                       (576 // handle.device.iv_size) * handle.device.sector_size)
        old = direct(v[role], offset=offset)
        before_count = blocks.native_status(handle.device)['encryptions']
        print(f'Injecting lower {mode} through {role} at carrier record10', flush=True)
        fault(mode)
        if mode == 'reads': assert rejected(lambda: direct(SOURCE)).errno == errno.EIO
        failure = rejected(lambda: direct(v[role], write=old if mode == 'writes' else None, offset=offset))
        assert failure.errno == errno.EIO
        failed = blocks.native_status(handle.device)
        assert failed['failed']
        spent = failed['encryptions'] - before_count
        assert (spent > 0) if mode == 'writes' else (spent == 0)
        fault()
        # Removing the fault does not clear the shared owner's fail-stop.
        for other in ('decoy', 'hidden'):
            assert rejected(lambda: direct(v[other])).errno == errno.EIO
            assert rejected(lambda: direct(v[other], write=old)).errno == errno.EIO
        handle.close()
        close_views(); absent()
        v = open_views()
        handle = owner()
        assert handle.device.generation != generation and not blocks.native_status(handle.device)['failed']
        handle.close()
        repaired = verify(v, unavailable=10)
        close_views(); absent()
        results.append(dict(view=role, fault=mode, failed_both_views=True, recreated=True, repaired=repaired, prepared_encryptions=spent))
        print(f'{role} lower {mode}: fail-stop, teardown, replay and recreation passed', flush=True)

# A legitimate fresh-IV primary rewrite destroys one hidden record only.
handle = owner(); dev = handle.device
handle.device.suspend(); dev.begin()
old = dev.read_iv(0, quiesced=True)
value = dev.prepare(0, old, os.urandom(dev.iv_size))
dev.apply(0, old, value); dev.end(); dev.resume(); handle.remove(); handle.close()
v = open_views()
assert rejected(lambda: direct(v['hidden'])).errno == errno.EIO
assert direct(v['hidden'], offset=512) == EXPECTED[512:1024]
handle = owner(); assert not blocks.native_status(handle.device)['failed']; handle.close()
direct(v['decoy'], write=direct(v['decoy']))
assert rejected(lambda: direct(v['hidden'])).errno == errno.EIO
handle = owner(); assert not blocks.native_status(handle.device)['failed']; handle.close()
direct(v['hidden'], write=EXPECTED[:512]); assert verify(v) is False
close_views(); absent()
results.append('local hidden EIO, invalid marker and direct repair remain isolated')

# Leave a closed image and complete oracles for independent authentication.
dm('remove', '--retry', 'piv-test-fault')
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0] == PRIMARY
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'fault-final.img'), 'bs=1M', 'status=none'], check=True)
subprocess.run(['rmmod', 'dm_piv'], check=True)
assert Path('/sys/module/dm_crypt').is_dir()
(W / 'fault-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Setup cleanup, foreign-name protection, direct lower read/write errors, fail-stop and recreation passed\n')
