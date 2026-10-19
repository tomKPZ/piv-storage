#!/usr/bin/env python3
"""Real lower-device EIO and root-ext4 ENOSPC; disposable guest only."""
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess

from pivstore.blocks import open_blocks, close_blocks, native_status
from pivstore.kernel_api import dm
from pivstore.kernel_owner import GuestOwner, guest_guard
from pivstore.native_log import inspect_log
from pivstore.blob import context
from types import SimpleNamespace

guest_guard('/dev/vdb')
W = Path('/mnt/piv-work')
STATE = Path('/var/tmp/piv-fault/state')
SOURCE = '/dev/mapper/piv-test-fault'
KEY = (W / 'hidden.key').read_bytes()
CREDENTIAL = W / 'passphrase.key'
STATE.mkdir(mode=0o700, parents=True)
shutil.copyfile(W / 'native.log', STATE / 'native.log')
os.chmod(STATE / 'native.log', 0o600)
(STATE / 'native.phase').write_bytes(b'ready\n')
os.chmod(STATE / 'native.phase', 0o600)
results = []


def lower(failed=False):
    table = ('0 262144 flakey /dev/vdb 0 0 3600 1 error_writes\n' if failed else
             '0 262144 linear /dev/vdb 0\n')
    if dm('info', 'piv-test-fault', check=False).returncode:
        dm('create', 'piv-test-fault', input=table)
    else:
        dm('suspend', '--noflush', 'piv-test-fault')
        dm('reload', 'piv-test-fault', input=table)
        dm('resume', 'piv-test-fault')


def open_views():
    return open_blocks(SOURCE, CREDENTIAL, KEY, state_directory=STATE, allow_test_stack=True)


def close_views():
    close_blocks(SOURCE, CREDENTIAL, allow_test_stack=True)


def status():
    owner = GuestOwner(SOURCE, CREDENTIAL, allow_test_stack=True)
    try:
        return native_status(owner.device)
    finally:
        owner.close()


def direct(path, size, offset=0, value=None):
    fd = os.open(path, os.O_RDWR | os.O_DIRECT | os.O_SYNC)
    try:
        with mmap.mmap(-1, 4096) as buffer:
            if value is None:
                assert os.preadv(fd, [memoryview(buffer)[:size]], offset) == size
                return bytes(buffer[:size])
            buffer[:size] = value
            assert os.pwritev(fd, [memoryview(buffer)[:size]], offset) == size
    finally:
        os.close(fd)


def tuple_hash():
    owner = GuestOwner(SOURCE, CREDENTIAL, allow_test_stack=True)
    fd = os.open('/dev/vdb', os.O_RDONLY | os.O_DIRECT)
    try:
        with mmap.mmap(-1, 4096) as buffer:
            def read_block(offset):
                assert offset % 4096 == 0
                assert os.preadv(fd, [buffer], offset) == 4096
                return bytes(buffer)
            digest = hashlib.sha256()
            cached_offset, cached = None, None
            for i in range(owner.layout.sectors):
                data, tag = owner.layout.offsets(i)
                digest.update(read_block(data))
                block = tag // 4096 * 4096
                if cached_offset != block:
                    cached_offset, cached = block, read_block(block)
                at = tag - block
                metadata = cached[at:at + 28]
                if len(metadata) < 28:
                    metadata += read_block(block + 4096)[:28 - len(metadata)]
                digest.update(metadata)
            return digest.hexdigest()
    finally:
        os.close(fd)
        owner.close()


def log_state():
    # Layout/identity here match setup; log inspection does not need primary keys.
    owner = GuestOwner(SOURCE, CREDENTIAL, allow_test_stack=True)
    try:
        identity = context(SimpleNamespace(uuid=owner.uuid, layout=owner.layout)) + b'/incremental/v2'
        return inspect_log(STATE / 'native.log', KEY, identity, owner.layout.sectors)
    finally:
        owner.close()


def expect_failed(action, allowed):
    try:
        action()
    except OSError as exc:
        assert exc.errno in allowed, (exc.errno, allowed)
        return exc.errno
    raise AssertionError('I/O unexpectedly succeeded')


def assert_fail_stop(views):
    assert status()['failed']
    for path, size in ((views['decoy'], 4096), (views['hidden'], 512)):
        expect_failed(lambda: direct(path, size), {errno.EIO})
        expect_failed(lambda: direct(path, size, value=bytes(size)), {errno.EIO})


def primary_hash(path):
    return subprocess.check_output(['sha256sum', path], text=True).split()[0]


lower()
views = open_views()
expected_primary = primary_hash(views['decoy'])
expected_hidden = Path(views['hidden']).read_bytes()
assert expected_primary == (W / 'expected-primary.sha256').read_text().strip()
assert expected_hidden == (W / 'expected-hidden-volume').read_bytes()
close_views()

for kind, role in [('device-eio', 'decoy'), ('device-eio', 'hidden'),
                   ('log-enospc', 'decoy'), ('log-enospc', 'hidden')]:
    views = open_views()
    before = log_state()
    before_tuples = tuple_hash()
    target = views[role]
    offset = 64 * 1024 * 1024 if role == 'decoy' else 0
    size = 4096 if role == 'decoy' else 512
    value = hashlib.shake_256((kind + role).encode()).digest(size)
    filler = Path('/var/tmp/piv-fault-fill')
    print('Fault case: ' + kind + '/' + role, flush=True)
    try:
        if kind == 'device-eio':
            lower(True)
        else:
            # Fully allocate free root-ext4 blocks as root, including reserved
            # blocks. fallocate creates unwritten extents, not a huge data copy.
            os.sync()
            fd = os.open(filler, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                allocated = 0
                for amount in (64 * 1024 * 1024, 1024 * 1024, 4096):
                    while True:
                        try:
                            os.posix_fallocate(fd, allocated, amount)
                        except OSError as exc:
                            assert exc.errno == errno.ENOSPC
                            break
                        allocated += amount
                os.fsync(fd)
                space = os.statvfs('/')
                print('Allocation exhausted: ' + json.dumps(dict(bytes_allocated=allocated,
                      free_blocks=space.f_bfree, available_blocks=space.f_bavail)), flush=True)
            finally:
                os.close(fd)
        error = expect_failed(lambda: direct(target, size, offset, value),
                              {errno.EIO} if kind == 'device-eio' else {errno.EIO, errno.ENOSPC})
        assert_fail_stop(views)
        after_tuples = tuple_hash()
    finally:
        filler.unlink(missing_ok=True)
        lower(False)
        os.sync()
    damaged = log_state()
    if kind == 'device-eio':
        assert damaged.pending is not None and len(damaged.used) == len(before.used) + (32 if role == 'decoy' else 64)
        if role == 'hidden':
            expected_hidden = value + expected_hidden[size:]
        else:
            # Compute exact full expected digest independently, after replay below.
            expected_primary = None
    else:
        assert after_tuples == before_tuples, 'Log failure reached primary mutation'
        assert damaged.pending is None
        assert before.used <= damaged.used
    close_views()  # Failed target must be torn down; no live transparent rebuild.
    views = open_views()
    recovered = log_state()
    assert recovered.used == damaged.used, 'Recovery allocated new primary nonces'
    assert recovered.pending is None and not recovered.trailing_bytes
    assert Path(views['hidden']).read_bytes() == expected_hidden
    if kind == 'device-eio' and role == 'decoy':
        assert direct(views['decoy'], size, offset) == value
        expected_primary = primary_hash(views['decoy'])
    else:
        assert primary_hash(views['decoy']) == expected_primary
    # Recovery must clear fail-stop, permitting a later successful transaction.
    previous = direct(views['hidden'], 512)
    direct(views['hidden'], 512, value=previous)
    assert direct(views['hidden'], 512) == previous
    assert primary_hash(views['decoy']) == expected_primary
    after_success = log_state()
    assert len(after_success.used) == len(recovered.used) + 64
    results.append(dict(fault=kind,role=role,error=error,nonces_before=len(before.used),
                        nonces_after_fault=len(damaged.used),nonces_after_recovery=len(recovered.used),
                        nonces_after_retry=len(after_success.used),partial_log_bytes=damaged.trailing_bytes,
                        primary_unchanged_before_recovery=after_tuples == before_tuples))
    (W / 'fault-progress.json').write_text(json.dumps(results, indent=2) + '\n')
    close_views()
    print('Passed: ' + kind + '/' + role, flush=True)

views = open_views()
assert primary_hash(views['decoy']) == expected_primary
assert Path(views['hidden']).read_bytes() == expected_hidden
close_views()
shutil.copyfile(STATE / 'native.log', W / 'native-fault.log')
(W / 'expected-fault-primary.sha256').write_text(expected_primary + '\n')
(W / 'expected-fault-hidden').write_bytes(expected_hidden)
(W / 'fault-results.json').write_text(json.dumps(results, indent=2) + '\n')
dm('remove', 'piv-test-fault')
subprocess.run(['rmmod', 'dm_crypt'], check=True)
subprocess.run(['modprobe', 'dm_crypt'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(CREDENTIAL), '/dev/vdb', 'piv-stock'], check=True)
assert primary_hash('/dev/mapper/piv-stock') == expected_primary
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'fault-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'result.txt').write_text('Native device EIO/root-ext4 ENOSPC, fail-stop, exact replay, nonce history and stock verification passed\n')
print('All native fault cases passed', flush=True)
