#!/usr/bin/env python3
"""Closed-state maintenance, live refusal, replay, ENOSPC and publication cut."""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from pivstore import compaction
from pivstore.blocks import open_blocks, close_blocks
from pivstore.kernel_api import dm
from pivstore.kernel_owner import guest_guard
from pivstore.native_log import HEADER, inspect_log
from pivstore.blob import context
from pivstore.profile import Image
from types import SimpleNamespace


guest_guard('/dev/vdb')
W = Path('/mnt/piv-work')
STATE = Path('/var/tmp/piv-compact/state')
STATE.mkdir(mode=0o700, parents=True)
LOG = STATE / 'native.log'
shutil.copyfile(W / 'native-fault.log', LOG); os.chmod(LOG, 0o600)
(STATE / 'native.phase').write_bytes(b'ready\n'); os.chmod(STATE / 'native.phase', 0o600)
KEY = (W / 'hidden.key').read_bytes()
CREDENTIAL = W / 'passphrase.key'
# Geometry/UUID only; live journal recovery remains in the kernel.
from pivstore.kernel_owner import GuestOwner
owner = GuestOwner('/dev/vdb', CREDENTIAL)
IDENTITY = context(SimpleNamespace(uuid=owner.uuid, layout=owner.layout)) + b'/incremental/v2'
SECTORS = owner.device.sectors
owner.remove(); owner.close()


def inspect():
    return inspect_log(LOG, KEY, IDENTITY, SECTORS)


def compact():
    return compaction.compact_state('/dev/vdb', CREDENTIAL, KEY, state_directory=STATE)


def validate():
    views = open_blocks('/dev/vdb', CREDENTIAL, KEY, state_directory=STATE)
    assert Path(views['hidden']).read_bytes() == (W / 'expected-fault-hidden').read_bytes()
    digest = subprocess.check_output(['sha256sum', views['decoy']], text=True).split()[0]
    assert digest == (W / 'expected-fault-primary.sha256').read_text().strip()
    close_blocks('/dev/vdb', CREDENTIAL)


initial = inspect()
assert initial.ready and initial.pending is None and not initial.trailing_bytes
expected_history = hashlib.sha256(b''.join(sorted(initial.used))).hexdigest()
(W / 'expected-history.sha256').write_text(expected_history + '\n')
(W / 'expected-history-count').write_text(str(len(initial.used)) + '\n')
views = open_blocks('/dev/vdb', CREDENTIAL, KEY, state_directory=STATE)
original = LOG.read_bytes()
try:
    compact()
except BlockingIOError:
    pass
else:
    raise AssertionError('Compaction accepted active views')
assert LOG.read_bytes() == original
assert Path(views['hidden']).read_bytes() == (W / 'expected-fault-hidden').read_bytes()
close_blocks('/dev/vdb', CREDENTIAL)
print('Active-view refusal passed; compacting closed log', flush=True)
first = compact()
assert first['nonces'] == len(initial.used)
assert first['compacted_bytes'] < first['previous_bytes']
assert inspect().used == initial.used
assert dm('info', 'piv-native', check=False).returncode != 0
validate()
print('Closed compaction and both logical views passed', flush=True)
subprocess.run(['python3', '-m', 'pivstore', 'compact-state', '--device', '/dev/vdb',
                '--key-file', str(CREDENTIAL), '--hidden-key-file', str(W / 'hidden.key'),
                '--state-directory', str(STATE)], check=True)
assert inspect().used == initial.used

# Simulate loss of only the final completion marker of a real, already-applied
# kernel transaction. This known authenticated prefix has ALL reservations and
# exact current tuples. Never do this to an arbitrary log or valuable volume.
# Use the ORIGINAL real WAL log, which matches the unchanged backing data.
LOG.write_bytes(original)
fd = os.open(LOG, os.O_RDWR)
try:
    end = os.fstat(fd).st_size
    last = HEADER.unpack(os.pread(fd, HEADER.size, end - 104))
    assert last[2:4] == (3, 0)
    os.ftruncate(fd, end - 104); os.fsync(fd)
finally:
    os.close(fd)
assert inspect().pending is not None
replay = compact()
assert inspect().used == initial.used and inspect().pending is None
validate()
print('Pending exact-tuple recovery before compaction passed', flush=True)

# Real root ext4 ENOSPC must leave the canonical log complete and recoverable.
original = LOG.read_bytes()
filler = Path('/var/tmp/piv-compaction-fill')
try:
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
    finally:
        os.close(fd)
    try:
        compact()
    except OSError as exc:
        assert exc.errno == errno.ENOSPC, exc.errno
    else:
        raise AssertionError('Expected real compaction ENOSPC')
finally:
    filler.unlink(missing_ok=True)
    os.sync()
assert LOG.read_bytes() == original
assert inspect().used == initial.used
assert not list(STATE.glob('.piv-compacting-*'))
compact(); validate()
print('Compaction ENOSPC preserved canonical log and all reservations', flush=True)
(W / 'compaction-results.json').write_text(json.dumps(dict(first=first, replay=replay,
    nonces=len(initial.used), history_sha256=expected_history,
    active_refused=True, enospc_preserved=True), indent=2) + '\n')

# Cut the VM after atomic publication, before explicit parent-directory fsync.
# Both possible canonical logs have identical history and verified current data.
def cut(phase):
    if phase == 'published':
        (W / 'cut-boundary.json').write_text(json.dumps(dict(phase=phase,
            file_fsynced=True, parent_fsync_called=False, kernel_log_detached=True)) + '\n')
        print('PIV_POWER_CUT', flush=True)
        while True:
            time.sleep(1)
compaction._checkpoint = cut
compact()
raise AssertionError('Expected QEMU interruption')
