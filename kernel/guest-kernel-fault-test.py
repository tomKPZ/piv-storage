#!/usr/bin/env python3
"""Fail a real journal write, then recover using exact prepared tuples."""
import errno
from pathlib import Path
import subprocess
from pivstore.kernel_api import dm
from pivstore.kernel_owner import GuestOwner
from pivstore.kernel_store import KernelStore

w = Path('/mnt/piv-work')
key = (w / 'hidden.key').read_bytes()
state = Path('/var/tmp/piv-power/state')
subprocess.run(['modprobe', 'dm_flakey'], check=True)
dm('create', 'piv-test-fault', input='0 262144 linear /dev/vdb 0\n')
owner = GuestOwner('/dev/mapper/piv-test-fault', w / 'passphrase.key', allow_test_stack=True)
store = KernelStore(owner.device, state, key, owner.uuid)
store.truncate_hidden(0)
store.write_hidden(0, b'recovered after journal write error')

def fail_writes(phase):
    if phase == 'journaled':
        dm('suspend', 'piv-test-fault')
        dm('reload', 'piv-test-fault', input='0 262144 flakey /dev/vdb 0 0 1 1 error_writes\n')
        dm('resume', 'piv-test-fault')
store._checkpoint = fail_writes
try:
    store.flush()
except OSError as exc:
    assert exc.errno == errno.EIO, exc.errno
else:
    raise AssertionError('Expected native integrity journal write failure')
assert (state / 'pending').exists()
assert dm('resume', 'piv-native', check=False).returncode != 0
store.close()
# A failed integrity instance is fail-stop. Repair the test device and recreate
# the closed stack; never clear the error flag and blindly continue that instance.
dm('suspend', 'piv-test-fault')
dm('reload', 'piv-test-fault', input='0 262144 linear /dev/vdb 0\n')
dm('resume', 'piv-test-fault')
owner.remove(); owner.close()
owner = GuestOwner('/dev/mapper/piv-test-fault', w / 'passphrase.key', allow_test_stack=True)
with KernelStore(owner.device, state, key, owner.uuid) as recovered:
    assert recovered.read_hidden(0, 100) == b'recovered after journal write error'
assert not (state / 'pending').exists()
owner.remove(); owner.close()
dm('remove', '--retry', 'piv-test-fault')
(w / 'fault-result.txt').write_text('Native journal write EIO, fail-stop gate and exact-tuple recovery passed\n')
