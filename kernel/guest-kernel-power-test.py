#!/usr/bin/env python3
"""Guest phase one: commit prefix, then die with delayed lower writes in flight."""
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from pivstore.kernel_api import dm
from pivstore.kernel_owner import GuestOwner
from pivstore.kernel_store import KernelStore

WORK = Path('/mnt/piv-work')
STATE = Path('/var/tmp/piv-power/state')
key = (WORK / 'hidden.key').read_bytes()
owner = GuestOwner('/dev/vdb', WORK / 'passphrase.key')
with KernelStore(owner.device, STATE, key, owner.uuid, initialize=True) as store:
    store.write_hidden(0, b'old before VM cut')
    store.flush()
owner.remove(); owner.close()
dm('create', 'piv-test-delay', input='0 262144 delay /dev/vdb 0 0 /dev/vdb 0 1000\n')
owner = GuestOwner('/dev/mapper/piv-test-delay', WORK / 'passphrase.key', allow_test_stack=True)
store = KernelStore(owner.device, STATE, key, owner.uuid)
store.truncate_hidden(0)
store.write_hidden(0, b'power-cut recovered native payload')
ready = threading.Event()
errors = []
def checkpoint(phase):
    if phase == 'applied:95':
        ready.set()
store._checkpoint = checkpoint

def flush():
    try:
        store.flush()
    except BaseException as exc:
        errors.append(repr(exc))
worker = threading.Thread(target=flush)
worker.start()
assert ready.wait(1200), errors
number = Path('/dev/mapper/piv-test-delay').stat().st_rdev
inflight = Path(f'/sys/dev/block/{os.major(number)}:{os.minor(number)}/inflight')
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    values = list(map(int, inflight.read_text().split()))
    if values[1] > 0 and worker.is_alive():
        assert (STATE / 'pending').exists()
        (WORK / 'cut-boundary.json').write_text(json.dumps({
            'applied_prefix_at_least': 96, 'delayed_write_in_flight': values[1],
            'delay_ms': 1000, 'external_journal_durable_before_apply': True}) + '\n')
        print('\nPIV_POWER_CUT', flush=True)
        while True:
            time.sleep(.2)
    time.sleep(.01)
raise AssertionError('No delayed write observed at power-cut boundary')
