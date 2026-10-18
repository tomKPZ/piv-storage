#!/usr/bin/env python3
"""Test-only mounted service that dies during a partially applied transaction."""
import os
from pathlib import Path
import signal
from pivstore.kernel_owner import GuestOwner
from pivstore.kernel_store import KernelStore
from pivstore.fuse_frontend import mount
w = Path('/mnt/piv-work')
owner = GuestOwner('/dev/vdb', w / 'passphrase.key')
try:
    with KernelStore(owner.device, '/var/tmp/piv-native/state',
                     (w / 'hidden.key').read_bytes(), owner.uuid) as store:
        owner.presentation()
        def crash(phase):
            if phase == 'applied:40':
                os.kill(os.getpid(), signal.SIGKILL)
        store._checkpoint = crash
        mount(store, '/run/piv-hidden', fsname='pivstore-kernel-' + owner.uuid)
finally:
    owner.close()
