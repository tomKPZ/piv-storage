#!/usr/bin/env python3
"""Final setup ABI/fresh seeding, native writes and complete primary preservation."""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

from pivstore.blocks import SETUP, open_blocks, close_blocks, native_status
from pivstore.kernel_api import command
from pivstore.kernel_owner import GuestOwner

W = Path('/mnt/piv-work')
STATE = Path('/var/tmp/piv-dual/state')
KEY = (W / 'hidden.key').read_bytes()
owner = GuestOwner('/dev/vdb', W / 'passphrase.key')
owner.device.suspend(); owner.device.begin()
request = bytearray(SETUP.pack(1, SETUP.size, owner.device.generation, 1, 1, 1,
                              KEY, b'x', b'/var/tmp/nonexistent', 0, 0, 0, 0))
try:
    fcntl.ioctl(owner.device.fd, command(12, SETUP.size, 1), request, True)
except OSError as exc:
    assert exc.errno == errno.EFAULT
else:
    raise AssertionError('Invalid nonce seed pointer was accepted')
request[:] = bytes(len(request))
owner.device.end(); owner.device.resume(); owner.remove(); owner.close()
value = open_blocks('/dev/vdb', W / 'passphrase.key', KEY, state_directory=STATE, initialize=True)
assert value['hidden_bytes'] == 281600
payload = hashlib.shake_256(b'final native seed/copy test').digest(1700)
fd = os.open(value['hidden'], os.O_RDWR)
assert os.pwrite(fd, payload, 511) == len(payload)
os.fsync(fd); os.close(fd)
expected = bytes(511) + payload + bytes(281600 - 511 - len(payload))
assert Path(value['hidden']).read_bytes() == expected
fd = os.open(value['decoy'], os.O_RDWR)
old = os.pread(fd, 4096, 32 * 4096)
os.pwrite(fd, old, 32 * 4096); os.fsync(fd); os.close(fd)
assert Path(value['hidden']).read_bytes() == expected
actual = subprocess.check_output(['sha256sum', value['decoy']], text=True).split()[0]
assert actual == 'b54b4937b0a9539574c7525d1634b3052cbb3836ca8d46211bb1cf03e4aaf1c4'
close_blocks('/dev/vdb', W / 'passphrase.key')
value = open_blocks('/dev/vdb', W / 'passphrase.key', KEY, state_directory=STATE)
assert Path(value['hidden']).read_bytes() == expected
close_blocks('/dev/vdb', W / 'passphrase.key')
shutil.copyfile(STATE / 'native.log', W / 'native.log')
(W / 'expected-hidden-volume').write_bytes(expected)
(W / 'expected-primary.sha256').write_text(actual + '\n')
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'dual-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'initial-result.txt').write_text('Final seed copy ABI/EFAULT, adoption marker, native RMW, reopen and whole-primary preservation passed\n')
print('Final native seed and block checks passed', flush=True)
