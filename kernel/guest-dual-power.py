#!/usr/bin/env python3
"""Abrupt VM loss during kernel-owned WAL/native-integrity transaction."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import time

from pivstore.blocks import open_blocks, native_status
from pivstore.kernel_api import dm
from pivstore.kernel_owner import GuestOwner, crypt

W = Path('/mnt/piv-work')
STATE = Path('/var/tmp/piv-dual/state')
KEY = (W / 'hidden.key').read_bytes()
offset = 64 * 1024 * 1024
replacement = hashlib.shake_256(b'native dual VM interruption').digest(4096)
crypt('open', '--readonly', '--key-file', W / 'passphrase.key', '/dev/vdb', 'piv-stock')
hash_value = hashlib.sha256()
with open('/dev/mapper/piv-stock', 'rb', buffering=0) as stream:
    position = 0
    while value := stream.read(1024 * 1024):
        value = bytearray(value)
        lo, hi = max(position, offset), min(position + len(value), offset + len(replacement))
        if lo < hi: value[lo - position:hi - position] = replacement[lo - offset:hi - offset]
        hash_value.update(value); position += len(value)
crypt('close', 'piv-stock')
(W / 'expected-power-primary.sha256').write_text(hash_value.hexdigest() + '\n')
subprocess.run(['rmmod', 'dm_crypt'], check=True)
subprocess.run(['insmod', '/root/piv-module/dm-crypt.ko'], check=True)
dm('create', 'piv-test-delay', input='0 262144 delay /dev/vdb 0 0 /dev/vdb 0 5000\n')
source = '/dev/mapper/piv-test-delay'
open_blocks(source, W / 'passphrase.key', KEY, state_directory=STATE, allow_test_stack=True)
owner = GuestOwner(source, W / 'passphrase.key', allow_test_stack=True)
status = native_status(owner.device); owner.close()
(W / 'expected-power-nonces').write_text(str(status['nonces'] + 32) + '\n')
number = Path(source).stat().st_rdev
inflight = Path(f'/sys/dev/block/{os.major(number)}:{os.minor(number)}/inflight')
log = STATE / 'native.log'
header = struct.Struct('<8sQII32s32s')

def last_frame_kind():
    result = None
    with log.open('rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        stream.seek(status['log_bytes'])  # Only NEW frames; never rescan history in the I/O window.
        while stream.tell() < size:
            value = stream.read(header.size)
            if len(value) != header.size: break
            magic, seq, kind, length, salt, previous = header.unpack(value)
            assert magic == b'PIVNLOG1' and length <= 96 * 4148 + 4
            if stream.tell() + length + 16 > size: break
            stream.seek(length + 16, 1); result = kind
    return result

fd = os.open('/dev/mapper/piv-native-decoy', os.O_RDWR)
monitor = os.fork()
if monitor == 0:
    os.close(fd)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        writes = list(map(int, inflight.read_text().split()))[1]
        delayed = int(dm('status', 'piv-test-delay').stdout.split()[4])
        if (writes or delayed) and last_frame_kind() == 2:
            (W / 'cut-boundary.json').write_text(json.dumps({
                'inflight_writes': writes, 'queued_delayed_writes': delayed, 'delay_ms': 5000, 'last_complete_log_frame': 'WAL',
                'controller': 'kernel workqueue', 'observer': 'independent process'}) + '\n')
            print('\nPIV_POWER_CUT', flush=True)
            while True: time.sleep(.2)
        time.sleep(.005)
    raise AssertionError('No delayed native write with published kernel WAL observed')
assert os.pwrite(fd, replacement, offset) == len(replacement)
os.fsync(fd)
os.close(fd)
os.waitpid(monitor, 0)
raise AssertionError('Expected QEMU interruption during native write')
