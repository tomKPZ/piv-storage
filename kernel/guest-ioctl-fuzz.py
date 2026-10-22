#!/usr/bin/env python3
"""Guest-only fuzzing of the dm-piv control ioctls (no kernel changes).

Three phases on the disposable /dev/vdb fixture: an idle private owner without
native state; the same owner suspended inside a control transaction (where
SETUP and END are reachable); then active paired views with concurrent view
reads. Each step
sends a seeded random command (every defined number, correct or wrong size and
direction, or a random number) with a template-valid or mutated structure, a
short/page-crossing buffer that ends in a PROT_NONE page, or a raw invalid
pointer. Any errno is acceptable. Failures are: an owner that reports
failed, a crash or hang, a kernel self-report (the suite scans the console and
dmesg), or any change to primary or hidden contents. Deliberately excluded,
because they succeed legitimately and are destructive by design: SETUP with
INITIALIZE and keyslot operations on slot 0. The former userspace IV and
prepare/apply controls (numbers 1-4, 8-11) were removed on 2026-10-22; they are
still sent and must return ENOTTY. Keyslot add/remove on slots 1-3 may succeed (random KEKs) and are
left in place; the final reopen with the original key must still work.
"""
import ctypes
import errno
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import random
import struct
import subprocess
import threading
import time

from pivstore.blocks import base_identity, close_blocks, native_status, open_blocks
from pivstore.kernel_owner import GuestOwner

W = Path('/mnt/piv-work')
KEY, HKEY = W / 'passphrase.key', (W / 'hidden.key').read_bytes()
EXPECTED = (W / 'expected-hidden-volume').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
STEPS = int(os.environ.get('PIV_FUZZ_STEPS', '100000'))
SEED = int(os.environ.get('PIV_FUZZ_SEED', str(int.from_bytes(os.urandom(8), 'little'))))
rng = random.Random(SEED)
libc = ctypes.CDLL(None, use_errno=True)
libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]

# number: (size, direction) from kernel/piv-control.h (1 = write, 2 = read).
COMMANDS = {0: (48, 2), 1: (48, 3), 2: (48, 3), 3: (4176, 3), 4: (4176, 1), 5: (48, 1), 6: (48, 1),
            7: (16, 2), 8: (48, 1), 9: (4176, 3), 10: (4176, 3), 11: (4176, 1), 12: (216, 3),
            13: (48, 1), 14: (40, 2), 15: (64, 1)}
REMOVED = {1, 2, 3, 4, 8, 9, 10, 11}  # former userspace IV/tuple controls: ENOTTY
SETUP_SCANS = 16  # template-valid SETUPs scan the whole primary; keep them rare


def command(number, size, direction):
    return direction << 30 | size << 16 | ord('P') << 8 | number


class Arena:
    """Two pages; the second is PROT_NONE so buffers can end at a fault."""
    def __init__(self, size):
        self.pages = (size + 4095) // 4096 + 1
        self.map = mmap.mmap(-1, self.pages * 4096)
        self.base = ctypes.addressof(ctypes.c_char.from_buffer(self.map))
        if libc.mprotect(ctypes.c_void_p(self.base + (self.pages - 1) * 4096), 4096, 0):
            raise OSError(ctypes.get_errno(), 'mprotect')

    def place(self, data, tail):
        """Copy @data so that only its first len-@tail bytes are accessible."""
        start = (self.pages - 1) * 4096 - (len(data) - tail)
        self.map[start:start + len(data) - tail] = data[:len(data) - tail]
        return self.base + start


ARENA = Arena(8192)


def template(number, size, device, sectors, context):
    sector = rng.choice([0, 1, sectors - 1, sectors, sectors + 1, 2**63, 2**64 - 1,
                         rng.randrange(sectors)])
    generation = device.generation if rng.random() < 0.9 else rng.getrandbits(64)
    version = {12: 6, 15: 1}.get(number, 2) if rng.random() < 0.9 else rng.getrandbits(32)
    length = size if rng.random() < 0.9 else rng.choice([0, size - 1, size + 1, rng.getrandbits(32)])
    if number == 12:
        flags = rng.choice([0, 0, 0, 8, 2, 4, 16, 32, 64, rng.getrandbits(32)]) & ~1  # never INITIALIZE
        clen = len(context) if rng.random() < 0.8 else rng.choice([0, 127, 128, 129, rng.getrandbits(32)])
        # SETUP ABI 6: parity (0/4/8/16, INITIALIZE only), a reserved word and
        # the FILL output counts (must be zero on input). FILL (64) is sent:
        # with the random KEK no keyslot authenticates, so it never writes.
        parity = rng.choice([0, 0, 0, 4, 8, 16, 5, rng.getrandbits(32)])
        reserved = 0 if rng.random() < 0.9 else rng.getrandbits(32)
        counts = (0, 0, 0) if rng.random() < 0.9 else tuple(rng.getrandbits(64) for _ in range(3))
        body = struct.pack('=IIQII32s128sIIQQQ', version, length, generation, flags, clen,
                           rng.randbytes(32), context.ljust(128, b'\0')[:128], parity, reserved, *counts)
    elif number == 15:
        slot = rng.choice([1, 2, 3, 4, 5, 2**32 - 1])  # never slot 0
        op = rng.choice([1, 2, 0, 3, rng.getrandbits(32)])
        body = struct.pack('=IIQII32sII', version, length, generation, slot, op, rng.randbytes(32), 0, 0)
    elif size == 4176:
        tuple_ = bytes(4128) if rng.random() < 0.3 else rng.randbytes(4128)
        body = struct.pack('=IIQQ16sI4128sI', version, length, generation, sector,
                           rng.randbytes(16) if rng.random() < 0.5 else bytes(16),
                           rng.choice([0, 0, 1, rng.getrandbits(32)]), tuple_, 0)
    else:
        body = struct.pack('=IIQQ16sII', version, length, generation, sector, bytes(16), 0, 0)
        body = body[:size].ljust(size, b'\0')
    return mutate(bytearray(body))


def mutate(body):
    for _ in range(rng.choice([0, 0, 1, 2, 8])):
        body[rng.randrange(len(body))] = rng.getrandbits(8)
    return bytes(body)


def step(fd, device, sectors, context, stats, scans):
    roll = rng.random()
    if roll < 0.85:
        number = rng.choice(list(COMMANDS))
        size, direction = COMMANDS[number]
        if rng.random() < 0.1:
            size, direction = rng.choice([0, 8, 47, 49, 192, 216, 4176, 16383]), rng.randrange(4)
    else:
        number, size, direction = rng.randrange(64), rng.randrange(1 << 14), rng.randrange(4)
    if number == 12 and (size, direction) == COMMANDS[12]:
        if scans[0] >= SETUP_SCANS:
            number = 14
            size, direction = COMMANDS[14]
        else:
            scans[0] += 1
    data = template(number, max(size, 1), device, sectors, context)
    mode = rng.random()
    if mode < 0.75:
        pointer = ARENA.place(data, 0) if len(data) <= 4096 else None
        buffer = None if pointer else ctypes.create_string_buffer(data, len(data))
        pointer = pointer or ctypes.addressof(buffer)
    elif mode < 0.9:
        tail = rng.randrange(1, len(data) + 1) if len(data) <= 4096 else 0
        pointer = ARENA.place(data, tail) if len(data) <= 4096 else 1
    else:
        pointer = rng.choice([0, 1, 4095, 0xffff888000000000, 0xffffffffff600000, 2**64 - 1,
                              rng.getrandbits(47)])
    result = libc.ioctl(fd, command(number, size, direction), ctypes.c_void_p(pointer))
    key = f'{number}:{size}:{direction}' if number in COMMANDS and (size, direction) == COMMANDS[number] else 'other'
    outcome = 'ok' if result == 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
    stats.setdefault(key, {}).setdefault(outcome, 0)
    stats[key][outcome] += 1
    if number in REMOVED:
        assert result != 0 and ctypes.get_errno() == errno.ENOTTY, (number, size, direction, outcome)
    if number == 15 and result == 0:
        stats.setdefault('keyslot_changes', 0)
        stats['keyslot_changes'] += 1


def fuzz(owner, label):
    device, sectors = owner.device, owner.device.sectors
    context = base_identity(owner)
    stats, scans, started = {}, [0], time.monotonic()
    for _ in range(STEPS):
        step(device.fd, device, sectors, context, stats, scans)
    status = native_status(device)
    assert not status['failed'], (label, status)
    print(f'{label}: {STEPS} ioctls in {time.monotonic() - started:.1f}s, status {status}', flush=True)
    return dict(steps=STEPS, seconds=round(time.monotonic() - started, 1), status=status, outcomes=stats)


results = dict(seed=SEED)
print(f'seed {SEED}', flush=True)

# Phase 1: idle private owner, no native state (most data ioctls are reachable).
owner = GuestOwner('/dev/vdb', KEY)
assert owner.created
try:
    results['idle'] = fuzz(owner, 'idle owner')
finally:
    owner.remove()
    owner.close()

# Phase 2: the owner suspended inside a control transaction.
owner = GuestOwner('/dev/vdb', KEY)
assert owner.created
device = owner.device
try:
    device.suspend()
    device.begin()
    results['transaction'] = fuzz(owner, 'transaction')
    try:
        device.end()
    except OSError:
        device.begin()  # a fuzzed END may already have closed the transaction
        device.end()
    device.resume()
finally:
    owner.remove()
    owner.close()

# Phase 3: active paired views while another thread keeps reading both views.
views = open_blocks('/dev/vdb', KEY, HKEY)
stop = threading.Event()


def reader():
    local = random.Random(SEED ^ 1)  # keep the main sequence reproducible
    while not stop.is_set():
        for path in (views['decoy'], views['hidden']):
            with open(path, 'rb', buffering=0) as stream:
                stream.seek(local.randrange(0, 1 << 20) & ~4095)
                stream.read(16384)


thread = threading.Thread(target=reader, daemon=True)
thread.start()
owner = GuestOwner('/dev/vdb', KEY)
try:
    results['active'] = fuzz(owner, 'active views')
finally:
    stop.set()
    thread.join()
    owner.close()
close_blocks('/dev/vdb', KEY)

# Integrity: reopen with the original key; both views unchanged.
views = open_blocks('/dev/vdb', KEY, HKEY)
assert subprocess.check_output(['sha256sum', views['decoy']], text=True).split()[0] == PRIMARY
assert Path(views['hidden']).read_bytes() == EXPECTED
owner = GuestOwner('/dev/vdb', KEY)
assert not native_status(owner.device)['failed']
owner.close()
close_blocks('/dev/vdb', KEY)
subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(KEY), '/dev/vdb', 'piv-stock'], check=True)
try:
    assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-stock'], text=True).split()[0] == PRIMARY
finally:
    subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
(W / 'fuzz-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Control ioctl fuzzing (idle owner and active views), reopen and stock verification passed\n')
