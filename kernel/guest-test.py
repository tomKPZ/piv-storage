#!/usr/bin/env python3
"""Guest-only K0/K1 authenticated-read test. DM tables containing test keys stay in process memory."""
import errno
import fcntl
import glob
import hashlib
import json
import time
import mmap
import os
import struct
import stat
import subprocess


def run(*args, **kw):
    return subprocess.run(args, check=True, **kw)


def digest():
    h = hashlib.sha256()
    with open('/dev/mapper/piv-kernel', 'rb', buffering=0) as src:
        while block := src.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def rejected(fn, expected):
    try:
        fn()
    except OSError as exc:
        assert exc.errno in expected, exc.errno
    else:
        raise AssertionError('operation unexpectedly accepted')


assert os.geteuid() == 0
assert os.uname().release == '6.12.113+deb13-amd64'
assert subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '/mnt/piv-work']).strip() == b'9p'
path = '/dev/mapper/piv-kernel'
assert not glob.glob('/dev/pivctl-*')
sector_size = json.loads(subprocess.check_output(
    ['cryptsetup', 'luksDump', '--dump-json-metadata', '/dev/vdb'], text=True))['segments']['0']['sector_size']
expected_sector_size = sector_size
factor = sector_size // 512
boundary = 32768 // factor
# Feature disabled: stock writes still work (rewrite the same synthetic plaintext).
fd = os.open(path, os.O_RDWR)
first = os.pread(fd, sector_size, 0)
assert os.pwrite(fd, first, 0) == sector_size
os.fsync(fd)
os.close(fd)
before = digest()
assert before == open('/mnt/piv-work/expected.sha256').read().strip()
table = subprocess.check_output(['dmsetup', 'table', '--showkeys', 'piv-kernel'], text=True).split()
assert table[2] == 'crypt' and len(table) == 9 + int(table[8])
table[8] = str(int(table[8]) + 1)
table.append('piv_control')
# Read-only owner mode cannot supply the required lower write access.
p = subprocess.run(['dmsetup', 'create', '--readonly', 'piv-unsupported'],
                   input=' '.join(table) + '\n', text=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
assert p.returncode != 0 and 'Invalid argument' in p.stderr
run('dmsetup', 'suspend', 'piv-kernel')
run('dmsetup', 'reload', 'piv-kernel', input=' '.join(table) + '\n', text=True)
run('dmsetup', 'resume', 'piv-kernel')
del table
run('udevadm', 'settle')
controls = glob.glob('/dev/pivctl-*')
assert len(controls) == 1
assert stat.S_IMODE(os.stat(controls[0]).st_mode) == 0o600
assert subprocess.check_output(['blockdev', '--getro', path]).strip() == b'0'
assert subprocess.check_output(['blockdev', '--getro', path + '_dif']).strip() == b'0'
ctl = os.open(controls[0], os.O_RDONLY)
fmt = '=IIQQIIIIII'
size = struct.calcsize(fmt)
query = (2 << 30) | (size << 16) | (ord('P') << 8)
buf = bytearray(size)
fcntl.ioctl(ctl, query, buf, True)
version, length, generation, sectors, sector_size, iv, tag, tup, flags, reserved = struct.unpack(fmt, buf)
assert (version, length, sector_size, iv, tag, tup, flags, reserved) == (1, size, expected_sector_size, 12, 16, 28, 15, 0)
assert sectors * sector_size == int(subprocess.check_output(['blockdev', '--getsize64', path]))
assert generation > 0
rejected(lambda: fcntl.ioctl(ctl, query + 2, buf), {errno.ENOTTY})
rejected(lambda: fcntl.ioctl(ctl, query, 0), {errno.EFAULT})
read_fmt = '=IIQQ12sIII'
read_size = struct.calcsize(read_fmt)
read_command = (3 << 30) | (read_size << 16) | (ord('P') << 8) | 1


def read_iv(fd, owner, index, **changes):
    fields = dict(version=1, size=read_size, generation=owner, sector=index,
                  iv=bytes(12), r0=0, r1=0, r2=0)
    fields.update(changes)
    request = bytearray(struct.pack(read_fmt, *fields.values()))
    original = bytes(request)
    try:
        fcntl.ioctl(fd, read_command, request, True)
    except OSError:
        assert request == original, 'failed read changed output buffer'
        raise
    result = struct.unpack(read_fmt, request)
    assert result[:4] == tuple(fields.values())[:4]
    assert result[5:] == (0, 0, 0)
    return result[4]


selected = (0, 1, boundary - 1, boundary, sectors - 1)
observed = {str(i): read_iv(ctl, generation, i).hex() for i in selected}
assert read_iv(ctl, generation, boundary).hex() == observed[str(boundary)]
for changes in ({'version': 0}, {'size': 0}, {'iv': bytes([1]) * 12}, {'r2': 1}):
    rejected(lambda: read_iv(ctl, generation, 0, **changes), {errno.EINVAL})
for index in (sectors, 2**64 - 1):
    rejected(lambda: read_iv(ctl, generation, index), {errno.ERANGE})
rejected(lambda: read_iv(ctl, generation + 1, 0), {errno.ESTALE})
rejected(lambda: fcntl.ioctl(ctl, read_command, 0), {errno.EFAULT})
run('dmsetup', 'suspend', 'piv-kernel')
rejected(lambda: read_iv(ctl, generation, 0), {errno.EBUSY})
run('dmsetup', 'resume', 'piv-kernel')
assert read_iv(ctl, generation, 0).hex() == observed['0']
# Handshake guarantees the child is reading before the suspend cycles begin.
started_r, started_w = os.pipe()
stop_r, stop_w = os.pipe()
os.set_blocking(stop_r, False)
pid = os.fork()
if pid == 0:
    os.close(started_r)
    os.close(stop_w)
    try:
        assert read_iv(ctl, generation, 1).hex() == observed['1']
        os.write(started_w, b'1')
        os.close(started_w)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if os.read(stop_r, 1):
                    os._exit(0)
            except BlockingIOError:
                pass
            try:
                assert read_iv(ctl, generation, 1).hex() == observed['1']
            except OSError as exc:
                assert exc.errno == errno.EBUSY
        os._exit(1)
    except BaseException:
        os._exit(1)
os.close(started_w)
os.close(stop_r)
assert os.read(started_r, 1) == b'1'
os.close(started_r)
for _ in range(3):
    run('dmsetup', 'suspend', 'piv-kernel')
    run('dmsetup', 'resume', 'piv-kernel')
os.write(stop_w, b'1')
os.close(stop_w)
assert os.waitpid(pid, 0)[1] == 0

pid = os.fork()
if pid == 0:
    try:
        os.setgid(65534)
        os.setuid(65534)
        rejected(lambda: fcntl.ioctl(ctl, query, buf), {errno.EPERM})
        rejected(lambda: read_iv(ctl, generation, 0), {errno.EPERM})
        os._exit(0)
    except BaseException:
        os._exit(1)
assert os.waitpid(pid, 0)[1] == 0
# Bypass the writable owner's page cache to exercise its bio mutation filter.
fd = os.open(path, os.O_RDWR | os.O_DIRECT)
with mmap.mmap(-1, 4096) as block:
    rejected(lambda: os.pwrite(fd, block, 0), {errno.EIO, errno.EROFS})
# BLKDISCARD and BLKZEROOUT: must not modify primary even if rejected above map.
for operation in (0x1277, 0x127f):
    rejected(lambda: fcntl.ioctl(fd, operation, struct.pack('=QQ', 0, 4096)),
             {errno.EIO, errno.EROFS, errno.EOPNOTSUPP, errno.ENOTTY})
os.fsync(fd)
os.close(fd)
assert digest() == before
# The presentation also rejects buffered writes before they can dirty page cache.
run('dmsetup', 'create', '--readonly', 'piv-view',
    input=f'0 {sectors * factor} linear {path} 0\n', text=True)
assert subprocess.check_output(['blockdev', '--getro', '/dev/mapper/piv-view']).strip() == b'1'
view = os.open('/dev/mapper/piv-view', os.O_WRONLY)
rejected(lambda: os.pwrite(view, first, 0), {errno.EROFS, errno.EPERM})
os.close(view)
run('dmsetup', 'remove', '--retry', 'piv-view')
# Prepared tuples are durable before the first apply in this sector experiment.
from pivstore.kernel_api import KernelDevice, validate_integrity_table
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
native = KernelDevice(controls[0], path)
validate_integrity_table(subprocess.check_output(['dmsetup', 'table', 'piv-kernel_dif'], text=True),
                         sectors, os.stat('/dev/vdb').st_rdev, 16777216, sector_size,
                         int(subprocess.check_output(['dmsetup', 'table', 'piv-kernel_dif'], text=True).split('journal_sectors:')[1].split()[0]))
assert native.read_primary_sector(0) == first
rejected(lambda: native.read_primary_sector(sectors), {errno.ERANGE})
rejected(lambda: native.prepare_primary(0, bytes.fromhex(observed['0']), os.urandom(12), first), {errno.EBUSY})
rejected(native.begin, {errno.EBUSY})
native.suspend()
rejected(lambda: native.prepare(0, bytes.fromhex(observed['0']), os.urandom(12)), {errno.EBUSY})
native.begin()
rejected(lambda: native.read_primary_sector(0), {errno.EBUSY})
rejected(lambda: fcntl.ioctl(ctl, (1 << 30) | (48 << 16) | (ord('P') << 8) | 5,
                             bytearray(struct.pack(read_fmt, 1, 48, generation, 0, bytes(12), 0, 0, 0)), True),
         {errno.EBUSY})
prepared = []
for index in selected:
    old = bytes.fromhex(observed[str(index)])
    new = os.urandom(12)
    value = native.prepare(index, old, new)
    # Independently verify the native encryption/AAD against a maintained library.
    with open('/mnt/piv-work/volume.key', 'rb') as keyfile:
        primary_key = keyfile.read()
    plaintext = AESGCM(primary_key).decrypt(new, value[:sector_size] + value[4096:4112], struct.pack('<Q', index * factor) + new)
    assert plaintext == hashlib.shake_256(b'piv-control-v1' + index.to_bytes(8, 'little')).digest(sector_size)
    prepared.append((index, old, value))
with open('/mnt/piv-work/prepared-tuples.bin', 'wb') as journal:
    for index, old, value in prepared:
        journal.write(struct.pack('<Q12s', index, old) + value)
    journal.flush()
    os.fsync(journal.fileno())
index, old, value = prepared[0]
if sector_size == 512:
    assert not any(value[512:4096])
    bad = bytearray(value); bad[512] = 1
    rejected(lambda: native.apply(index, old, bytes(bad)), {errno.EINVAL})
rejected(lambda: native.apply(index, bytes([9]) * 12, value), {errno.ESTALE})
bad = bytearray(value); bad[0] ^= 1
rejected(lambda: native.apply(index, old, bytes(bad)), {errno.EBADMSG, errno.EIO})
nonce = os.urandom(12)
encrypted = AESGCM(primary_key).encrypt(nonce, bytes(sector_size), struct.pack('<Q', index * factor) + nonce)
changed = encrypted[:sector_size].ljust(4096, b'\0') + encrypted[sector_size:] + nonce
rejected(lambda: native.apply(index, old, changed), {errno.EPERM})
for index, old, value in prepared:
    assert native.read_iv(index, quiesced=True) == old
    native.apply(index, old, value)
    native.apply(index, old, value)  # exact idempotent replay, no reencryption
    assert native.read_iv(index, quiesced=True) == value[-12:]
    observed[str(index)] = value[-12:].hex()
    rejected(lambda: native.prepare(index, value[-12:], value[-12:]), {errno.EINVAL})
# Distinct primary-write operations authenticate old/new tuples but permit a
# changed plaintext. Legacy hidden APPLY must still refuse that exact candidate.
old = bytes.fromhex(observed['0'])
nonce = os.urandom(12)
rejected(lambda: native.prepare_primary(0, old, old, bytes(sector_size)), {errno.EINVAL})
rejected(lambda: native.prepare_primary(0, os.urandom(12), nonce, bytes(sector_size)), {errno.ESTALE})
changed = native.prepare_primary(0, old, nonce, bytes(sector_size))
assert AESGCM(primary_key).decrypt(nonce, changed[:sector_size] + changed[4096:4112], struct.pack('<Q', 0) + nonce) == bytes(sector_size)
rejected(lambda: native.apply(0, old, changed), {errno.EPERM})
bad = bytearray(changed); bad[4096] ^= 1
rejected(lambda: native.apply_primary(0, old, bytes(bad)), {errno.EBADMSG, errno.EIO})
native.apply_primary(0, old, changed)
native.apply_primary(0, old, changed)
# Restore original plaintext with a fresh IV, never by restoring the old tuple.
restored_iv = os.urandom(12)
restored = native.prepare_primary(0, nonce, restored_iv, first)
native.apply_primary(0, nonce, restored)
observed['0'] = restored_iv.hex()
p = subprocess.run(['dmsetup', 'resume', 'piv-kernel'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
assert p.returncode != 0  # transaction gate survives until explicit end
p = subprocess.run(['dmsetup', 'message', 'piv-kernel', '0', 'key', 'wipe'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
assert p.returncode != 0
native.end()
native.resume()
assert digest() == before
# Controller death leaves the transaction gate closed; a fresh fd adopts it.
native.suspend(); native.begin(); native.close()
p = subprocess.run(['dmsetup', 'resume', 'piv-kernel'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
assert p.returncode != 0
native = KernelDevice(controls[0], path)
native.begin(); native.end(); native.resume(); native.close()

# Key wipe is allowed only while suspended; controls must remain blocked.
# Drain probes from the preceding asynchronous resume before making the owner
# deliberately unresumable; a queued blkid read would otherwise hold it open.
run('udevadm', 'settle')
run('dmsetup', 'suspend', 'piv-kernel')
run('dmsetup', 'message', 'piv-kernel', '0', 'key', 'wipe')
rejected(lambda: read_iv(ctl, generation, 0), {errno.EBUSY})
p = subprocess.run(['dmsetup', 'resume', 'piv-kernel'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
assert p.returncode != 0
# Existing fd must not keep the target alive or dereference its freed cc.
# Stock cryptsetup's table parser does not recognize the opt-in token.
run('dmsetup', 'remove', '--retry', 'piv-kernel')
run('dmsetup', 'remove', '--retry', 'piv-kernel_dif')
rejected(lambda: fcntl.ioctl(ctl, query, buf), {errno.ENODEV})
rejected(lambda: read_iv(ctl, generation, 0), {errno.ENODEV})
assert not glob.glob('/dev/pivctl-*')
# The open control pins the module until release.
p = subprocess.run(['rmmod', 'dm_crypt'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
assert p.returncode != 0
os.close(ctl)
# Corrupt only the closed guest-owned disk, never underneath a live mapping.
placements = json.load(open('/mnt/piv-work/read-layout.json'))['corruption']
for placement in placements:
    raw = os.open('/dev/vdb', os.O_RDWR)
    old = os.pread(raw, 1, placement['offset'])
    assert os.pwrite(raw, bytes([old[0] ^ 1]), placement['offset']) == 1
    os.fsync(raw)
    os.close(raw)
    run('cryptsetup', 'open', '--disable-keyring', '--key-file',
        '/mnt/piv-work/passphrase.key', '/dev/vdb', 'piv-kernel')
    fields = subprocess.check_output(['dmsetup', 'table', '--showkeys', 'piv-kernel'], text=True).split()
    fields[8] = str(int(fields[8]) + 1)
    fields.append('piv_control')
    run('dmsetup', 'suspend', 'piv-kernel')
    run('dmsetup', 'reload', 'piv-kernel', input=' '.join(fields) + '\n', text=True)
    run('dmsetup', 'resume', 'piv-kernel')
    del fields
    run('udevadm', 'settle')
    current = os.open(glob.glob('/dev/pivctl-*')[0], os.O_RDONLY)
    profile = bytearray(size)
    fcntl.ioctl(current, query, profile, True)
    owner = struct.unpack(fmt, profile)[2]
    assert owner != generation
    rejected(lambda: read_iv(current, owner, placement['sector']), {errno.EBADMSG, errno.EIO})
    assert read_iv(current, owner, 1).hex() == observed['1']
    broken = KernelDevice(glob.glob('/dev/pivctl-*')[0], path)
    rejected(lambda: broken.read_primary_sector(placement['sector']), {errno.EBADMSG, errno.EIO})
    broken.suspend(); broken.begin()
    bad_index = placement['sector']
    old_iv = bytes.fromhex(observed[str(bad_index)])
    rejected(lambda: broken.prepare_primary(bad_index, old_iv, os.urandom(12), bytes(sector_size)),
             {errno.EBADMSG, errno.EIO})
    rejected(lambda: broken.prepare(bad_index, old_iv, os.urandom(12)),
             {errno.EBADMSG, errno.EIO})
    exact = next(value for i, old, value in prepared if i == bad_index)
    rejected(lambda: broken.apply(bad_index, old_iv, exact), {errno.EBADMSG, errno.EIO})
    rejected(lambda: broken.apply_primary(bad_index, old_iv, exact), {errno.EBADMSG, errno.EIO})
    broken.close()
    run('dmsetup', 'remove', '--retry', 'piv-kernel')
    run('dmsetup', 'remove', '--retry', 'piv-kernel_dif')
    rejected(lambda: read_iv(current, owner, 1), {errno.ENODEV})
    os.close(current)
    raw = os.open('/dev/vdb', os.O_RDWR)
    assert os.pwrite(raw, old, placement['offset']) == 1
    os.fsync(raw)
    os.close(raw)
run('rmmod', 'dm_crypt')
run('modprobe', 'dm_crypt')
run('cryptsetup', 'open', '--readonly', '--key-file', '/mnt/piv-work/passphrase.key', '/dev/vdb', 'piv-kernel')
assert digest() == before
run('cryptsetup', 'close', 'piv-kernel')
with open('/mnt/piv-work/read-results.json', 'w') as output:
    json.dump(observed, output, sort_keys=True)
with open('/mnt/piv-work/result.txt', 'w') as output:
    output.write('Kernel prepare/apply, read, corruption, lifecycle and stock readback passed\n')
