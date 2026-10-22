#!/usr/bin/env python3
"""Activation on arbitrary block devices and the remaining safety checks.

pivsetup no longer confines activation to the pinned guest's 128/512 MiB
/dev/vdb. This guest test (scripts/guest-devices.sh) proves activation on
other devices -- a 300 MiB second disk, a loop device over a guest-root file,
a dm-linear mapping at an offset and a GPT partition reached through a udev
symlink, two owners at once -- and that the checks that protect users remain:
root, block devices only, no partitioned whole disk, no independent holder or
exclusive opener, the /run owner lock, foreign mappings under the owner name,
mapping-name validation and the required --device. /dev/vdb is the closed
native fixture (control keys and oracles); every other disk is formatted here
with stock cryptsetup and the fixture's profile.
"""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

from pivstore import blocks
from pivstore.kernel_api import dm, mapping_identity

W = Path('/mnt/piv-work')
KEY = W / 'passphrase.key'
HKEY = (W / 'hidden.key').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
HIDDEN = (W / 'expected-hidden-volume').read_bytes()
RUN = Path('/run/piv-devices')
RUN.mkdir(mode=0o700, exist_ok=True)
PIVSETUP = blocks.binary()
results = dict(safety=[], devices=[])

metadata = json.loads(subprocess.check_output(['cryptsetup', 'luksDump', '--dump-json-metadata', '/dev/vdb']))
segment = metadata['segments']['0']
CIPHER, SECTOR = segment['encryption'], segment['sector_size']
# LUKS2 metadata names the kernel algorithm; luksFormat takes cryptsetup's name.
INTEGRITY = {'aead': 'aead', 'hmac(sha256)': 'hmac-sha256'}[segment['integrity']['type']]
KEY_BITS = {'aegis128-random': 128, 'aes-xts-random': 512}[CIPHER]


def run(*args, check=True, **kw):
    return subprocess.run([str(a) for a in args], check=check, capture_output=True, text=True, **kw)


def settle():
    run('udevadm', 'settle')


def pivsetup_fails(args, expected, *, prefix=()):
    """Run pivsetup directly; it must fail with @expected in its message."""
    result = run(*prefix, PIVSETUP, *args, check=False)
    assert result.returncode == 1, (args, result.returncode, result.stdout, result.stderr)
    assert expected in result.stderr, (args, result.stderr)
    return result.stderr


def no_owner(name='piv-native'):
    for suffix in ('', '_dif', '-decoy', '-hidden'):
        assert mapping_identity(name + suffix) is None, name + suffix


def refused(label, expected_errno, action, name='piv-native'):
    try:
        action()
    except OSError as error:
        assert error.errno == expected_errno, (label, error)
    else:
        raise AssertionError(f'{label}: activation was not refused')
    no_owner(name)
    results['safety'].append(label)
    print('refused:', label, flush=True)


def open_fixture(**kw):
    return blocks.open_blocks('/dev/vdb', KEY, HKEY, **kw)


# --- Remaining safety checks (they replace the removed guard tests) ---------

# Root is required before any key file is read.
pivsetup_fails(['open-blocks', '--device', '/dev/vdb', '--key-file', '/nonexistent',
                '--hidden-key-file', '/nonexistent'], 'requires root',
               prefix=('setpriv', '--reuid=65534', '--regid=65534', '--clear-groups'))
results['safety'].append('unprivileged caller')
# --device has no default any more; removed escape hatches are unknown options.
pivsetup_fails(['open-blocks', '--key-file', KEY, '--hidden-key-file', W / 'hidden.key'], '--device is required')
pivsetup_fails(['close-blocks', '--key-file', KEY], '--device is required')
pivsetup_fails(['migrate', '--source-key-file', KEY, '--source-hidden-key-file', W / 'hidden.key',
                '--target', '/dev/vdc', '--target-key-file', KEY, '--target-hidden-key-file', W / 'hidden.key'],
               '--source is required')
for flag in ('--allow-test-stack', '--allow-second-disk'):
    pivsetup_fails(['open-blocks', '--device', '/dev/vdb', '--key-file', KEY, '--hidden-key-file',
                    W / 'hidden.key', flag], 'Unrecognized argument')
results['safety'].append('required --device, removed confinement flags')
# Only block devices: a regular file holding a real LUKS2 header, a character
# device, a directory and a missing path.
header_copy = Path('/var/tmp/piv-luks-header.img')
run('dd', 'if=/dev/vdb', f'of={header_copy}', 'bs=1M', 'count=16', 'status=none')
for path, message in ((header_copy, 'is not a block device'), ('/dev/null', 'is not a block device'),
                      ('/var/tmp', 'is not a block device'), ('/dev/piv-missing', 'Cannot access')):
    pivsetup_fails(['open-blocks', '--device', path, '--key-file', KEY, '--hidden-key-file', W / 'hidden.key'],
                   message)
    no_owner()
header_copy.unlink()
results['safety'].append('non-block devices')
pivsetup_fails(['open-blocks', '--device', '/dev/vdb', '--name', 'native', '--key-file', KEY,
                '--hidden-key-file', W / 'hidden.key'], 'Invalid experimental mapping name')
results['safety'].append('mapping name')

# An independent stock mapping (a holder) and an exclusive opener: EBUSY.
run('cryptsetup', 'open', '--readonly', '--key-file', KEY, '/dev/vdb', 'stock-holder')
holder = mapping_identity('stock-holder')
refused('independent stock holder', errno.EBUSY, open_fixture)
assert mapping_identity('stock-holder') == holder
run('cryptsetup', 'close', 'stock-holder')
exclusive = os.open('/dev/vdb', os.O_RDONLY | os.O_EXCL)
try:
    refused('exclusive opener', errno.EBUSY, open_fixture)
finally:
    os.close(exclusive)

# The volatile per-volume owner lock in /run.
uuid = run('cryptsetup', 'luksUUID', '/dev/vdb').stdout.strip().lower()
Path('/run/pivstore').mkdir(mode=0o700, exist_ok=True)
lock = os.open(f'/run/pivstore/{uuid}.lock', os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(lock, fcntl.LOCK_EX)
try:
    refused('owner lock held', errno.EWOULDBLOCK, open_fixture)
finally:
    os.close(lock)

# A stock crypt mapping already named like the owner (matching LUKS DM UUID)
# is not adopted, and neither open nor close removes it.
run('cryptsetup', 'open', '--readonly', '--key-file', KEY, '/dev/vdb', 'piv-native')
identity = mapping_identity('piv-native')
for action in (open_fixture, lambda: blocks.close_blocks('/dev/vdb', KEY)):
    try:
        action()
    except (OSError, ValueError) as error:
        assert 'native control' in str(error), error
    else:
        raise AssertionError('Stock mapping under the owner name was adopted')
    assert mapping_identity('piv-native') == identity
    assert dm('table', 'piv-native').stdout.split()[2] == 'crypt'
    assert mapping_identity('piv-native-decoy') is None and mapping_identity('piv-native-hidden') is None
run('cryptsetup', 'close', 'piv-native')
no_owner()
results['safety'].append('stock mapping under the owner name')

# The fixture itself still opens and matches its oracles.
views = open_fixture()
assert run('sha256sum', views['decoy']).stdout.split()[0] == PRIMARY
assert Path(views['hidden']).read_bytes() == HIDDEN
blocks.close_blocks('/dev/vdb', KEY)
print('safety checks passed', flush=True)


# --- Arbitrary devices --------------------------------------------------------

class Volume:
    """A stock LUKS2 volume (fixture profile) formatted on @device here."""

    def __init__(self, label, device, name):
        self.label, self.device, self.name = label, str(device), name
        self.key = RUN / f'{label}.passphrase'
        self.key.write_bytes(secrets.token_bytes(32))
        self.hidden_key = secrets.token_bytes(32)
        self.raw = int(run('blockdev', '--getsize64', self.device).stdout)
        started = time.monotonic()
        run('cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--cipher', CIPHER,
            '--key-size', KEY_BITS, '--sector-size', SECTOR, '--integrity', INTEGRITY,
            '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000', '--key-file', self.key, self.device)
        stock = f'stock-{label}'
        run('cryptsetup', 'open', '--key-file', self.key, self.device, stock)
        digest = hashlib.sha256()
        with open(f'/dev/mapper/{stock}', 'r+b', buffering=0) as out:
            size = os.lseek(out.fileno(), 0, os.SEEK_END)
            os.lseek(out.fileno(), 0, os.SEEK_SET)
            for offset in range(0, size, 1 << 20):
                chunk = secrets.token_bytes(min(1 << 20, size - offset))
                assert out.write(chunk) == len(chunk)
                digest.update(chunk)
            os.fsync(out.fileno())
        run('cryptsetup', 'close', stock)
        self.primary = digest.hexdigest()
        self.format_seconds = time.monotonic() - started

    def open(self, device=None, **kw):
        views = blocks.open_blocks(device or self.device, self.key, self.hidden_key, name=self.name, **kw)
        settle()
        return views

    def close(self, device=None):
        blocks.close_blocks(device or self.device, self.key, name=self.name)
        no_owner(self.name)

    def initialize_and_fill(self):
        views = self.open(initialize=True)
        self.hidden = secrets.token_bytes(views['hidden_bytes'])
        fd = os.open(views['hidden'], os.O_WRONLY)
        try:
            assert os.write(fd, self.hidden) == len(self.hidden)
            os.fsync(fd)
        finally:
            os.close(fd)
        assert run('sha256sum', views['decoy']).stdout.split()[0] == self.primary
        self.views = views
        return views

    def verify(self, views):
        run('sh', '-c', 'echo 3 > /proc/sys/vm/drop_caches')
        assert run('sha256sum', views['decoy']).stdout.split()[0] == self.primary, self.label
        assert Path(views['hidden']).read_bytes() == self.hidden, self.label

    def stock_check(self):
        run('cryptsetup', 'open', '--readonly', '--key-file', self.key, self.device, f'stock-{self.label}')
        assert run('sha256sum', f'/dev/mapper/stock-{self.label}').stdout.split()[0] == self.primary
        run('cryptsetup', 'close', f'stock-{self.label}')

    def record(self, **extra):
        results['devices'].append(dict(label=self.label, device=self.device, raw_bytes=self.raw,
                                       hidden_bytes=len(self.hidden), sector_size=SECTOR, cipher=CIPHER,
                                       format_seconds=round(self.format_seconds, 1), **extra))
        print(f'device {self.label} ({self.device}, {self.raw} bytes): passed', flush=True)

    def export(self, image):
        """Raw image plus synthetic keys and oracles for the host check."""
        key = W / f'{self.label}-volume.key'
        run('cryptsetup', 'luksDump', '--batch-mode', '--dump-volume-key', '--volume-key-file', key,
            '--key-file', self.key, self.device)
        (W / f'{self.label}-hidden.key').write_bytes(self.hidden_key)
        (W / f'{self.label}-expected-primary.sha256').write_text(self.primary + '\n')
        (W / f'{self.label}-expected-hidden-volume').write_bytes(self.hidden)
        run('dd', f'if={self.device}', f'of={W / image}', 'bs=1M', 'status=none')


assert int(run('blockdev', '--getsize64', '/dev/vdc').stdout) == 300 << 20
# A whole 300 MiB disk and a loop device over a guest-root file (never over
# 9p), active at the same time under different owner names.
disk = Volume('disk', '/dev/vdc', 'piv-disk')
loop_file = Path('/var/tmp/piv-loop.img')
with loop_file.open('xb') as stream:
    stream.truncate((201 << 20) + 3 * 4096)
loop_device = run('losetup', '--find', '--show', loop_file).stdout.strip()
loop = Volume('loop', loop_device, 'piv-loop')
disk_views = disk.initialize_and_fill()
loop_views = loop.initialize_and_fill()
disk.verify(disk_views)
loop.verify(loop_views)
# Busy-device protection on an active owner's backing device.
refused('second owner on an owned device', errno.EBUSY,
        lambda: blocks.open_blocks('/dev/vdc', disk.key, disk.hidden_key, name='piv-other'), name='piv-other')
disk.close()
loop.close()
# Reopen through a symlink (followed; identity comes from the device number).
link = RUN / 'loop-link'
link.symlink_to(loop_device)
loop.verify(loop.open(link))
loop.close(link)
disk.verify(disk.open())
disk.close()
disk.stock_check()
loop.stock_check()
disk.record(kind='whole disk, 300 MiB')

# Decoy geometry matches stock dm-crypt: the view's logical block size is the
# primary sector size, so a filesystem created through it mounts through
# stock cryptsetup (with a 512-byte view on a 4096-byte volume, mke2fs would
# accept 1 KiB blocks that stock dm-crypt cannot serve). The hidden view is
# unaffected.
views = disk.open()
assert int(run('blockdev', '--getss', views['decoy']).stdout) == SECTOR
assert int(run('blockdev', '--getpbsz', views['decoy']).stdout) == SECTOR
if SECTOR > 512:
    refused_fs = run('mkfs.ext4', '-q', '-F', '-E', 'nodiscard', '-b', '1024', views['decoy'], check=False)
    assert refused_fs.returncode != 0, refused_fs
run('mkfs.ext4', '-q', '-F', '-E', 'nodiscard', '-L', 'pivdecoy', views['decoy'])
mountpoint = RUN / 'mnt'
mountpoint.mkdir(exist_ok=True)
payload = secrets.token_bytes(3 << 20)
run('mount', views['decoy'], mountpoint)
try:
    (mountpoint / 'payload.bin').write_bytes(payload)
finally:
    run('umount', mountpoint)
assert Path(views['hidden']).read_bytes() == disk.hidden
disk.close()
run('cryptsetup', 'open', '--readonly', '--key-file', disk.key, disk.device, 'stock-fs')
try:
    assert int(run('blockdev', '--getss', '/dev/mapper/stock-fs').stdout) == SECTOR
    run('mount', '-o', 'ro,noload', '/dev/mapper/stock-fs', mountpoint)
    try:
        assert (mountpoint / 'payload.bin').read_bytes() == payload
    finally:
        run('umount', mountpoint)
finally:
    run('cryptsetup', 'close', 'stock-fs')
views = disk.open()
assert Path(views['hidden']).read_bytes() == disk.hidden
disk.close()
results['filesystem'] = dict(view_logical_block=SECTOR, ext4_1k_refused=SECTOR > 512,
                             ext4_through_view_mounted_by_stock=True, hidden_preserved=True)
print('decoy filesystem: created through the view, mounted through stock dm-crypt', flush=True)
loop.export('devices-loop.img')
loop.record(kind='loop device over a guest-root file', concurrent_with='disk', reopened_via='symlink')
run('losetup', '--detach', loop_device)
loop_file.unlink()

# A dm-linear mapping at a 2 MiB offset into the disk; meanwhile the whole disk
# has an independent holder and is refused.
sectors = (150 << 20) // 512
dm('create', 'test-linear', input=f'0 {sectors} linear /dev/vdc 4096\n')
settle()
linear = Volume('linear', '/dev/mapper/test-linear', 'piv-linear')
refused('whole disk under a dm-linear holder', errno.EBUSY,
        lambda: blocks.open_blocks('/dev/vdc', disk.key, disk.hidden_key, name='piv-disk'), name='piv-disk')
linear.verify(linear.initialize_and_fill())
linear.close()
linear.verify(linear.open())
linear.close()
linear.stock_check()
linear.record(kind='dm-linear at a 2 MiB offset')
dm('remove', '--retry', 'test-linear')

# GPT partitions: the partitioned whole disk is refused; the second partition
# is used through its udev by-partlabel symlink.
run('wipefs', '--all', '/dev/vdc')
subprocess.run(['sfdisk', '--quiet', '/dev/vdc'], input='label: gpt\nsize=64MiB, name=pivspare\nname=pivtest\n',
               text=True, check=True)
settle()
try:
    blocks.open_blocks('/dev/vdc', disk.key, disk.hidden_key, name='piv-disk')
except ValueError as error:
    assert 'partition table' in str(error), error
else:
    raise AssertionError('Partitioned whole disk was accepted')
no_owner('piv-disk')
results['safety'].append('partitioned whole disk')
partlabel = Path('/dev/disk/by-partlabel/pivtest')
assert partlabel.is_symlink() and partlabel.resolve() == Path('/dev/vdc2')
part = Volume('partition', partlabel, 'piv-part')
part.verify(part.initialize_and_fill())
part.close()
part.verify(part.open('/dev/vdc2'))
part.close('/dev/vdc2')
part.stock_check()
part.export('devices-partition.img')
part.record(kind='GPT partition via /dev/disk/by-partlabel', partition_bytes=part.raw)

(W / 'devices-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Arbitrary-device activation and remaining safety checks passed\n')
