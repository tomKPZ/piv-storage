#!/usr/bin/python3
"""Run with ONLY an initramfs root, no persistent OS disk attached."""
import hashlib
import os
from pathlib import Path
import subprocess
from pivstore.blocks import open_blocks, close_blocks

mounts = Path('/proc/mounts').read_text()
assert ' ext4 ' not in mounts and ' ext2 ' not in mounts
assert not Path('/var/lib/pivstore').exists()
root_mount = next(line for line in mounts.splitlines() if line.split()[1] == '/')
assert root_mount.split()[2] in ('rootfs', 'tmpfs', 'ramfs')
value = open_blocks('/dev/vdb', '/piv/passphrase.key', Path('/piv/hidden.key').read_bytes())
expected = Path('/piv/expected-hidden-volume').read_bytes()
assert value['hidden_bytes'] == len(expected)
assert Path(value['hidden']).read_bytes() == expected
fd = os.open(value['hidden'], os.O_RDWR)
old = os.pread(fd, 512, 0)
os.pwrite(fd, b'early-boot-test'.ljust(512, b'\0'), 0); os.fsync(fd)
assert os.pread(fd, 512, 0) == b'early-boot-test'.ljust(512, b'\0')
os.pwrite(fd, old, 0); os.fsync(fd); os.close(fd)
fd = os.open(value['decoy'], os.O_RDWR)
old = os.pread(fd, 4096, 0)
os.pwrite(fd, old, 0); os.fsync(fd); os.close(fd)
assert Path(value['hidden']).read_bytes() == expected
with Path(value['decoy']).open('rb') as stream:
    assert hashlib.file_digest(stream, 'sha256').hexdigest() == Path('/piv/expected-primary.sha256').read_text().strip()
close_blocks('/dev/vdb', '/piv/passphrase.key')
assert not Path('/var/lib/pivstore').exists()
print('PIV_EARLY_BOOT_PASS: both writable devices on RAM root, no persistent root filesystem', flush=True)
