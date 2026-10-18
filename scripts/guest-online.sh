#!/bin/bash
# Disposable VM integration only. /dev/vdb is supplied by scripts/vm.py.
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
test -b /dev/vdb
cd /mnt/piv-work
test -f passphrase.key
test -f volume.key
test -f hidden.key
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 update
apt-get -y --no-install-recommends install cryptsetup-bin=2:2.7.5-2 \
    libcryptsetup12=2:2.7.5-2 python3-cryptography python3-pyfuse3 python3-trio \
    nbd-client fuse3 e2fsprogs
test "$(uname -r)" = 6.12.113+deb13-amd64
modprobe nbd nbds_max=1 max_part=0
modprobe fuse
mkdir -p /opt/piv-code/pivstore
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
export PYTHONPATH=/opt/piv-code
mkdir -p /var/tmp/piv-online /run/piv-hidden /run/piv-primary /run/piv-init
service_pid=
cleanup() {
    umount /run/piv-primary 2>/dev/null || true
    nbd-client -d /dev/nbd0 2>/dev/null || true
    fusermount3 -u /run/piv-hidden 2>/dev/null || true
    if test -n "$service_pid"; then kill "$service_pid" 2>/dev/null || true; fi
    umount /run/piv-init 2>/dev/null || true
    cryptsetup close piv-init 2>/dev/null || true
}
trap cleanup EXIT

# Create a real primary filesystem before online ownership. This invalidates any
# incoming hidden data; all inputs are disposable. Close stock mappings first.
cryptsetup open --key-file passphrase.key /dev/vdb piv-init
mkfs.ext4 -q -F /dev/mapper/piv-init
mount /dev/mapper/piv-init /run/piv-init
python3 - <<'PY'
import hashlib
from pathlib import Path
data = hashlib.shake_256(b'piv-online-primary-fixture-v1').digest(512 * 1024)
Path('/run/piv-init/primary.bin').write_bytes(data)
Path('primary-file.sha256').write_text(hashlib.sha256(data).hexdigest() + '\n')
PY
sync
umount /run/piv-init
sha256sum /dev/mapper/piv-init | cut -d ' ' -f 1 > online-primary.sha256
cryptsetup close piv-init
# Service backing lives on the guest's local ext4, never on 9p or a raw device.
dd if=/dev/vdb of=/var/tmp/piv-online/current.img bs=1M status=none
chmod 600 /var/tmp/piv-online/current.img

start_service() {
    python3 -m pivstore serve /var/tmp/piv-online/current.img \
        --volume-key-file volume.key --hidden-key-file hidden.key \
        --socket /var/tmp/piv-online/primary.sock --mountpoint /run/piv-hidden "$@" \
        >> service.log 2>&1 &
    service_pid=$!
    for attempt in $(seq 1 180); do
        if mountpoint -q /run/piv-hidden; then break; fi
        if ! kill -0 "$service_pid" 2>/dev/null; then cat service.log; return 1; fi
        sleep 1
    done
    mountpoint -q /run/piv-hidden
    nbd-client -unix /var/tmp/piv-online/primary.sock -N primary /dev/nbd0
    test "$(blockdev --getro /dev/nbd0)" = 1
    mount -o ro,noload /dev/nbd0 /run/piv-primary
}
stop_service() {
    umount /run/piv-primary
    nbd-client -d /dev/nbd0
    fusermount3 -u /run/piv-hidden
    wait "$service_pid"
    service_pid=
}

start_service --initialize
python3 - <<'PY'
import errno
import hashlib
import os
from pathlib import Path
import threading

expected_primary = Path('primary-file.sha256').read_text().strip()
errors = []
stop = threading.Event()
primary_fd = os.open('/dev/nbd0', os.O_RDONLY)
offsets = (0, 4096, 16 * 1024 * 1024 - 4096, 16 * 1024 * 1024)
blocks = {offset: os.pread(primary_fd, 4096, offset) for offset in offsets}
def reader():
    try:
        while not stop.is_set():
            assert hashlib.sha256(Path('/run/piv-primary/primary.bin').read_bytes()).hexdigest() == expected_primary
            for offset in offsets:
                os.posix_fadvise(primary_fd, offset, 4096, os.POSIX_FADV_DONTNEED)
                assert os.pread(primary_fd, 4096, offset) == blocks[offset]
    except BaseException as exc:
        errors.append(repr(exc))
thread = threading.Thread(target=reader)
thread.start()
try:
    with open('/run/piv-hidden/payload', 'r+b', buffering=0) as stream:
        stream.write(b'first online version')
        os.fsync(stream.fileno())
        stream.truncate(4)
        stream.seek(4)
        stream.write(b' mounted update\n')
        os.fsync(stream.fileno())
        stream.seek(0)
        data = stream.read()
        assert data == b'firs mounted update\n'
        Path('online-payload.expected').write_bytes(data)
    try:
        fd = os.open('/dev/nbd0', os.O_WRONLY)
    except OSError as exc:
        assert exc.errno in (errno.EROFS, errno.EACCES)
    else:
        try:
            try:
                os.pwrite(fd, blocks[0], 0)
            except OSError as exc:
                assert exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
            else:
                raise AssertionError('Primary block device accepted an actual write')
        finally:
            os.close(fd)
finally:
    stop.set()
    thread.join(timeout=30)
    os.close(primary_fd)
assert not thread.is_alive()
assert not errors, errors
PY
sha256sum /dev/nbd0 | cut -d ' ' -f 1 > online-before-restart.sha256
cmp online-primary.sha256 online-before-restart.sha256
stop_service

start_service
cmp online-payload.expected /run/piv-hidden/payload
sha256sum /dev/nbd0 | cut -d ' ' -f 1 > online-after-restart.sha256
cmp online-primary.sha256 online-after-restart.sha256
stop_service

# Final independent stock Linux check, only after the service has released it.
loop=$(losetup --find --show --read-only /var/tmp/piv-online/current.img)
cryptsetup open --readonly --key-file passphrase.key "$loop" piv-init
sha256sum /dev/mapper/piv-init | cut -d ' ' -f 1 > online-stock.sha256
cmp online-primary.sha256 online-stock.sha256
cryptsetup close piv-init
losetup -d "$loop"
python3 -m pivstore unpack /var/tmp/piv-online/current.img \
    --hidden-key-file hidden.key --output /var/tmp/piv-online/recovered.bin
cmp online-payload.expected /var/tmp/piv-online/recovered.bin
cp /var/tmp/piv-online/current.img online-final.img
uname -a > kernel.txt
dpkg-query -W -f='${Package}\t${Version}\n' > packages.tsv
printf 'Mounted online FUSE/NBD workflow, restart and stock-kernel verification passed\n' > result.txt
trap - EXIT
sync
