#!/bin/bash
# Build and run only on vm.py's disposable virtio disk.
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
test -b /dev/vdb
test "$(blockdev --getsize64 /dev/vdb)" = 134217728
test "$(uname -r)" = 6.12.113+deb13-amd64
cd /mnt/piv-work
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 update
apt-get -y --no-install-recommends install \
  cryptsetup-bin=2:2.7.5-2 libcryptsetup12=2:2.7.5-2 python3 python3-cryptography \
  e2fsprogs
mkdir -p /opt/piv-code/pivstore /root/piv-module /run/piv-init
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
export PYTHONPATH=/opt/piv-code
# Reuse only a module already built by guest-dual.sh on the EXACT pinned kernel.
cp experimental-dm-crypt.ko /root/piv-module/dm-crypt.ko
sha256sum experimental-dm-crypt.ko > module.sha256
modprobe dm_integrity
modprobe dm_crypt
modprobe dm_delay
modprobe dm_flakey
# Establish a real readonly-primary filesystem before hidden ownership.
cryptsetup open --key-file passphrase.key /dev/vdb piv-init
mkfs.ext4 -q -F /dev/mapper/piv-init
mount /dev/mapper/piv-init /run/piv-init
python3 - <<'PY'
import hashlib
from pathlib import Path
value = hashlib.shake_256(b'piv-native-primary-v1').digest(512 * 1024)
Path('/run/piv-init/primary.bin').write_bytes(value)
Path('primary-file.sha256').write_text(hashlib.sha256(value).hexdigest() + '\n')
PY
sync
umount /run/piv-init
sha256sum /dev/mapper/piv-init | cut -d ' ' -f 1 > primary-before.sha256
cryptsetup close piv-init
rmmod dm_crypt
insmod /root/piv-module/dm-crypt.ko
python3 guest-dual-test.py
dmesg > dmesg.txt
dpkg-query -W -f='${Package}\t${Version}\n' > packages.tsv
sync
bash /mnt/piv-work/guest-early-build.sh
