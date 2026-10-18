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
  linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make patch \
  cryptsetup-bin=2:2.7.5-2 libcryptsetup12=2:2.7.5-2 python3 python3-cryptography \
  python3-pyfuse3 python3-trio fuse3 e2fsprogs
mkdir -p /opt/piv-code/pivstore /root/piv-module /run/piv-init
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
export PYTHONPATH=/opt/piv-code
tar -xf scaffold.tar -C /root/piv-module
make -C /lib/modules/"$(uname -r)"/build M=/root/piv-module CC=gcc-14 modules
cp /root/piv-module/dm-crypt.ko experimental-dm-crypt.ko
cp /boot/config-"$(uname -r)" kernel.config
cp /lib/modules/"$(uname -r)"/build/.config headers.config
python3 check-config.py kernel.config headers.config
modprobe dm_integrity
modprobe dm_crypt
modprobe fuse
modprobe dm_delay
modprobe dm_flakey
# Record the unchanged deterministic primary before the first hidden update.
cryptsetup open --readonly --key-file passphrase.key /dev/vdb piv-init
sha256sum /dev/mapper/piv-init | cut -d ' ' -f 1 > primary-before.sha256
cryptsetup close piv-init
sync
rmmod dm_crypt
insmod /root/piv-module/dm-crypt.ko
python3 guest-kernel-power-test.py
dmesg > dmesg.txt
dpkg-query -W -f='${Package}\t${Version}\n' > packages.tsv
sync
