#!/bin/bash
# Disposable vm.py guest only; never run against host devices.
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
  cryptsetup-bin=2:2.7.5-2 libcryptsetup12=2:2.7.5-2 python3 python3-cryptography
mkdir -p /opt/piv-code/pivstore
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
export PYTHONPATH=/opt/piv-code
mkdir /root/piv-module
tar -xf scaffold.tar -C /root/piv-module
cd /root/piv-module
make -C /lib/modules/"$(uname -r)"/build M="$PWD" CC=gcc-14 modules
cp dm-crypt.ko /mnt/piv-work/experimental-dm-crypt.ko
modinfo dm-crypt.ko > /mnt/piv-work/module-info.txt
sha256sum /lib/modules/"$(uname -r)"/build/Module.symvers > /mnt/piv-work/symvers.sha256
cp /boot/config-"$(uname -r)" /mnt/piv-work/kernel.config
cp /lib/modules/"$(uname -r)"/build/.config /mnt/piv-work/headers.config
python3 /mnt/piv-work/check-config.py /mnt/piv-work/kernel.config /mnt/piv-work/headers.config
modprobe dm_integrity
modprobe dm_crypt
rmmod dm_crypt
insmod ./dm-crypt.ko
cleanup() {
    dmsetup remove --retry piv-view 2>/dev/null || true
    dmsetup remove --retry piv-kernel 2>/dev/null || true
    dmsetup remove --retry piv-kernel_dif 2>/dev/null || true
}
trap cleanup EXIT
cryptsetup open --disable-keyring --key-file /mnt/piv-work/passphrase.key /dev/vdb piv-kernel
python3 /mnt/piv-work/guest-test.py
trap - EXIT
dmesg > /mnt/piv-work/dmesg.txt
dpkg-query -W -f='${Package}\t${Version}\n' > /mnt/piv-work/packages.tsv
sync
