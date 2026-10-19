#!/bin/bash
# Build boot-test inputs from a CLOSED native fixture and its expected views.
set -euo pipefail
umask 077
test "$(uname -r)" = 6.12.113+deb13-amd64
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
cd /mnt/piv-work
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 update
apt-get -y --no-install-recommends install cryptsetup-bin=2:2.7.5-2 libcryptsetup12=2:2.7.5-2 python3
mkdir -p /opt/piv-code/pivstore /root/piv-module
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
cp experimental-dm-crypt.ko /root/piv-module/dm-crypt.ko
bash /mnt/piv-work/guest-early-build.sh
