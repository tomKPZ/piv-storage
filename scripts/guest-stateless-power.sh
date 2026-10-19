#!/bin/bash
set -euo pipefail
umask 077
test "$(uname -r)" = 6.12.113+deb13-amd64
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
cd /mnt/piv-work
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 update
apt-get -y --no-install-recommends install cryptsetup-bin=2:2.7.5-2 libcryptsetup12=2:2.7.5-2 python3 python3-cryptography
mkdir -p /opt/piv-code/pivstore
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
export PYTHONPATH=/opt/piv-code
modprobe dm_integrity
modprobe dm_delay
modprobe dm_crypt
rmmod dm_crypt
insmod experimental-dm-crypt.ko
python3 guest-stateless-power.py
