#!/bin/bash
source /mnt/piv-work/guest-common.sh
if test -e /mnt/piv-work/scaffold.tar; then
    guest_packages linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make patch
    guest_build_module
else
    guest_packages
fi
guest_code
modprobe dm_delay
if test -e /mnt/piv-work/scaffold.tar; then
    guest_load_module
else
    guest_load_module /mnt/piv-work/experimental-dm-piv.ko
fi
mount -t tracefs tracefs /sys/kernel/tracing
python3 /mnt/piv-work/guest-cancel-test.py
guest_record
