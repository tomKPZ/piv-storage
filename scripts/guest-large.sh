#!/bin/bash
source /mnt/piv-work/guest-common.sh
test "$(blockdev --getsize64 /dev/vdb)" = 536870912
bash /mnt/piv-work/guest-control.sh
rm result.txt
if test -e /mnt/piv-work/scaffold.tar; then
    guest_packages linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make patch
    guest_build_module
else
    guest_packages
fi
guest_code
modprobe dm_flakey
if test -e /mnt/piv-work/scaffold.tar; then
    guest_load_module
else
    guest_load_module /mnt/piv-work/experimental-dm-piv.ko
fi
python3 /mnt/piv-work/guest-large-test.py
guest_record
