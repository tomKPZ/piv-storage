#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_packages
guest_code
if test -e /mnt/piv-work/scaffold.tar; then
    guest_packages linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make patch
    guest_build_module
    guest_load_module
else
    guest_load_module /mnt/piv-work/experimental-dm-piv.ko
fi
python3 /mnt/piv-work/guest-batch-test.py
guest_record
