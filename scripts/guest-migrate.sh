#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_packages
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
test "$(blockdev --getsize64 /dev/vdc)" = 536870912
python3 /mnt/piv-work/guest-migrate-test.py
guest_record
