#!/bin/bash
# `ext4power` suite, first boot: ext4 on single-slot and A/B hidden views,
# workload, then a power-cut request (kernel/guest-ext4-power.py).
source /mnt/piv-work/guest-common.sh
test "$(blockdev --getsize64 /dev/vdc)" -ge 4294967296
guest_packages
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
python3 /mnt/piv-work/guest-ext4-power.py cut
