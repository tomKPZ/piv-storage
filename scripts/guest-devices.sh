#!/bin/bash
# Arbitrary-device activation and remaining safety checks (kernel/guest-devices-test.py).
# /dev/vdb: closed native fixture; /dev/vdc: 300 MiB blank (--second-blank-mib 300).
source /mnt/piv-work/guest-common.sh
guest_packages fdisk=2.41.5-0+deb13u1
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
python3 /mnt/piv-work/guest-devices-test.py
guest_record
