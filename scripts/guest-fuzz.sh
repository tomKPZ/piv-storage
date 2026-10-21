#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_packages python3-cryptography
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
python3 /mnt/piv-work/guest-ioctl-fuzz.py
guest_record
