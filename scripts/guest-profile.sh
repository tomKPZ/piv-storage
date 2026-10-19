#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_packages
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
python3 /mnt/piv-work/guest-profile-test.py
guest_record
