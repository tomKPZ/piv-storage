#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_packages linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make patch
guest_code
guest_build_module
guest_load_module
python3 /mnt/piv-work/guest-profile-test.py
guest_record
