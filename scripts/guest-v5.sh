#!/bin/bash
source /mnt/piv-work/guest-common.sh
# gcc-14 builds the userspace RS cross-check harness (kernel/piv-rs-test.c).
guest_packages python3-cryptography python3-argon2 gcc-14
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
python3 /mnt/piv-work/guest-v5-test.py
guest_record
