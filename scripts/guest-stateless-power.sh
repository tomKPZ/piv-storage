#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_packages python3-cryptography
guest_code
modprobe dm_delay
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
python3 guest-stateless-power.py
