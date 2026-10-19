#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_packages
guest_code
modprobe dm_integrity
modprobe dm_crypt
guest_stock_live_start
mkdir -p /sys/kernel/tracing
mount -t tracefs tracefs /sys/kernel/tracing
python3 /mnt/piv-work/guest-controls-test.py
guest_record
