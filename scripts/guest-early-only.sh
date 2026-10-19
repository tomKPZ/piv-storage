#!/bin/bash
# Build boot-test inputs from a CLOSED native fixture and its expected views.
source /mnt/piv-work/guest-common.sh
guest_packages
guest_code
mkdir -p /root/piv-module
cp experimental-dm-crypt.ko /root/piv-module/dm-crypt.ko
bash /mnt/piv-work/guest-early-build.sh
