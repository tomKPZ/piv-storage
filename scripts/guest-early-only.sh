#!/bin/bash
# Build boot-test inputs from a CLOSED native fixture and its expected views.
source /mnt/piv-work/guest-common.sh
guest_packages
guest_code
mkdir -p /root/piv-module
cp experimental-dm-piv.ko /root/piv-module/dm-piv.ko
bash /mnt/piv-work/guest-early-build.sh
