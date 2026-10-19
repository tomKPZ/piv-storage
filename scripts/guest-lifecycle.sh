#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_packages linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
mkdir -p /root/piv-io-test /sys/kernel/tracing
cp piv-io-test.c /root/piv-io-test/
printf 'obj-m += piv-io-test.o\n' > /root/piv-io-test/Makefile
make -C /lib/modules/"$(uname -r)"/build M=/root/piv-io-test CC=gcc-14 modules
insmod /root/piv-io-test/piv-io-test.ko
mount -t tracefs tracefs /sys/kernel/tracing
python3 /mnt/piv-work/guest-lifecycle-test.py
guest_record
