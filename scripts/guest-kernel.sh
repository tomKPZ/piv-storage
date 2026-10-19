#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_packages python3-cryptography \
    linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make patch
guest_code
guest_build_module
guest_load_module
cd /root/piv-module
cleanup() {
    dmsetup remove --retry piv-view 2>/dev/null || true
    dmsetup remove --retry piv-kernel 2>/dev/null || true
    dmsetup remove --retry piv-kernel_dif 2>/dev/null || true
}
trap cleanup EXIT
cryptsetup open --disable-keyring --key-file /mnt/piv-work/passphrase.key /dev/vdb piv-kernel
python3 /mnt/piv-work/guest-test.py
trap - EXIT
guest_record
