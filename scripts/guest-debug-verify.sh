#!/bin/bash
# Confirm the derived image boots the marked sanitizer kernel.
source /mnt/piv-work/guest-common.sh
test "$(uname -r)" = 6.12.113+deb13-amd64-pivdbg
test -e /etc/piv-debug-kernel
dmesg | grep -E 'KernelAddressSanitizer initialized|kmemleak|Lock dependency validator' \
    > /mnt/piv-work/debug-boot.txt
grep -q 'KernelAddressSanitizer initialized' /mnt/piv-work/debug-boot.txt
grep -q 'Lock dependency validator' /mnt/piv-work/debug-boot.txt
uname -a > /mnt/piv-work/uname.txt
printf 'Sanitizer kernel boot verified\n' > /mnt/piv-work/result.txt
sync
