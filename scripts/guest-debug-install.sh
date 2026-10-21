#!/bin/bash
# Install the sanitizer kernel packages into this (derived) guest image, mark
# the image explicitly for the guest guards and make the debug kernel the boot
# default. Run by scripts/build_debug_kernel.py; the resulting overlay becomes a
# read-only base image.
source /mnt/piv-work/guest-common.sh
RELEASE=6.12.113+deb13-amd64-pivdbg
dpkg -i /mnt/piv-work/linux-image-${RELEASE}_*.deb /mnt/piv-work/linux-headers-${RELEASE}_*.deb
test -e /boot/vmlinuz-$RELEASE && test -d /lib/modules/$RELEASE/build
{ printf 'release=%s\n' "$RELEASE"; sha256sum /mnt/piv-work/*.deb; } > /etc/piv-debug-kernel
sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
grep -q '^GRUB_DEFAULT=saved' /etc/default/grub
update-grub
entry="Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux $RELEASE"
grep -q "Debian GNU/Linux, with Linux $RELEASE'" /boot/grub/grub.cfg
grub-set-default "$entry"
grub-editenv list > /mnt/piv-work/grubenv.txt
cp /etc/piv-debug-kernel /mnt/piv-work/piv-debug-kernel.txt
printf 'Debug kernel installed and selected\n' > /mnt/piv-work/result.txt
sync
