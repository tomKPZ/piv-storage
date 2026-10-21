#!/bin/bash
# Confirm the derived image boots the marked newer-kernel port target.
source /mnt/piv-work/guest-common.sh
test "$(uname -r)" = 7.2.9+deb13-amd64
test -e /etc/piv-port-kernel
test -d /lib/modules/"$(uname -r)"/build
uname -a > /mnt/piv-work/uname.txt
printf 'Port kernel boot verified\n' > /mnt/piv-work/result.txt
sync
