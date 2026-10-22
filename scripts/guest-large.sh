#!/bin/bash
source /mnt/piv-work/guest-common.sh
# PIV_LARGE_DEVICE=/dev/vdc runs on vm.py's arbitrary-size second disk
# (--second-blank-mib); the default is the 512 MiB /dev/vdb.
export PIV_LARGE_DEVICE=${PIV_LARGE_DEVICE:-/dev/vdb}
case "$PIV_LARGE_DEVICE" in
    /dev/vdb) test "$(blockdev --getsize64 /dev/vdb)" = 536870912 ;;
    /dev/vdc) test -b /dev/vdc ;;
    *) exit 1 ;;
esac
PIV_CONTROL_DEVICE=$PIV_LARGE_DEVICE bash /mnt/piv-work/guest-control.sh
rm result.txt
if test -e /mnt/piv-work/scaffold.tar; then
    guest_packages linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make patch
    guest_build_module
else
    guest_packages
fi
guest_code
modprobe dm_flakey
if test -e /mnt/piv-work/scaffold.tar; then
    guest_load_module
else
    guest_load_module /mnt/piv-work/experimental-dm-piv.ko
fi
python3 /mnt/piv-work/guest-large-test.py
guest_record
