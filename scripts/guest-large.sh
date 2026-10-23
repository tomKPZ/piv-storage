#!/bin/bash
# `large` suite (scripts/suite.py): a fresh stock volume of the profile given
# by PIV_PRIMARY_CIPHER/PIV_INTEGRITY/PIV_SECTOR_SIZE on the 512 MiB /dev/vdb,
# or with PIV_LARGE_DEVICE=/dev/vdc on vm.py's arbitrary-size second disk
# (--second-blank-mib), then kernel/guest-large-test.py with the native run's
# module.
source /mnt/piv-work/guest-common.sh
export PIV_LARGE_DEVICE=${PIV_LARGE_DEVICE:-/dev/vdb}
case "$PIV_LARGE_DEVICE" in
    /dev/vdb) test "$(blockdev --getsize64 /dev/vdb)" = 536870912 ;;
    /dev/vdc) test -b /dev/vdc ;;
    *) exit 1 ;;
esac
PIV_CONTROL_DEVICE=$PIV_LARGE_DEVICE bash /mnt/piv-work/guest-control.sh
rm result.txt
guest_packages
guest_code
modprobe dm_flakey
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
python3 /mnt/piv-work/guest-large-test.py
guest_record
