#!/bin/bash
# `profile` suite: read/setup profiling and probe counts, then the decoy
# write-batching counts (formerly the separate `batch` suite) on the same disk.
source /mnt/piv-work/guest-common.sh
guest_packages
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
python3 /mnt/piv-work/guest-profile-test.py
# guest-profile-test.py unloads dm_piv for its stock readback.
insmod /mnt/piv-work/experimental-dm-piv.ko
python3 /mnt/piv-work/guest-batch-test.py
guest_record
printf 'Profiling, probe counts, batch counts, complete oracles and stock readback passed\n' > /mnt/piv-work/result.txt
sync
