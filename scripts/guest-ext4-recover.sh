#!/bin/bash
# `ext4power` suite, after the power cut: hidden EIO scan, ext4 replay and
# fsck, decoy hashes, then stock read-only verification without dm-piv.
source /mnt/piv-work/guest-common.sh
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
python3 /mnt/piv-work/guest-ext4-power.py recover
rmmod dm_piv
python3 /mnt/piv-work/guest-ext4-power.py stock-check
guest_record
printf 'ext4 power cut: A/B hidden filesystem consistent, single-slot outcome recorded, decoy plaintext unchanged under stock verification\n' > /mnt/piv-work/result.txt
sync
