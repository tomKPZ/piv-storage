#!/bin/bash
source /mnt/piv-work/guest-common.sh
if test "${PIV_PREBUILT:-0}" = 1; then
    guest_packages python3-cryptography e2fsprogs
    mkdir -p /root/piv-module
    cp experimental-dm-piv.ko /root/piv-module/dm-piv.ko
    sha256sum experimental-dm-piv.ko > module.sha256
else
    guest_packages python3-cryptography e2fsprogs \
        linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make patch
    guest_build_module
fi
guest_code
mkdir -p /run/piv-init
modprobe dm_integrity
modprobe dm_crypt
# Establish a real readonly-primary filesystem before hidden ownership.
cryptsetup open --key-file passphrase.key /dev/vdb piv-init
mkfs.ext4 -q -F /dev/mapper/piv-init
mount /dev/mapper/piv-init /run/piv-init
python3 - <<'PY'
import hashlib
from pathlib import Path
value = hashlib.shake_256(b'piv-native-primary-v1').digest(512 * 1024)
Path('/run/piv-init/primary.bin').write_bytes(value)
Path('primary-file.sha256').write_text(hashlib.sha256(value).hexdigest() + '\n')
PY
sync
umount /run/piv-init
sha256sum /dev/mapper/piv-init | cut -d ' ' -f 1 > primary-before.sha256
cryptsetup close piv-init
guest_load_module
python3 guest-dual-test.py
guest_record
