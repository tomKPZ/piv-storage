#!/bin/bash
# Execute only inside the disposable guest created by scripts/vm.py.
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
cd /mnt/piv-work
test -b /dev/vdb
case "$(blockdev --getsize64 /dev/vdb)" in
    134217728|536870912) ;;
    *) echo "Unsupported disposable guest disk size" >&2; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 update
apt-get -y --no-install-recommends install \
    cryptsetup-bin=2:2.7.5-2 libcryptsetup12=2:2.7.5-2 python3
test "$(uname -r)" = 6.12.113+deb13-amd64
PIV_SECTOR_SIZE=${PIV_SECTOR_SIZE:-4096}
case "$PIV_SECTOR_SIZE" in 512|4096) ;; *) exit 1;; esac
# AEGIS-128 is the only supported profile (format v4 needs 16-byte IVs).
PIV_PRIMARY_CIPHER=${PIV_PRIMARY_CIPHER:-aegis128-random}
case "$PIV_PRIMARY_CIPHER" in
    aegis128-random) primary_integrity=aead; primary_key_bytes=16 ;;
    *) exit 1 ;;
esac
modprobe dm_integrity
modprobe dm_crypt

# Synthetic keys are runtime-only files in the ignored, private run directory.
head -c "$primary_key_bytes" /dev/urandom > volume.key
head -c 32 /dev/urandom > passphrase.key
device=/dev/vdb
cleanup() {
    cryptsetup close piv-control 2>/dev/null || true
}
trap cleanup EXIT

cryptsetup luksFormat --batch-mode --type luks2 --cipher "$PIV_PRIMARY_CIPHER" \
    --key-size "$((primary_key_bytes * 8))" --sector-size "$PIV_SECTOR_SIZE" --integrity "$primary_integrity" \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --volume-key-file volume.key --key-file passphrase.key "$device"
# PIV_NO_JOURNAL=1: persist stock --integrity-no-journal in the LUKS2 header
# (config flag "no-journal"); every later open then uses a direct-mode table.
if test "${PIV_NO_JOURNAL:-0}" = 1; then
    cryptsetup open --integrity-no-journal --persistent --key-file passphrase.key "$device" piv-control
else
    cryptsetup open --key-file passphrase.key "$device" piv-control
fi
size=$(blockdev --getsize64 /dev/mapper/piv-control)
python3 - "$size" "$PIV_SECTOR_SIZE" <<'PY'
import hashlib
import sys

size = int(sys.argv[1])
sector = int(sys.argv[2])
digest = hashlib.sha256()
with open('/dev/mapper/piv-control', 'wb', buffering=0) as out:
    for start in range(0, size // sector, 1024):
        # Batch writes while retaining deterministic, distinct sector contents.
        block = b''.join(hashlib.shake_256(b'piv-control-v1' + index.to_bytes(8, 'little')).digest(sector)
                         for index in range(start, min(start + 1024, size // sector)))
        if out.write(block) != len(block):
            raise RuntimeError('short primary write')
        digest.update(block)
with open('expected.sha256', 'w') as out:
    out.write(digest.hexdigest() + '\n')
PY
sync
cryptsetup status piv-control > primary-status.txt
dmsetup table piv-control_dif > integrity-table.txt
cryptsetup close piv-control
cryptsetup luksDump --dump-json-metadata "$device" > luks.json
# integritysetup dump has no offset argument. Give it a standalone copy of
# the superblock; inspection requires neither activation nor a loop device.
python3 - <<'PY'
import json
offset = int(json.load(open('luks.json'))['segments']['0']['offset'])
with open('/dev/vdb', 'rb', buffering=0) as source:
    source.seek(offset)
    header = source.read(4096)
    if len(header) != 4096:
        raise RuntimeError('short integrity superblock read')
with open('/run/piv-integrity-header.bin', 'wb') as out:
    out.write(header)
PY
integritysetup dump /run/piv-integrity-header.bin > integrity-dump.txt

# Reopen read-only through stock Linux and authenticate/read every sector.
cryptsetup open --readonly --key-file passphrase.key "$device" piv-control
sha256sum /dev/mapper/piv-control | cut -d ' ' -f 1 > actual.sha256
cmp expected.sha256 actual.sha256
cryptsetup close piv-control
trap - EXIT

uname -a > kernel.txt
cp "/boot/config-$(uname -r)" kernel.config
cryptsetup --version > cryptsetup-version.txt
dpkg-query -W -f='${Package}\t${Version}\n' > packages.tsv
sha256sum "$device" | cut -d ' ' -f 1 > image.sha256
printf '%s\n' "$size" > primary-size.txt
printf 'Stock-kernel full-volume readback passed\n' > result.txt
sync
