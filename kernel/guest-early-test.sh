#!/bin/sh
# Run with ONLY an initramfs root, no persistent OS disk attached and no
# Python: activation uses the static pivsetup binary alone.
set -eux  # trace to the console: an unexpected set -e exit must be diagnosable
fail() { echo "PIV_EARLY_BOOT_FAIL: $*"; exit 1; }
D=/dev/mapper/piv-native-decoy
H=/dev/mapper/piv-native-hidden

test -d /sys/module/dm_crypt && test -d /sys/module/dm_piv || fail 'modules not loaded'
if grep -q -e ' ext4 ' -e ' ext2 ' /proc/mounts; then fail 'persistent filesystem mounted'; fi
test ! -e /var/lib/pivstore || fail 'persistent native state present'
root_type=
while read -r device mountpoint type rest; do
    if [ "$mountpoint" = / ]; then root_type=$type; fi
done < /proc/mounts
case "$root_type" in rootfs|tmpfs|ramfs) ;; *) fail "unexpected root filesystem $root_type" ;; esac
if command -v python3 >/dev/null 2>&1; then fail 'python3 present in the test initramfs'; fi

pivsetup open-blocks --device /dev/vdb --key-file /piv/passphrase.key \
    --hidden-key-file /piv/hidden.key > /run/open.json
set -- $(dmsetup table piv-native)
test "$3" = piv-crypt || fail "owner target is $3"
grep -q "\"hidden_bytes\": $(stat -c %s /piv/expected-hidden-volume)\$" /run/open.json || fail 'hidden size'
cmp "$H" /piv/expected-hidden-volume || fail 'hidden contents'

# One hidden block write, readback and restore. Plain dd options only: the
# initramfs dd may be busybox (no iflag/oflag=direct). Buffered 512-byte writes
# read their whole page first, and every block here is valid.
dd if=/piv/early-block of="$H" bs=512 count=1 conv=notrunc && sync
echo 3 > /proc/sys/vm/drop_caches
dd if="$H" bs=512 count=1 | cmp - /piv/early-block || fail 'hidden write'
dd if=/piv/expected-hidden-volume of="$H" bs=512 count=1 conv=notrunc && sync
# A same-data decoy rewrite must preserve every hidden byte.
dd if="$D" of=/run/decoy0 bs=4096 count=1
dd if=/run/decoy0 of="$D" bs=4096 count=1 conv=notrunc && sync
echo 3 > /proc/sys/vm/drop_caches
cmp "$H" /piv/expected-hidden-volume || fail 'hidden preserved'

set -- $(sha256sum "$D")
test "$1" = "$(cat /piv/expected-primary.sha256)" || fail 'primary digest'

pivsetup close-blocks --device /dev/vdb --key-file /piv/passphrase.key
rmmod dm_piv
test -d /sys/module/dm_crypt || fail 'stock dm_crypt unloaded'
test ! -e /var/lib/pivstore || fail 'persistent native state created'
echo 'PIV_EARLY_BOOT_PASS: both writable devices on RAM root via static pivsetup, no persistent root filesystem, no Python'
