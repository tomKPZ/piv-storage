#!/bin/bash
# Deployment test, phase 2: after the reboot of the same disks, the installed
# initramfs (DKMS module, static pivsetup, embedded synthetic keys) must have
# opened both views before the root filesystem was mounted.
source /mnt/piv-work/guest-common.sh
fail() { echo "DEPLOY FAIL: $*" >&2; exit 1; }
test -e deploy-phase1.txt
cp /run/pivsetup/status initramfs-status.txt || fail "no initramfs activation status"
grep -qx 'piv-native: opened' /run/pivsetup/status || { cat /run/pivsetup/status; fail "initramfs activation"; }
# Nothing but the status lines reaches the booted system (no JSON, logs or
# prompted secrets).
test "$(ls -A /run/pivsetup)" = status || { ls -la /run/pivsetup; fail "initramfs leftovers in /run/pivsetup"; }
test ! -e /pivsetup || fail "initramfs work directory survived switch_root"
test "$(dmsetup table piv-native | cut -d ' ' -f 3)" = piv-crypt
test -b /dev/mapper/piv-native-decoy
test -b /dev/mapper/piv-native-hidden
case "$(modinfo -n dm-piv)" in */updates/dkms/dm-piv.ko*) ;; *) fail "module is not the DKMS build" ;; esac
test -d /sys/module/dm_piv
# The views were opened early: dm-piv was loaded from the initramfs before the
# root filesystem was first mounted (kernel log order).
dmesg > reboot-dmesg.txt
module_line=$(grep -n 'dm_piv: ' reboot-dmesg.txt | head -n 1 | cut -d: -f1)
root_line=$(grep -n 'EXT4-fs (vda1): mounted filesystem' reboot-dmesg.txt | head -n 1 | cut -d: -f1)
test -n "$module_line" && test -n "$root_line" && test "$module_line" -lt "$root_line" ||
    fail "dm-piv was not loaded before the root filesystem was mounted"
cmp /dev/mapper/piv-native-hidden expected-hidden-volume
test "$(sha256sum /dev/mapper/piv-native-decoy | cut -d ' ' -f 1)" = "$(cat expected-primary.sha256)"
# One hidden block write/readback/restore through the boot-opened views.
head -c 4096 /dev/urandom > /run/piv-block
dd if=/run/piv-block of=/dev/mapper/piv-native-hidden bs=4096 count=1 oflag=direct conv=notrunc status=none
dd if=/dev/mapper/piv-native-hidden bs=4096 count=1 iflag=direct status=none | cmp - /run/piv-block
dd if=expected-hidden-volume of=/dev/mapper/piv-native-hidden bs=4096 count=1 oflag=direct conv=notrunc status=none
pivsetup close-blocks --device /dev/vdb --key-file /etc/piv/passphrase.key
test ! -e /dev/mapper/piv-native
modprobe -r dm-piv
cryptsetup open --readonly --key-file passphrase.key /dev/vdb piv-stock
test "$(sha256sum /dev/mapper/piv-stock | cut -d ' ' -f 1)" = "$(cat expected-primary.sha256)"
cryptsetup close piv-stock
dd if=/dev/vdb of=deploy-final.img bs=1M status=none
# Leave freshly opened (unmounted) views active for systemd-shutdown, which
# detaches every DM device; the suite host-checks the disk after power-off.
modprobe dm-piv
pivsetup open-blocks --device /dev/vdb --key-file /etc/piv/passphrase.key --hidden-key-file /etc/piv/hidden.key > /dev/null
dmsetup ls > active-at-shutdown.txt
grep -q '^piv-native-hidden' active-at-shutdown.txt
dmesg > reboot-dmesg.txt
dpkg-query -W -f='${Package}\t${Version}\n' > packages.tsv
printf 'DKMS install and signature, installed activation, initramfs boot activation and stock verification passed\n' > result.txt
sync
