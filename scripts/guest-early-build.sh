#!/bin/bash
# Build a private test initramfs with synthetic test keys; never publish it.
set -euo pipefail
umask 077
cd /mnt/piv-work
mkdir -p /etc/initramfs-tools/hooks
cat > /etc/initramfs-tools/hooks/piv-test <<'HOOK'
#!/bin/sh
set -e
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0;; esac
. /usr/share/initramfs-tools/hook-functions
copy_exec /usr/bin/python3.13
copy_exec /usr/sbin/cryptsetup
copy_exec /usr/sbin/dmsetup
copy_exec /usr/sbin/blockdev
copy_exec /usr/sbin/modprobe
# kmod dlopens decompression libraries; ldd alone does not discover them.
copy_exec /usr/lib/x86_64-linux-gnu/liblzma.so.5
copy_exec /usr/lib/x86_64-linux-gnu/libzstd.so.1
copy_exec /usr/lib/x86_64-linux-gnu/libz.so.1
mkdir -p "${DESTDIR}/usr/lib/python3.13" "${DESTDIR}/piv"
cp -a /usr/lib/python3.13/. "${DESTDIR}/usr/lib/python3.13/"
# Native setup intentionally needs no Python cryptography or CFFI extension.
cp -a /opt/piv-code/pivstore "${DESTDIR}/piv/pivstore"
cp /root/piv-module/dm-crypt.ko "${DESTDIR}/piv/dm-crypt.ko"
cp /mnt/piv-work/passphrase.key /mnt/piv-work/hidden.key /mnt/piv-work/guest-early-test.py \
 /mnt/piv-work/expected-hidden-volume /mnt/piv-work/expected-primary.sha256 "${DESTDIR}/piv/"
manual_add_modules virtio_blk
manual_add_modules dm_integrity
manual_add_modules aegis128
manual_add_modules gcm
manual_add_modules ghash_generic
manual_add_modules ctr
manual_add_modules chacha_generic
manual_add_modules poly1305_generic
manual_add_modules chacha20poly1305
manual_add_modules hmac
manual_add_modules sha256_generic
HOOK
chmod 700 /etc/initramfs-tools/hooks/piv-test
mkinitramfs -o /var/tmp/piv-base.initrd "$(uname -r)"
mkdir /var/tmp/piv-unpacked
unmkinitramfs /var/tmp/piv-base.initrd /var/tmp/piv-unpacked
PIV_INIT_ROOT=/var/tmp/piv-unpacked/main
test -d "$PIV_INIT_ROOT" || PIV_INIT_ROOT=/var/tmp/piv-unpacked
cat > "$PIV_INIT_ROOT/init" <<'INIT'
#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /dev /proc /sys /run
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /run
mount -t tmpfs tmpfs /run
modprobe virtio_blk
modprobe dm_integrity
insmod /piv/dm-crypt.ko
export PYTHONPATH=/piv
export PYTHONDONTWRITEBYTECODE=1
python3.13 -S /piv/guest-early-test.py
rc=$?
echo PIV_EARLY_BOOT_EXIT=$rc
poweroff -f
INIT
chmod 700 "$PIV_INIT_ROOT/init"
(cd "$PIV_INIT_ROOT" && find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1) > early-test.initrd
cp /boot/vmlinuz-"$(uname -r)" early-test.vmlinuz
sha256sum early-test.initrd early-test.vmlinuz > early-boot-build.sha256
printf 'Private test initramfs created; includes disposable synthetic credentials.\n' > early-boot-build.txt
sync
