#!/bin/bash
# Build a KASAN/UBSAN/lockdep debug variant of the pinned Debian 6.12.113
# kernel inside a disposable guest (never on the host). Output: Debian
# packages for linux-image/linux-headers with release
# 6.12.113+deb13-amd64-pivdbg, written to the share. Built in tmpfs; start the
# VM with plenty of CPUs and RAM (scripts/build_debug_kernel.py does).
source /mnt/piv-work/guest-common.sh
guest_packages linux-source-6.12=6.12.113-1 build-essential bc bison flex libelf-dev libssl-dev \
    dwarves cpio kmod rsync dpkg-dev debhelper gcc-14 python3
dpkg-query -W -f='${Package}\t${Version}\n' linux-source-6.12 gcc-14 > /mnt/piv-work/debug-build-packages.tsv
RELEASE_SUFFIX=+deb13-amd64-pivdbg
mkdir -p /root/kbuild && mount -t tmpfs -o size=28g tmpfs /root/kbuild
cd /root/kbuild
tar -xf /usr/src/linux-source-6.12.tar.xz
cd linux-source-6.12
cp /boot/config-"$(uname -r)" .config
# Restrict modules to what the guest suites load (plus their dependencies).
for module in virtio_blk virtio_net virtio_rng 9p 9pnet_virtio dm_mod dm_crypt dm_integrity \
    dm_flakey dm_delay loop ext4 aegis128 gcm ghash_generic ctr chacha_generic poly1305_generic \
    chacha20poly1305 hmac sha256_generic aesni_intel; do
    modprobe "$module" || true
done
lsmod > /root/kbuild/lsmod.txt
cp /root/kbuild/lsmod.txt /mnt/piv-work/debug-lsmod.txt
{ yes '' || true; } | make LSMOD=/root/kbuild/lsmod.txt localmodconfig > /dev/null
scripts/config \
    --set-str LOCALVERSION "" -d LOCALVERSION_AUTO \
    -e KASAN -e KASAN_GENERIC -e KASAN_INLINE -e KASAN_VMALLOC \
    -e UBSAN -e UBSAN_BOUNDS -e UBSAN_SHIFT -e UBSAN_BOOL -e UBSAN_ENUM \
    -e PROVE_LOCKING -e DEBUG_ATOMIC_SLEEP -e DEBUG_LIST -e DEBUG_SG \
    -e DEBUG_KMEMLEAK -d DEBUG_KMEMLEAK_DEFAULT_OFF \
    -d DEBUG_INFO_BTF -d DEBUG_INFO_DWARF5 -d DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT -e DEBUG_INFO_NONE \
    --set-str SYSTEM_TRUSTED_KEYS "" --set-str SYSTEM_REVOCATION_KEYS "" \
    -d MODULE_SIG_FORCE
make olddefconfig > /dev/null
for option in KASAN UBSAN PROVE_LOCKING DEBUG_ATOMIC_SLEEP DEBUG_KMEMLEAK DM_CRYPT DM_INTEGRITY CRYPTO_AEGIS128; do
    grep -E "^CONFIG_${option}=(y|m)" .config
done > /mnt/piv-work/debug-config-check.txt
cp .config /mnt/piv-work/debug-kernel.config
# The suffix comes from LOCALVERSION= on every make call (it also stops
# setlocalversion from appending "+").
make -s LOCALVERSION="$RELEASE_SUFFIX" kernelrelease > /mnt/piv-work/debug-kernelrelease.txt
test "$(cat /mnt/piv-work/debug-kernelrelease.txt)" = "6.12.113${RELEASE_SUFFIX}"
make -j"$(nproc)" CC=gcc-14 LOCALVERSION="$RELEASE_SUFFIX" bindeb-pkg > /mnt/piv-work/debug-build.log 2>&1
cp ../linux-image-6.12.113${RELEASE_SUFFIX}_*.deb ../linux-headers-6.12.113${RELEASE_SUFFIX}_*.deb /mnt/piv-work/
sha256sum /mnt/piv-work/*.deb > /mnt/piv-work/debug-debs.sha256
printf 'Debug kernel 6.12.113%s built\n' "$RELEASE_SUFFIX" > /mnt/piv-work/result.txt
sync
