#!/bin/bash
# Install the dm-piv deployment pieces on a Debian-style system with
# initramfs-tools. Research prototype without external cryptographic review;
# see packaging/README.md before using it on anything but disposable storage.
#
#   install.sh pivsetup BINARY   static pivsetup -> /usr/local/sbin/pivsetup
#   install.sh dkms [SRC]        module sources (default: kernel/ of this tree)
#                                -> /usr/src/dm-piv-VERSION, dkms add/build/install
#   install.sh dkms-remove       dkms remove --all and delete the sources
#   install.sh initramfs         initramfs-tools hook and local-top script
#
# PIV_DKMS_VERSION overrides the DKMS package version (default 0.1).
set -euo pipefail
umask 022
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
version=${PIV_DKMS_VERSION:-0.1}
case "$version" in *[!0-9A-Za-z.+~-]*|'') echo "invalid PIV_DKMS_VERSION" >&2; exit 2 ;; esac
sources=(Makefile dm-piv.c piv-control.h piv-control.inc piv-native.inc piv-rs.inc)

need_root() {
    test "$(id -u)" = 0 || { echo "install.sh: run as root" >&2; exit 1; }
}

case "${1:-}" in
    pivsetup)
        need_root
        binary=${2:?usage: install.sh pivsetup BINARY}
        # The release build is a static executable; refuse anything else.
        head -c 4 "$binary" | cmp -s - <(printf '\177ELF') || { echo "not an ELF binary: $binary" >&2; exit 1; }
        install -D -m 0755 "$binary" /usr/local/sbin/pivsetup
        echo "Installed /usr/local/sbin/pivsetup"
        ;;
    dkms)
        need_root
        command -v dkms >/dev/null || { echo "dkms is not installed" >&2; exit 1; }
        src=${2:-$repo/kernel}
        destination=/usr/src/dm-piv-$version
        test ! -e "$destination" || { echo "$destination exists; run dkms-remove first" >&2; exit 1; }
        for file in "${sources[@]}"; do test -f "$src/$file" || { echo "missing $src/$file" >&2; exit 1; }; done
        mkdir -p "$destination"
        for file in "${sources[@]}"; do install -m 0644 "$src/$file" "$destination/$file"; done
        sed "s/#VERSION#/$version/" "$here/dkms/dkms.conf" > "$destination/dkms.conf"
        dkms add -m dm-piv -v "$version"
        dkms build -m dm-piv -v "$version"
        dkms install -m dm-piv -v "$version"
        ;;
    dkms-remove)
        need_root
        dkms remove -m dm-piv -v "$version" --all || true
        rm -rf "/usr/src/dm-piv-$version"
        ;;
    initramfs)
        need_root
        test -d /etc/initramfs-tools || { echo "initramfs-tools is not installed" >&2; exit 1; }
        install -D -m 0755 "$here/initramfs-tools/hooks/pivsetup" /etc/initramfs-tools/hooks/pivsetup
        install -D -m 0755 "$here/initramfs-tools/scripts/local-top/pivsetup" \
            /etc/initramfs-tools/scripts/local-top/pivsetup
        # Keep the generated initramfs private (it may embed keys).
        install -D -m 0644 "$here/initramfs-tools/conf.d/pivsetup" /etc/initramfs-tools/conf.d/pivsetup
        install -D -m 0644 "$here/pivtab.example" /etc/pivtab.example
        echo "Installed the initramfs hook. Create /etc/pivtab (see /etc/pivtab.example), then run update-initramfs -u."
        ;;
    *)
        sed -n '2,12p' "$0" >&2
        exit 2
        ;;
esac
