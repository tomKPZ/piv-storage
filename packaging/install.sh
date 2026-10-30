#!/bin/bash
# Install pivsetup and the DKMS dm-piv module on a Debian-style system.
# Research prototype without external cryptographic review; see
# packaging/README.md before using it on anything but disposable storage.
#
#   install.sh pivsetup BINARY   static pivsetup -> /usr/local/sbin/pivsetup
#   install.sh dkms [SRC]        module sources (default: kernel/ of this tree)
#                                -> /usr/src/dm-piv-VERSION, dkms add/build/install
#   install.sh dkms-remove       dkms remove --all and delete the sources
#
# The DKMS package version is packaging/VERSION (pivsetup's version, checked by
# its unit tests); PIV_DKMS_VERSION overrides it.
set -euo pipefail
umask 022
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
version=${PIV_DKMS_VERSION:-$(cat "$here/VERSION")}
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
        # Only release builds: the guest-test build (cargo feature test-hooks)
        # honours PIVSETUP_TEST_* variables. Checked on an executable copy.
        install -D -m 0755 "$binary" /usr/local/sbin/.pivsetup.new
        reported=$(/usr/local/sbin/.pivsetup.new --version 2>&1 || true)
        if ! grep -qx 'test hooks: no' <<< "$reported"; then
            rm -f /usr/local/sbin/.pivsetup.new
            echo "$binary is not a release build of pivsetup (scripts/build_pivsetup.py without --test-hooks)" >&2
            exit 1
        fi
        mv /usr/local/sbin/.pivsetup.new /usr/local/sbin/pivsetup
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
    *)
        sed -n '2,12p' "$0" >&2
        exit 2
        ;;
esac
