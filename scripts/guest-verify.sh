#!/bin/bash
# Verify an already prepared data disk; never formats or writes primary data.
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
test -b /dev/vdb
cd /mnt/piv-work
test -f passphrase.key
test -f expected.sha256
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 update
apt-get -y --no-install-recommends install cryptsetup-bin=2:2.7.5-2 libcryptsetup12=2:2.7.5-2
test "$(uname -r)" = 6.12.113+deb13-amd64
sha256sum /dev/vdb | cut -d ' ' -f 1 > raw-before.sha256
trap 'cryptsetup close piv-verify 2>/dev/null || true' EXIT
cryptsetup open --readonly --key-file passphrase.key /dev/vdb piv-verify
sha256sum /dev/mapper/piv-verify | cut -d ' ' -f 1 > actual.sha256
cmp expected.sha256 actual.sha256
cryptsetup close piv-verify
trap - EXIT
sha256sum /dev/vdb | cut -d ' ' -f 1 > raw-after.sha256
cmp raw-before.sha256 raw-after.sha256
uname -a > kernel.txt
cryptsetup --version > cryptsetup-version.txt
dpkg-query -W -f='${Package}\t${Version}\n' > packages.tsv
printf 'Stock-kernel output-image readback passed; raw image unchanged\n' > result.txt
sync
