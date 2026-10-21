#!/bin/bash
# Static hardening build of the staged module: W=1 extra warnings and sparse
# (C=2 checks every file). Build only; nothing is loaded, the disk is untouched.
# Writes hardening-w1.log, hardening-sparse.log and hardening-summary.txt with
# the warning lines that refer to our sources (kernel headers are excluded).
source /mnt/piv-work/guest-common.sh
guest_packages linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make sparse
dpkg-query -W -f='${Package}\t${Version}\n' sparse > /mnt/piv-work/sparse-version.txt
build=/lib/modules/"$(uname -r)"/build
for mode in w1 sparse; do
    rm -rf /root/piv-module && mkdir -p /root/piv-module
    tar -xf /mnt/piv-work/scaffold.tar -C /root/piv-module
    if [ "$mode" = w1 ]; then extra=(W=1 V=1); else extra=(C=2); fi
    make -C "$build" M=/root/piv-module CC=gcc-14 "${extra[@]}" modules \
        > /mnt/piv-work/hardening-$mode.log 2>&1
done
# Evidence that W=1 reached the compiler (it adds e.g. -Wmissing-prototypes).
grep -q -- '-Wmissing-prototypes' /mnt/piv-work/hardening-w1.log
grep -q 'CHECK   /root/piv-module/dm-piv.c' /mnt/piv-work/hardening-sparse.log
{
    for mode in w1 sparse; do
        echo "== $mode: warnings in our sources"
        grep -E '/root/piv-module/[^:]+:[0-9]+' /mnt/piv-work/hardening-$mode.log \
            | grep -Ei 'warning|error' | sed 's#/root/piv-module/##' | sort -u || true
    done
} > /mnt/piv-work/hardening-summary.txt
cat /mnt/piv-work/hardening-summary.txt
printf 'Hardening builds completed (see hardening-summary.txt)\n' > /mnt/piv-work/result.txt
sync
