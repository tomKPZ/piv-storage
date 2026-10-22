#!/bin/bash
# Probe stock cryptsetup 2.7.5: online reencryption and resize on LUKS2 + integrity.
source /mnt/piv-work/guest-common.sh
guest_packages
set +e
cd /run
out=/mnt/piv-work/probe.txt
head -c 32 /dev/urandom > k
run() { echo "\$ $*" >> $out; "$@" >> $out 2>&1; echo "exit=$?" >> $out; }
for profile in "aegis128-random aead"; do
    set -- $profile
    echo "===== $1 + $2" >> $out
    truncate -s 0 img; truncate -s 64M img
    L=$(losetup --find --show img)
    cryptsetup luksFormat --batch-mode --type luks2 --cipher $1 --integrity $2 $( [ $1 = aegis128-random ] && echo --key-size 128 ) --sector-size 4096 \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file k $L >> $out 2>&1; echo "format exit=$?" >> $out
    run cryptsetup open --key-file k $L p; run cryptsetup luksDump $L
    echo "-- online reencrypt (new volume key, same cipher)" >> $out
    run cryptsetup reencrypt --batch-mode --key-file k --pbkdf pbkdf2 --pbkdf-force-iterations 1000 $L
    echo "-- online reencrypt (cipher change)" >> $out
    run cryptsetup reencrypt --batch-mode --key-file k --cipher aes-xts-plain64 --pbkdf pbkdf2 \
        --pbkdf-force-iterations 1000 $L
    echo "-- offline reencrypt" >> $out
    cryptsetup close p
    run cryptsetup reencrypt --batch-mode --key-file k --pbkdf pbkdf2 --pbkdf-force-iterations 1000 $L
    echo "-- grow backing file then resize the active mapping" >> $out
    losetup -d $L; truncate -s 96M img; L=$(losetup --find --show img)
    run cryptsetup open --key-file k $L p; run cryptsetup luksDump $L
    echo "before: $(blockdev --getsize64 /dev/mapper/p)" >> $out
    run cryptsetup resize --key-file k p
    echo "after: $(blockdev --getsize64 /dev/mapper/p)" >> $out
    echo "-- shrink active mapping by 8 MiB" >> $out
    run cryptsetup resize --key-file k --size $(( ($(blockdev --getsz /dev/mapper/p) - 16384) )) p
    echo "after: $(blockdev --getsize64 /dev/mapper/p)" >> $out
    cryptsetup close p || true
    losetup -d $L
done
integritysetup --help | grep -i -E "resize|recalc" >> $out || true
cryptsetup --version >> $out
echo ok > /mnt/piv-work/result.txt
