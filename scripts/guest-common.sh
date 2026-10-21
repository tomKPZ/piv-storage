# Shared scaffolding for the pinned disposable vm.py guest. Source this file.
set -euo pipefail
umask 077
test "$(id -u)" = 0
# The pinned kernel, its sanitizer build only on an explicitly marked debug
# image, or the newer-kernel port target only on a marked port image.
case "$(uname -r)" in
    6.12.113+deb13-amd64) ;;
    6.12.113+deb13-amd64-pivdbg) test -e /etc/piv-debug-kernel ;;
    7.2.9+deb13-amd64) test -e /etc/piv-port-kernel ;;
    *) echo "Unsupported guest kernel" >&2; exit 1 ;;
esac
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
test -b /dev/vdb
case "$(blockdev --getsize64 /dev/vdb)" in
    134217728|536870912) ;;
    *) echo "Unsupported disposable guest disk size" >&2; exit 1 ;;
esac
cd /mnt/piv-work

guest_packages() {
    export DEBIAN_FRONTEND=noninteractive
    local packages=(cryptsetup-bin=2:2.7.5-2 libcryptsetup12=2:2.7.5-2 python3 e2fsprogs "$@")
    # Provisioned images (vm.py provision) already contain every pinned package
    # and their lists; --no-download succeeds only if nothing must be fetched.
    if test -e /etc/piv-provisioned &&
        apt-get -y --no-install-recommends --no-download install "${packages[@]}"; then
        cp /etc/piv-provisioned /mnt/piv-work/guest-provisioned.txt
        return
    fi
    apt-get -o Acquire::Retries=2 update
    apt-get -y --no-install-recommends install "${packages[@]}"
}

guest_code() {
    mkdir -p /opt/piv-code/pivstore
    mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
    export PYTHONPATH=/opt/piv-code
    # The Rust setup frontend (scripts/build_pivsetup.py), shared per run.
    if test -e /mnt/piv-work/pivsetup; then
        install -m 0755 /mnt/piv-work/pivsetup /usr/local/sbin/pivsetup
        sha256sum /usr/local/sbin/pivsetup > /mnt/piv-work/pivsetup.sha256
    fi
}

guest_build_module() {
    mkdir -p /root/piv-module
    tar -xf scaffold.tar -C /root/piv-module
    make -C /lib/modules/"$(uname -r)"/build M=/root/piv-module CC=gcc-14 modules
    cp /root/piv-module/dm-piv.ko experimental-dm-piv.ko
    modinfo /root/piv-module/dm-piv.ko > module-info.txt
    sha256sum /lib/modules/"$(uname -r)"/build/Module.symvers > symvers.sha256
    cp /boot/config-"$(uname -r)" kernel.config
    if test -e /etc/piv-debug-kernel; then
        # Sanitizer build: bindeb-pkg headers ship no .config; require instead
        # that the module's vermagic names exactly the running debug kernel.
        test "$(modinfo -F vermagic /root/piv-module/dm-piv.ko | cut -d ' ' -f 1)" = "$(uname -r)"
        grep -q '^CONFIG_KASAN=y' kernel.config
        return
    fi
    cp /lib/modules/"$(uname -r)"/build/.config headers.config
    python3 check-config.py kernel.config headers.config "$(uname -r)"
}

# A disposable ordinary encrypted filesystem remains mounted throughout our tests.
# Use the guest root's ext4, never a loop file backed by the 9p share.
guest_stock_live_start() {
    test ! -e /dev/mapper/piv-stock-live
    truncate -s 0 /var/tmp/piv-stock-live.img
    truncate -s 16M /var/tmp/piv-stock-live.img
    head -c 32 /dev/urandom > /var/tmp/piv-stock-live.key
    cryptsetup open --type plain --cipher aes-xts-plain64 --key-size 256 \
        --key-file /var/tmp/piv-stock-live.key /var/tmp/piv-stock-live.img piv-stock-live
    mkfs.ext4 -q -F /dev/mapper/piv-stock-live
    mkdir -p /run/piv-stock-live
    mount /dev/mapper/piv-stock-live /run/piv-stock-live
    printf 'Ordinary encrypted filesystem remains writable.\n' > /var/tmp/piv-stock-live.expected
    cp /var/tmp/piv-stock-live.expected /run/piv-stock-live/marker
    sync -f /run/piv-stock-live/marker
    guest_stock_live_check
}

guest_stock_live_check() {
    test -d /sys/module/dm_crypt
    test "$(cat /sys/module/dm_crypt/refcnt)" -gt 0
    test "$(dmsetup table piv-stock-live | cut -d ' ' -f 3)" = crypt
    cmp /var/tmp/piv-stock-live.expected /run/piv-stock-live/marker
    cp /var/tmp/piv-stock-live.expected /run/piv-stock-live/after
    sync -f /run/piv-stock-live/after
    cmp /var/tmp/piv-stock-live.expected /run/piv-stock-live/after
}

guest_load_module() {
    modprobe dm_integrity
    modprobe dm_crypt
    guest_stock_live_start
    insmod "${1:-/root/piv-module/dm-piv.ko}"
    test -d /sys/module/dm_piv
    dmsetup targets > /mnt/piv-work/loaded-targets.txt
    guest_stock_live_check
}

guest_record() {
    guest_stock_live_check
    printf 'Stock crypt stayed loaded with a writable mounted encrypted filesystem.\n' > /mnt/piv-work/coexistence-result.txt
    # Sanitizer kernels: force a final kmemleak scan and keep the full report
    # (backtraces name the allocating code) for triage of any suspected leak.
    if test -w /sys/kernel/debug/kmemleak; then
        echo scan > /sys/kernel/debug/kmemleak
        cat /sys/kernel/debug/kmemleak > /mnt/piv-work/kmemleak.txt
    fi
    dmesg > /mnt/piv-work/dmesg.txt
    dpkg-query -W -f='${Package}\t${Version}\n' > /mnt/piv-work/packages.tsv
    sync
}
