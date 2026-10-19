# Shared scaffolding for the pinned disposable vm.py guest. Source this file.
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "$(uname -r)" = 6.12.113+deb13-amd64
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
test -b /dev/vdb
test "$(blockdev --getsize64 /dev/vdb)" = 134217728
cd /mnt/piv-work

guest_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o Acquire::Retries=2 update
    apt-get -y --no-install-recommends install \
        cryptsetup-bin=2:2.7.5-2 libcryptsetup12=2:2.7.5-2 python3 "$@"
}

guest_code() {
    mkdir -p /opt/piv-code/pivstore
    mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
    export PYTHONPATH=/opt/piv-code
}

guest_build_module() {
    mkdir -p /root/piv-module
    tar -xf scaffold.tar -C /root/piv-module
    make -C /lib/modules/"$(uname -r)"/build M=/root/piv-module CC=gcc-14 modules
    cp /root/piv-module/dm-crypt.ko experimental-dm-crypt.ko
    modinfo /root/piv-module/dm-crypt.ko > module-info.txt
    sha256sum /lib/modules/"$(uname -r)"/build/Module.symvers > symvers.sha256
    cp /boot/config-"$(uname -r)" kernel.config
    cp /lib/modules/"$(uname -r)"/build/.config headers.config
    python3 check-config.py kernel.config headers.config
}

guest_load_module() {
    modprobe dm_integrity
    modprobe dm_crypt
    rmmod dm_crypt
    insmod "${1:-/root/piv-module/dm-crypt.ko}"
}

guest_record() {
    dmesg > /mnt/piv-work/dmesg.txt
    dpkg-query -W -f='${Package}\t${Version}\n' > /mnt/piv-work/packages.tsv
    sync
}
