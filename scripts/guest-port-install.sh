#!/bin/bash
# Install the Debian trixie-backports kernel into this (derived) guest image for
# the newer-kernel port, mark the image explicitly for the guest guards and make
# that kernel the boot default. Also compiles the staged module against its
# headers (build log in the share) so API breakage shows up before booting it.
# Run by scripts/build_port_image.py; the resulting overlay becomes a read-only
# base image.
source /mnt/piv-work/guest-common.sh
VERSION=7.2.9-1~bpo13+1
export DEBIAN_FRONTEND=noninteractive
echo 'deb http://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/piv-backports.list
apt-get -o Acquire::Retries=2 update
apt-get -y --no-install-recommends install -t trixie-backports \
    linux-image-amd64="$VERSION" linux-headers-amd64="$VERSION"
apt-get -y --no-install-recommends install gcc-14 make
RELEASE=$(dpkg-query -W -f='${Depends}' linux-image-amd64 | sed -E 's/.*linux-image-([^ ,(]+).*/\1/')
test -e /boot/vmlinuz-"$RELEASE" && test -d /lib/modules/"$RELEASE"/build
mkdir -p /root/piv-module && tar -xf scaffold.tar -C /root/piv-module
set +e
make -C /lib/modules/"$RELEASE"/build M=/root/piv-module CC=gcc-14 modules > /mnt/piv-work/port-build.log 2>&1
echo "exit=$?" >> /mnt/piv-work/port-build.log
set -e
{ printf 'release=%s\nversion=%s\n' "$RELEASE" "$VERSION"; } > /etc/piv-port-kernel
sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
update-grub
grub-set-default "Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux $RELEASE"
grub-editenv list > /mnt/piv-work/grubenv.txt
cp /etc/piv-port-kernel /mnt/piv-work/piv-port-kernel.txt
dpkg-query -W -f='${Package}\t${Version}\n' 'linux-*' > /mnt/piv-work/port-packages.tsv
printf 'Port kernel installed and selected\n' > /mnt/piv-work/result.txt
sync
