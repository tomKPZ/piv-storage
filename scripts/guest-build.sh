#!/bin/bash
# Build-only: compile the staged module against the pinned guest headers and
# record provenance. No module is loaded and the data disk is untouched.
source /mnt/piv-work/guest-common.sh
guest_packages linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make
guest_build_module
dpkg-query -W -f='${Package}\t${Version}\n' > /mnt/piv-work/packages.tsv
sync
