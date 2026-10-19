#!/bin/bash
# Same tests, reusing an already built exact-kernel module.
set -euo pipefail
PIV_PREBUILT=1 bash /mnt/piv-work/guest-dual.sh
bash /mnt/piv-work/guest-early-build.sh
