#!/bin/bash
set -euo pipefail
export PIV_SECTOR_SIZE=512 PIV_PRIMARY_CIPHER=aegis128-random
bash /mnt/piv-work/guest-large.sh
