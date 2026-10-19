#!/bin/bash
set -euo pipefail
PIV_PRIMARY_CIPHER=aegis128-random PIV_SECTOR_SIZE=4096 bash /mnt/piv-work/guest-control.sh
