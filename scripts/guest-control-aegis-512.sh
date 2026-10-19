#!/bin/bash
set -euo pipefail
PIV_PRIMARY_CIPHER=aegis128-random PIV_SECTOR_SIZE=512 bash /mnt/piv-work/guest-control.sh
