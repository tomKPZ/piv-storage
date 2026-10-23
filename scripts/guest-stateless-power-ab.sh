#!/bin/bash
# `powerab` suite: the power suite with an A/B hidden volume (--ab).
export PIV_POWER_AB=1
exec bash /mnt/piv-work/guest-stateless-power.sh
