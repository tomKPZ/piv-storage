#!/bin/bash
set -euo pipefail
umask 077
test "$(uname -r)" = 6.12.113+deb13-amd64
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
cd /mnt/piv-work
mkdir -p /opt/piv-code/pivstore
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
export PYTHONPATH=/opt/piv-code
dd if=/dev/vdb of=/var/tmp/pre-replay.img bs=1M status=none
python3 - <<'PY'
from pathlib import Path
from pivstore.profile import Image, UnsupportedImage
try:
    with Image('/var/tmp/pre-replay.img'):
        pass
except UnsupportedImage as exc:
    assert 'journal' in str(exc).lower()
    Path('pre-replay-state.txt').write_text(str(exc) + '\n')
else:
    raise AssertionError('Expected nonempty native journal')
PY
modprobe dm_integrity
modprobe dm_crypt
rmmod dm_crypt
insmod /root/piv-module/dm-crypt.ko
python3 -m pivstore open-blocks --device /dev/vdb --key-file passphrase.key --hidden-key-file hidden.key --state-directory /var/tmp/piv-dual/state > recovered-devices.json
python3 - <<'PY'
from pathlib import Path
import subprocess
from pivstore.blocks import native_status
from pivstore.kernel_owner import GuestOwner
w = Path('/mnt/piv-work')
assert Path('/dev/mapper/piv-native-hidden').read_bytes() == (w / 'expected-hidden-volume').read_bytes()
assert subprocess.check_output(['sha256sum', '/dev/mapper/piv-native-decoy'], text=True).split()[0] == (w / 'expected-power-primary.sha256').read_text().strip()
owner = GuestOwner('/dev/vdb', w / 'passphrase.key')
assert native_status(owner.device)['nonces'] == int((w / 'expected-power-nonces').read_text())
owner.close()
PY
python3 -m pivstore close-blocks --device /dev/vdb --key-file passphrase.key
cp /var/tmp/piv-dual/state/native.log native-power.log
rmmod dm_crypt
modprobe dm_crypt
cryptsetup open --readonly --key-file passphrase.key /dev/vdb piv-stock
sha256sum /dev/mapper/piv-stock | cut -d ' ' -f 1 > power-primary-after.sha256
cmp expected-power-primary.sha256 power-primary-after.sha256
cryptsetup close piv-stock
dmesg > reboot-dmesg.txt
dd if=/dev/vdb of=dual-power-final.img bs=1M status=none
printf 'Both native writable block views, kernel-owned WAL, in-flight VM loss, dual journal recovery, no recovery encryption and stock readback passed\n' > power-result.txt
sync
