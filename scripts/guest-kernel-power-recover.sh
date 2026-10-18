#!/bin/bash
# Second boot on the SAME disks after host SIGKILL of QEMU.
set -euo pipefail
umask 077
test "$(uname -r)" = 6.12.113+deb13-amd64
test "$(findmnt -n -o FSTYPE /mnt/piv-work)" = 9p
cd /mnt/piv-work
mkdir -p /opt/piv-code/pivstore
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
export PYTHONPATH=/opt/piv-code
# Inspect a closed snapshot before activating any integrity mapping/replay.
dd if=/dev/vdb of=/var/tmp/pre-replay.img bs=1M status=none
python3 - <<'PY'
from pivstore.profile import Image, UnsupportedImage
from pathlib import Path
try:
    with Image('/var/tmp/pre-replay.img'):
        pass
except UnsupportedImage as exc:
    assert 'journal' in str(exc).lower(), str(exc)
    Path('pre-replay-state.txt').write_text(str(exc) + '\n')
else:
    raise AssertionError('Expected unreplayed nonempty integrity journal')
PY
modprobe dm_integrity
modprobe dm_crypt
rmmod dm_crypt
insmod /root/piv-module/dm-crypt.ko
python3 - <<'PY'
from pathlib import Path
from pivstore.kernel_owner import GuestOwner
from pivstore.kernel_store import KernelStore
w = Path('/mnt/piv-work')
owner = GuestOwner('/dev/vdb', w / 'passphrase.key')
with KernelStore(owner.device, '/var/tmp/piv-power/state', (w / 'hidden.key').read_bytes(), owner.uuid) as store:
    assert store.read_hidden(0, 100) == b'power-cut recovered native payload'
assert not Path('/var/tmp/piv-power/state/pending').exists()
owner.remove(); owner.close()
PY
python3 guest-kernel-fault-test.py
rmmod dm_crypt
modprobe dm_crypt
cryptsetup open --readonly --key-file passphrase.key /dev/vdb piv-stock
sha256sum /dev/mapper/piv-stock | cut -d ' ' -f 1 > primary-after.sha256
cmp primary-before.sha256 primary-after.sha256
cryptsetup close piv-stock
dmesg > reboot-dmesg.txt
dd if=/dev/vdb of=power-final.img bs=1M status=none
printf 'recovered after journal write error' > expected-payload
printf 'In-flight QEMU cut, native integrity journal replay, whole-record roll-forward, native journal EIO recovery and stock readback passed\n' > result.txt
sync
