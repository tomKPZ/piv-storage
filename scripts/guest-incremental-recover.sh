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
python3 - <<'PY'
from pathlib import Path
from pivstore.kernel_owner import GuestOwner
from pivstore.incremental_store import IncrementalStore
w = Path('/mnt/piv-work')
owner = GuestOwner('/dev/vdb', w / 'passphrase.key')
with IncrementalStore(owner.device, '/var/tmp/piv-incremental/state', (w / 'hidden.key').read_bytes(), owner.uuid) as store:
    assert store.read_hidden(0, 1000) == (w / 'expected-payload').read_bytes()
assert not Path('/var/tmp/piv-incremental/state/pending-v2').exists()
owner.remove(); owner.close()
PY
rmmod dm_crypt
modprobe dm_crypt
cryptsetup open --readonly --key-file passphrase.key /dev/vdb piv-stock
sha256sum /dev/mapper/piv-stock | cut -d ' ' -f 1 > primary-after.sha256
cmp expected-primary.sha256 primary-after.sha256
cryptsetup close piv-stock
dmesg > reboot-dmesg.txt
dd if=/dev/vdb of=incremental-final.img bs=1M status=none
printf 'Incremental hidden records, mounted writable ext4/NBD, FUSE, controller death, in-flight VM cut, dual-journal replay and stock primary hash passed\n' > result.txt
sync
