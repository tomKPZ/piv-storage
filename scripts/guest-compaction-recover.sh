#!/bin/bash
# Reboot continuation on the same disposable root/data disks.
set -euo pipefail
umask 077
test "$(uname -r)" = 6.12.113+deb13-amd64
cd /mnt/piv-work
mkdir -p /opt/piv-code/pivstore
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
export PYTHONPATH=/opt/piv-code
modprobe dm_integrity
modprobe dm_crypt
rmmod dm_crypt
insmod /root/piv-module/dm-crypt.ko
python3 - <<'PY'
import hashlib
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from pivstore.blocks import open_blocks, close_blocks, native_status
from pivstore.kernel_owner import GuestOwner
from pivstore.native_log import inspect_log
from pivstore.blob import context
w = Path('/mnt/piv-work')
state = Path('/var/tmp/piv-compact/state')
key = (w / 'hidden.key').read_bytes()
views = open_blocks('/dev/vdb', w / 'passphrase.key', key, state_directory=state)
assert Path(views['hidden']).read_bytes() == (w / 'expected-fault-hidden').read_bytes()
assert subprocess.check_output(['sha256sum', views['decoy']], text=True).split()[0] == (w / 'expected-fault-primary.sha256').read_text().strip()
owner = GuestOwner('/dev/vdb', w / 'passphrase.key')
identity = context(SimpleNamespace(uuid=owner.uuid, layout=owner.layout)) + b'/incremental/v2'
log = inspect_log(state / 'native.log', key, identity, owner.device.sectors)
assert log.ready and log.pending is None and not log.trailing_bytes
assert len(log.used) == native_status(owner.device)['nonces'] == int((w / 'expected-history-count').read_text())
assert hashlib.sha256(b''.join(sorted(log.used))).hexdigest() == (w / 'expected-history.sha256').read_text().strip()
owner.close()
close_blocks('/dev/vdb', w / 'passphrase.key')
shutil.copyfile(state / 'native.log', w / 'native-compacted.log')
PY
rmmod dm_crypt
modprobe dm_crypt
cryptsetup open --readonly --key-file passphrase.key /dev/vdb piv-stock
sha256sum /dev/mapper/piv-stock | cut -d ' ' -f 1 > stock-primary.sha256
cmp expected-fault-primary.sha256 stock-primary.sha256
cryptsetup close piv-stock
dd if=/dev/vdb of=compaction-final.img bs=1M status=none
dmesg > reboot-dmesg.txt
dpkg-query -W -f='${Package}\t${Version}\n' > packages.tsv
printf 'Closed native compaction, ENOSPC, pending replay, publication VM loss, full history and stock readback passed\n' > result.txt
sync
