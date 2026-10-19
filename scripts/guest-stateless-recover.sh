#!/bin/bash
set -euo pipefail
umask 077
cd /mnt/piv-work
mkdir -p /opt/piv-code/pivstore
mount -t 9p -o trans=virtio,version=9p2000.L,ro pivcode /opt/piv-code/pivstore
export PYTHONPATH=/opt/piv-code
modprobe dm_integrity
modprobe dm_crypt
rmmod dm_crypt
insmod experimental-dm-crypt.ko
python3 - <<'PY'
import errno
import json
import mmap
import os
from pathlib import Path
import subprocess
from pivstore.blocks import open_blocks, close_blocks
w = Path('/mnt/piv-work')
v = open_blocks('/dev/vdb', w / 'passphrase.key', (w / 'hidden.key').read_bytes())
old = (w / 'power-old-hidden').read_bytes()
new = (w / 'power-new-block').read_bytes()
fd = os.open(v['hidden'], os.O_RDWR | os.O_DIRECT)
buf = mmap.mmap(-1, 512)
try:
    os.preadv(fd, [buf], 0)
except OSError as exc:
    assert exc.errno == errno.EIO
    outcome = 'EIO'
else:
    assert buf[:] in (old[:512], new)
    outcome = 'complete-old' if buf[:] == old[:512] else 'complete-new'
# Direct reads of all other blocks must still work after local EIO.
for i in range(1, len(old) // 512):
    assert os.preadv(fd, [buf], i * 512) == 512
    assert buf[:] == old[i * 512:(i + 1) * 512]
assert subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0] == (w / 'power-primary.sha256').read_text().strip()
# Decoy can still write; unavailable records stay unavailable rather than zeros.
decoy = os.open(v['decoy'], os.O_RDWR | os.O_DIRECT)
primary = mmap.mmap(-1, 4096)
os.preadv(decoy, [primary], 0)
os.pwritev(decoy, [primary], 0); os.fsync(decoy); os.close(decoy); primary.close()
if outcome == 'EIO':
    try: os.preadv(fd, [buf], 0)
    except OSError as exc: assert exc.errno == errno.EIO
    else: raise AssertionError('Decoy write silently repaired damaged hidden block')
buf[:] = old[:512]
os.pwritev(fd, [buf], 0); os.fsync(fd); os.close(fd); buf.close()
assert Path(v['hidden']).read_bytes() == old
close_blocks('/dev/vdb', w / 'passphrase.key')
(w / 'power-results.json').write_text(json.dumps(dict(affected_block=outcome,
    other_hidden_blocks_unchanged=True, primary_unchanged=True, repair_passed=True)) + '\n')
PY
rmmod dm_crypt
modprobe dm_crypt
cryptsetup open --readonly --key-file passphrase.key /dev/vdb piv-stock
sha256sum /dev/mapper/piv-stock | cut -d ' ' -f 1 > stock-primary.sha256
cmp power-primary.sha256 stock-primary.sha256
cryptsetup close piv-stock
dd if=/dev/vdb of=stateless-power-final.img bs=1M status=none
dmesg > reboot-dmesg.txt
printf 'Partial-carrier VM interruption, stock journal replay, local EIO isolation/repair and stock full-primary verification passed\n' > result.txt
sync
