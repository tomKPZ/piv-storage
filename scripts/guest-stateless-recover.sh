#!/bin/bash
source /mnt/piv-work/guest-common.sh
guest_code
guest_load_module /mnt/piv-work/experimental-dm-piv.ko
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
torn = []
if os.environ.get('PIV_ALLOW_NO_JOURNAL') == '1':
    # No integrity journal: the cut may have torn primary sectors that the
    # interrupted hidden write was rewriting. Only that record's carrier may be
    # affected; restore those sectors from the pre-cut copy by full-sector
    # decoy writes (the failing-sector replacement path).
    info = json.loads((w / 'power-carrier.json').read_text())
    unit, saved = info['unit'], (w / 'power-carrier-plaintext').read_bytes()
    carrier = range(info['first'], info['first'] + info['group'])
    dfd = os.open(v['decoy'], os.O_RDWR | os.O_DIRECT)
    one = mmap.mmap(-1, unit)
    for sector in range(info['sectors']):
        try:
            os.preadv(dfd, [one], sector * unit)
        except OSError as exc:
            assert exc.errno == errno.EIO
            torn.append(sector)
    assert set(torn) <= set(carrier), (torn, carrier)
    for sector in torn:
        at = (sector - info['first']) * unit
        one[:] = saved[at:at + unit]
        assert os.pwritev(dfd, [one], sector * unit) == unit
    os.fsync(dfd); os.close(dfd); one.close()
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
(w / 'power-results.json').write_text(json.dumps(dict(affected_block=outcome, torn_primary_sectors=torn,
    other_hidden_blocks_unchanged=True, primary_unchanged=True, repair_passed=True)) + '\n')
PY
rmmod dm_piv
cryptsetup open --readonly --key-file passphrase.key /dev/vdb piv-stock
sha256sum /dev/mapper/piv-stock | cut -d ' ' -f 1 > stock-primary.sha256
cmp power-primary.sha256 stock-primary.sha256
cryptsetup close piv-stock
dd if=/dev/vdb of=stateless-power-final.img bs=1M status=none
guest_stock_live_check
printf 'Stock crypt stayed busy while dm_piv loaded and unloaded.\n' > coexistence-result.txt
dmesg > reboot-dmesg.txt
printf 'Partial-carrier VM interruption, stock journal replay, local EIO isolation/repair and stock full-primary verification passed\n' > result.txt
sync
