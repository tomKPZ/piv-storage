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
info = json.loads((w / 'power-carrier.json').read_text())
unit, first, group, span = info['unit'], info['first'], info['group'], info['span']
carrier = range(first, first + span)
saved = (w / 'power-carrier-plaintext').read_bytes()


def unreadable():
    """Primary sectors whose decoy reads fail (EIO), per sector on error."""
    bad, dfd, chunk = [], os.open(v['decoy'], os.O_RDONLY | os.O_DIRECT), 256
    one, many = mmap.mmap(-1, unit), mmap.mmap(-1, chunk * unit)
    try:
        for start in range(0, info['sectors'], chunk):
            n = min(chunk, info['sectors'] - start)
            try:
                os.preadv(dfd, [memoryview(many)[:n * unit]], start * unit)
                continue
            except OSError as exc:
                assert exc.errno == errno.EIO
            for sector in range(start, start + n):
                try:
                    os.preadv(dfd, [one], sector * unit)
                except OSError as exc:
                    assert exc.errno == errno.EIO
                    bad.append(sector)
    finally:
        os.close(dfd); one.close(); many.close()
    return bad


def runs(sectors):
    out = []
    for s in sectors:
        if out and out[-1][1] == s - 1: out[-1][1] = s
        else: out.append([s, s])
    return out


fd = os.open(v['hidden'], os.O_RDWR | os.O_DIRECT)
buf = mmap.mmap(-1, 4096)       # format v5: 4096-byte hidden blocks
try:
    os.preadv(fd, [buf], 0)
except OSError as exc:
    assert exc.errno == errno.EIO
    outcome = 'EIO'
else:
    assert buf[:] in (old[:4096], new)
    outcome = 'complete-old' if buf[:] == old[:4096] else 'complete-new'
# A/B: the previous version survives an interrupted write (never EIO).
assert not (info['ab'] and outcome == 'EIO'), 'A/B block unavailable after the cut'
torn = unreadable()
torn_groups = sorted({(s - 112) // group - 2 for s in torn})
hidden_write_before_repair = None
if info['no_journal']:
    # No integrity journal: the cut may tear primary sectors that the
    # interrupted hidden write was rewriting (data and tag of a sector from
    # different writes). Only that request's carrier may be affected.
    assert set(torn) <= set(carrier), (torn, carrier)
    if torn:
        # Hidden writes stay strict: the target slot's carrier no longer
        # authenticates, so rewriting the block fails locally (EIO, no
        # fail-stop) until the decoy sectors are replaced.
        try:
            buf[:] = old[:4096]
            os.pwritev(fd, [buf], 0); os.fsync(fd)
        except OSError as exc:
            assert exc.errno == errno.EIO
            hidden_write_before_repair = 'EIO'
        else:
            hidden_write_before_repair = 'written'
    # Restore the torn sectors' plaintext from the pre-cut copy by full-sector
    # decoy writes (the failing-sector replacement path keeps the fragments).
    dfd = os.open(v['decoy'], os.O_RDWR | os.O_DIRECT)
    one = mmap.mmap(-1, unit)
    for sector in torn:
        at = (sector - first) * unit
        one[:] = saved[at:at + unit]
        assert os.pwritev(dfd, [one], sector * unit) == unit
    os.fsync(dfd); os.close(dfd); one.close()
    assert not unreadable()
else:
    # The journal leaves no primary sector torn.
    assert not torn, torn
# Direct reads of all other blocks must still work after local EIO. The full
# decoy hash below reads every primary sector (torn ones were restored above).
for i in range(1, len(old) // 4096):
    assert os.preadv(fd, [buf], i * 4096) == 4096
    assert buf[:] == old[i * 4096:(i + 1) * 4096]
assert subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0] == (w / 'power-primary.sha256').read_text().strip()
# Decoy can still write; unavailable records stay unavailable rather than zeros.
decoy = os.open(v['decoy'], os.O_RDWR | os.O_DIRECT)
primary = mmap.mmap(-1, 4096)
os.preadv(decoy, [primary], 0)
os.pwritev(decoy, [primary], 0); os.fsync(decoy); os.close(decoy); primary.close()
if outcome == 'EIO' and hidden_write_before_repair != 'written':
    try: os.preadv(fd, [buf], 0)
    except OSError as exc: assert exc.errno == errno.EIO
    else: raise AssertionError('Decoy write silently repaired damaged hidden block')
buf[:] = old[:4096]
os.pwritev(fd, [buf], 0); os.fsync(fd); os.close(fd); buf.close()
assert Path(v['hidden']).read_bytes() == old
close_blocks('/dev/vdb', w / 'passphrase.key')
(w / 'power-results.json').write_text(json.dumps(dict(affected_block=outcome, ab=info['ab'],
    no_journal=info['no_journal'], torn_primary_sectors=len(torn), torn_runs=runs(torn), torn_groups=torn_groups,
    carrier_first=first, carrier_span=span, hidden_write_before_decoy_repair=hidden_write_before_repair,
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
printf 'Partial-carrier VM interruption, stock journal replay or direct-mode tear repair, local EIO isolation/repair and stock full-primary verification passed\n' > result.txt
sync
