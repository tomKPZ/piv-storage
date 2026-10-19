#!/usr/bin/env python3
"""Observe a partially persisted carrier and kill QEMU during delayed I/O."""
import json
import mmap
import os
from pathlib import Path
import subprocess
import threading
import time
from pivstore.blocks import open_blocks, close_blocks
from pivstore.kernel_api import dm
from pivstore.kernel_owner import GuestOwner

w = Path('/mnt/piv-work')
initial = open_blocks('/dev/vdb', w / 'passphrase.key', (w / 'hidden.key').read_bytes(), initialize=True)
(w / 'expected-hidden-volume').write_bytes(Path(initial['hidden']).read_bytes())
close_blocks('/dev/vdb', w / 'passphrase.key')
dm('create', 'piv-test-delay', input='0 262144 delay /dev/vdb 0 0 /dev/vdb 0 1000\n')
views = open_blocks('/dev/mapper/piv-test-delay', w / 'passphrase.key',
                    (w / 'hidden.key').read_bytes(), allow_test_stack=True)
owner = GuestOwner('/dev/mapper/piv-test-delay', w / 'passphrase.key', allow_test_stack=True)
layout = owner.layout
owner.close()
base = layout.offsets(0)[1]
assert base % 512 == 0
raw = os.open('/dev/vdb', os.O_RDONLY | os.O_DIRECT)
buffer = mmap.mmap(-1, 1536)
def carrier():
    assert os.preadv(raw, [buffer], base) == 1536
    return [buffer[i * 28 + 16:i * 28 + 28] for i in range(48)]
before = carrier()
journal_base = layout.integrity_offset + 8 * 512
journal_bytes = layout.journal_sections * layout.journal_section_sectors * 512
journal = mmap.mmap(-1, journal_bytes)
known_ids = {0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444}
def committed_new_ivs():
    # Pinned no-MAC journal: address8, saved tails8 per 512-byte data unit, tuple28.
    factor = layout.sector_size // 512
    stride = layout.journal_entry_bytes
    iv_at = 8 + factor * 8 + 16
    assert os.preadv(raw, [journal], journal_base) == journal_bytes
    changed = set()
    for section in range(layout.journal_sections):
        section_base = section * layout.journal_section_sectors * 512
        ids = {int.from_bytes(journal[section_base + i * 512 + 504:section_base + (i + 1) * 512], 'little') ^ (section << 32) ^ i
               for i in range(layout.journal_section_sectors)}
        if len(ids) != 1 or not ids.issubset(known_ids): continue
        for header in range(8):
            for entry in range(504 // stride):
                at = section_base + header * 512 + entry * stride
                sector = int.from_bytes(journal[at:at + 8], 'little')
                if sector % factor or sector >= 48 * factor: continue
                index = sector // factor
                if journal[at + iv_at:at + iv_at + 12] != before[index]: changed.add(index)
    return changed
old = (w / 'expected-hidden-volume').read_bytes()
new = b'partial-record power cut'.ljust(512, b'!')
(w / 'power-new-block').write_bytes(new)
(w / 'power-old-hidden').write_bytes(old)
(w / 'power-primary.sha256').write_text(subprocess.check_output(['sha256sum', views['decoy']], text=True).split()[0] + '\n')
os.sync()
errors = []
def writer():
    try:
        value = mmap.mmap(-1, 512); value[:] = new
        fd = os.open(views['hidden'], os.O_RDWR | os.O_DIRECT)
        assert os.pwritev(fd, [value], 0) == 512
        os.fsync(fd); os.close(fd); value.close()
    except BaseException as exc: errors.append(repr(exc))
thread = threading.Thread(target=writer); thread.start()
deadline = time.monotonic() + 300
while time.monotonic() < deadline:
    current = carrier()
    changed = len({i for i, (a, b) in enumerate(zip(before, current)) if a != b} | committed_new_ivs())
    if 0 < changed < 48:
        (w / 'cut-boundary.json').write_text(json.dumps(dict(changed_committed_or_current_ivs=changed,
            mechanism='partial current/committed journal carrier observed with delayed lower writes',
            hardware_power_loss_tested=False)) + '\n')
        print('PIV_POWER_CUT', flush=True)
        while True: time.sleep(1)
    if not thread.is_alive(): raise AssertionError(f'Writer finished without partial boundary: {errors}, {changed}')
    time.sleep(.01)
raise AssertionError('No partial carrier observed')
