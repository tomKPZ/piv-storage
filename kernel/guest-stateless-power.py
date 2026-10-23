#!/usr/bin/env python3
"""Observe a partially persisted carrier and kill QEMU during delayed I/O.

PIV_POWER_AB=1 initializes with --ab (block 0's two slots are groups 2 and 3).
Journaled fixtures cut once part of the record's IVs is current or committed
in the journal. Stock persistent no-journal fixtures (PIV_NO_JOURNAL=1, direct
mode) have no journal to observe: the cut lands as soon as any data or tag
byte of the carrier changed on disk while the writer's fsync is outstanding,
an in-flight state whose tears the recovery script measures.
"""
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
from pivstore.records import shaped_extent

w = Path('/mnt/piv-work')
AB = os.environ.get('PIV_POWER_AB') == '1'
NO_JOURNAL = os.environ.get('PIV_NO_JOURNAL') == '1'
initial = open_blocks('/dev/vdb', w / 'passphrase.key', (w / 'hidden.key').read_bytes(), initialize=True, ab=AB)
(w / 'expected-hidden-volume').write_bytes(Path(initial['hidden']).read_bytes())
close_blocks('/dev/vdb', w / 'passphrase.key')
dm('create', 'piv-test-delay', input='0 262144 delay /dev/vdb 0 0 /dev/vdb 0 1000\n')
views = open_blocks('/dev/mapper/piv-test-delay', w / 'passphrase.key',
                    (w / 'hidden.key').read_bytes())
owner = GuestOwner('/dev/mapper/piv-test-delay', w / 'passphrase.key')
layout = owner.layout
owner.close()
# Hidden block 0's record: after 112 keyslot sectors and two 687-sector
# directory groups (format v5, no parity); with A/B its slots 0 and 1 are the
# next two groups. The span covers every sector the write may touch: the
# group(s) shaped to 4 KiB edges (at 512-byte sectors the last sectors of
# directory group 1 and the first of the next record get decoy-write IVs).
group, unit = 687, layout.sector_size
first, end = shaped_extent(112 + 2 * group, group * (2 if AB else 1), unit, layout.sectors)
span = end - first
start = layout.offsets(first)[1]
base = start // 512 * 512
skip = start - base
assert layout.offsets(first + span - 1)[1] == start + (span - 1) * layout.tuple_bytes
data_start = layout.offsets(first)[0]
assert layout.offsets(first + span - 1)[0] == data_start + (span - 1) * unit
raw = os.open('/dev/vdb', os.O_RDONLY | os.O_DIRECT)
tuple_size = layout.tuple_bytes
carrier_bytes = ((skip + span * tuple_size + 511) // 512) * 512
buffer = mmap.mmap(-1, carrier_bytes)
data_buffer = mmap.mmap(-1, span * unit)
def carrier():
    assert os.preadv(raw, [buffer], base) == carrier_bytes
    return [buffer[skip + i * tuple_size + layout.tag_bytes:skip + (i + 1) * tuple_size] for i in range(span)]
def tuples():
    assert os.preadv(raw, [buffer], base) == carrier_bytes
    return [buffer[skip + i * tuple_size:skip + (i + 1) * tuple_size] for i in range(span)]
def ciphertexts():
    assert os.preadv(raw, [data_buffer], data_start) == span * unit
    return [data_buffer[i * unit:(i + 1) * unit] for i in range(span)]
before = carrier()
journal_base = layout.integrity_offset + 8 * 512
journal_bytes = layout.journal_sections * layout.journal_section_sectors * 512
journal = mmap.mmap(-1, journal_bytes)
known_ids = {0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444}
def committed_new_ivs():
    # Pinned no-MAC journal: address8, saved tails8 per 512-byte data unit, tuple (tag || IV).
    factor = layout.sector_size // 512
    stride = layout.journal_entry_bytes
    iv_at = 8 + factor * 8 + layout.tag_bytes
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
                if sector % factor: continue
                index = sector // factor - first
                if not 0 <= index < span: continue
                if journal[at + iv_at:at + iv_at + layout.iv_bytes] != before[index]: changed.add(index)
    return changed
old = bytearray((w / 'expected-hidden-volume').read_bytes())
# Decoy plaintext of the span: without the journal, torn sectors lose theirs
# and the recovery restores it by full-sector decoy writes.
decoy = os.open(views['decoy'], os.O_RDONLY | os.O_DIRECT)
saved = mmap.mmap(-1, span * unit)
assert os.preadv(decoy, [saved], first * unit) == span * unit
os.close(decoy)
(w / 'power-carrier-plaintext').write_bytes(saved[:])
(w / 'power-carrier.json').write_text(json.dumps(dict(first=first, group=group, span=span, unit=unit, ab=AB,
    no_journal=NO_JOURNAL, sectors=layout.sectors)) + '\n')
(w / 'power-primary.sha256').write_text(subprocess.check_output(['sha256sum', views['decoy']], text=True).split()[0] + '\n')
contents = [b'partial-record power cut'.ljust(4096, b'!'), b'partial-record power cut, retry'.ljust(4096, b'?')]


def writer(new, errors):
    try:
        value = mmap.mmap(-1, 4096); value[:] = new
        fd = os.open(views['hidden'], os.O_RDWR | os.O_DIRECT)
        assert os.pwritev(fd, [value], 0) == 4096
        os.fsync(fd); os.close(fd); value.close()
    except BaseException as exc: errors.append(repr(exc))


if NO_JOURNAL:
    # Direct mode: dm-integrity writes data in place and tags through its
    # metadata buffers, with no journal; nothing orders the two on disk.
    new = contents[0]
    (w / 'power-new-block').write_bytes(new)
    (w / 'power-old-hidden').write_bytes(old)
    before_tuples, before_data = tuples(), ciphertexts()
    os.sync()
    errors = []
    thread = threading.Thread(target=writer, args=(new, errors)); thread.start()
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline and thread.is_alive():
        now_tuples, now_data = tuples(), ciphertexts()
        tags = {i for i in range(span) if now_tuples[i] != before_tuples[i]}
        data = {i for i in range(span) if now_data[i] != before_data[i]}
        if tags or data:
            slots = sorted({(first + i - 112) // group - 2 for i in tags | data})   # -1: directory group 1
            (w / 'cut-boundary.json').write_text(json.dumps(dict(
                mechanism='in-flight direct-mode carrier observed with delayed lower writes',
                no_journal=True, ab=AB, span_sectors=span, changed_tuples=len(tags), changed_data=len(data),
                changed_both=len(tags & data), changed_data_only=len(data - tags), changed_tuples_only=len(tags - data),
                changed_groups=slots, hardware_power_loss_tested=False)) + '\n')
            print('PIV_POWER_CUT', flush=True)
            while True: time.sleep(1)
        time.sleep(.01)
    raise AssertionError(f'No in-flight carrier change observed before the writer finished: {errors}')

# A record write is a few multi-sector bios; the writer's fsync then flushes.
# dm-integrity commits its journal on that flush, or earlier once free entries
# fall to the 50%
# watermark (journal_watermark:50), which queues an asynchronous commit of the
# sections filled so far. A 4096-byte record exceeds the journal, so it is
# always committed in parts. A 512-byte record fits below the watermark and
# would be committed by the final flush alone (one journal write, so no
# partial carrier reaches the disk). The activation starts with an empty
# journal; the setup checkpoint uses one section. Commit enough
# identical-plaintext decoy rewrites (each commits at least one whole section)
# that the record crosses the watermark early, leaving 2-3 sections of margin
# so the prefill itself never triggers dm-integrity's writeback. Whether the
# asynchronous commit snapshots part of the record is a scheduling race, so a
# 512-byte attempt that completes whole is repeated on a fresh activation.
per_section = 8 * (504 // layout.journal_entry_bytes)
entries = layout.journal_sections * per_section
threshold = (entries * 50 + 50) // 100
prefill = max(0, (entries - threshold) // per_section - 3) if group < entries - threshold else 0
attempts = []


def prefill_journal():
    volume = int(subprocess.check_output(['blockdev', '--getsize64', views['decoy']]))
    for k in range(prefill):
        offset = volume - (k + 1) * 16384
        chunk = mmap.mmap(-1, 16384)
        fd = os.open(views['decoy'], os.O_RDWR | os.O_DIRECT)
        try:
            assert os.preadv(fd, [chunk], offset) == 16384
            assert os.pwritev(fd, [chunk], offset) == 16384
            # Plain writes are not flushed by dm-piv (stock semantics); the
            # fsync commits each prefill request as before.
            os.fsync(fd)
        finally:
            os.close(fd)
            chunk.close()


for attempt in range(6 if prefill else 1):
    if attempt:
        close_blocks('/dev/mapper/piv-test-delay', w / 'passphrase.key')
        views = open_blocks('/dev/mapper/piv-test-delay', w / 'passphrase.key',
                            (w / 'hidden.key').read_bytes())
    new = contents[attempt % 2]
    (w / 'power-new-block').write_bytes(new)
    (w / 'power-old-hidden').write_bytes(old)
    prefill_journal()
    before = carrier()
    os.sync()
    errors = []
    thread = threading.Thread(target=writer, args=(new, errors)); thread.start()
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        current = carrier()
        changed = len({i for i, (a, b) in enumerate(zip(before, current)) if a != b} | committed_new_ivs())
        if 0 < changed < group:
            (w / 'cut-boundary.json').write_text(json.dumps(dict(changed_committed_or_current_ivs=changed, total_carrier_ivs=group,
                no_journal=False, ab=AB,
                mechanism='partial current/committed journal carrier observed with delayed lower writes',
                journal_prefill_requests=prefill, journal_entries=entries, attempt=attempt + 1,
                earlier_attempts=attempts, hardware_power_loss_tested=False)) + '\n')
            print('PIV_POWER_CUT', flush=True)
            while True: time.sleep(1)
        if not thread.is_alive(): break
        time.sleep(.01)
    else:
        raise AssertionError('Writer did not finish and no partial carrier was observed')
    thread.join()
    assert not errors, errors
    # Completed whole: block 0 now holds @new; retry with the other content.
    attempts.append(dict(attempt=attempt + 1, outcome='completed-whole', changed=changed))
    print(f'Attempt {attempt + 1}: record write completed whole ({changed} IVs); retrying', flush=True)
    old[:4096] = new
raise AssertionError(f'No partial carrier observed: {attempts}')
