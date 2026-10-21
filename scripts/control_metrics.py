"""Read-only descriptive metrics for matched disposable controls; no p-values."""
from collections import Counter
import hashlib
import math
import re
import zlib


def workload(layout):
    span = 90 * layout.sector_size  # one format v4 record
    return [('sector', 0, layout.sector_size, False),
            ('4k', span - 4096, 4096, False),
            ('16k', 3 * span - 8192, 16384, False),
            ('same-data', 5 * span, layout.sector_size, True)]


def payload(label, size):
    return hashlib.shake_256(('matched-control/' + label).encode()).digest(size)


def byte_statistics(data):
    if not data: raise ValueError('Empty sample')
    counts = Counter(data)
    expected = len(data) / 256
    return dict(bytes=len(data), ones_fraction=sum(b.bit_count() for b in data) / (8 * len(data)),
                entropy_bits_per_byte=-sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values()),
                byte_chi_square=sum((counts[b] - expected) ** 2 / expected for b in range(256)),
                zlib_ratio=len(zlib.compress(data)) / len(data))


def region(layout, offset):
    if offset < layout.integrity_offset: return 'luks'
    relative = offset - layout.integrity_offset
    if relative < 4096: return 'superblock'
    if relative < layout.initial_sectors * 512: return 'journal'
    within = (relative // 512 - layout.initial_sectors) % (layout.interleave_sectors + layout.metadata_run_sectors)
    return 'metadata_area' if within < layout.metadata_run_sectors else 'data_area'


def trace_summary(text, layout, device, file_size):
    counts, writes = Counter(), Counter()
    events = 0
    pattern = re.compile(r'block_bio_queue:\s+(\d+,\d+)\s+(\S+)\s+(\d+)\s+\+\s+(\d+)')
    for match in pattern.finditer(text):
        dev, flags, sector, size = match.groups()
        if dev != device: continue
        events += 1
        counts[flags] += 1
        sector, size = int(sector), int(size)
        if (sector + size) * 512 > file_size: raise ValueError('Trace extent outside disk')
        if 'W' in flags:
            for index in range(sector, sector + size): writes[region(layout, index * 512)] += 512
    if not events: raise ValueError('No matching block events')
    return dict(events=events, flags=dict(counts), queued_write_bytes=dict(writes),
                total_queued_write_bytes=sum(writes.values()))


def journal_sample(data, layout):
    """Observe commit-ID-consistent sections; never replay or trust a live sample."""
    if len(data) != layout.journal_sections * layout.journal_section_sectors * 512:
        raise ValueError('Wrong journal sample length')
    known = {0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444}
    valid, addresses, malformed = 0, [], 0
    factor = layout.sector_size // 512
    for section in range(layout.journal_sections):
        base = section * layout.journal_section_sectors * 512
        ids = {int.from_bytes(data[base + i * 512 + 504:base + (i + 1) * 512], 'little') ^ (section << 32) ^ i
               for i in range(layout.journal_section_sectors)}
        if len(ids) != 1 or not ids.issubset(known): continue
        valid += 1
        for header in range(8):
            for entry in range(504 // layout.journal_entry_bytes):
                at = base + header * 512 + entry * layout.journal_entry_bytes
                if data[at + 4:at + 8] == b'\xff' * 4: continue
                address = int.from_bytes(data[at:at + 8], 'little')
                if address % factor or address >= layout.primary_bytes // 512: malformed += 1
                else: addresses.append(address // factor)
    return dict(commit_consistent_sections=valid, rejected_sections=layout.journal_sections - valid,
                entries=len(addresses), malformed_entries=malformed, primary_sectors=sorted(set(addresses)),
                atomic_snapshot=False)
