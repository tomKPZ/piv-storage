"""Lower write extents from block:block_bio_queue traces (write shaping
evidence); no keys or block I/O."""
import re

LINE = re.compile(r'block_bio_queue:\s+(\d+),(\d+)\s+(\S+)\s+(\d+)\s+\+\s+(\d+)')


def write_extents(text, device, sector_size):
    """Contiguous runs [lo, hi) of primary sectors that non-empty write bios
    to @device ('major,minor', the lower dm-integrity device) covered, sorted
    (the union: rewrites of adjacent records share aligned units). Empty flush
    bios are ignored."""
    spans = []
    for match in LINE.finditer(text):
        major, minor, rwbs, start, count = match.groups()
        start, count = int(start), int(count)
        if f'{major},{minor}' != device or 'W' not in rwbs or not count:
            continue
        assert start * 512 % sector_size == 0 and count * 512 % sector_size == 0, match.group(0)
        spans.append((start * 512 // sector_size, (start + count) * 512 // sector_size))
    runs = []
    for lo, hi in sorted(spans):
        if runs and lo <= runs[-1][1]:
            runs[-1][1] = max(runs[-1][1], hi)
        else:
            runs.append([lo, hi])
    return [tuple(run) for run in runs]


def check_shaped(text, device, sector_size, expected, sectors, align=4096):
    """Assert the traced lower writes of one rewrite are exactly the runs
    @expected, each starting and ending on an @align-byte edge (or at the
    device end @sectors). Returns the runs."""
    runs = write_extents(text, device, sector_size)
    assert runs == [tuple(run) for run in expected], (runs, expected)
    unit = max(1, align // sector_size)
    for lo, hi in runs:
        assert lo % unit == 0 and (hi % unit == 0 or hi == sectors), (lo, hi, unit)
    return runs
