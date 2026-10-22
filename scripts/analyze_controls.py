#!/usr/bin/env python3
"""Authenticate matched closed controls and report observations, never deniability."""
import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from control_metrics import workload, payload, byte_statistics, region, trace_summary, journal_sample
from pivstore.profile import Image
from pivstore.records import decode_image
from pivstore.sector import SectorCodec


def analyze(root, primary_key, hidden_key):
    manifest = json.loads((root / 'control-results.json').read_text())
    arms = {}
    common_layout, common_before, common_after, header = None, None, None, None
    for entry in manifest['arms']:
        name = entry['arm']
        if name not in ('stock', 'native') or name in arms:
            raise ValueError('Invalid or duplicate arm')
        with Image(root / (name + '-before.img')) as before, Image(root / (name + '-after.img')) as after:
            layout = before.layout
            if layout != after.layout or asdict(layout) != manifest['layout']:
                raise ValueError('Layout mismatch')
            prefix = hashlib.sha256(before.read(layout.integrity_offset, 0)).hexdigest()
            assert hashlib.sha256(after.read(layout.integrity_offset, 0)).hexdigest() == prefix
            if common_layout is None: common_layout, header = layout, prefix
            assert common_layout == layout and prefix == header
            codec = SectorCodec(primary_key, layout.sector_size, before.encryption, before.integrity)
            digest_before, digest_after = hashlib.sha256(), hashlib.sha256()
            changed_iv, changed_plain, same_plain_reencrypted = [], [], []
            requested = set()
            for _, offset, size, _ in workload(layout):
                requested.update(range(offset // layout.sector_size, (offset + size) // layout.sector_size))
            ivs = []
            for index in range(layout.sectors):
                data_at, tuple_at = layout.offsets(index)
                old_tuple = before.read(layout.tuple_bytes, tuple_at)
                new_tuple = after.read(layout.tuple_bytes, tuple_at)
                old = codec.decrypt(index, before.read(layout.sector_size, data_at), old_tuple)
                new = codec.decrypt(index, after.read(layout.sector_size, data_at), new_tuple)
                expected = bytearray(old)
                for label, offset, size, same in workload(layout):
                    lo, hi = max(index * layout.sector_size, offset), min((index + 1) * layout.sector_size, offset + size)
                    if lo < hi and not same:
                        expected[lo - index * layout.sector_size:hi - index * layout.sector_size] = payload(label, size)[lo - offset:hi - offset]
                assert new == expected, (name, index, 'Unexpected primary bytes')
                digest_before.update(old); digest_after.update(new)
                ivs.append(new_tuple[16:])
                if old != new: changed_plain.append(index)
                if old_tuple[16:] != new_tuple[16:]:
                    changed_iv.append(index)
                    if old == new: same_plain_reencrypted.append(index)
            # Format v5 decoy writes change only the requested sectors' IVs, like stock.
            assert set(changed_iv) == requested, (name, sorted(set(changed_iv) ^ requested)[:16])
            assert len(set(ivs)) == len(ivs), 'Duplicate CURRENT IV'
            primary_before, primary_after = digest_before.hexdigest(), digest_after.hexdigest()
            assert primary_before == entry['before_primary'] and primary_after == entry['after_primary']
            if common_before is None: common_before, common_after = primary_before, primary_after
            assert primary_before == common_before and primary_after == common_after
            carrier = b''.join(ivs)
            # Count changed physical 512-byte units, including retained journal bytes.
            physical = Counter()
            for offset in range(0, before.size, 512):
                if before.read(512, offset) != after.read(512, offset): physical[region(layout, offset)] += 1
            hidden = decode_image(after, hidden_key) if name == 'native' else None
            if hidden is not None: assert hidden == bytes(len(hidden))
            physical_io = trace_summary((root / (name + '.trace')).read_text(), layout, entry['trace_device'], before.size)
            assert physical_io['total_queued_write_bytes'] > 0, 'Write workload has no captured lower writes'
            arms[name] = dict(authenticated_primary_sectors=layout.sectors, primary_before=primary_before,
                primary_after=primary_after, changed_primary_iv_sectors=len(changed_iv),
                changed_primary_plaintext_sectors=len(changed_plain),
                unchanged_primary_plaintext_reencrypted=len(same_plain_reencrypted),
                changed_iv_indices=changed_iv, changed_physical_512_units=dict(physical),
                current_iv_duplicates=len(ivs) - len(set(ivs)),
                byte_statistics={'all_iv_bytes': byte_statistics(carrier)},
                physical_io=physical_io,
                live_journal=journal_sample((root / (name + '-journal.bin')).read_bytes(), layout),
                native_hidden_bytes_verified=len(hidden) if hidden is not None else None)
    if set(arms) != {'stock', 'native'}: raise ValueError('Missing control arm')
    assert arms['native']['changed_iv_indices'] == arms['stock']['changed_iv_indices']
    return dict(layout=manifest['layout'], encryption=manifest['encryption'], luks_header_sha256=header,
                native_format=5, native_iv_footprint_matches='stock',
                arms=arms, conclusion='Matched-workload IV footprints: native (format v5) equals stock. No indistinguishability proof.',
                limits=['One synthetic volume per profile; sequential same-key arms and fresh evolving CRNG.',
                        'Native initialization precedes its baseline; initialization itself is excluded from workload trace.',
                        'Trace counts are submissions in a bounded window, not physical media bytes or stable timing.',
                        'Live journal reads race background work and are not atomic snapshots.',
                        'Descriptive byte statistics have no security acceptance threshold.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('share', type=Path)
    parser.add_argument('--volume-key-file', type=Path, required=True)
    parser.add_argument('--hidden-key-file', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(analyze(args.share, args.volume_key_file.read_bytes(), args.hidden_key_file.read_bytes()), indent=2))


if __name__ == '__main__': main()
