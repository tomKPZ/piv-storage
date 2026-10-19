#!/usr/bin/env python3
"""Independent closed-volume compaction verification, including exact tuples."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pivstore.blob import context
from pivstore.native_log import inspect_log
from pivstore.profile import Image
from pivstore.records import decode_image


def check(source, source_log, run, primary_key, hidden_key):
    share = Path(run) / 'share'
    with Image(source) as before, Image(share / 'compaction-final.img') as after:
        assert before.uuid == after.uuid and before.layout == after.layout
        primary = before.verify(primary_key)
        assert after.verify(primary_key) == primary
        old = inspect_log(source_log, hidden_key, context(before) + b'/incremental/v2', before.layout.sectors)
        new = inspect_log(share / 'native-compacted.log', hidden_key,
                          context(after) + b'/incremental/v2', after.layout.sectors)
        for state in (old, new):
            assert state.ready and state.pending is None and not state.trailing_bytes
        assert new.used == old.used
        assert new.valid_bytes < old.valid_bytes
        assert int((share / 'expected-history-count').read_text()) == len(new.used)
        assert hashlib.sha256(b''.join(sorted(new.used))).hexdigest() == (share / 'expected-history.sha256').read_text().strip()
        digest = hashlib.sha256()
        for index in range(before.layout.sectors):
            data, tag = before.layout.offsets(index)
            original = before.read(4096, data) + before.read(28, tag)
            assert original == after.read(4096, data) + after.read(28, tag), index
            digest.update(original)
        hidden = decode_image(before, hidden_key)
        assert decode_image(after, hidden_key) == hidden
        assert hidden == (share / 'expected-fault-hidden').read_bytes()
        ivs = list(after.iv_slots())
        assert len(set(ivs)) == len(ivs) and set(ivs) <= new.used
        return dict(primary_sha256=primary, authenticated_sectors=after.layout.sectors,
                    unchanged_tuple_sha256=digest.hexdigest(), hidden_bytes=len(hidden),
                    nonces=len(new.used), previous_bytes=old.valid_bytes,
                    compacted_bytes=new.valid_bytes, previous_frames=old.frames,
                    compacted_frames=new.frames)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('source_log', type=Path)
    parser.add_argument('run', type=Path)
    parser.add_argument('--volume-key-file', type=Path, required=True)
    parser.add_argument('--hidden-key-file', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.source, args.source_log, args.run,
                           args.volume_key_file.read_bytes(), args.hidden_key_file.read_bytes()), indent=2))
