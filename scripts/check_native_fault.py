#!/usr/bin/env python3
"""Independently verify a completed native-fault VM against its closed input."""
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
from pivstore.sector import SectorCodec


def check(source, run, primary_key, hidden_key):
    share = Path(run) / 'share'
    results = json.loads((share / 'fault-results.json').read_text())
    expected_cases = [('device-eio', 'decoy'), ('device-eio', 'hidden'),
                      ('log-enospc', 'decoy'), ('log-enospc', 'hidden')]
    assert [(r['fault'], r['role']) for r in results] == expected_cases
    previous = results[0]['nonces_before']
    for result in results:
        assert result['nonces_before'] == previous
        previous = result['nonces_after_retry']
        assert result['nonces_after_recovery'] == result['nonces_after_fault']
        assert result['nonces_after_retry'] == result['nonces_after_recovery'] + 64
        if result['fault'] == 'device-eio':
            assert result['nonces_after_fault'] == result['nonces_before'] + (32 if result['role'] == 'decoy' else 64)
        else:
            assert result['primary_unchanged_before_recovery']
            assert result['nonces_after_fault'] - result['nonces_before'] in (0, 32 if result['role'] == 'decoy' else 64)
    codec = SectorCodec(primary_key)
    replacement = hashlib.shake_256(b'device-eiodecoy').digest(4096)
    digest = hashlib.sha256()
    with Image(source) as before:
        expected_hidden = decode_image(before, hidden_key)
        initial = inspect_log(share / 'native.log', hidden_key,
                              context(before) + b'/incremental/v2', before.layout.sectors)
        assert initial.ready and initial.pending is None and not initial.trailing_bytes
        assert len(initial.used) == results[0]['nonces_before']
        for sector in range(before.layout.sectors):
            data, tag = before.layout.offsets(sector)
            value = codec.decrypt(sector, before.read(4096, data), before.read(28, tag))
            digest.update(replacement if sector == 64 * 1024 * 1024 // 4096 else value)
        expected_hidden = hashlib.shake_256(b'device-eiohidden').digest(512) + expected_hidden[512:]
    with Image(share / 'fault-final.img') as after:
        actual = after.verify(primary_key)
        assert actual == digest.hexdigest() == (share / 'expected-fault-primary.sha256').read_text().strip()
        assert decode_image(after, hidden_key) == expected_hidden == (share / 'expected-fault-hidden').read_bytes()
        state = inspect_log(share / 'native-fault.log', hidden_key,
                            context(after) + b'/incremental/v2', after.layout.sectors)
        assert state.ready and state.pending is None and not state.trailing_bytes
        assert len(state.used) == results[-1]['nonces_after_retry']
        assert initial.used <= state.used
        ivs = list(after.iv_slots())
        assert len(set(ivs)) == len(ivs) and set(ivs) <= state.used
        return dict(primary_sha256=actual, authenticated_sectors=after.layout.sectors,
                    hidden_bytes=len(expected_hidden), log_frames=state.frames,
                    reserved_nonces=len(state.used), cases=results)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('run', type=Path)
    parser.add_argument('--volume-key-file', type=Path, required=True)
    parser.add_argument('--hidden-key-file', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.source, args.run, args.volume_key_file.read_bytes(),
                           args.hidden_key_file.read_bytes()), indent=2))
