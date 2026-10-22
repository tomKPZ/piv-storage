#!/usr/bin/env python3
"""Independently authenticate a closed stateless VM output; never mutate it."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pivstore.profile import Image
from pivstore.records import decode_image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--volume-key-file', type=Path, required=True)
    parser.add_argument('--hidden-key-file', type=Path, required=True)
    parser.add_argument('--expected-primary', type=Path, required=True)
    parser.add_argument('--expected-hidden', type=Path, required=True)
    args = parser.parse_args()
    with args.volume_key_file.open('rb') as stream:
        primary_key = stream.read(129)
    with args.hidden_key_file.open('rb') as stream:
        hidden_key = stream.read(33)
    with Image(args.image) as image:
        primary = image.verify(primary_key)
        assert primary == args.expected_primary.read_text().strip(), 'Primary mismatch'
        # --hidden-key-file is a keyslot KEK; the layout comes from the keyslot.
        # Strict: stored RS parity must equal the reference encoder's.
        hidden = decode_image(image, hidden_key, strict=True)
        assert hidden == args.expected_hidden.read_bytes(), 'Hidden mismatch'
        ivs = list(image.iv_slots())
        assert len(set(ivs)) == image.layout.sectors, 'Duplicate CURRENT primary IV'
        image.check_unchanged()
        print(json.dumps(dict(primary_sha256=primary,
            authenticated_primary_sectors=len(ivs),
            hidden_bytes=len(hidden), hidden_sha256=hashlib.sha256(hidden).hexdigest(),
            current_ivs_unique=True, historical_nonce_usage_known=False), indent=2))


if __name__ == '__main__':
    main()
