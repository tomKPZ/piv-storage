#!/usr/bin/env python3
"""Create nonsecret guest corruption offsets or compare returned IVs offline."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pivstore.profile import Image

with Image(Path(sys.argv[1])) as image:
    if len(sys.argv) == 2:
        boundary = 32768 // (image.layout.sector_size // 512)
        data, tag = image.layout.offsets(boundary)
        print(json.dumps({'corruption': [
            {'sector': boundary, 'offset': data},
            {'sector': boundary, 'offset': tag},
            {'sector': boundary, 'offset': tag + 16}]}))
    else:
        expected = json.loads(Path(sys.argv[2]).read_text())
        for index, value in expected.items():
            _, offset = image.layout.offsets(int(index))
            assert image.read(image.layout.iv_bytes, offset + 16).hex() == value, index
        print('Kernel-authenticated IV results match independent offline layout reads')
