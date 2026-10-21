#!/usr/bin/env python3
"""Offline migration into a new volume: primary rekey, cipher change and resize."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from pivstore.blocks import close_blocks, migrate, open_blocks

W = Path('/mnt/piv-work')
KEY, HKEY = W / 'passphrase.key', (W / 'hidden.key').read_bytes()
EXPECTED = (W / 'expected-hidden-volume').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
TARGET = '/dev/vdc'
TKEY, TKEK = Path('/run/target-passphrase.key'), os.urandom(32)
TKEY.write_bytes(os.urandom(32))
os.chmod(TKEY, 0o600)

# New LUKS2 AEGIS-128 target: new volume key (rekey), new cipher and a larger disk.
# Keep the source's sector size so the (smaller-per-byte) v4 hidden volume
# still fits; migrate() itself refuses a target that is too small.
sector_size = json.loads(subprocess.check_output(['cryptsetup', 'luksDump', '--dump-json-metadata', '/dev/vdb'],
                                                 text=True))['segments']['0']['sector_size']
subprocess.run(['cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--cipher', 'aegis128-random',
                '--key-size', '128', '--sector-size', str(sector_size), '--integrity', 'aead',
                '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000', '--key-file', str(TKEY), TARGET],
               check=True)
result = migrate('/dev/vdb', KEY, HKEY, TARGET, TKEY, TKEK, target_format=4, allow_second_disk=True)
assert result['decoy']['sha256'] == PRIMARY, result
assert result['hidden']['sha256'] == hashlib.sha256(EXPECTED).hexdigest(), result
assert result['decoy']['target_bytes'] > result['decoy']['bytes']
# Migration copies only. (Activating the source still writes ordinary journal
# metadata, e.g. its setup checkpoint, so the raw image is not bit-identical.)
v = open_blocks('/dev/vdb', KEY, HKEY)
assert subprocess.check_output(['sha256sum', v['decoy']], text=True).split()[0] == PRIMARY
assert Path(v['hidden']).read_bytes() == EXPECTED
close_blocks('/dev/vdb', KEY)

# Reopen the target alone (format v4 detected from its keyslot) and recheck.
v = open_blocks(TARGET, TKEY, TKEK, allow_second_disk=True)
with open(v['decoy'], 'rb') as f:
    assert hashlib.sha256(f.read(result['decoy']['bytes'])).hexdigest() == PRIMARY
hidden = Path(v['hidden']).read_bytes()
assert hidden[:len(EXPECTED)] == EXPECTED and not any(hidden[len(EXPECTED):])
close_blocks(TARGET, TKEY, allow_second_disk=True)
subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(TKEY), TARGET, 'piv-stock'], check=True)
with open('/dev/mapper/piv-stock', 'rb') as f:
    assert hashlib.sha256(f.read(result['decoy']['bytes'])).hexdigest() == PRIMARY
subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
(W / 'migrate-results.json').write_text(json.dumps(result, indent=2) + '\n')
(W / 'result.txt').write_text('Migration to a rekeyed, larger AEGIS-128 format v4 volume passed\n')
