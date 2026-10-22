#!/usr/bin/env python3
"""Offline migration (pivsetup migrate) into a new AEGIS-128 format v5 volume.

The target on /dev/vdc is a freshly luksFormatted 512 MiB disk with a new
volume key (rekey), 512-byte sectors (a sector-size change for the 4096-byte
profile) and A/B records. Checks the refusal paths, then both views of both
volumes, and finally the target's primary through stock dm-crypt alone.
"""
import errno
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
SOURCE, TARGET = '/dev/vdb', '/dev/vdc'
TKEY, TKEK = Path('/run/target-passphrase.key'), os.urandom(32)
TKEY.write_bytes(os.urandom(32))
os.chmod(TKEY, 0o600)
results = {}


def mappings():
    names = subprocess.check_output(['dmsetup', 'ls'], text=True)
    # Only mappings this test's setup can create (guest_code keeps its own).
    return sorted(line.split()[0] for line in names.splitlines()
                  if line.startswith(('piv-src', 'piv-dst', 'piv-native')))


def sha256_prefix(path, length):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while length:
            data = stream.read(min(1 << 20, length))
            assert data, 'short read'
            digest.update(data)
            length -= len(data)
    return digest.hexdigest()


def refused(expected_text, *args, **kwargs):
    try:
        migrate(*args, **kwargs)
    except (OSError, ValueError) as error:
        assert expected_text in str(error), error
        assert mappings() == [], mappings()
        return str(error)
    raise AssertionError('migration unexpectedly succeeded')


subprocess.run(['cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--cipher', 'aegis128-random',
                '--key-size', '128', '--sector-size', '512', '--integrity', 'aead',
                '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000', '--key-file', str(TKEY), TARGET],
               check=True, stdout=subprocess.DEVNULL)

# Refusals leave no mappings behind: the same device (also through a symlink,
# caught by its device number) and a target held by an exclusive opener (the
# source opens first, so this also checks its cleanup).
link = Path('/run/piv-migrate-source-link')
link.symlink_to(SOURCE)
held = os.open(TARGET, os.O_RDONLY | os.O_EXCL)
try:
    results['refusals'] = [
        refused('different devices', SOURCE, KEY, HKEY, SOURCE, KEY, TKEK),
        refused('different devices', SOURCE, KEY, HKEY, link, KEY, TKEK),
        refused('in use', SOURCE, KEY, HKEY, TARGET, TKEY, TKEK),
    ]
finally:
    os.close(held)
    link.unlink()

result = migrate(SOURCE, KEY, HKEY, TARGET, TKEY, TKEK, ab=True, parity=4)
assert result['verified'] is True, result
assert result['decoy']['target_bytes'] > result['decoy']['bytes'], result
assert result['hidden']['bytes'] == len(EXPECTED), result
assert result['hidden']['target_bytes'] >= len(EXPECTED), result
assert mappings() == [], mappings()
results['migrate'] = result

# Migration copies only. (Activating the source still writes ordinary journal
# metadata, e.g. its setup checkpoint, so the raw image is not bit-identical.)
v = open_blocks(SOURCE, KEY, HKEY)
assert sha256_prefix(v['decoy'], result['decoy']['bytes']) == PRIMARY
assert Path(v['hidden']).read_bytes() == EXPECTED
close_blocks(SOURCE, KEY)

# The target authenticates only with its own key (A/B layout and RS parity from
# the keyslot).
try:
    open_blocks(TARGET, TKEY, HKEY)
    raise AssertionError('target opened with the source hidden key')
except OSError as error:
    assert error.errno == errno.EKEYREJECTED, error
assert mappings() == [], mappings()
v = open_blocks(TARGET, TKEY, TKEK)
assert v['hidden_bytes'] == result['hidden']['target_bytes'], (v, result)
assert sha256_prefix(v['decoy'], result['decoy']['bytes']) == PRIMARY
hidden = Path(v['hidden']).read_bytes()
assert hidden[:len(EXPECTED)] == EXPECTED and not any(hidden[len(EXPECTED):])
close_blocks(TARGET, TKEY)

# Unmodified Linux authenticates the migrated primary on its own.
subprocess.run(['rmmod', 'dm_piv'], check=True)
subprocess.run(['cryptsetup', 'open', '--readonly', '--key-file', str(TKEY), TARGET, 'piv-stock'], check=True)
try:
    assert sha256_prefix('/dev/mapper/piv-stock', result['decoy']['bytes']) == PRIMARY
finally:
    subprocess.run(['cryptsetup', 'close', 'piv-stock'], check=True)
(W / 'migrate-results.json').write_text(json.dumps(results, indent=2) + '\n')
(W / 'result.txt').write_text('Migration to a rekeyed, larger, 512-byte-sector A/B parity-4 AEGIS-128 v5 volume passed\n')
