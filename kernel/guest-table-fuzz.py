#!/usr/bin/env python3
"""Guest-only fuzzing of the dm-piv table constructors and messages.

piv-crypt: seeded token-level mutations of an otherwise valid owner table over
a scratch dm-integrity device (the _dif layer of a stock LUKS2 AEGIS-128
loop file in /run, never the fixture), including the read-only mode, plus target messages; constructions
that succeed are removed again, exercising ctr/dtr and control registration.
piv-view: mutated view tables (owner path, generation, role, length, offset)
against the active fixture owner, first with both views present (every create
must fail) and then with the hidden view removed (only the exact table may
succeed). Failures are crashes, kernel self-reports (scanned by the suite),
unexpected successes, or changed fixture contents.
"""
import json
import os
from pathlib import Path
import random
import subprocess

from pivstore.blocks import close_blocks, open_blocks

W = Path('/mnt/piv-work')
KEY, HKEY = W / 'passphrase.key', (W / 'hidden.key').read_bytes()
EXPECTED = (W / 'expected-hidden-volume').read_bytes()
PRIMARY = (W / 'expected-primary.sha256').read_text().strip()
STEPS = int(os.environ.get('PIV_TABLE_FUZZ_STEPS', '1500'))
SEED = int(os.environ.get('PIV_FUZZ_SEED', str(int.from_bytes(os.urandom(8), 'little'))))
rng = random.Random(SEED)
results = dict(seed=SEED)


def dm(*args, table=None):
    return subprocess.run(['dmsetup', '--noudevsync', *args], input=table, text=True,
                          capture_output=True)


def lines(text):
    return [line.split()[0] for line in text.splitlines() if line.split()]


def try_create(name, table, readonly=False):
    result = dm('create', name, *(['--readonly'] if readonly else []), table=table)
    if result.returncode == 0:
        assert dm('remove', '--retry', name).returncode == 0, name
        return True
    assert dm('info', name).returncode != 0, f'failed create left {name}'
    return False


def mutate_tokens(tokens, pool):
    tokens = list(tokens)
    for _ in range(rng.choice([1, 1, 2, 3])):
        roll, i = rng.random(), rng.randrange(len(tokens))
        if roll < 0.45:
            tokens[i] = rng.choice(pool)
        elif roll < 0.6:
            del tokens[i]
            if not tokens:
                tokens = ['0']
        elif roll < 0.75:
            tokens.insert(i, rng.choice(pool))
        elif roll < 0.9:
            text = tokens[i] or 'x'
            j = rng.randrange(len(text))
            tokens[i] = text[:j] + chr(rng.choice([0x30, 0x39, 0x61, 0x66, 0x3a, 0x2d, 0x7e, 0x47])) + text[j + 1:]
        else:
            tokens[i] = tokens[i] * rng.choice([2, 64])
    return tokens


# --- piv-crypt over a scratch integrity device ------------------------------
crypt_stats = {}
image = Path('/run/piv-fuzz-integrity.img')
for sector in (4096, 512):
    with image.open('wb') as stream:
        stream.truncate(64 * 1024 * 1024)
    loop = subprocess.check_output(['losetup', '--find', '--show', str(image)], text=True).strip()
    try:
        # integritysetup always adds an internal hash (no external tag profile),
        # so build the lower device the stock way: a LUKS2 AEGIS-128 volume
        # whose crypt layer is removed again, leaving its fz-int_dif mapping.
        keyfile = Path('/run/piv-fuzz.key')
        keyfile.write_bytes(os.urandom(32))
        subprocess.run(['cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--cipher',
                        'aegis128-random', '--key-size', '128', '--integrity', 'aead', '--sector-size',
                        str(sector), '--integrity-no-wipe', '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations',
                        '1000', '--key-file', str(keyfile), loop], check=True, capture_output=True)
        subprocess.run(['cryptsetup', 'open', '--key-file', str(keyfile), loop, 'fz-int'], check=True,
                       capture_output=True)
        keyfile.unlink()
        assert dm('remove', '--retry', 'fz-int').returncode == 0
        length = int(subprocess.check_output(['blockdev', '--getsz', '/dev/mapper/fz-int_dif'], text=True))
        length -= length % (sector // 512)
        key = os.urandom(16).hex()  # synthetic; the table goes through stdin only
        features = ['piv_control', 'integrity:32:aead'] + ([f'sector_size:{sector}'] if sector != 512 else [])
        valid = ['0', str(length), 'piv-crypt', 'capi:aegis128-random', key, '0', '/dev/mapper/fz-int_dif', '0',
                 str(len(features)), *features]
        pool = ['capi:aegis128-random', 'capi:gcm(aes)-random', 'aes-xts-plain64', key, key[:-2], key + '00',
                'zz' * 16, '0', '1', '-1', '18446744073709551615', '18446744073709551616', '/dev/mapper/fz-int_dif',
                loop, '/dev/vdb', '/dev/null', '/dev/mapper/nonexistent', '2', '3', '4', '9999999999',
                'piv_control', 'integrity:32:aead', 'integrity:28:aead', 'integrity:4294967295:aead',
                'sector_size:512', 'sector_size:4096', 'sector_size:1024', 'sector_size:', '', str(length),
                str(length - 1), str(length + 8), 'piv-crypt', 'piv-view']
        stats = crypt_stats.setdefault(sector, {'created': 0, 'rejected': 0, 'valid_created': 0})
        assert try_create('piv-fuzz-crypt', ' '.join(valid) + '\n'), 'valid scratch owner table rejected'
        stats['valid_created'] += 1
        for step in range(STEPS):
            tokens = mutate_tokens(valid, pool) if rng.random() < 0.95 else valid
            readonly = rng.random() < 0.1
            created = try_create('piv-fuzz-crypt', ' '.join(tokens) + '\n', readonly)
            stats['created' if created else 'rejected'] += 1
        # Messages on a live owner: only "key wipe" is accepted.
        assert dm('create', 'piv-fuzz-crypt', table=' '.join(valid) + '\n').returncode == 0
        messages = ['key wipe', 'key', 'key set 00', 'KEY WIPE', '', 'x' * 4000, 'key wipe extra']
        stats['messages'] = {m[:16]: dm('message', 'piv-fuzz-crypt', '0', *m.split()).returncode
                             for m in messages}
        assert dm('remove', '--retry', 'piv-fuzz-crypt').returncode == 0
    finally:
        dm('remove', '--retry', 'piv-fuzz-crypt')
        dm('remove', '--retry', 'fz-int')
        dm('remove', '--retry', 'fz-int_dif')
        subprocess.run(['losetup', '-d', loop], check=True)
        image.unlink()
results['crypt'] = crypt_stats
print(f'piv-crypt: {crypt_stats}', flush=True)

# --- piv-view against the active fixture owner ------------------------------
views = open_blocks('/dev/vdb', KEY, HKEY)
tables = {role: dm('table', f'piv-native-{role}').stdout.strip() for role in ('decoy', 'hidden')}
view_stats = {}


def canonical(tokens):
    """Semantic form of a view table: empty tokens vanish when joined, numbers
    may carry leading zeros and the owner may be a path or major:minor."""
    words = [t for t in tokens if t]
    if len(words) != 6:
        return words
    out = []
    for index, word in enumerate(words):
        if index in (0, 1, 4) and word.isdigit():
            word = str(int(word))
        elif index == 3 and word.startswith('/') and os.path.exists(word):
            rdev = os.stat(word).st_rdev
            word = f'{os.major(rdev)}:{os.minor(rdev)}'
        out.append(word)
    return out


def view_round(label, allowed_exact):
    stats = view_stats.setdefault(label, {'created': 0, 'rejected': 0})
    for role, table in tables.items():
        valid = table.split()
        generation, owner = valid[4], valid[3]
        pool = [owner, '/dev/mapper/piv-native', '/dev/vdb', '/dev/mapper/piv-native-decoy', '/dev/null',
                generation, str(int(generation) + 1), '0', '18446744073709551615', '-1', 'hidden', 'decoy',
                'both', '', '1', valid[1], str(int(valid[1]) + 1), str(int(valid[1]) - 1), 'piv-view']
        for _ in range(STEPS // 4):
            tokens = mutate_tokens(valid, pool)
            exact = canonical(tokens) == canonical(valid)
            created = try_create('piv-fuzz-view', ' '.join(tokens) + '\n')
            if created and not (exact and role in allowed_exact):
                raise AssertionError(f'unexpected view creation: {tokens}')
            stats['created' if created else 'rejected'] += 1


view_round('both-views-present', ())
assert dm('remove', '--retry', 'piv-native-hidden').returncode == 0
view_round('hidden-view-removed', ('hidden',))
assert dm('create', 'piv-native-hidden', table=tables['hidden'] + '\n').returncode == 0
assert dm('mknodes', 'piv-native-hidden').returncode == 0
assert Path(views['hidden']).read_bytes() == EXPECTED
results['view'] = view_stats
print(f'piv-view: {view_stats}', flush=True)
assert subprocess.check_output(['sha256sum', views['decoy']], text=True).split()[0] == PRIMARY
close_blocks('/dev/vdb', KEY)
assert not [n for n in lines(dm('ls').stdout) if n.startswith(('piv-fuzz', 'fz-int'))]
(W / 'table-fuzz-results.json').write_text(json.dumps(results, indent=2) + '\n')
