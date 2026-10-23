#!/usr/bin/env python3
"""ext4 on the hidden view across a simulated power cut (`ext4power` suite).

`cut`: formats two stock volumes (the profile's cipher, 512-byte sectors) on
dm-linear halves of vm.py's second disk, initializes one single-slot and one
with --ab, creates ext4 on each hidden view, runs a concurrent create/fsync/
unlink workload on both and requests the power cut (vm.py kills QEMU) while
writes are in flight. `recover` (after the reboot): scans every hidden block
for EIO, mounts (journal replay), checks every fsync'ed file, runs e2fsck
-fn, and checks that the decoy plaintext of both volumes is unchanged
(through dm-piv, then stock read-only cryptsetup). A/B must stay fully
consistent; single-slot outcomes are recorded as found (docs/native-faults.md).

PIV_NO_JOURNAL=1 (the `*-nojournal` profiles) persists stock
--integrity-no-journal on both volumes (direct mode). The cut may then tear
primary sectors of in-flight hidden writes: `recover` scans the decoy first,
requires every torn sector to lie in hidden record carriers, records them and
restores their (all-zero, luksFormat-wiped) plaintext by full-sector decoy
writes before the hidden checks; hidden writes over a torn carrier would
otherwise fail (strict hidden writes).
"""
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import random
import secrets
import subprocess
import sys
import threading
import time

from pivstore.blocks import close_blocks, open_blocks
from pivstore.kernel_api import dm

W = Path('/mnt/piv-work')
KEY = W / 'ext4-passphrase.key'
HKEY_FILE = W / 'ext4-hidden.key'
DISK = '/dev/vdc'
MODES = {'single': dict(ab=False), 'ab': dict(ab=True)}
STATE = W / 'ext4-power-state.json'
GROUP = 687                     # format v5 record sectors (no parity)


def sh(*args, check=True):
    return subprocess.run([str(a) for a in args], check=check, text=True, capture_output=True)


def half_devices():
    sectors = int(sh('blockdev', '--getsz', DISK).stdout)
    half = sectors // 2 // 8 * 8
    for index, mode in enumerate(MODES):
        name = f'piv-test-ext4{mode}'
        if dm('info', name, check=False).returncode:
            dm('create', name, input=f'0 {half} linear {DISK} {index * half}\n')
    sh('udevadm', 'settle')
    return {mode: f'/dev/mapper/piv-test-ext4{mode}' for mode in MODES}


def open_mode(mode, source, **options):
    views = open_blocks(source, KEY, HKEY_FILE.read_bytes(), name=f'piv-{mode}', **options)
    sh('udevadm', 'settle')
    return views


def sha256_device(path):
    return sh('sha256sum', path).stdout.split()[0]


def content(label, i):
    size = 4096 * (1 + (i * 7919) % 4)
    seed = hashlib.sha256(f'{label}/{i}'.encode()).digest()
    return (seed * (size // 32 + 1))[:size]


def durable_append(path, line):
    with open(path, 'a') as handle:
        handle.write(line + '\n')
        handle.flush()
        os.fsync(handle.fileno())


def workload(mode, root, stop, counters):
    """Create files (every 4th fsync'ed and recorded only after its fsync and
    the directory fsync), unlink older unrecorded ones, rename some."""
    manifest = W / f'ext4-{mode}-manifest.txt'
    recorded = set()
    i = 0
    while not stop.is_set():
        directory = root / f'd{i % 8}'
        directory.mkdir(exist_ok=True)
        path = directory / f'f{i}'
        data = content(mode, i)
        try:
            with open(path, 'wb') as handle:
                handle.write(data)
                if i % 4 == 0 and len(recorded) < 400:
                    handle.flush()
                    os.fsync(handle.fileno())
                    fd = os.open(directory, os.O_RDONLY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    durable_append(manifest, f'{path.relative_to(root)} {hashlib.sha256(data).hexdigest()}')
                    recorded.add(i)
            old = i - 24
            if old >= 0 and old not in recorded:
                old_path = root / f'd{old % 8}' / f'f{old}'
                if i % 3:
                    old_path.unlink(missing_ok=True)
                elif old_path.exists():
                    old_path.rename(root / f'd{old % 8}' / f'r{old}')
                    (root / f'd{old % 8}' / f'r{old}').unlink()
        except OSError as error:
            if error.errno != errno.ENOSPC:
                counters[mode + '_errors'] = counters.get(mode + '_errors', 0) + 1
                counters[mode + '_last_error'] = repr(error)
                time.sleep(0.05)
        i += 1
        counters[mode] = i


def cut():
    KEY.write_bytes(secrets.token_bytes(32))
    HKEY_FILE.write_bytes(secrets.token_bytes(32))
    cipher = os.environ.get('PIV_PRIMARY_CIPHER', 'aes-xts-random')
    profile = (['--cipher', 'aegis128-random', '--key-size', '128', '--integrity', 'aead']
               if cipher == 'aegis128-random' else
               ['--cipher', 'aes-xts-random', '--key-size', '512', '--integrity', 'hmac-sha256'])
    no_journal = os.environ.get('PIV_NO_JOURNAL') == '1'
    sources = half_devices()
    state = dict(profile=cipher, sector_size=512, no_journal=no_journal, modes={})
    for mode, source in sources.items():
        sh('cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', *profile, '--sector-size', '512',
           '--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000', '--key-file', KEY, source)
        if no_journal:
            # Persist stock no-journal once (the documented setup step).
            sh('cryptsetup', 'open', '--integrity-no-journal', '--persistent', '--key-file', KEY, source,
               f'piv-persist-{mode}')
            sh('cryptsetup', 'close', f'piv-persist-{mode}')
        views = open_mode(mode, source, initialize=True, **MODES[mode])
        mke2fs = sh('mkfs.ext4', '-q', '-F', '-b', '4096', views['hidden'])
        info = sh('dumpe2fs', '-h', views['hidden']).stdout
        state['modes'][mode] = dict(source=source, hidden_bytes=views['hidden_bytes'],
                                    decoy_sha256=sha256_device(views['decoy']),
                                    decoy_bytes=int(sh('blockdev', '--getsize64', views['decoy']).stdout),
                                    has_journal='has_journal' in info, mke2fs=mke2fs.stdout[-200:])
        assert state['modes'][mode]['has_journal'], info
        if no_journal:
            # Torn sectors are restored to the luksFormat wipe's zeros.
            zero = hashlib.sha256()
            chunk = bytes(1 << 20)
            for at in range(0, state['modes'][mode]['decoy_bytes'], len(chunk)):
                zero.update(chunk[:min(len(chunk), state['modes'][mode]['decoy_bytes'] - at)])
            assert state['modes'][mode]['decoy_sha256'] == zero.hexdigest(), 'decoy is not all zeros'

        mount = Path(f'/run/piv-ext4-{mode}')
        mount.mkdir(exist_ok=True)
        sh('mount', '-t', 'ext4', '-o', 'commit=5', views['hidden'], mount)
        baseline = mount / 'baseline'
        baseline.mkdir()
        for i in range(64):
            (baseline / f'b{i}').write_bytes(content('baseline-' + mode, i))
        os.sync()
    STATE.write_text(json.dumps(state, indent=2) + '\n')
    os.sync()
    stop, counters = threading.Event(), {}
    threads = [threading.Thread(target=workload, args=(mode, Path(f'/run/piv-ext4-{mode}'), stop, counters),
                                daemon=True) for mode in MODES]
    for thread in threads:
        thread.start()
    # Long enough for several ext4 commits (commit=5) and dm-integrity
    # journal commits under load; the cut then lands amid writes.
    time.sleep(20 + random.random() * 5)
    durable_append(W / 'ext4-cut-counters.txt', json.dumps(counters))
    print('PIV_POWER_CUT', flush=True)
    while True:
        time.sleep(1)


def scan_hidden(path, size):
    eio = []
    fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
    with mmap.mmap(-1, 4096) as buf:
        try:
            for block in range(size // 4096):
                try:
                    assert os.preadv(fd, [buf], block * 4096) == 4096
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    eio.append(block)
        finally:
            os.close(fd)
    return eio


def unreadable_sectors(path, size, chunk=2048):
    """512-byte decoy sectors whose O_DIRECT reads fail (EIO), per sector on error."""
    bad = []
    fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
    with mmap.mmap(-1, chunk * 512) as many, mmap.mmap(-1, 512) as one:
        try:
            for first in range(0, size // 512, chunk):
                n = min(chunk, size // 512 - first)
                try:
                    os.preadv(fd, [memoryview(many)[:n * 512]], first * 512)
                    continue
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                for sector in range(first, first + n):
                    try:
                        os.preadv(fd, [one], sector * 512)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        bad.append(sector)
        finally:
            os.close(fd)
    return bad


def runs(sectors):
    out = []
    for sector in sectors:
        if out and out[-1][1] == sector - 1:
            out[-1][1] = sector
        else:
            out.append([sector, sector])
    return out


def repair_torn(path, sectors):
    fd = os.open(path, os.O_RDWR | os.O_DIRECT)
    with mmap.mmap(-1, 512) as zero:
        try:
            for sector in sectors:
                assert os.pwritev(fd, [zero], sector * 512) == 512
            os.fsync(fd)
        finally:
            os.close(fd)


def check_files(mode, root):
    bad = dict(missing=[], mismatch=[], eio=[])
    entries = [(f'baseline/b{i}', hashlib.sha256(content('baseline-' + mode, i)).hexdigest()) for i in range(64)]
    manifest = W / f'ext4-{mode}-manifest.txt'
    if manifest.exists():
        entries += [tuple(line.split()) for line in manifest.read_text().splitlines() if line.strip()]
    for name, digest in entries:
        try:
            data = (root / name).read_bytes()
        except FileNotFoundError:
            bad['missing'].append(name)
            continue
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            bad['eio'].append(name)
            continue
        if hashlib.sha256(data).hexdigest() != digest:
            bad['mismatch'].append(name)
    return len(entries), bad


def kernel_lines(since):
    lines = sh('dmesg').stdout.splitlines()[since:]
    return [line for line in lines if 'EXT4' in line or 'JBD2' in line or 'piv' in line][-20:]


def recover():
    state = json.loads(STATE.read_text())
    sources = half_devices()
    results = dict(profile=state['profile'], sector_size=512, no_journal=state.get('no_journal', False),
                   cut_counters=(W / 'ext4-cut-counters.txt').read_text().strip()
                   if (W / 'ext4-cut-counters.txt').exists() else None, modes={})
    for mode, source in sources.items():
        expected = state['modes'][mode]
        views = open_mode(mode, source)
        result = dict(hidden_blocks=views['hidden_bytes'] // 4096)
        result['eio_blocks'] = scan_hidden(views['hidden'], views['hidden_bytes'])
        result['eio_block_count'] = len(result['eio_blocks'])
        result['eio_blocks'] = result['eio_blocks'][:64]
        torn = unreadable_sectors(views['decoy'], expected['decoy_bytes'])
        result['torn_primary_sectors'] = len(torn)
        result['torn_runs'] = runs(torn)[:16]
        # Hidden record groups (g >= 2 are hidden-block records) holding torn sectors.
        result['torn_groups'] = sorted({(sector - 112) // GROUP for sector in torn if sector >= 112})
        if state.get('no_journal'):
            # Only in-flight hidden writes rewrite carriers (the decoy is never
            # written here): every torn sector lies in a hidden-block record.
            assert all(sector >= 112 + 2 * GROUP for sector in torn), result['torn_runs']
            repair_torn(views['decoy'], torn)
            assert not unreadable_sectors(views['decoy'], expected['decoy_bytes'])
            result['eio_blocks_after_decoy_repair'] = scan_hidden(views['hidden'], views['hidden_bytes'])[:64]
        else:
            assert not torn, result['torn_runs']
        result['decoy_unchanged'] = sha256_device(views['decoy']) == expected['decoy_sha256']
        mount = Path(f'/run/piv-ext4-{mode}')
        mount.mkdir(exist_ok=True)
        since = len(sh('dmesg').stdout.splitlines())
        attempt = sh('mount', '-t', 'ext4', views['hidden'], mount, check=False)
        result['mount_rc'] = attempt.returncode
        result['mount_stderr'] = attempt.stderr.strip()[-300:]
        if attempt.returncode:
            result['kernel_after_mount'] = kernel_lines(since)
            fsck = sh('e2fsck', '-fn', views['hidden'], check=False)
            result['fsck_n_before_repair_rc'] = fsck.returncode
            fsck = sh('e2fsck', '-fy', views['hidden'], check=False)
            result['fsck_y_rc'] = fsck.returncode
            result['fsck_y_tail'] = fsck.stdout.strip().splitlines()[-6:]
            again = sh('mount', '-t', 'ext4', views['hidden'], mount, check=False)
            result['mount_after_repair_rc'] = again.returncode
            mounted = again.returncode == 0
        else:
            mounted = True
        if mounted:
            result['files_checked'], result['bad_files'] = check_files(mode, mount)
            result['kernel_after_check'] = kernel_lines(since)
            sh('umount', mount)
            fsck = sh('e2fsck', '-fn', views['hidden'], check=False)
            result['fsck_after_mount_rc'] = fsck.returncode
            result['fsck_after_mount_tail'] = fsck.stdout.strip().splitlines()[-6:]
        results['modes'][mode] = result
        close_blocks(source, KEY, name=f'piv-{mode}')
    (W / 'ext4-power-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2), flush=True)
    for mode, result in results['modes'].items():
        assert result['decoy_unchanged'], mode
    ab = results['modes']['ab']
    # A/B keeps the previous version of every interrupted block: no EIO, the
    # journal replays, fsync'ed files survive and the filesystem is clean.
    assert ab['eio_block_count'] == 0 and ab['mount_rc'] == 0, ab
    assert not any(ab['bad_files'].values()) and ab['fsck_after_mount_rc'] == 0, ab


def stock_check():
    """After rmmod: stock read-only cryptsetup authenticates every decoy
    sector of both volumes and returns the pre-cut plaintext."""
    state = json.loads(STATE.read_text())
    sources = half_devices()
    for mode, source in sources.items():
        sh('cryptsetup', 'open', '--readonly', '--key-file', KEY, source, f'piv-stock-{mode}')
        try:
            assert sha256_device(f'/dev/mapper/piv-stock-{mode}') == state['modes'][mode]['decoy_sha256'], mode
        finally:
            sh('cryptsetup', 'close', f'piv-stock-{mode}')
    for mode in MODES:
        dm('remove', f'piv-test-ext4{mode}')


if __name__ == '__main__':
    {'cut': cut, 'recover': recover, 'stock-check': stock_check}[sys.argv[1]]()
