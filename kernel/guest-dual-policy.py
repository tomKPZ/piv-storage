#!/usr/bin/env python3
"""Reopen an existing native log without bootstrap; refuse lost history/keys."""
import errno
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

from pivstore.blocks import open_blocks, close_blocks, native_status
from pivstore.kernel_owner import GuestOwner

W = Path('/mnt/piv-work')
STATE = Path('/var/tmp/piv-policy/state')
STATE.mkdir(mode=0o700, parents=True)
log = STATE / 'native.log'
shutil.copyfile(W / 'native.log', log); os.chmod(log, 0o600)
(STATE / 'native.phase').write_bytes(b'ready\n')
os.chmod(STATE / 'native.phase', 0o600)
key = (W / 'hidden.key').read_bytes()

def open_key(value=key):
    return open_blocks('/dev/vdb', W / 'passphrase.key', value, state_directory=STATE)

def close():
    close_blocks('/dev/vdb', W / 'passphrase.key')

def validate():
    result = open_key()
    assert result['hidden_bytes'] == 281600
    assert Path(result['hidden']).read_bytes() == (W / 'expected-hidden-volume').read_bytes()
    assert subprocess.check_output(['sha256sum', result['decoy']], text=True).split()[0] == (W / 'expected-primary.sha256').read_text().strip()
    owner = GuestOwner('/dev/vdb', W / 'passphrase.key')
    count = native_status(owner.device)['nonces']; owner.close()
    close()
    return count

before = hashlib.sha256(log.read_bytes()).digest()
count = validate()
wrong = bytes([key[0] ^ 1]) + key[1:]
try:
    open_key(wrong)
except OSError as exc:
    assert exc.errno == errno.EBADMSG
else:
    raise AssertionError('Kernel accepted a wrong hidden key')
assert validate() == count
saved = STATE / 'saved.log'
log.rename(saved)
try:
    open_key()
except ValueError as exc:
    assert 'Missing native history' in str(exc)
else:
    raise AssertionError('Missing native history was reset')
assert not log.exists()
log.touch(mode=0o600)
try:
    open_key()
except ValueError as exc:
    assert 'Missing native history' in str(exc)
else:
    raise AssertionError('Empty native history was reset')
assert log.stat().st_size == 0
log.unlink(); saved.rename(log)
assert validate() == count
assert hashlib.sha256(log.read_bytes()).digest() == before
subprocess.run(['dd', 'if=/dev/vdb', 'of=' + str(W / 'policy-final.img'), 'bs=1M', 'status=none'], check=True)
(W / 'result.txt').write_text('Final setup policy: no bootstrap needed, wrong key and missing/empty history refused, retry/reopen unchanged and no nonce consumption\n')
