#!/usr/bin/env python3
"""Fetch verified Debian source archives and stage the small module experiment."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    destination = Path(sys.argv[1]).resolve()
    cache = ROOT / 'downloads/kernel'
    cache.mkdir(parents=True, exist_ok=True)
    for entry in json.loads((ROOT / 'environment/kernel-sources.json').read_text()):
        path = cache / entry['filename']
        if not path.exists():
            temporary = path.with_suffix('.partial')
            with urllib.request.urlopen(entry['url'], timeout=60) as response:
                with temporary.open('wb') as out:
                    shutil.copyfileobj(response, out)
            temporary.replace(path)
        with path.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        if checksum != entry['sha256']:
            raise RuntimeError(f'Checksum mismatch: {path.name}')
    source_name = 'linux-6.12.113/drivers/md/dm-crypt.c'
    with tarfile.open(cache / 'linux_6.12.113.orig.tar.xz') as archive:
        source = archive.extractfile(source_name).read()
        audit = archive.extractfile('linux-6.12.113/drivers/md/dm-audit.h').read()
    if source != (ROOT / 'vendor/dm-crypt-v6.12.113.c').read_bytes():
        raise RuntimeError('Debian orig differs from reviewed dm-crypt')
    # Refuse to silently ignore Debian changes to the two compiled source files.
    with tarfile.open(cache / 'linux_6.12.113-1.debian.tar.xz') as archive:
        for entry in archive:
            if entry.isfile() and '/patches/' in entry.name:
                contents = archive.extractfile(entry).read()
                for name in (b'drivers/md/dm-crypt.c', b'drivers/md/dm-audit.h'):
                    if name in contents:
                        raise RuntimeError(f'Review distro patch before building: {entry.name}')
    subprocess.run([sys.executable, str(ROOT / 'kernel/prepare.py'),
                    str(destination)], check=True)
    (destination / 'dm-audit.h').write_bytes(audit)
    print(f'Staged verified module experiment: {destination}')


if __name__ == '__main__':
    main()
