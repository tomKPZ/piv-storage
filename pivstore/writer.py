"""Copy-output sector rewrites. Never modifies the source or replaces a destination."""

import os
from pathlib import Path
import secrets
import tempfile

from .sector import SectorCodec

from .profile import Image, UnsupportedImage


def write_exact(fd, data, offset):
    while data:
        count = os.pwrite(fd, data, offset)
        if count <= 0:
            raise OSError('Short output write')
        offset += count
        data = data[count:]


def randomize_copy(source, output, key, sectors):
    """Experiment: replace selected IVs with independently random fresh values."""
    sectors = sorted(set(sectors))
    if not sectors:
        raise ValueError('Select at least one primary sector')

    def plan(original, used):
        result = {}
        for index in sectors:
            if not 0 <= index < original.layout.sectors:
                raise ValueError('Selected primary sector out of range')
            for _ in range(16):
                iv = secrets.token_bytes(12)
                if iv not in used and iv not in result.values():
                    break
            else:
                raise RuntimeError('Unable to select a fresh IV')
            result[index] = iv
        return result

    return rewrite_copy(source, output, key, plan)


def rewrite_copy(source, output, key, make_plan):
    """Validate all input/output primary data and publish an exclusive copy."""
    with Image(source) as original:
        return rewrite_open_image(original, output, key, make_plan)


def rewrite_open_image(original, output, key, make_plan):
    """Copy a held, locked Image; ownership and closing remain with its caller."""
    codec = SectorCodec(key)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('Output must not exist')
    expected = original.verify(key)
    # This catches current-image collisions only, not historical nonce reuse.
    used = set(original.iv_slots())
    if len(used) != original.layout.sectors:
        raise UnsupportedImage('Repeated current primary IV; refusing to write')
    plan = make_plan(original, used)
    if not plan:
        raise ValueError('Empty update plan')
    for index, iv in plan.items():
        if not 0 <= index < original.layout.sectors or len(iv) != 12:
            raise ValueError('Invalid update plan')
    if len(set(plan.values())) != len(plan) or used.intersection(plan.values()):
        raise ValueError('Update plan repeats a current or replacement primary IV')
    fd, temporary_name = tempfile.mkstemp(prefix='.pivstore-', suffix='.partial',
                                           dir=output.parent)
    temporary = Path(temporary_name)
    try:
        position = 0
        while position < original.size:
            data = original.read(min(1024 * 1024, original.size - position), position)
            write_exact(fd, data, position)
            position += len(data)
        for index, iv in sorted(plan.items()):
            data_offset, tag_offset = original.layout.offsets(index)
            ciphertext = original.read(4096, data_offset)
            metadata = original.read(28, tag_offset)
            plaintext = codec.decrypt(index, ciphertext, metadata)
            encrypted, metadata = codec.encrypt(index, plaintext, iv)
            write_exact(fd, encrypted, data_offset)
            write_exact(fd, metadata, tag_offset)
        with Image(temporary) as candidate:
            if candidate.verify(key) != expected:
                raise UnsupportedImage('Output primary plaintext differs from input')
        original.check_unchanged()
        os.fsync(fd)
        # A same-filesystem hard link atomically publishes without replacing
        # an existing name. Filesystems without hard links are unsupported.
        os.link(temporary, output)
        temporary.unlink()
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(fd)
        temporary.unlink(missing_ok=True)
    return {'primary_sha256': expected, 'rewritten_sector_count': len(plan)}
