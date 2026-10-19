"""Shared public volume context; no userspace crypto dependency at activation."""
import struct


def context(image):
    return (b'pivstore/volume/v3\0' + image.uuid.encode('ascii') + b'\0' +
            struct.pack('<QQ', image.layout.primary_bytes, image.layout.sector_size))
