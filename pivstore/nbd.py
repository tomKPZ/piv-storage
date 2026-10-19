"""Bounded, local-only fixed-newstyle NBD primary export with simple replies.

Implements EXPORT_NAME, INFO/GO, LIST, ABORT and bounded simple transmission.
Stores opt into write-through WRITE/FLUSH/FUA. Default exports remain read-only;
prohibited writes are drained and rejected even for raw clients.
"""

import errno
import os
from pathlib import Path
import socket
import socketserver
import struct
import threading

from .profile import UnsupportedImage

MAGIC = 0x4E42444D41474943
OPTION_MAGIC = 0x49484156454F5054
REPLY_OPTION_MAGIC = 0x3E889045565A9
REQUEST_MAGIC = 0x25609513
REPLY_MAGIC = 0x67446698
MAX_REQUEST = 1024 * 1024
EXPORT_FLAGS = 3  # Default HAS_FLAGS | READ_ONLY.
WRITABLE_FLAGS = 13  # HAS_FLAGS | SEND_FLUSH | SEND_FUA; all writes durable.


def receive(sock, size):
    result = bytearray()
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data:
            raise EOFError
        result.extend(data)
    return bytes(result)


def option_reply(sock, option, kind, payload=b''):
    sock.sendall(struct.pack('>QIII', REPLY_OPTION_MAGIC, option, kind, len(payload)) + payload)


def session(sock, store):
    export_flags = WRITABLE_FLAGS if getattr(store, 'primary_writable', False) else EXPORT_FLAGS
    sock.sendall(struct.pack('>QQH', MAGIC, OPTION_MAGIC, 3))
    flags, = struct.unpack('>I', receive(sock, 4))
    if flags & ~3 or not flags & 1:
        return
    while True:
        magic, option, length = struct.unpack('>QII', receive(sock, 16))
        if magic != OPTION_MAGIC or length > 4096:
            return
        payload = receive(sock, length)
        if option == 2:  # ABORT
            option_reply(sock, option, 1 if not payload else 0x80000003)
            return
        if option == 1:  # EXPORT_NAME
            if payload not in (b'', b'primary'):
                return
            sock.sendall(struct.pack('>QH', store.primary_bytes, export_flags) +
                         (b'' if flags & 2 else b'\0' * 124))
            break
        if option == 3 and not payload:  # LIST
            option_reply(sock, option, 2, struct.pack('>I', 7) + b'primary')
            option_reply(sock, option, 1)
            continue
        if option in (6, 7):  # INFO / GO
            if len(payload) < 6:
                option_reply(sock, option, 0x80000003)
                continue
            name_length, = struct.unpack_from('>I', payload)
            if name_length > len(payload) - 6:
                option_reply(sock, option, 0x80000003)
                continue
            name = payload[4:4 + name_length]
            count, = struct.unpack_from('>H', payload, 4 + name_length)
            if len(payload) != 6 + name_length + 2 * count:
                option_reply(sock, option, 0x80000003)
                continue
            if name not in (b'', b'primary'):
                option_reply(sock, option, 0x80000006)
                continue
            option_reply(sock, option, 3, struct.pack('>HQH', 0, store.primary_bytes, export_flags))
            # Byte-addressable server; the kernel frontend normally uses 512-byte
            # requests. Minimum 1 avoids imposing an unnegotiated alignment limit.
            option_reply(sock, option, 3, struct.pack('>HIII', 3, 1, 4096, MAX_REQUEST))
            option_reply(sock, option, 1)
            if option == 7:
                break
            continue
        option_reply(sock, option, 0x80000001)  # Unsupported, including structured replies.

    while True:
        magic, request_flags, command, handle, offset, length = struct.unpack(
            '>IHHQQI', receive(sock, 28))
        if magic != REQUEST_MAGIC or length > MAX_REQUEST:
            return
        if command == 2:  # DISC: no reply
            return
        if command == 1:  # WRITE always has a payload, including prohibited writes.
            data = receive(sock, length)
        result = b''
        error = 0
        try:
            if getattr(store, 'primary_writable', False) and command in (1, 3):
                if command == 1:
                    if request_flags & ~1 or not length:
                        error = errno.EINVAL
                    else:
                        store.write_primary(offset, data)  # Write-through, including FUA.
                elif request_flags or length or offset:
                    error = errno.EINVAL
                else:
                    store.flush()
            elif command != 0:
                error = errno.EPERM if command in (1, 4, 6) else errno.EINVAL
            elif request_flags or not length:
                error = errno.EINVAL
            else:
                result = store.read_primary(offset, length)
        except UnsupportedImage:
            error = errno.EIO
        except OSError as exc:
            error = errno.EINVAL if exc.errno == errno.EINVAL else errno.EIO
        sock.sendall(struct.pack('>IIQ', REPLY_MAGIC, error, handle) + (result if not error else b''))


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.connections_lock:
            self.server.connections.add(self.request)
        try:
            session(self.request, self.server.store)
        except (EOFError, ConnectionError, OSError):
            pass
        finally:
            with self.server.connections_lock:
                self.server.connections.discard(self.request)


class PrimaryServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, path, store):
        self.path = Path(path)
        self.store = store
        self.connections = set()
        self.connections_lock = threading.Lock()
        # Never unlink another server's socket; callers choose a private directory.
        super().__init__(str(path), _Handler)
        os.chmod(path, 0o600)
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.thread is not None:
            self.shutdown()
            self.thread.join(timeout=5)
        with self.connections_lock:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.server_close()
        self.path.unlink(missing_ok=True)
