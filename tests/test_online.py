"""Single-owner, atomic publication, restart and local NBD contract tests."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import errno
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import unittest
from unittest import mock

from pivstore.nbd import (MAGIC, OPTION_MAGIC, REPLY_OPTION_MAGIC, REQUEST_MAGIC,
                          REPLY_MAGIC, PrimaryServer, receive)
from pivstore.online import OnlineStore
from pivstore.profile import Image, UnsupportedImage
from tests.test_kernel_fixture import FixtureCase


class OnlineTests(FixtureCase):
    def setUp(self):
        self.current = self.path.with_name(self._testMethodName + '.img')
        shutil.copyfile(self.path, self.current)
        self.hidden = os.urandom(32)

    def store(self, **kwargs):
        return OnlineStore(self.current, self.key, self.hidden, initialize=True, **kwargs)

    def test_buffered_sparse_writes_truncate_and_restart(self):
        with self.store() as store:
            original = store.read_primary(4000, 9000)
            store.write_hidden(4, b'ab')
            store.truncate_hidden(12)
            self.assertEqual(store.read_hidden(0, 100), b'\0' * 4 + b'ab' + b'\0' * 6)
            store.flush()
            self.assertEqual(store.read_primary(4000, 9000), original)
            self.assertEqual(store.encrypted_sectors, store.image.layout.sectors)
            store.truncate_hidden(6)
            store.flush()
        with OnlineStore(self.current, self.key, self.hidden) as store:
            self.assertEqual(store.read_hidden(0, 100), b'\0' * 4 + b'ab')
            self.assertEqual(store.primary_hash, self.expected)

    def test_exclusive_owner_and_image_lock_survive_replacement(self):
        with self.store() as store:
            for committed in (False, True):
                if committed:
                    store.flush()
                with self.assertRaises(BlockingIOError):
                    self.store()
                # Test the lock directly rather than making cryptsetup wait on it.
                import fcntl
                with self.current.open('rb') as stream:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(stream.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)

    def test_capacity_read_bounds_and_primary_write_rejection(self):
        with self.store() as store:
            with self.assertRaises(OSError) as result:
                store.write_primary(0, b'x')
            self.assertEqual(result.exception.errno, errno.EROFS)
            for offset, length in [(-1, 1), (store.primary_bytes, 1), (0, -1)]:
                with self.assertRaises(OSError):
                    store.read_primary(offset, length)
            self.assertEqual(store.read_primary(store.primary_bytes, 0), b'')
            with self.assertRaises(OSError) as result:
                store.write_hidden(store.capacity, b'x')
            self.assertEqual(result.exception.errno, errno.ENOSPC)
            store.write_hidden(0, b'last acknowledged payload')
            store.flush()
            store.write_hidden(0, b'unflushed')
        with OnlineStore(self.current, self.key, self.hidden) as store:
            self.assertEqual(store.read_hidden(0, 100), b'last acknowledged payload')

    def test_session_budget_blocks_encryption_without_touching_image(self):
        with self.store(max_sector_encryptions=1) as store:
            with self.assertRaises(OSError) as result:
                store.flush()
            self.assertEqual(result.exception.errno, errno.EDQUOT)
            self.assertFalse(store.failed)
            self.assertEqual(store.encrypted_sectors, 0)
            self.assertEqual(store.read_primary(0, 4), self._expected_start(4))

    @staticmethod
    def _expected_start(length):
        import hashlib
        return hashlib.shake_256(b'piv-control-v1' + b'\0' * 8).digest(4096)[:length]

    def test_primary_reads_wait_for_commit(self):
        with self.store() as store, ThreadPoolExecutor(max_workers=2) as pool:
            entered = threading.Event()
            release = threading.Event()
            def checkpoint(phase):
                if phase == 'prepared':
                    entered.set()
                    if not release.wait(10):
                        raise TimeoutError('test commit timeout')
            store._checkpoint = checkpoint
            commit = pool.submit(store.flush)
            self.assertTrue(entered.wait(10))
            read = pool.submit(store.read_primary, 0, 4)
            try:
                with self.assertRaises(FutureTimeout):
                    read.result(timeout=0.05)
            finally:
                release.set()
            commit.result(timeout=10)
            self.assertEqual(read.result(timeout=10), self._expected_start(4))

    def test_authentication_failure_stops_both_views(self):
        with self.store() as store:
            with mock.patch.object(store.codec, 'decrypt', side_effect=UnsupportedImage('injected corruption')):
                with self.assertRaises(UnsupportedImage):
                    store.read_primary(0, 4096)
            with self.assertRaises(OSError):
                store.read_hidden(0, 1)
            with self.assertRaises(OSError):
                store.flush()

    def test_failure_after_publication_requires_restart_with_complete_image(self):
        with self.store() as store:
            store.write_hidden(0, b'new complete record')
            def checkpoint(phase):
                if phase == 'published':
                    raise OSError('injected post-publication failure')
            store._checkpoint = checkpoint
            with self.assertRaises(OSError):
                store.flush()
            with self.assertRaises(OSError):
                store.read_primary(0, 1)
        with OnlineStore(self.current, self.key, self.hidden) as store:
            self.assertEqual(store.read_hidden(0, 100), b'new complete record')
            self.assertEqual(store.primary_hash, self.expected)

    def test_process_crash_chooses_complete_canonical_image(self):
        hidden_file = self.current.with_suffix('.key')
        fd = os.open(hidden_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(self.hidden)
        script = '''
import os, signal, sys
from pathlib import Path
from pivstore.online import OnlineStore
with OnlineStore(sys.argv[1], Path(sys.argv[2]).read_bytes(), Path(sys.argv[3]).read_bytes()) as store:
    store.write_hidden(0, b'new')
    store.truncate_hidden(3)
    def checkpoint(phase):
        if phase == sys.argv[4]:
            os.kill(os.getpid(), signal.SIGKILL)
    store._checkpoint = checkpoint
    store.flush()
'''
        for phase in ('prepared', 'published', 'durable'):
            current = self.current.with_name(f'{phase}.img')
            shutil.copyfile(self.path, current)
            with OnlineStore(current, self.key, self.hidden, initialize=True) as store:
                store.write_hidden(0, b'old')
                store.flush()
            result = subprocess.run([sys.executable, '-c', script, str(current),
                                     str(self.fixture / 'share/volume.key'), str(hidden_file), phase],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr.decode(errors='replace'))
            with OnlineStore(current, self.key, self.hidden) as store:
                self.assertEqual(store.read_hidden(0, 100), b'old' if phase == 'prepared' else b'new')
                self.assertEqual(store.primary_hash, self.expected)

    def test_local_nbd_negotiation_reads_and_write_rejection(self):
        with self.store() as store:
            path = self.current.with_suffix('.sock')
            server = PrimaryServer(path, store)
            server.start()
            try:
                with socket.socket(socket.AF_UNIX) as sock:
                    sock.settimeout(10)
                    sock.connect(str(path))
                    self.assertEqual(struct.unpack('>QQH', receive(sock, 18)), (MAGIC, OPTION_MAGIC, 3))
                    sock.sendall(struct.pack('>I', 3))
                    sock.sendall(struct.pack('>QII', OPTION_MAGIC, 8, 0))
                    self.assertEqual(struct.unpack('>QIII', receive(sock, 20)),
                                     (REPLY_OPTION_MAGIC, 8, 0x80000001, 0))
                    payload = struct.pack('>I', 7) + b'primary' + struct.pack('>HH', 1, 3)
                    sock.sendall(struct.pack('>QII', OPTION_MAGIC, 7, len(payload)) + payload)
                    replies = []
                    while True:
                        magic, option, kind, length = struct.unpack('>QIII', receive(sock, 20))
                        self.assertEqual((magic, option), (REPLY_OPTION_MAGIC, 7))
                        data = receive(sock, length)
                        replies.append((kind, data))
                        if kind == 1:
                            break
                    self.assertEqual(replies[0], (3, struct.pack('>HQH', 0, store.primary_bytes, 3)))
                    def request(command, offset, length, payload=b''):
                        sock.sendall(struct.pack('>IHHQQI', REQUEST_MAGIC, 0, command, 42, offset, length) + payload)
                        magic, error, handle = struct.unpack('>IIQ', receive(sock, 16))
                        self.assertEqual((magic, handle), (REPLY_MAGIC, 42))
                        return error
                    self.assertEqual(request(0, 100, 9000), 0)
                    self.assertEqual(receive(sock, 9000), store.read_primary(100, 9000))
                    self.assertEqual(request(1, 0, 3, b'bad'), errno.EPERM)
                    self.assertEqual(request(0, store.primary_bytes, 512), errno.EINVAL)
                    self.assertEqual(request(0, 0, 4), 0)
                    self.assertEqual(receive(sock, 4), self._expected_start(4))
                    store.failed = True
                    self.assertEqual(request(0, 0, 4), errno.EIO)
                    sock.sendall(struct.pack('>IHHQQI', REQUEST_MAGIC, 0, 2, 0, 0, 0))
            finally:
                server.stop()


if __name__ == '__main__':
    unittest.main()
