"""Allow larger synthetic fixtures without broadening the device/guest boundary."""
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pivstore.kernel_owner import guest_guard


class GuestGuardTests(unittest.TestCase):
    def guarded(self, size, source='/dev/vdb', allow_test_stack=False, allow_second_disk=False, *,
                mode=stat.S_IFBLK,
                vendor='QEMU', kernel='6.12.113+deb13-amd64', uid=0, debug_marker=False):
        with patch('pivstore.kernel_owner.os.geteuid', return_value=uid), \
             patch('pivstore.kernel_owner.os.uname', return_value=SimpleNamespace(release=kernel)), \
             patch('pivstore.kernel_owner.Path.read_text', return_value=vendor), \
             patch('pivstore.kernel_owner.Path.exists', return_value=debug_marker), \
             patch('pivstore.kernel_owner.Path.stat', return_value=SimpleNamespace(st_mode=mode)), \
             patch('pivstore.kernel_owner.subprocess.check_output', return_value=str(size)):
            return guest_guard(source, allow_test_stack, allow_second_disk)

    def test_debug_kernel_needs_explicit_image_marker(self):
        size = 128 * 1024 * 1024
        with self.assertRaises(ValueError):
            self.guarded(size, kernel='6.12.113+deb13-amd64-pivdbg')
        self.assertEqual(self.guarded(size, kernel='6.12.113+deb13-amd64-pivdbg', debug_marker=True), size)
        with self.assertRaises(ValueError):
            self.guarded(size, kernel='6.12.113+deb13-amd64-other', debug_marker=True)

    def test_only_explicit_fixture_sizes(self):
        for mib in (128, 512):
            self.assertEqual(self.guarded(mib * 1024 * 1024), mib * 1024 * 1024)
        for size in (0, 128 * 1024 * 1024 + 512, 256 * 1024 * 1024, 1024 * 1024 * 1024):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.guarded(size)

    def test_larger_size_does_not_relax_guest_or_device_identity(self):
        size = 512 * 1024 * 1024
        for fields in ({'source': '/dev/sda'}, {'source': '/dev/vdc'}, {'mode': stat.S_IFREG},
                       {'vendor': 'other'}, {'kernel': 'other'}, {'uid': 1000},
                       {'source': '/dev/mapper/piv-test-fault'}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.guarded(size, **fields)
        self.assertEqual(self.guarded(size, '/dev/mapper/piv-test-fault', True), size)

    def test_second_disk_needs_explicit_opt_in(self):
        size = 512 * 1024 * 1024
        with self.assertRaises(ValueError):
            self.guarded(size, '/dev/vdc', allow_test_stack=True)
        self.assertEqual(self.guarded(size, '/dev/vdc', allow_second_disk=True), size)
        for fields in ({'source': '/dev/vdd'}, {'source': '/dev/sda'}, {'mode': stat.S_IFREG}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.guarded(size, allow_second_disk=True, **{'source': '/dev/vdc', **fields})
