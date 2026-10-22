"""Activation device checks: no test confinement (any guest, kernel, path or
size), but root, block devices, sane sizes, no partitioned whole disks and
exclusive use are still required (pivstore.kernel_owner mirrors owner.rs)."""
import errno
import os
import stat
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from pivstore import kernel_owner
from pivstore.kernel_owner import check_device, check_unclaimed, has_partitions


class DeviceCheckTests(unittest.TestCase):
    def checked(self, size, source='/dev/vdb', *, mode=stat.S_IFBLK, uid=0, partitions=False):
        with patch('pivstore.kernel_owner.os.geteuid', return_value=uid), \
             patch('pivstore.kernel_owner.Path.stat',
                   return_value=SimpleNamespace(st_mode=mode, st_rdev=os.makedev(252, 16))), \
             patch('pivstore.kernel_owner.has_partitions', return_value=partitions), \
             patch('pivstore.kernel_owner.subprocess.check_output', return_value=str(size)):
            return check_device(source)

    def test_any_device_path_and_size(self):
        for source in ('/dev/vdb', '/dev/vdc', '/dev/sda3', '/dev/nvme0n1p2', '/dev/loop7',
                       '/dev/mapper/piv-test-fault', '/dev/disk/by-partuuid/x'):
            for size in (512, 128 << 20, 300 << 20, 3 << 30, 8 << 40):
                with self.subTest(source=source, size=size):
                    self.assertEqual(self.checked(size, source), size)

    def test_no_guest_or_kernel_confinement(self):
        # The former QEMU vendor / pinned-release checks are gone.
        with patch('pivstore.kernel_owner.os.uname', return_value=SimpleNamespace(release='6.1.0-other')), \
             patch('pivstore.kernel_owner.Path.read_text', return_value='Some Vendor'):
            self.assertEqual(self.checked(1 << 30, '/dev/sdb1'), 1 << 30)

    def test_root_required(self):
        with self.assertRaises(PermissionError):
            self.checked(128 << 20, uid=1000)

    def test_non_block_devices_refused(self):
        for mode in (stat.S_IFREG, stat.S_IFCHR, stat.S_IFDIR, stat.S_IFIFO):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.checked(128 << 20, mode=mode)

    def test_bad_sizes_refused(self):
        for size in (0, 511, (128 << 20) + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.checked(size)

    def test_partitioned_whole_disk_refused(self):
        with self.assertRaisesRegex(ValueError, 'partition'):
            self.checked(1 << 30, '/dev/sda', partitions=True)

    def test_partition_detection_from_sysfs(self):
        with tempfile.TemporaryDirectory() as root:
            disk = Path(root) / 'disk'
            (disk / 'sda1').mkdir(parents=True)
            (disk / 'queue').mkdir()
            part = Path(root) / 'part'
            part.mkdir()
            (part / 'partition').write_text('1\n')
            bare = Path(root) / 'bare'
            (bare / 'queue').mkdir(parents=True)
            real = kernel_owner.Path
            for directory, expected in ((disk, False), (part, False), (bare, False)):
                with self.subTest(directory=directory.name), \
                     patch('pivstore.kernel_owner.Path', lambda _p, d=directory: real(d)):
                    self.assertEqual(has_partitions(os.makedev(8, 0)), expected)
            (disk / 'sda1' / 'partition').write_text('1\n')
            with patch('pivstore.kernel_owner.Path', lambda _p: real(disk)):
                self.assertTrue(has_partitions(os.makedev(8, 0)))

    def test_claimed_device_reports_busy(self):
        with patch('pivstore.kernel_owner.os.open', side_effect=OSError(errno.EBUSY, 'busy')):
            with self.assertRaises(OSError) as caught:
                check_unclaimed('/dev/sdb1')
        self.assertEqual(caught.exception.errno, errno.EBUSY)
        self.assertIn('in use', str(caught.exception))
        with patch('pivstore.kernel_owner.os.open', return_value=99), \
             patch('pivstore.kernel_owner.os.close') as closed:
            check_unclaimed('/dev/sdb1')
        closed.assert_called_once_with(99)


if __name__ == '__main__':
    unittest.main()
