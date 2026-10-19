"""Failure cleanup keeps ownership boundaries and the original error."""
import errno
import unittest
from unittest.mock import Mock, patch

from pivstore.blocks import open_blocks
from pivstore.kernel_api import remove_mapping


class CleanupTests(unittest.TestCase):
    def test_replaced_mapping_is_not_removed(self):
        with patch('pivstore.kernel_api.mapping_identity', return_value=('253', '5', 'foreign')), \
             patch('pivstore.kernel_api.dm') as dm:
            with self.assertRaisesRegex(ValueError, 'changed mapping'):
                remove_mapping('piv-test', ('253', '4', 'ours'))
            dm.assert_not_called()

    def test_discard_checks_identity_then_drains_private_table(self):
        identity = ('253', '4', 'ours')
        with patch('pivstore.kernel_api.mapping_identity', return_value=identity), \
             patch('pivstore.kernel_api.dm') as dm:
            remove_mapping('piv-test', identity, discard=True)
        self.assertEqual([call.args for call in dm.call_args_list], [
            ('wipe_table', '--noflush', 'piv-test'), ('remove', '--retry', 'piv-test')])
        with patch('pivstore.kernel_api.mapping_identity', return_value=('253', '5', 'foreign')), \
             patch('pivstore.kernel_api.dm') as dm:
            with self.assertRaises(ValueError):
                remove_mapping('piv-test', identity, discard=True)
            dm.assert_not_called()

    def test_abort_is_limited_to_new_private_owner(self):
        from pivstore.kernel_owner import GuestOwner
        owner = GuestOwner.__new__(GuestOwner)
        owner.created = False
        owner.device = Mock()
        with self.assertRaises(ValueError): owner.remove(abort=True)
        owner.device.close.assert_not_called()
        owner.created = True
        owner.name, owner.lower_name = 'piv-test', 'piv-test_dif'
        owner.mappings = {owner.name: ('253', '4', 'ours'), owner.lower_name: ('253', '3', 'lower')}
        with patch('pivstore.kernel_owner.remove_mapping') as remove:
            owner.remove(abort=True)
        self.assertEqual([call.kwargs for call in remove.call_args_list],
                         [{'discard': True}, {'discard': False}])

    def test_setup_unwinds_partial_view_creation(self):
        for fail_at in ('setup', 'first-view', 'second-view'):
            for created_owner in (True, False):
                with self.subTest(fail_at=fail_at, created_owner=created_owner):
                    owner = Mock(created=created_owner, uuid='00000000-0000-0000-0000-000000000000')
                    owner.device.sectors = 96
                    owner.device.sector_size = 4096
                    owner.device.generation = 1
                    mappings = {}
                    error = OSError(errno.EIO, 'injected setup failure')
                    calls = []
                    def dm(*args, **kw):
                        calls.append(args)
                        if args[0] == 'create':
                            mappings[args[1]] = ('253', str(len(mappings)), args[3])
                            if fail_at == ('first-view' if args[1].endswith('decoy') else 'second-view'):
                                raise error  # kernel creation succeeded; subsequent step failed
                    def remove(name, identity):
                        self.assertEqual(mappings[name], identity)
                        del mappings[name]
                    with patch('pivstore.blocks.GuestOwner', return_value=owner), \
                         patch('pivstore.blocks.native_status', return_value={'active': False, 'hidden_bytes': 1024}), \
                         patch('pivstore.blocks.native_setup', side_effect=error if fail_at == 'setup' else None), \
                         patch('pivstore.blocks.mapping_identity', side_effect=lambda name: mappings.get(name)), \
                         patch('pivstore.blocks.remove_mapping', side_effect=remove), \
                         patch('pivstore.blocks.dm', side_effect=dm):
                        if created_owner:
                            with self.assertRaises(OSError) as raised:
                                open_blocks('/dev/vdb', 'private-key-file', bytes(32))
                            self.assertIs(raised.exception, error)
                            owner.remove.assert_called_once()
                        else:
                            with self.assertRaises(FileExistsError):
                                open_blocks('/dev/vdb', 'private-key-file', bytes(32))
                            owner.remove.assert_not_called()
                            owner.device.suspend.assert_not_called()
                    self.assertFalse(mappings)
                    owner.close.assert_called_once()

    def test_keyboard_interrupt_unwinds_created_owner(self):
        owner = Mock(created=True, uuid='00000000-0000-0000-0000-000000000000')
        owner.device.sectors = 96
        owner.device.sector_size = 4096
        error = KeyboardInterrupt()
        with patch('pivstore.blocks.GuestOwner', return_value=owner), \
             patch('pivstore.blocks.native_status', return_value={'active': False}), \
             patch('pivstore.blocks.mapping_identity', return_value=None), \
             patch('pivstore.blocks.native_setup', side_effect=error):
            with self.assertRaises(KeyboardInterrupt) as raised:
                open_blocks('/dev/vdb', 'private-key-file', bytes(32))
        self.assertIs(raised.exception, error)
        owner.remove.assert_called_once_with(abort=True)
        owner.close.assert_called_once()

    def test_cancelled_setup_wipes_ioctl_key_buffer(self):
        from pivstore.blocks import native_setup
        seen = []
        def interrupt(fd, command, data, mutate):
            seen.append(data)
            raise KeyboardInterrupt
        with patch('pivstore.blocks.fcntl.ioctl', side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                native_setup(Mock(fd=7, generation=1), bytes(range(32)), b'test context')
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0], bytes(len(seen[0])))

    def test_cleanup_failure_does_not_mask_storage_error(self):
        owner = Mock(created=True)
        error = OSError(errno.EIO, 'primary failure')
        owner.remove.side_effect = OSError(errno.EBUSY, 'still in use')
        with patch('pivstore.blocks.GuestOwner', return_value=owner), \
             patch('pivstore.blocks.native_status', side_effect=error):
            with self.assertRaises(OSError) as raised:
                open_blocks('/dev/vdb', 'private-key-file', bytes(32))
        self.assertIs(raised.exception, error)
        self.assertIn('cleanup incomplete', error.__notes__[0])
        owner.close.assert_called_once()
