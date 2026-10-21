"""Cleanup boundaries of the test instrumentation and the pivsetup client.

Setup unwinding itself now lives in the Rust pivsetup binary (rust/src/blocks.rs);
it is exercised end to end by the guest fault/cancel suites through explicit
PIVSETUP_TEST_FAIL / PIVSETUP_TEST_GATE hooks.
"""
import errno
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

from pivstore import blocks
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


class ClientTests(unittest.TestCase):
    def test_errors_map_back_to_python_exceptions(self):
        error = blocks.error_from(1, 'pivsetup: [Errno 129] Key was rejected by service\n'
                                     'pivsetup: No hidden record authenticated: wrong hidden key\n')
        self.assertIsInstance(error, OSError)
        self.assertEqual(error.errno, errno.EKEYREJECTED)
        self.assertIn('No hidden record authenticated', error.__notes__[0])
        self.assertIsInstance(blocks.error_from(1, 'pivsetup: [Errno 17] Public view name is already in use'),
                              FileExistsError)
        value = blocks.error_from(1, 'pivsetup: Refusing to remove unrelated view piv-native-hidden')
        self.assertIsInstance(value, ValueError)
        self.assertIn('unrelated view', str(value))
        self.assertIsInstance(blocks.error_from(130, 'pivsetup: [Errno 4] Interrupted'), KeyboardInterrupt)
        self.assertIsInstance(blocks.error_from(1, 'thread panicked'), ValueError)

    def test_open_arguments_never_contain_key_material(self):
        args = blocks.open_args('/dev/vdb', '/w/passphrase.key', '/run/secret', initialize=True, format=4,
                                ab=True, allow_test_stack=True)
        self.assertEqual(args, ['open-blocks', '--device', '/dev/vdb', '--key-file', '/w/passphrase.key',
                                '--name', 'piv-native', '--hidden-key-file', '/run/secret', '--initialize',
                                '--format', '4', '--ab', '--allow-test-stack'])
        self.assertIn('--hidden-passphrase-file', blocks.open_args('/dev/vdb', 'k', 's', passphrase=True))

    def test_secret_file_is_private_and_removed(self):
        real = tempfile.mkstemp
        with tempfile.TemporaryDirectory() as directory, \
             patch('pivstore.blocks.tempfile.mkstemp', side_effect=lambda **kw: real(prefix='s', dir=directory)):
            with blocks.secret_file(b'synthetic') as path:
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                self.assertEqual(Path(path).read_bytes(), b'synthetic')
            self.assertFalse(Path(path).exists())

    def test_passphrase_kek_cross_check_vectors(self):
        # Same vectors as rust/tests/*.hex (Rust/Python KDF parity).
        vectors = Path(__file__).resolve().parents[1] / 'rust/tests'
        self.assertEqual(blocks.passphrase_kek(b'pw', b'ctx', 'scrypt').hex(),
                         (vectors / 'scrypt-pw-ctx.hex').read_text().strip())
        self.assertEqual(blocks.passphrase_kek(b'pw', b'ctx').hex(),
                         (vectors / 'argon2id-pw-ctx.hex').read_text().strip())
        with self.assertRaises(ValueError):
            blocks.passphrase_kek(b'pw', b'ctx', 'pbkdf2')


if __name__ == '__main__':
    unittest.main()
