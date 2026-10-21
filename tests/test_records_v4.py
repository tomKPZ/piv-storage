"""Format v4 reference codec: fragment-local refresh and whole-record authentication."""
import hashlib
import unittest

from pivstore.profile import UnsupportedImage
from pivstore.records_v4 import (DATA, FRAGMENT, GROUP, KEYSLOT_AREA, RANDOM_BYTES, Fragments,
                                 RecordsV4, context)

IDENTITY = context('00000000-0000-4000-8000-000000000000', 128 * 1024 * 1024, 4096)
KEY = bytes(range(32))


class RecordV4Tests(unittest.TestCase):
    def setUp(self):
        self.records = RecordsV4(28244, IDENTITY, KEY)

    def test_geometry(self):
        self.assertEqual((FRAGMENT, GROUP, KEYSLOT_AREA), (6, 90, 112))
        self.assertEqual(self.records.count, (28244 - 112) // 90 - 2)
        self.assertEqual(self.records.first_sector(self.records.group_of(0)), 112 + 2 * 90)

    def test_round_trip_and_fresh_encoding(self):
        data = hashlib.shake_256(b'v4').digest(DATA)
        first, second = self.records.encode(3, data), self.records.encode(3, data)
        self.assertEqual(self.records.decode(3, first), data)
        self.assertEqual(self.records.decode(3, second), data)
        self.assertTrue(all(a != b for a, b in zip(first, second)))

    def test_decoy_refresh_changes_only_touched_iv(self):
        data = bytes([7]) * DATA
        ivs = self.records.encode(5, data)
        start = self.records.first_sector(self.records.group_of(5))
        refreshed = list(ivs)
        for j in (0, 17, 89):
            refreshed[j] = self.records.fragments.refresh(start + j, ivs[j])
            self.assertNotEqual(refreshed[j], ivs[j])
        self.assertEqual(sum(a != b for a, b in zip(ivs, refreshed)), 3)
        self.assertEqual(self.records.decode(5, refreshed), data)

    def test_mixed_versions_and_wrong_key_rejected(self):
        old = self.records.encode(2, bytes(DATA))
        new = self.records.encode(2, bytes([1]) * DATA)
        for cut in (1, 45, 89):
            with self.assertRaises(UnsupportedImage):
                self.records.decode(2, new[:cut] + old[cut:])
        with self.assertRaises(UnsupportedImage):
            RecordsV4(28244, IDENTITY, bytes(32)).decode(2, new)
        # Address binding: a record moved to another index does not authenticate.
        start2 = self.records.first_sector(self.records.group_of(2))
        start4 = self.records.first_sector(self.records.group_of(4))
        frag = self.records.fragments
        moved = [frag.encode(start4 + j, frag.decode(start2 + j, iv)) for j, iv in enumerate(new)]
        with self.assertRaises(UnsupportedImage):
            self.records.decode(4, moved)

    def test_tweak_separation_and_inversion(self):
        frag = Fragments(bytes(32), bytes([1]) * 32)
        value = bytes(RANDOM_BYTES) + b'abcdef'
        self.assertNotEqual(frag.encode(1, value), frag.encode(2, value))
        for sector in (0, 1, 2 ** 40):
            self.assertEqual(frag.decode(sector, frag.encode(sector, value)), value)

    def test_deterministic_vector(self):
        # Fixed randoms make a reproducible vector for kernel cross-checks.
        ivs = self.records.encode(0, bytes(DATA), randoms=[bytes(RANDOM_BYTES)] * GROUP)
        self.assertEqual(self.records.decode(0, ivs), bytes(DATA))
        self.assertEqual(len(set(ivs)), GROUP)


if __name__ == '__main__':
    unittest.main()


class RecordV4ABTests(unittest.TestCase):
    def setUp(self):
        self.records = RecordsV4(28244, IDENTITY, KEY, ab=True)

    def test_geometry_halves_capacity(self):
        self.assertEqual(self.records.count, ((28244 - 112) // 90 - 2) // 2)
        self.assertEqual(self.records.group_of(3, 1), 2 + 7)

    def test_newest_valid_slot_wins_and_torn_slot_falls_back(self):
        old, new = bytes([1]) * DATA, bytes([2]) * DATA
        a = self.records.encode(1, old, generation=1, slot=0)
        b = self.records.encode(1, new, generation=2, slot=1)
        self.assertEqual(self.records.decode(1, a, b), new)
        torn = list(b)
        torn[40] = bytes(16)  # an interrupted write of slot 1
        self.assertEqual(self.records.decode(1, a, torn), old)
        with self.assertRaises(UnsupportedImage):
            self.records.decode(1, [bytes(16)] * GROUP, torn)

    def test_slots_are_not_interchangeable(self):
        a = self.records.encode(1, bytes(DATA), generation=1, slot=0)
        frag = self.records.fragments
        start_a = self.records.first_sector(self.records.group_of(1, 0))
        start_b = self.records.first_sector(self.records.group_of(1, 1))
        moved = [frag.encode(start_b + j, frag.decode(start_a + j, iv)) for j, iv in enumerate(a)]
        with self.assertRaises(UnsupportedImage):
            self.records.decode(1, [bytes(16)] * GROUP, moved)


class ContextTests(unittest.TestCase):
    def test_ab_mode_changes_every_key(self):
        uuid = '00000000-0000-4000-8000-000000000000'
        plain = RecordsV4(28244, context(uuid, 1 << 27, 4096), KEY)
        ab = RecordsV4(28244, context(uuid, 1 << 27, 4096, True), KEY, ab=True)
        ivs = ab.encode(0, bytes(DATA), generation=1, slot=0)
        with self.assertRaises(UnsupportedImage):
            plain.decode(0, ivs)


class KeyslotTests(unittest.TestCase):
    def test_unlock_any_slot_and_replica_and_reject_wrong_kek(self):
        from pivstore.records_v4 import KEYSLOT_AREA, KEYSLOT_SECTORS, Keyslot, unlock
        master, kek = bytes([9]) * 32, bytes([5]) * 32
        ivs = [bytes([i % 251]) * 16 for i in range(KEYSLOT_AREA)]
        slot = Keyslot(IDENTITY, kek, 2)
        for replica in (0, 1):
            first = slot.first_sector(replica)
            ivs[first:first + KEYSLOT_SECTORS] = slot.encode(master, 1, replica)
        self.assertEqual(unlock(ivs, IDENTITY, kek), (2, 1, master))
        # One damaged replica still unlocks through the other.
        ivs[slot.first_sector(0)] = bytes(16)
        self.assertEqual(unlock(ivs, IDENTITY, kek), (2, 1, master))
        with self.assertRaises(UnsupportedImage):
            unlock(ivs, IDENTITY, bytes(32))

    def test_directory_round_trip_and_strict_parsing(self):
        from pivstore.records_v4 import directory_data, parse_directory
        keys = {0: (bytes([1]) * 32, bytes([2]) * 32), 3: (bytes([3]) * 32, bytes([4]) * 32)}
        self.assertEqual(parse_directory(directory_data(keys)), keys)
        bad = bytearray(directory_data(keys)); bad[65] = 2
        with self.assertRaises(UnsupportedImage):
            parse_directory(bytes(bad))
