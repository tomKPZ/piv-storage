"""Format v5 reference codec: fragment-local refresh, whole-record
authentication, keyslot parameters and Reed–Solomon parity."""
import hashlib
import random
import unittest

from pivstore import rs
from pivstore.format import base_context, layout_context
from pivstore.profile import UnsupportedImage
from pivstore.records import (DATA, DATA_FRAGMENTS, FRAGMENT, KEYSLOT_AREA, KEYSLOT_SECTORS, RANDOM_BYTES,
                              Fragments, Keyslot, Records, block_count, correct_fragments, directory_data,
                              group_sectors, parity_fragments, parse_directory, unlock)

UUID = '00000000-0000-4000-8000-000000000000'
BASE = base_context(UUID, 128 * 1024 * 1024, 4096)
KEY = bytes(range(32))
SECTORS = 28216          # 128 MiB AEGIS-128 fixture, 4096-byte sectors


class GeometryTests(unittest.TestCase):
    def test_constants_and_fixture_capacities(self):
        self.assertEqual((FRAGMENT, DATA_FRAGMENTS, KEYSLOT_AREA, DATA), (6, 687, 112, 4096))
        self.assertEqual([group_sectors(p) for p in (0, 4, 8, 16)], [687, 699, 711, 735])
        # docs/format-v5.md capacity table.
        self.assertEqual(block_count(28216), 38)
        self.assertEqual(block_count(28216, rs_parity=8), 37)
        self.assertEqual(block_count(213008), 307)
        self.assertEqual(block_count(213008, rs_parity=8), 297)
        self.assertEqual(block_count(213008, ab=True), 153)
        self.assertEqual(block_count(112 + 3 * 687), 1)
        self.assertEqual(block_count(112 + 3 * 687 - 1), 0)
        self.assertEqual(block_count(112 + 4 * 687, ab=True), 1)
        self.assertEqual(block_count(112 + 4 * 687 - 1, ab=True), 0)
        with self.assertRaises(ValueError):
            group_sectors(2)

    def test_context_binds_layout(self):
        self.assertTrue(BASE.startswith(b'pivstore/volume/v5\0') and len(BASE) == 19 + 36 + 1 + 16)
        self.assertEqual(layout_context(BASE, True, 12, 8), BASE + b'/layout/\x01\x0c\x08')
        with self.assertRaises(ValueError):
            layout_context(BASE, False, 9, 0)
        with self.assertRaises(ValueError):
            layout_context(BASE, False, 12, 5)


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.records = Records(SECTORS, BASE, KEY)

    def test_geometry(self):
        self.assertEqual(self.records.count, (SECTORS - 112) // 687 - 2)
        self.assertEqual(self.records.first_sector(self.records.group_of(0)), 112 + 2 * 687)
        self.assertEqual(self.records.area_end(), 112 + 687 * (2 + self.records.count))

    def test_round_trip_and_fresh_encoding(self):
        data = hashlib.shake_256(b'v5').digest(DATA)
        first, second = self.records.encode(3, data), self.records.encode(3, data)
        self.assertEqual(len(first), 687)
        self.assertEqual(self.records.decode(3, first), data)
        self.assertEqual(self.records.decode(3, second), data)
        self.assertTrue(all(a != b for a, b in zip(first, second)))

    def test_rejects_wrong_lengths(self):
        with self.assertRaises(ValueError):
            self.records.encode(0, bytes(512))
        with self.assertRaises(UnsupportedImage):
            self.records.decode(0, self.records.encode(0, bytes(DATA))[:-1])

    def test_decoy_refresh_changes_only_touched_iv(self):
        data = bytes([7]) * DATA
        ivs = self.records.encode(5, data)
        start = self.records.first_sector(self.records.group_of(5))
        refreshed = list(ivs)
        for j in (0, 17, 686):
            refreshed[j] = self.records.fragments.refresh(start + j, ivs[j])
            self.assertNotEqual(refreshed[j], ivs[j])
        self.assertEqual(sum(a != b for a, b in zip(ivs, refreshed)), 3)
        self.assertEqual(self.records.decode(5, refreshed), data)

    def test_mixed_versions_wrong_key_and_layout_rejected(self):
        old = self.records.encode(2, bytes(DATA))
        new = self.records.encode(2, bytes([1]) * DATA)
        for cut in (1, 343, 686):
            with self.assertRaises(UnsupportedImage):
                self.records.decode(2, new[:cut] + old[cut:])
        with self.assertRaises(UnsupportedImage):
            Records(SECTORS, BASE, bytes(32)).decode(2, new)
        # Address binding: a record moved to another index does not authenticate.
        start2 = self.records.first_sector(self.records.group_of(2))
        start4 = self.records.first_sector(self.records.group_of(4))
        frag = self.records.fragments
        moved = [frag.encode(start4 + j, frag.decode(start2 + j, iv)) for j, iv in enumerate(new)]
        with self.assertRaises(UnsupportedImage):
            self.records.decode(4, moved)

    def test_nonzero_padding_rejected(self):
        group = self.records.group_of(1)
        first = self.records.first_sector(group)
        payload = bytearray(self.records.seal(group, bytes(DATA), 0))
        payload[-1] = 1
        frag = self.records.fragments
        ivs = [frag.encode(first + j, bytes(RANDOM_BYTES) + bytes(payload[j * 6:j * 6 + 6])) for j in range(687)]
        with self.assertRaises(UnsupportedImage):
            self.records.decode(1, ivs)

    def test_tweak_separation_and_inversion(self):
        frag = Fragments(bytes(32), bytes([1]) * 32)
        value = bytes(RANDOM_BYTES) + b'abcdef'
        self.assertNotEqual(frag.encode(1, value), frag.encode(2, value))
        for sector in (0, 1, 2 ** 40):
            self.assertEqual(frag.decode(sector, frag.encode(sector, value)), value)

    def test_deterministic_vector(self):
        # Fixed randoms make a reproducible vector for kernel cross-checks.
        ivs = self.records.encode(0, bytes(DATA), randoms=[bytes(RANDOM_BYTES)] * 687)
        self.assertEqual(self.records.decode(0, ivs), bytes(DATA))
        self.assertEqual(len(set(ivs)), 687)
        self.assertEqual(hashlib.sha256(b''.join(ivs)).hexdigest()[:16],
                         hashlib.sha256(b''.join(self.records.encode(
                             0, bytes(DATA), randoms=[bytes(RANDOM_BYTES)] * 687))).hexdigest()[:16])


class RecordABTests(unittest.TestCase):
    def setUp(self):
        self.records = Records(SECTORS, BASE, KEY, ab=True)

    def test_geometry_halves_capacity(self):
        self.assertEqual(self.records.count, ((SECTORS - 112) // 687 - 2) // 2)
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
            self.records.decode(1, [bytes(16)] * 687, torn)

    def test_slots_are_not_interchangeable(self):
        a = self.records.encode(1, bytes(DATA), generation=1, slot=0)
        frag = self.records.fragments
        start_a = self.records.first_sector(self.records.group_of(1, 0))
        start_b = self.records.first_sector(self.records.group_of(1, 1))
        moved = [frag.encode(start_b + j, frag.decode(start_a + j, iv)) for j, iv in enumerate(a)]
        with self.assertRaises(UnsupportedImage):
            self.records.decode(1, [bytes(16)] * 687, moved)


class ContextTests(unittest.TestCase):
    def test_layout_changes_every_key(self):
        plain = Records(SECTORS, BASE, KEY)
        for other in (Records(SECTORS, BASE, KEY, ab=True), Records(SECTORS, BASE, KEY, rs_parity=4)):
            self.assertNotEqual(plain.mac_key, other.mac_key)
            self.assertNotEqual(plain.fragments.mask(0), other.fragments.mask(0))
        ab = Records(SECTORS, BASE, KEY, ab=True)
        ivs = ab.encode(0, bytes(DATA), generation=1, slot=0)
        with self.assertRaises(UnsupportedImage):
            plain.decode(0, ivs)


class ParityTests(unittest.TestCase):
    """RS parity (docs/format-v5.md): p unreadable or damaged sectors per lane."""

    def setUp(self):
        self.rng = random.Random(5)

    def record(self, parity, index=1):
        records = Records(213008, base_context(UUID, 213008 * 512, 512), KEY, rs_parity=parity)
        data = self.rng.randbytes(DATA)
        return records, data, records.encode(index, data)

    def test_parity_layout_and_lane_codewords(self):
        records, _data, _ivs = self.record(4)
        payload = records.seal(records.group_of(0), bytes(DATA), 0)
        self.assertEqual(len(payload), 699 * FRAGMENT)
        parity = payload[687 * 6:]
        self.assertEqual(parity, parity_fragments(payload[:687 * 6], 4))
        # Lane 1, byte 2: data fragments 1, 4, ..., then parity at 688, 691, ...
        word = [payload[j * 6 + 2] for j in range(1, 687, 3)] + [payload[(687 + 3 * i + 1) * 6 + 2] for i in range(4)]
        self.assertFalse(any(rs.syndromes(word, 4)))

    def test_erasures_up_to_parity_per_lane_recover(self):
        for parity in (4, 8, 16):
            records, data, ivs = self.record(parity)
            group = records.group
            # p erased sectors in every lane (3p in total), including parity sectors.
            lost = []
            for lane in range(3):
                lost += self.rng.sample([j for j in range(group) if j % 3 == lane], parity)
            damaged = list(ivs)
            for j in lost:
                damaged[j] = self.rng.randbytes(16)
            first = records.first_sector(records.group_of(1))
            self.assertEqual(records.open_group(records.group_of(1), damaged, erasures=lost)[1], data)
            # A burst of 3p consecutive sectors is p per lane.
            burst = list(range(100, 100 + 3 * parity))
            damaged = list(ivs)
            for j in burst:
                damaged[j] = bytes(16)
            self.assertEqual(records.open_group(records.group_of(1), damaged, erasures=burst)[1], data)
            del first

    def test_more_erasures_than_parity_fail(self):
        for parity in (4, 8):
            records, _data, ivs = self.record(parity)
            lost = [3 * i for i in range(parity + 1)]  # p + 1 in lane 0
            damaged = list(ivs)
            for j in lost:
                damaged[j] = self.rng.randbytes(16)
            with self.assertRaises(UnsupportedImage):
                records.open_group(records.group_of(1), damaged, erasures=lost)

    def test_errors_only_correction(self):
        records, data, ivs = self.record(8)
        damaged = list(ivs)
        for j in (0, 3, 6, 9, 1, 4, 7, 10, 2, 5, 8, 11):   # 4 errors per lane, unmarked
            damaged[j] = self.rng.randbytes(16)
        self.assertEqual(records.open_group(records.group_of(1), damaged)[1], data)

    def test_mixed_version_errors_may_recover_new(self):
        records, _old, old_ivs = self.record(16)
        new = self.rng.randbytes(DATA)
        new_ivs = records.encode(1, new)
        # An interrupted rewrite: the last few sectors still carry the old version.
        torn = new_ivs[:-12] + old_ivs[-12:]
        self.assertEqual(records.open_group(records.group_of(1), torn)[1], new)

    def test_never_wrong_data_accepted(self):
        # Far beyond the bound: decoding fails or a miscorrection is rejected by
        # the SIV tag; it never returns other data.
        records, data, ivs = self.record(4)
        for trial in range(20):
            damaged = list(ivs)
            for j in self.rng.sample(range(records.group), 40):
                damaged[j] = self.rng.randbytes(16)
            with self.assertRaises(UnsupportedImage):
                records.open_group(records.group_of(1), damaged)

    def test_strict_mode_checks_stored_parity(self):
        records, data, ivs = self.record(4)
        group = records.group_of(1)
        self.assertEqual(records.open_group(group, ivs, strict=True)[1], data)
        first = records.first_sector(group)
        damaged = list(ivs)
        damaged[690] = records.fragments.refresh(first + 690, ivs[690])   # payload kept: still exact
        self.assertEqual(records.open_group(group, damaged, strict=True)[1], data)
        damaged[690] = bytes(16)
        self.assertEqual(records.open_group(group, damaged)[1], data)
        with self.assertRaises(UnsupportedImage):
            records.open_group(group, damaged, strict=True)

    def test_parity_fragments_without_parity_rejected(self):
        with self.assertRaises(ValueError):
            correct_fragments(bytes(687 * 6), 0)


class RSTests(unittest.TestCase):
    """GF(2^8) RS: 0x11d, fcr 0, alpha 2 (dm-verity FEC parameters)."""

    def test_generator_and_known_vector(self):
        # g(x) = (x + 1)(x + 2)(x + 4)(x + 8) over GF(2^8)/0x11d.
        self.assertEqual(rs.generator(4), [1, 15, 54, 120, 64])
        self.assertEqual(rs.encode([1, 2, 3, 4], 4), rs.encode([1, 2, 3, 4], 4))
        self.assertFalse(any(rs.syndromes([1, 2, 3, 4] + rs.encode([1, 2, 3, 4], 4), 4)))

    def test_correctable_patterns(self):
        rng = random.Random(1)
        for parity in (4, 8, 16):
            for _ in range(60):
                data = [rng.randrange(256) for _ in range(229)]
                word = data + rs.encode(data, parity)
                erasures = rng.randrange(parity + 1)
                errors = rng.randrange((parity - erasures) // 2 + 1)
                positions = rng.sample(range(len(word)), erasures + errors)
                bad = list(word)
                for k in positions:
                    bad[k] ^= rng.randrange(1, 256)
                self.assertEqual(rs.decode(bad, parity, positions[:erasures]), word)

    def test_uncorrectable_raises_or_differs(self):
        rng = random.Random(2)
        data = [rng.randrange(256) for _ in range(229)]
        word = data + rs.encode(data, 16)
        with self.assertRaises(rs.DecodeError):
            rs.decode(word, 16, range(17))
        failures = 0
        for _ in range(50):
            bad = list(word)
            for k in rng.sample(range(len(word)), 9):
                bad[k] ^= rng.randrange(1, 256)
            try:
                self.assertNotEqual(rs.decode(bad, 16), word)
            except rs.DecodeError:
                failures += 1
        self.assertGreater(failures, 40)


class KeyslotTests(unittest.TestCase):
    def test_unlock_any_slot_and_replica_and_reject_wrong_kek(self):
        master, kek = bytes([9]) * 32, bytes([5]) * 32
        ivs = [bytes([i % 251]) * 16 for i in range(KEYSLOT_AREA)]
        slot = Keyslot(BASE, kek, 2)
        for replica in (0, 1):
            first = slot.first_sector(replica)
            ivs[first:first + KEYSLOT_SECTORS] = slot.encode(master, 1, replica, rs_parity=8)
        self.assertEqual(unlock(ivs, BASE, kek), (2, 1, master, 8))
        # One damaged replica still unlocks through the other.
        ivs[slot.first_sector(0)] = bytes(16)
        self.assertEqual(unlock(ivs, BASE, kek), (2, 1, master, 8))
        with self.assertRaises(UnsupportedImage):
            unlock(ivs, BASE, bytes(32))

    def test_keyslot_plaintext_layout_and_strict_parameters(self):
        master, kek = bytes([9]) * 32, bytes([5]) * 32
        plain = Keyslot.plain(master, 1, 16)
        self.assertEqual(plain[:8], bytes([5, 0, 0, 0, 1, 0, 0, 0]))
        self.assertEqual((plain[8:40], plain[40], plain[41], plain[42:]), (master, 12, 16, bytes(22)))
        slot = Keyslot(BASE, kek, 0)
        bad = {'version': b'\x04' + plain[1:], 'flags': plain[:4] + b'\x02' + plain[5:],
               'block': plain[:40] + b'\x09' + plain[41:], 'parity': plain[:41] + b'\x05' + plain[42:],
               'reserved': plain[:63] + b'\x01'}
        for name, value in bad.items():
            ivs = slot.encode(None, 0, 0, plain=value)
            with self.assertRaises(UnsupportedImage, msg=name):
                slot.open(ivs, 0)
        self.assertEqual(slot.open(slot.encode(None, 0, 0, plain=plain), 0), (1, master, 16))

    def test_directory_round_trip_and_strict_parsing(self):
        keys = {0: (bytes([1]) * 32, bytes([2]) * 32), 3: (bytes([3]) * 32, bytes([4]) * 32)}
        data = directory_data(keys)
        self.assertEqual(len(data), DATA)
        self.assertEqual(parse_directory(data), keys)
        bad = bytearray(data); bad[65] = 2
        with self.assertRaises(UnsupportedImage):
            parse_directory(bytes(bad))
        bad = bytearray(data); bad[4095] = 1
        with self.assertRaises(UnsupportedImage):
            parse_directory(bytes(bad))


if __name__ == '__main__':
    unittest.main()
