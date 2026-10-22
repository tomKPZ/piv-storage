# Observed stock layout and independent verification

How stock LUKS2 + dm-integrity lay out the supported profiles, as parsed by the
independent read-only decoders (`pivstore/profile.py`, `pivstore/sector.py`) and
validated by pivsetup (`rust/src/profile.rs`). Generated images and random keys
are not committed; reproduce fixtures with docs/development.md
(`scripts/guest-control.sh` via `scripts/suite.py`).

## Provenance

- Guest: pinned Debian 13 cloud image (environment/guest.json), kernel
  6.12.113+deb13-amd64, cryptsetup/libcryptsetup 2:2.7.5-2, run under QEMU.
- Fixtures: 128 MiB `/dev/vdb`, `cryptsetup luksFormat --type luks2 --cipher C
  --integrity I --sector-size S` with a cheap test PBKDF; AEGIS fixtures use a
  16-byte volume key, AES-XTS fixtures a 64-byte XTS key (cryptsetup appends
  the 32-byte HMAC-SHA256 key).
- Upstream functions checked in the source subset pinned by
  environment/sources.json: `crypt_convert_block_aead`, `iv_tag_from_dmreq`,
  `calculate_journal_section_size`, `calculate_device_limits`,
  `get_data_sector`, `get_metadata_sector_and_offset`, `init_journal`,
  `replay_journal`, `dm_integrity_postsuspend`, and cryptsetup's
  `INTEGRITY_tag_size`. Debian patch equivalence has not been established by full
  source comparison; independent kernel readback provides the behavioural check.

Every native/suite output image is verified on the host by
`scripts/check_stateless.py`: full primary authentication (AEGIS-128 via the
pinned SUPERCOP reference, AES-XTS + HMAC-SHA256 with cryptography), hidden
decoding and current-IV uniqueness. This is evidence for the
tested profiles and geometry; it does not establish arbitrary configurations,
hardware crash durability or deniability.

## LUKS and integrity parameters

One LUKS2 dynamic crypt segment at offset 16,777,216 bytes, zero `iv_tweak`,
`<cipher>-random` encryption and the matching integrity type; journal encryption
and journal integrity are none. The dm-integrity superblock begins at the
segment offset: magic `integrt\0`, version 4, log2 interleave sectors 15, flags 8
(fixed padding), log2 sectors per block 3 (4096) or 0 (512). Fields are
little-endian; addressing sectors are 512 bytes unless stated otherwise.

Each primary sector's metadata tuple is `tag ‖ IV16`:

| Profile | Active transform | Tag | Tuple | Primary authentication |
| --- | --- | ---: | ---: | --- |
| `aegis128-random` / `aead` | `capi:aegis128-random` (original AEGIS-128, not AEGIS-128L) | 16 | 32 | AEAD, AAD = `LE64(i·f) ‖ IV` |
| `aes-xts-random` / `hmac-sha256` | dm-crypt `authenc(hmac(sha256),xts(aes))` | 32 | 48 | tag = `HMAC-SHA256(LE64(i·f) ‖ IV ‖ ciphertext)`, IV = XTS tweak |

Here i is the primary encryption-sector index and f = S/512: the address is in
512-byte units even for 4096-byte sectors (using i directly fails
authentication for nonzero i). The authenc volume key is XTS key (32 or 64
bytes) ‖ 32-byte HMAC key. Other XTS ciphers and HMAC digests are refused.

## Geometry formulas

With tuple size T and f = S/512:

```
entry          = round_up(8 + 8·f + T, 8)              journal entry bytes
section        = 8 + 8·f·⌊504 / entry⌋                 sectors per journal section
initial        = 8 + section · journal_sections        superblock + journal
metadata_run   = round_up(T · 32768/f, 4096) / 512     sectors per metadata run
area, within   = divmod(i·f, 32768)
base           = segment_offset + (initial + area·(32768 + metadata_run))·512
ciphertext_at  = base + (metadata_run + within)·512
tuple_at       = base + (within / f)·T
```

These were checked against the pinned dm-integrity source and the stock
fixtures below. Format defaults depend on geometry and versions; the fixtures do
not establish arbitrary-profile support.

## Observed 128 MiB fixtures

Read from the stock fixtures with `python3 -m pivstore inspect`. Hidden bytes are format v4 without
A/B ([format-v4.md](format-v4.md)); A/B halves them.

| Profile | S | Tuple | Journal sections × sectors (entries/section) | Initial | Metadata run | Primary sectors | Hidden bytes |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| AEGIS | 4096 | 32 | 7 × 264 (32) | 1,856 | 256 | 28,216 | 158,720 |
| XTS + HMAC-SHA256 | 4096 | 48 | 7 × 264 (32) | 1,856 | 384 | 28,104 | 158,208 |
| AEGIS | 512 | 32 | 23 × 88 (80) | 2,032 | 2,048 | 213,008 | 1,209,856 |
| XTS + HMAC-SHA256 | 512 | 48 | 32 × 64 (56) | 2,056 | 3,072 | 205,816 | 1,168,896 |

The lower dm-integrity table has `interleave_sectors:32768`, `fix_padding`,
`block_size:4096` (4096-byte profiles only), `journal_sectors` equal to the
journal size above (for example 1,848 and 2,024 for AEGIS),
`journal_watermark:50` and `commit_time:10000` (journaled mode `J`) and a
`buffer_sectors` value dm-integrity chooses itself (a power of two up to 128);
pivsetup accepts exactly these options. A stock `--integrity-no-journal`
volume (direct mode `D`) is refused
([journal-atomicity.md](journal-atomicity.md)).

## Conservative journal handling

There is no generic clean-journal flag to trust. The offline parser checks every
journal sector's trailing commit ID, normalized by section and sector indices,
against the no-crypto upstream commit constants; IDs must agree within each
section, and every journal entry's `sector_hi` must be `0xffffffff` (unused). It
rejects populated, malformed, encrypted, MACed, bitmap, recalculating, inline,
alternative-version and unknown-flag profiles.

This deliberately rejects recoverable journals rather than replaying them: the
offline diagnostics read only cleanly closed images. The kernel's postsuspend
path drains writes and initializes unused journal entries, so closed stock and
native images satisfy these checks. Native activation delegates any replay to
Linux before authenticated access; the module never edits raw storage outside
the lower dm-integrity device, so dm-integrity's journal semantics apply to all
of its writes.
