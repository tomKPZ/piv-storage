# Larger native geometry

The module has no fixed primary size cap. Setup rejects primary-sector counts
above `MAX_LFS_FILESIZE / primary_sector_size`, so the pinned 64-bit kernel's
signed file-offset domain bounds all primary byte arithmetic; the public map
path also checks a sector offset before shifting it into bytes. This is an
arithmetic boundary, not a claim that every size below it is tested or
practical. Activation stays restricted to the pinned QEMU guest's /dev/vdb with
128 or 512 MiB raw disks, plus the explicitly opted-in test wrappers with
identity/table validation. No generic host-device deployment is enabled.

The frontend passes the actual validated raw byte size to the integrity
parser. `vm.py run --blank-mib 512` creates a fresh 512 MiB blank disk; copied
`--data-image` inputs must be regular 128 or 512 MiB files (the two options are
mutually exclusive) and are copied before attaching.

## Bounds and properties

- Primary indices, record indices, capacities and byte offsets are 64-bit.
  Sector counts are checked before multiplying by the sector size.
- Format v5 geometry: 112 keyslot sectors and two G-sector directory groups,
  then one G-sector record per 4096-byte hidden block (G = 687 + 3p), so hidden
  capacity is `(floor((sectors - 112) / G) - 2) * 4096` bytes (half with
  `--ab`). Primary sectors after the last complete record carry no hidden data.
- Range reads stay at most 1024 sectors (4 MiB at 4096-byte sectors); a write
  rewrites at most G sectors (one record, at most 735; 2.9 MiB of RAM at
  4096-byte sectors) or 256 decoy sectors per request, and at most 16 view
  requests (8 initialization records) run at once. The small 32-bit counters describe bounded requests, not whole-volume
  extents.
- Public workers check `offset <= limit` and `bytes <= limit - offset` before
  computing request ends; mapped sector-to-byte conversion is checked first.
  Initialization indices and their products stay below the same bound.
- Primary AEAD/AAD, hidden encoding, ownership, journaling, flush and fail-stop
  rules are independent of volume size; there is no size-specific ABI, cache or
  persistent state.

Kernel per-request memory is bounded independently of volume size. Default
setup scans only the keyslot area, so reopening is constant time; `--verify`
and `--initialize` do work proportional to volume size while holding the setup
lifecycle lock. [Cooperative cancellation](cancellation.md) checks pending
signals between read ranges and complete initialization records; it does not
interrupt stalled lower I/O or roll back records already written. Host
diagnostic image decoding and IV scans use memory proportional to image
geometry and are not a constant-memory large-storage interface.

The per-owner encryption counter is a resetting diagnostic cap at 2^40 (it was
2^32, which a 512-byte-sector initialization reaches around 2 TiB). Full
initialization consumes one encryption per carrier sector (keyslot, directory
and every record), so only an initialization of about 2^40 sectors (512 TiB at
512-byte sectors) could hit the cap after partial changes. Neither a larger disk nor reopening solves per-key
lifetime accounting. There is no claim of unrestricted initialization size,
nonce safety across history or crash recovery.

## Resize, rekey and cipher change

Live resize, grow/shrink, live rekey and live cipher change are out of scope.
Changing an existing volume's UUID or geometry changes the hidden key context,
so there is no in-place conversion either. Offline `pivsetup migrate` copies
both views into a freshly formatted volume of any supported size, profile or
sector size and verifies both.

scripts/probe-stock-reencrypt.sh (run with vm.py, 2026-10-22) checked pinned
cryptsetup 2.7.5 on LUKS2 volumes with an integrity profile (aegis128-random/aead
and aes-xts-random/hmac-sha256, 4096-byte sectors):

- `cryptsetup reencrypt` (online volume-key change, online cipher change and
  offline) refuses: "Reencryption of device with integrity profile is not
  supported."
- `cryptsetup resize` of the active mapping after growing the backing device,
  and an explicit shrink, both refuse with "Unsupported parameters on device";
  the size stays unchanged.

Stock tooling therefore offers no live rekey, cipher change or resize for these
volumes; any live variant would have to be implemented here.

## Large-geometry guest test

scripts/guest-large.sh (default AEGIS-128/4096) and scripts/guest-large-512.sh
(AEGIS-128/512) format a fresh guest-owned 512 MiB blank disk with stock
cryptsetup, write deterministic primary plaintext, generate a synthetic hidden
key and run kernel/guest-large-test.py:

- Full initialization with the exact expected encryption count
  (28 + G + G per record), complete primary hash preservation, and hidden
  writes at block 0, beyond 256 MiB of primary and at the last block.
- Decoy writes/readback/restore across 256 MiB, at high unaligned offsets,
  integrity interleave and record boundaries, the last 16 KiB and sector, and
  the record-free tail; every affected hidden block keeps its plaintext.
- End-of-device reads return EOF without changing the buffer; past-end writes
  fail without marking the owner failed or wrapping to low addresses.
- A high-address lower read error (dm-flakey) and a witnessed ciphertext
  corruption of the last record's last carrier sector: the decoy read of a
  16 KiB request (within one work item) leaves the caller buffer unchanged, the failure is local
  (same owner continues) and complete oracles match after reopening; with only
  data corrupted, the last hidden block still reads correctly (raw IV, SIV
  tag).
- Timed initialization and reopen, custom unload and stock full-primary
  authentication. `large-results.json` records geometry and timings.

Last recorded timings (2026-10-22, KVM, concurrent requests, large-4096-009
and large-512-009): reopen 1.6 s (4096) / 1.6 s (512); initialization 6.9 s /
15.7 s. The host was about 3× slower in that session than for large-*-007
(batched writes, 2.6 s / 3.4 s, reopen 0.33 s / 0.26 s): the previous module
rerun in the same session (large-*-010-oldmodule) took 10.1 s / 27.1 s to
initialize and 2.2 s / 1.7 s to reopen. Format v4 with the per-sector write
path (2026-10-21) took 27.8 s / 168.5 s.

Host tests (tests/test_profile.py) check integrity layout arithmetic above
32-bit byte offsets with synthetic 8 GiB metadata for both sector sizes,
including truncated-extent rejection; this does not mean the module has run on
an 8 GiB disk. Guard tests reject other sizes, non-block paths, other
devices/guests/kernels and unprivileged activation.

This test is not part of suite.py; run it directly (fresh run directories;
generated disks and keys stay in ignored artifacts/):

```sh
python3 scripts/build_pivsetup.py
python3 scripts/vm.py run --code --script scripts/guest-large.sh \
  --blank-mib 512 --run-dir artifacts/large-4096-next \
  --share-file scripts/guest-control.sh \
  --share-file artifacts/stage-next/scaffold.tar \
  --share-file kernel/check-config.py --share-file kernel/guest-large-test.py \
  --share-file rust/target/x86_64-unknown-linux-gnu/release/pivsetup \
  --timeout 1800
python3 scripts/vm.py run --code --script scripts/guest-large-512.sh \
  --blank-mib 512 --run-dir artifacts/large-512-next \
  --share-file scripts/guest-large.sh --share-file scripts/guest-control.sh \
  --share-file artifacts/large-4096-next/share/experimental-dm-piv.ko \
  --share-file kernel/guest-large-test.py \
  --share-file rust/target/x86_64-unknown-linux-gnu/release/pivsetup \
  --timeout 1800
```

Verify each `share/large-final.img` with scripts/check_stateless.py using that
run's `share/volume.key`, `hidden.key`, `expected-primary.sha256` and
`expected-hidden-volume`. Original AEGIS-128 host verification needs the
optional reference library from [development.md](development.md); the module
and pivsetup do not.
