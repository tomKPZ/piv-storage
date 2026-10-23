# Larger native geometry

The module has no fixed primary size cap. Setup rejects primary-sector counts
above `MAX_LFS_FILESIZE / primary_sector_size`, so the pinned 64-bit kernel's
signed file-offset domain bounds all primary byte arithmetic; the public map
path also checks a sector offset before shifting it into bytes. This is an
arithmetic boundary, not a claim that every size below it is tested or
practical. pivsetup accepts block devices of any size (the 128/512 MiB
activation guard was removed on 2026-10-22); the largest tested volumes are
3 GiB at 4096-byte and 8 GiB at 512-byte sectors (below).

The frontend passes the actual validated raw byte size to the integrity
parser. In the harness, `vm.py run --blank-mib 512` creates a fresh 512 MiB
/dev/vdb and `--second-blank-mib N` a sparse /dev/vdc of N MiB (16–16384);
copied `--data-image` inputs must be regular 128 or 512 MiB files (the
harness guard's /dev/vdb sizes) and are copied before attaching.

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
setup scans only the keyslot area, so reopening is constant time; `--verify`,
`--initialize` and `--fill` do work proportional to volume size while holding
the setup lifecycle lock (`--initialize --quick` is constant time).
[Cooperative cancellation](native-faults.md#cancelling-activation-initialization-and-fill-cancel-suite) checks pending signals between
read ranges and rounds of complete initialization or fill records; it does not
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

A one-off probe (scripts/probe-stock-reencrypt.sh, run with vm.py on
2026-10-22; the script was removed after recording this result and remains in
git history) checked pinned
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

The explicit `large` suite of scripts/suite.py (scripts/guest-large.sh) formats
a fresh guest-owned 512 MiB blank disk with the profile under test (or, with
`PIV_LARGE_MIB=N` in the host environment, an N MiB second disk /dev/vdc) with
stock cryptsetup, writes deterministic primary plaintext, generates a synthetic hidden
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
- Timed quick initialization, a fill of every block (counts checked, all
  zeros read back), full initialization, reopen and a fill with nothing to
  write (every block valid), custom unload and stock full-primary
  authentication. `large-results.json` records geometry and timings.

Recorded timings (2026-10-22, KVM): the 512 MiB quick-initialization, fill
and full-initialization times of large-4096-011 and large-512-011, and the
large-*-009 initialization comparison against the previous module, are in
[configuration.md](configuration.md#large-volumes-and-initialization-time).
Not repeated there: reopen took 1.7 s / 1.7 s (4096/512) in -011 and
1.6 s / 1.6 s in -009. The host was about 3× slower in the -009 session than
for large-*-007 (batched writes: initialization 2.6 s / 3.4 s, reopen
0.33 s / 0.26 s); the previous module rerun in that session
(large-*-010-oldmodule) took 2.2 s / 1.7 s to reopen. Format v4 with the
per-sector write path (2026-10-21) took 27.8 s / 168.5 s to initialize.

Host tests (tests/test_profile.py) check integrity layout arithmetic above
32-bit byte offsets with synthetic 8 GiB metadata for both sector sizes,
including truncated-extent rejection; this does not mean the module has run on
an 8 GiB disk. Device-check tests (the Rust unit tests in rust/src/owner.rs:
`any_sector_multiple_size_is_accepted`, `root_is_required`,
`non_block_devices_are_refused`, `claimed_device_reports_busy`,
`partitioned_whole_disks_are_detected`; and the `devices` suite) accept any
size and path but reject non-block paths, partitioned whole disks, busy
devices and unprivileged activation.

Beyond 512 MiB (2026-10-22, KVM, AEGIS-128, `--second-blank-mib`, the
3 GiB and 2 GiB disks on /dev/vdc, all cases above including both high-address
faults; host check_stateless.py on vm.py's `second.img` authenticated every
primary sector and decoded every hidden block):

| Run | Raw | Sector | Primary sectors | Hidden | Quick init | Fill all | Full init | Reopen | Fill none | Host check |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| large-3g-012 | 3 GiB | 4096 | 770,149 | 4.4 MiB | 0.20 s | 5.9 s | 5.3 s | 0.21 s | 1.3 s | 19 s, 141 MB RSS |
| large-2g-512-012 | 2 GiB | 512 | 3,885,080 | 22.1 MiB | 0.20 s | 11.6 s | 8.8 s | 0.22 s | 2.6 s | 80 s |
| large-3g-013 | 3 GiB | 4096 | 770,149 | 4.4 MiB | 0.21 s | 6.9 s | 8.2 s | 0.28 s | 1.8 s | passed |
| suite-123-part3-large-8g | 8 GiB | 512 | 15,187,960 | 86.3 MiB | 0.29 s | 52.7 s | 95.7 s | 0.41 s | 16.4 s | passed |

The -012 runs used pivsetup 32d49336 (before the busy-device checks moved
ahead of the superblock read); large-3g-013 repeated the 3 GiB run with the
final pivsetup 4f5ace03 while a 16-VM suite matrix shared the host (hence the
slower times). suite-123-part3-large-8g (2026-10-23, the `large` suite with
`PIV_LARGE_MIB=8192`, AES-XTS + HMAC-SHA256, 512-byte sectors, all cases above)
is the first run with the real-volume journal size: its integrity dump shows
2,048 journal sections and the table `journal_sectors:131072` (64 MiB). Its
full initialization (95.7 s, about 78 MiB/s of primary data) took longer than
the fill of every block (52.7 s) in the same run; host-cache effects on the
8 GiB sparse image were not separated.

Run it with the native module of a suite matrix (fresh prefix; generated disks
and keys stay in ignored artifacts/):

```sh
python3 scripts/suite.py --prefix artifacts/large-next \
  --control artifacts/suite-016/aegis-512-control \
  --scaffold artifacts/part2-input-002/scaffold.tar --suites large
PIV_LARGE_MIB=3072 python3 scripts/suite.py --prefix artifacts/large-3g-next ...
```

suite.py host-checks the run's `share/large-final.img` (or vm.py's
`second.img` for a second disk) with scripts/check_stateless.py using that
run's own keys and oracles. Original AEGIS-128 host verification needs the
optional reference library from [development.md](development.md); the module
and pivsetup do not.
