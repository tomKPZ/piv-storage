# Larger native geometry

The native module's former 256 MiB primary cap is removed. Setup instead rejects
primary-sector counts exceeding MAX_LFS_FILESIZE / primary_sector_size. The
pinned 64-bit kernel's signed file-offset domain bounds primary byte arithmetic;
the public map path also checks a sector offset before shifting it into bytes.
This is an arithmetic boundary, not a claim that every smaller volume is tested
or practically usable. Activation remains restricted to the pinned QEMU guest,
/dev/vdb and explicitly supported 128 or 512 MiB raw disks. Test wrappers retain
their explicit opt-in and identity/table validation.

The frontend passes the actual validated raw byte size to the integrity parser,
instead of assuming 128 MiB. The VM runner can create a new 512 MiB blank disk
with --blank-mib 512; copied inputs must be regular 128/512 MiB files. It never
attaches the supplied image directly. --blank-mib and --data-image are mutually
exclusive. No generic host-device deployment was enabled.

## Bounds and unchanged properties

- Primary indices, record indices, capacities and byte offsets remain 64-bit.
  Sector counts are checked before multiplying by sector size. Hidden capacity
  is floor(primary_sectors/group)*512 and is smaller than primary capacity.
- A valid record index multiplied by group stays within primary_sectors. Range
  reads remain at most 16 KiB, write preparation at most 96 tuples/two groups.
  The small 32-bit counters describe bounded requests, not whole-volume extents.
- Public workers check offset <= limit and bytes <= limit-offset before computing
  request ends. Mapped sector-to-byte conversion is explicitly checked first.
  Native initialization indices and their products remain below the same bound.
- Full setup authentication and all existing primary AEAD/AAD, hidden encoding,
  ownership, journaling, flush and fail-stop rules are retained. No new ABI,
  record version, cache or persistent state is introduced.

Changing an existing volume's UUID or geometry changes hidden AAD. This milestone
supports larger newly formatted fixtures; it does not implement live resize,
grow/shrink, conversion or migration of an existing hidden volume.

Kernel per-request memory stays bounded independently of volume size. Setup and
initialization still do work proportional to volume size and hold the setup
lifecycle lock. [Cooperative cancellation](cancellation.md) now checks pending
signals between read ranges and complete initialization records. It does not
interrupt a stalled lower I/O or roll back already zeroed records. Diagnostic image decoding/current-IV scans also use memory proportional
to image geometry, and are not a constant-memory large-storage interface.

The 2^32 per-owner encryption cap remains a resetting diagnostic. Full hidden
initialization consumes one encryption per complete carrier sector; sufficiently
large initialization can hit the cap after partial changes. Neither enlarging
the disk nor opening it again solves per-key lifetime accounting. There is no
claim of unrestricted initialization size, nonce safety across history or crash
recovery. Existing hidden data must be extracted before unsupported resizing.

## Verified results (2026-10-19)

| 512 MiB raw fixture | AES-GCM / 4096 | Original AEGIS-128 / 512 |
| --- | ---: | ---: |
| Primary bytes | 512,344,064 | 485,490,688 |
| Primary sectors authenticated | 125,084 | 948,224 |
| Hidden bytes verified | 1,333,760 | 13,485,568 |
| Incomplete carrier-tail sectors | 44 | 20 |
| Activation with full hidden initialization | 93.25 s | 507.53 s |
| Subsequent activation without initialization | 9.83 s | 7.89 s |

Times include activation/frontend work and udev settling. These are concurrent
QEMU TCG test runs, not controlled benchmarks. The larger sector-count fixture's
long initialization motivates cancellable setup, not a performance guarantee.

Runs large-4096-001 and large-512-001 passed:

- Full hidden initialization, complete primary hash preservation and nonzero
  hidden records at low addresses, beyond the old primary cap and at the end.
- Nontrivial direct decoy writes/readback/restore across the old cap, high
  unaligned offsets, integrity interleaves, carrier boundaries and the actual
  incomplete tail. Affected hidden records retain their expected plaintext.
- End-of-device reads return EOF without changing the buffer. Past-end writes
  fail and do not mark the healthy owner failed or wrap to low addresses.
- High-address lower read EIO and a witnessed ciphertext read corruption in the
  last complete carrier. Failed caller buffers remain unchanged; both views
  stay failed after fault removal until teardown/recreation. Complete plaintext
  oracles match after recreation, with no hidden repair required.
- Clean reopen, custom-module unload and stock Linux full-primary authentication.
  Independent host decoding authenticates every primary sector, matches every
  hidden byte and finds distinct current IVs. It does not know nonce history.

large-lifecycle-128-001 additionally passed the existing AES4096 public lifecycle,
concurrent shared-carrier writes, exact flush/FUA ordering, busy mapping/module
protection, new generation, full oracles and stock verification. Independent host
verification passed. All three normal guests kept unrelated stock crypt mounted
and writable. No unexpected kernel BUG/Oops/WARNING or compiler warnings appeared;
unsigned module taint and injected I/O/authentication errors are expected.

Host tests also check layout arithmetic above 4 GiB byte offsets using synthetic
8 GiB metadata across both sector and tuple sizes, including truncated-extent
rejection. This does not mean the module has run on an 8 GiB disk. Guard tests
reject other sizes, non-block paths, other devices/guests/kernels and unprivileged
activation; only the named test wrappers receive the explicit exception.

## Reproduce

Stage/build only for the pinned guest. Generated disks and credentials stay in
ignored private artifacts directories:

```sh
python3 scripts/fetch_kernel.py vendor/kernel-build/large-next
mkdir -p artifacts/large-input-next
tar -cf artifacts/large-input-next/scaffold.tar -C vendor/kernel-build/large-next .
python3 scripts/vm.py run --code --script scripts/guest-large.sh \
  --blank-mib 512 --run-dir artifacts/large-4096-next \
  --share-file scripts/guest-control.sh \
  --share-file artifacts/large-input-next/scaffold.tar \
  --share-file kernel/check-config.py --share-file kernel/guest-large-test.py \
  --timeout 1800
python3 scripts/vm.py run --code --script scripts/guest-large-512.sh \
  --blank-mib 512 --run-dir artifacts/large-512-next \
  --share-file scripts/guest-large.sh --share-file scripts/guest-control.sh \
  --share-file artifacts/large-4096-next/share/experimental-dm-piv.ko \
  --share-file kernel/guest-large-test.py --timeout 1800
```

Each run creates fresh synthetic keys, formats its guest-owned blank disk using
stock cryptsetup defaults and generates deterministic primary plaintext before
native testing. large-final.img and complete expected views/keys are in run/share.
Use scripts/check_stateless.py with that run's share/volume.key, hidden.key,
expected-primary.sha256 and expected-hidden-volume for independent verification.
Original AEGIS host verification needs the optional pinned reference library
from development.md. The module/native frontend does not need that library.

Source stage: vendor/kernel-build/large-001; scaffold:
artifacts/large-input-001/scaffold.tar. Reused module:
artifacts/large-4096-001/share/experimental-dm-piv.ko, SHA-256
0a97560fd0df8a9709619725689eb9baaf128da4fd6cf7e2830387242bc95948.
Config/symbol checks and kernel/header/compiler pins are unchanged. Full reports
are large-results.json and host-verification.json under the named run directories.
