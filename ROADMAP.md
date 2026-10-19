# Implementation roadmap

This plan is provisional. The user's 2026-10-18 decision replaces the external
history/recovery architecture and explicitly drops backwards compatibility.
Earlier milestone detail and experiments remain in Git through b2503e2; they
are historical evidence, not requirements for the current implementation.

## Stateless native storage: implemented and verified

Architecture: one coordinated kernel owner, two writable native block devices,
ordinary stock dm-integrity persistence, no separate history/WAL/partition.
Each 512-byte hidden block is one address-bound authenticated record in 48 IVs.
Fresh salts/encodings replace persistent nonce reservations. Hidden damage is
local EIO; decoy writes preserve an encrypted invalid marker for unavailable
hidden data. Full-block hidden writes repair those records. Initialization is an
explicit destructive reset, not an inferred one-time adoption operation.

Implemented in this working tree:

- Native format/ABI 3, geometry-derived capacity, seeded-CRNG gate, volatile
  counters and per-owner encryption cap; no native file I/O or nonce history.
- Whole-block authentication, invalid-marker writes and decoy/hidden error
  separation; all tuples prepared in RAM then applied through stock integrity.
- Simplified setup and independent v3 decoder; legacy codecs, bootstrap,
  recovery/compaction modules and obsolete state-protocol tests removed.
- AES-GCM and ChaCha20-Poly1305 primary profiles at 512 or 4096 bytes per
  sector, including geometry-aware native I/O, journal/layout parsing, controls
  and independent diagnostics.
- Updated interface/security documentation. Results below distinguish tested behavior from untested guarantees.

Exit criteria (all passed):

1. Userspace codec/error/boundary tests pass against the stock fixture.
2. Matched guest module builds; fresh hidden initialization preserves the entire
   primary; both filesystems work concurrently and survive clean reopen.
3. Wrong-key/uninitialized/damaged hidden blocks do not prevent decoy access;
   invalid markers stay unavailable; full hidden writes repair them.
4. Independent host decoding agrees with kernel output; stock Linux authenticates
   every final primary sector and agrees on its plaintext hash.
5. Both views activate and perform I/O on an actual RAM-root initramfs without
   a persistent root disk mounted or attached.
6. Interrupt a genuinely partial hidden update. After stock journal replay,
   primary remains valid and hidden either authenticates a complete old/new
   block or returns EIO. No recovery-file dependency or silent fragment mixing.

## Next bounded work

After this milestone, address evidence from fault/early-boot experiments first.
Improve failed-setup cleanup of private mappings without touching unrelated
conflicting names. Add direct-I/O lower-device failure coverage for both views under the new
semantics. Confirm teardown/recreation after fail-stop and local hidden repair;
do not import the removed exact-transaction recovery expectations.

Then consider bounded batching to reduce repeated 48-primary-sector rewrites
for adjacent decoy sectors (especially eight 512-byte sectors in a 4096-byte
write), and per-sector read/setup overhead. Each hidden block still needs its
whole carrier group refreshed. Preserve fresh entropy, whole-block
authentication, correct flush/FUA completion and primary integrity. Any new
crash guarantee or in-carrier redundancy is a separate design decision.

Further work: detectability against matched ordinary controls, independent
cryptographic review, debug-kernel/lifecycle stress, explicit budget/rekey tooling,
larger geometry, generic device deployment and boot-time key provisioning. No
production, rollback-resistance or broad deniability claim is authorized by these
tests. A self-contained disk layout does not hide installed software or keys.

## Session handoff: stateless architecture (2026-10-18)

- Host suite: 19 tests passed with ResourceWarning treated as errors and
  PIV_FIXTURE=artifacts/control-003, no skips. Coverage includes each IV-aligned
  torn-record boundary, context/address/key mismatch, invalid-marker rejection,
  all-or-error private extraction and native/CLI imports without site-packages.
- artifacts/stateless-004 built the complete matched experimental module without
  compiler warnings. Source stage stateless-003 and its scaffold archive exactly
  match current kernel/piv-native.inc, piv-control.inc and piv-control.h.
  Pinned guest is Debian 6.12.113+deb13-amd64 / source 6.12.113-1, GCC14.2.0-19,
  cryptsetup2:2.7.5-2. Config/symbol pin checks passed. No full kernel build.
- artifacts/stateless-004 passed both writable filesystems (concurrent ext4 and
  ext2), setup-process exit, clean reopen, stock full-primary readback, absent
  hidden isolation/individual repair, damaged-record EIO/invalid-marker/repair,
  and wrong-hidden-key decoy access. Explicit initialization and all hidden
  updates preserved the complete primary hash before intended decoy FS writes.
  Kernel output independently decoded to all 301,056 expected hidden bytes;
  all 28,244 primary sectors authenticated, current IVs unique. Final primary:
  55ec89235dfd008d9b2e59f469e6f05899bd5b52a0fa1a913710ff22bc7b76a3.
  See host-verification.json and share/result.txt.
- artifacts/stateless-power-003 observed 32/48 changed IVs in current storage or
  a fully committed stock journal section, then SIGKILLed QEMU during delayed
  lower writes. On reboot, ordinary Linux replay left the affected hidden block
  returning EIO, with all other 587 blocks byte-identical. Decoy reads/writes
  still worked; its write kept an encrypted invalid marker unreadable, then a
  direct whole-block hidden write repaired it. Stock Linux and independent host
  checks authenticated all primary sectors with the ORIGINAL fixture hash:
  b54b4937b0a9539574c7525d1634b3052cbb3836ca8d46211bb1cf03e4aaf1c4.
  See cut-boundary.json, power-results.json and host-verification.json. Host page
  cache survived SIGKILL: this is not hardware power-loss evidence.
- artifacts/stateless-early-007 passed with the final module/current Python package on
  ACTUAL initramfs/RAM root, with no persistent OS filesystem attached/mounted.
  The only other disk is a blank 1 MiB enumeration spacer. No 9p share, external
  native state or Python crypto package is present; activation runs with Python
  -S. Full read/write/restore is checked on BOTH views, with independent host
  verification afterward. The clean build and boot inputs came directly from
  stateless-004's corrected guest builder, without manual overlays. Earlier
  early-005/006 also passed, before the internal error-sentinel fix.
- Final review separated the internal positive PN_UNAVAILABLE sentinel from
  negative Linux errors. BLK_STS_MEDIUM maps to -ENODATA and must fail-stop the
  shared owner, whereas hidden record unavailability must remain local. The
  final stateless-004/power-003 runs recheck native/filesystem/crash behavior
  after that fix. No crypto bytes, persistence protocol or external ABI changed.
- Native setup imports no cryptography: shared context is in format.py and
  primary sector crypto loads lazily only for offline verification. The builder
  supplies kmod's dynamically loaded decompression libraries, explicit proc/sys
  directories and required GCM/CTR/GHASH/ChaCha/Poly1305 modules. No full kernel
  build or persistent root dependency was introduced.
- Failed experiments are NOT trusted fixtures: stateless-001 omitted dm-audit.h
  by using the patch-only helper; stateless-002's first test attempted buffered
  repair of an absent block; power-001 watched final metadata but missed committed
  journal tuples. Early-001/003 lacked runtime dependencies, early-002's custom
  PID1 used an unsupported shell EXIT trap (panic before module load), early-004
  lacked proc/sys mount directories. These packaging/test errors drove the
  lightweight bootstrap and complete initramfs crypto-module list.
- No additional host installations, root privileges or host module loading.
  Whole hidden-block crash recovery, rollback
  resistance, strict lifetime nonce uniqueness and arbitrary host-device support
  remain deliberately absent. Targeted repair needs 512-byte DIRECT I/O;
  buffered sub-page writes can fail reading unavailable neighbors first.
- Next: direct-I/O lower-device EIO/fail-stop/recreate tests under the STATELESS
  semantics; preserve local hidden EIO isolation. Then assess bounded batching.

Final validation also passed Python compilation, shell syntax and git diff --check.
No unexpected compiler/kernel warnings, BUG or Oops diagnostics appeared.

## Session handoff: scaffolding cleanup complete

Removed the two obsolete guest-dual-fault/initial shell wrappers whose Python
entrypoints had already been deleted, and retired RO-view cleanup in GuestOwner.
Merged the short kernel architecture/implementation notes into native-blocks.md.
Shared guest guards, packages, build/load and provenance now live in
scripts/guest-common.sh, automatically frozen by vm.py including reboot. The
prebuilt test delegates to the same dual test body rather than maintaining a copy.
Core crypto, disk format, independent verifier and sector-control tests remain.
Ignored artifacts were preserved.

Verification: 19 host tests passed (no skips, ResourceWarning errors enabled),
Python compilation, shell syntax and whitespace checks passed. All three guest
runs exited zero: scaffold-native-001 (prebuilt-module dual filesystems, stock
readback and initramfs build), scaffold-power-001 (32/48 committed-IV VM loss,
reboot/local EIO/repair and stock readback), scaffold-kernel-002 (fresh matched
module build, sector controls, corruption and lifecycle checks). Independent host
primary/hidden verification also passed for the native and power-cut output images.
The first sector run failed when a pending udev probe held the deliberately
key-wiped owner open. The retained test now drains probes from asynchronous
resume before key wipe; all original teardown assertions remain. No driver,
crypto or disk-format changes were made. Next roadmap priorities are unchanged.

## Session handoff: 512-byte primary sectors

The user requested 512-byte primary encryption sectors alongside the existing
4096-byte profile. Hidden logical blocks remain 512 bytes in 48 IVs. LUKS,
integrity superblock, queried owner, native I/O and hidden context must agree on
the primary sector size. Journal parsing now derives the saved-tail count,
entry stride, section size and metadata-run size from that geometry. The
512-byte table omits block_size (stock default) and uses buffer_sectors:128;
4096 uses explicit block_size:4096 and buffer_sectors:32. No disk padding,
external state, IV-length change or new hidden encoding was introduced.

Implementation includes geometry-aware primary crypto/controls, native views,
setup/validation, independent verifier and all shared guest tests. Fixed control
messages retain zero padding to 4096 in RAM only; malformed padding is rejected.
Native setup's former 65,536-sector test cap is now 256 MiB of primary bytes;
the public guest guard remains one disposable 128 MiB disk. A sector-size change
requires a new stock volume, not reinterpretation of existing data.

Stock fixture artifacts/control-512-001 passed full kernel readback and all-sector
independent verification. Its primary capacity is 109,977,600 bytes in 214,800
sectors; hidden capacity is 2,291,200 bytes. The 4096 fixture stays unchanged.
Both fixtures passed all 21 host tests with ResourceWarning errors enabled,
including interleave boundaries, journal header entries, corruption, wrong keys,
truncation and both lower-table profiles. Native tests now exercise changed
512-byte-aligned decoy writes across carrier/metadata boundaries and at the end
of the device, compare surrounding bytes, preserve hidden data and restore with
fresh encryption. The final hidden block is also rewritten/read/restored.

Focused artifacts/sector512-kernel-001 built the matched module and passed
PREPARE/APPLY, primary mutation/restore, zero-padding rejection, independently
checked kernel AES-GCM/AAD, corruption at the interleave boundary, stale handles,
suspend/controller death/key wipe, and stock full-primary readback. Independent
host authentication of all 214,800 final sectors retained the original stock
fixture hash; returned IVs agree with offline raw offsets.

artifacts/sector4096-native-001 passed the expanded dual-filesystem tests and
stock readback using the new module. Independent host verification authenticated
all 28,244 primary sectors and decoded all 301,056 hidden bytes against the guest
oracles, with all current IVs distinct. The new 512-byte stock fixture does not
need a different hidden codec or external state.

artifacts/sector4096-early-001 also passed actual RAM-root activation and
read/write/restore of both views, with no persistent root disk or external
metadata. Independent primary/hidden verification passed afterward.
The first native attempt (sector512-native-001) built successfully but rejected
the lower table because its frozen userspace still required buffer_sectors:32.
The retained validator accepts the observed stock 128 for 512-byte sectors;
sector512-native-002 and the focused test use that correction. The failed run
is not a successful native fixture; its reviewed module build is reused.

artifacts/sector512-power-001 observed 32/48 changed current/committed IVs,
SIGKILLed QEMU, and rebooted the same disk through stock journal replay. The
partially updated hidden block returned EIO; the other 4,474 blocks stayed exact,
decoy data stayed unchanged, invalid-marker preservation passed, and a direct
whole-block write repaired the affected block. Stock readback and independent
host verification afterward authenticated all 214,800 primary sectors and all
2,291,200 hidden bytes with no duplicate CURRENT IVs. This remains VM interruption
with host page cache surviving, not hardware power-loss evidence.

artifacts/sector512-early-001 passed actual RAM-root activation and full
read/write/restore on both devices, using the closed repaired power-test fixture.
No persistent OS filesystem or external metadata was attached. Inputs came from
the unmodified shared builder in sector512-early-build-001; its primary oracle is
the power test's renamed digest. Independent host primary/hidden verification
passed afterward. Both sector sizes retain early-boot support.

artifacts/sector512-native-002 passed the expanded full native suite: original
primary hash after hidden initialization/updates, direct boundary/tail writes
and exact restore, final hidden-block rewrite, uninitialized/damaged/wrong-key
EIO isolation, encrypted invalid markers and targeted repair, concurrent ext4
and ext2, clean reopen and full stock-Linux primary authentication. Independent
host verification authenticated all 214,800 final primary sectors and decoded
all 2,291,200 hidden bytes against the guest oracles; all current IVs were unique.
The new module also passed the equivalent 4096-byte native regression above.

Both profiles passed RAM-root tests. Python compilation, changed-shell syntax
and git diff --check passed. Successful current guest logs contain no unexpected
kernel BUG/Oops/WARNING diagnostics. No additional host installations, host root privileges or
host modules were required. Changes are intentionally uncommitted.

Next priorities remain lower-device EIO/fail-stop/recreate coverage and bounded
batching. The 512-byte profile exposes the current per-sector processing cost:
setup and full logical-volume reads authenticate many more sectors, and an
ordinary 4096-byte decoy write may refresh one group eight times. Tests perform
repeated full-volume comparisons, so allow the documented 3600-second VM timeout.
Capacity/budget tradeoffs are in README; no throughput, hardware crash durability,
strict historical nonce safety or deniability guarantee was added.

## Session handoff: ChaCha20-Poly1305 primary encryption

The user requested ChaCha20-Poly1305 primary support alongside AES-GCM. Accepted
LUKS profiles are aes-gcm-random/integrity aead and chacha20-random/integrity
poly1305, both with 32-byte primary keys, 12-byte IVs, 16-byte tags and 512- or
4096-byte encryption sectors. Kernel registration whitelists the two exact
Crypto API specs; the primary encryption/decryption helpers remain the pinned
dm-crypt implementation. No native ABI, carrier mapping, hidden v3 bytes or
external persistence changes were introduced.

A standard-library-only profile map validates LUKS cipher/integrity pairs and
binds the active owner table to that selection, including reuse. The independent
codec explicitly chooses AESGCM or ChaCha20Poly1305 without a fallback. Inspect
reports the encryption name. The shared stock-fixture generator now has explicit
ChaCha wrappers for both sector sizes; focused kernel tests independently select
the maintained library primitive from the fixture metadata.

Stock chacha-control-4096-001 and chacha-control-512-001 passed Linux readback and
independent whole-primary authentication. Their layouts/capacities match the
same-size AES fixtures. All 24 host tests passed separately against each of the
four ordinary controls, with ResourceWarning errors enabled and no skips. New
coverage rejects mismatched cipher/integrity selections, wrong-cipher decode,
address/key/ciphertext/tag/IV changes and unknown-algorithm fallback. Native
setup still passes the Python -S/no-cryptography dependency check.

artifacts/chacha-aes-kernel-001 built the matched new module and passed the AES
sector/control/lifecycle/corruption suite and stock final primary readback.

artifacts/chacha-kernel-512-001 also built the matched module and passed the
ChaCha sector/control suite, including direct library comparison of prepared
kernel ciphertext/AAD, primary write/restore, padding/corruption rejection,
interleave-boundary reads, controller death, stale handles, key wipe and stock
final readback. Independent host verification authenticated all 214,800 final
primary sectors with the original fixture hash; kernel-returned IVs matched
independent raw offsets. The shared module source and controls work for both
primary algorithms without a separate encryption implementation.

artifacts/chacha-power-4096-001 cut QEMU at 32/48 changed current/committed IVs,
rebooted through stock replay, and passed primary preservation, local hidden EIO
isolation, unchanged other blocks, invalid-marker preservation and targeted
repair. Stock readback and independent host verification authenticated all
28,244 primary sectors and all 301,056 hidden bytes after repair, with distinct
current IVs. This tests the new primary AEAD under VM interruption; hardware
power loss and whole-hidden-record crash recovery remain unclaimed.

artifacts/chacha-native-4096-001 passed the full paired writable-device suite:
uninitialized/damaged/wrong-key isolation and repair, invalid-marker preservation,
changed decoy writes across carrier/metadata boundaries and at the device tail,
hidden preservation/last-block rewrite, concurrent ext4/ext2, clean reopen and
stock full-primary readback. Independent host verification authenticated all
28,244 primary sectors and decoded all 301,056 hidden bytes against guest oracles;
all current IVs were distinct. Hidden updates retained the original decoy hash
before intentional filesystem writes.

artifacts/chacha-early-4096-001 passed actual initramfs/RAM-root activation and
read/write/restore of both devices, with no persistent OS filesystem attached,
no external metadata and Python -S without cryptography. Independent host
primary/hidden verification passed afterward. Existing explicit crypto modules
in the shared initramfs builder were sufficient; no new bootstrap dependency
was needed for the primary ChaCha profile.

artifacts/chacha-native-512-001 passed the equivalent full paired-device suite
at 512-byte primary sectors, including boundary/tail mutations and exact restore,
secret preservation/repair/wrong-key isolation, concurrent ext4/ext2 and clean
reopen. Stock Linux authenticated every final primary sector. Independent host
verification matched all 214,800 primary sectors and 2,291,200 hidden bytes to
the guest oracles, with distinct current IVs. The shared test body and kernel
source were unchanged between the 4096- and 512-byte native runs.

artifacts/chacha-early-512-001 passed the same actual RAM-root activation and
read/write/restore checks at 512-byte primary sectors; independent host
primary/hidden verification passed afterward. Both primary sector sizes now
have full native/filesystem, stock compatibility, independent decoder and
RAM-root evidence for ChaCha20-Poly1305. The new module also retained AES control
compatibility; both AES stock fixtures passed the expanded host suite.

Python compilation, changed-shell syntax and git diff --check passed. Completed
guest runs contain no unexpected kernel BUG/Oops/WARNING diagnostics. No extra
host tools, host root privileges or host module loading were needed. The source
matches the frozen package/module inputs used in the VMs. Changes are left
uncommitted. Next priorities remain direct lower-device EIO/fail-stop/recreate
coverage and bounded batching; no additional crash, nonce-history, rollback,
general-host or deniability guarantee was introduced by cipher support.
