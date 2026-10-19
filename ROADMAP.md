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

Then consider bounded batching to reduce the current 48-primary-sector rewrite
per hidden block or intersecting decoy write. Preserve fresh entropy, whole-block
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
