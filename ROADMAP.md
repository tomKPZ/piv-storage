# Implementation roadmap

This plan is provisional. The user's 2026-10-18 decision replaces the external
history/recovery architecture and explicitly drops backwards compatibility.
Earlier milestone detail and experiments remain in Git through b2503e2; they
are historical evidence, not requirements for the current implementation.

## Stateless native storage: implemented and verified

Architecture: one coordinated kernel owner, two writable native block devices,
ordinary stock dm-integrity persistence, no separate history/WAL/partition.
Each 512-byte hidden block is one address-bound authenticated record in 48 IVs
for AES/ChaCha or 36 IVs for original AEGIS-128.
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
- AES-GCM, ChaCha20-Poly1305 and original AEGIS-128 primary profiles at 512 or 4096 bytes per
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

## Next bounded work: core module changes first

The user's 2026-10-19 priority change puts work requiring production module
changes ahead of standalone userspace tooling and assessment. Tests and concise
documentation remain part of each core change's exit criteria; this does not
mean postponing validation until after implementation. Known integrity or memory
safety defects take precedence over this ordering whenever discovered.

1. **Larger geometry support — complete.** Native setup now uses reviewed kernel
   file-offset bounds instead of the 256 MiB primary cap. Pinned frontend/fixture
   guards allow only 128 or 512 MiB guest disks. Both sector sizes passed on
   primary volumes above the old cap, including high-address and tail I/O,
   complete primary/hidden verification, stock authentication and preserved
   fail-stop behavior. See docs/large-volumes.md and the final handoff. This does
   not implement live resize or validate arbitrary sizes up to the arithmetic
   bound; memory and I/O remain bounded per request.
2. **Scalable activation and initialization — complete.** Setup yields and polls
   pending signals between authenticated ranges and whole initialization records;
   its owner-lock wait is interruptible. Witnessed cancellation, failed-attempt
   cleanup and healthy reopen passed on both tested volume sizes. Full scanning,
   seeded randomness and exclusive ownership remain mandatory. Completed records
   remain changed; cancellation is not rollback or a hard latency guarantee. See
   docs/cancellation.md and the final handoff for limits and evidence.
3. **Finer error isolation and wrong-key guard — complete (2026-10-20).**
   Failures before the first APPLY are local to the bio; APPLY/flush failures
   still stop the owner. Setup refuses (EKEYREJECTED) when no record
   authenticates unless `--uninitialized` or `--initialize` is given. See the
   handoff below. Group-scoped poisoning was deliberately not added: lower write
   faults already put dm-integrity into its sticky failed state. Original plan:
   - *Error isolation.* Any non-UNAVAILABLE error currently fails the whole
     owner (piv-native.inc). Target policy: primary authentication failure on
     reads or during PREPARE fails only that bio (nothing mutated); only
     APPLY-time or unknown-state lower errors poison state, ideally scoped to
     the affected group. Exit: per-class injection evidence that unaffected
     decoy/hidden I/O continues and poisoned ranges stay EIO until recreation.
   - *Wrong-key guard.* A wrong hidden key makes decoy writes destroy hidden
     data. Until the header (item 5) exists, refuse hidden-aware activation when
     no record authenticates unless an explicit fresh/uninitialized-carrier flag
     is given. The header later provides a fast key check.
   Broader resource/lifecycle hardening (allocation failure, queue bounds,
   teardown concurrency) continues evidence-led alongside, without speculative
   machinery or a large debug kernel built only to manufacture a change.
4. **Standalone target replacing the dm-crypt fork — implemented (2026-10-20);
   newer-kernel port still open.** kernel/dm-piv.c implements the owner target
   and per-sector AEAD (piv_aead) itself; no dm-crypt source is vendored or
   patched. See the handoff below for the matrix evidence. Original plan:
   The current patch is small (about 100 dm-crypt.c lines; the native code uses
   only crypt_convert_block_aead_iv, crypt_convert_init, crypt_integrity_io_alloc,
   req_pool and config fields), but vendoring all of dm-crypt.c forces exact
   source matching and upstream fix tracking. Implement the per-sector AEAD path
   directly with the crypto API and bio integrity payloads over dm-integrity,
   reproducing the stable Linux AAD/IV/tag layout. Exit: existing native,
   fault, lifecycle, power and control suites pass unchanged on the pinned
   guest; stock crypt coexistence retained; cross-checks agree byte-for-byte.
   Then port/test on one newer public distribution kernel series, inside a guest
   only (never the host), to demonstrate build portability.
5. **Format v4 — phases 1-3 implemented (2026-10-20); phase 4 (no-journal)
   open.** Fragments, SIV records, keyslots with directory, passphrase KEKs,
   keyslot add/remove and A/B slots work in the kernel and the independent
   Python decoder (docs/format-v4.md). Initialization still defaults to v3.
   Phase 4 is blocked on a policy decision (docs/journal-atomicity.md).
   Original plan: User decisions
   (2026-10-20) to design together, because they share the record encoding:
   - *Fragment-local re-randomization (the real footprint fix; implement).* A
     decoy write re-randomizes only the IVs it touches plus required
     authentication material, not the whole group. Primarily for 16-byte IVs
     (e.g. ~8 random + ~8 payload bytes per sector). Analyze nonce uniqueness
     per sector, authentication without old/new mixing, capacity and whether
     AES/ChaCha 12-byte IVs remain viable. Attacks the 192-vs-7 footprint,
     nonce-budget use, write throughput and wear together.
   - *Encrypted hidden header (approved).* Indistinguishable from carrier IVs;
     no public magic. Provides fast key check, key wrapping (passphrase change /
     multiple passphrases without rewriting records, KDF salt/params) and format
     version/flags/metadata. No persistent encryption counter (rejected).
     Address header corruption (e.g. replicas) as a single point of failure.
   - *A/B record slots (option, possibly default).* Two slots per hidden block
     with an encrypted generation; reads return the newest valid slot so a torn
     write leaves the previous version readable. Half capacity, double scan reads.
   - *Journal mode.* Support stock `--integrity-no-journal` (removes on-disk
     history; likely default). Before fixing the default, run the concrete
     experiment below, since journal-provided group atomicity could change it.
6. **Journal atomicity — answered from source plus prior power-cut evidence
   (2026-10-20); see docs/journal-atomicity.md.** The journal cannot make a
   carrier group atomic: multi-section commits and reservation splits. Per-block
   atomicity comes from A/B slots. Recommendation: keep journaled default;
   no-journal needs a torn-sector policy decision. Original plan: Determine
   whether a whole carrier group submitted as one bio commits within a single
   dm-integrity journal transaction across power loss. If so, journaled mode
   may give atomic hidden records at no capacity cost, trading against history
   retention. Record evidence before choosing the format v4 journal default.
7. **AEGIS-128 recommended — documentation done; xts/hmac investigated.**
   README leads with AEGIS-128 and v4 requires it. Pinned cryptsetup emits
   `capi:authenc(<auth>,<mode>)-<iv>` for non-AEAD integrity (e.g.
   aes-xts-random + hmac-sha256), and dm-crypt stores random IVs for it, so the
   profile is stock. Supporting it needs 32-byte tags (the UPDATE ABI and tuple
   offsets assume 16) plus authenc key encoding: deferred. Fixture defaults stay
   AES for continuity of existing evidence. Original plan: 128-bit
   IVs make the random-IV birthday term negligible and give more capacity and
   less amplification. Document AES-GCM as the budget-limited option; update
   fixtures/docs/examples to lead with AEGIS-128. Investigate stock
   `aes-xts-random` + `--integrity hmac-sha256` as a further profile (16-byte
   random IVs; IV repetition under XTS reveals equality rather than enabling
   forgery). Unverified; check cryptsetup support and layout first.
8. **Performance — write profiling added (2026-10-20).** guest-v4-test records
   48 random 4 KiB O_DSYNC decoy writes per format: on AEGIS/4096 v3 spent 36
   encryptions per write and v4 exactly 1 (TCG: 2.21 s vs 0.39 s). No further
   write-path change is justified by these numbers yet. Original plan: Current bounded
   authenticated read batching and 16 KiB decoy write batching are complete.
   Add write throughput/latency and wear-amplification profiling (user
   approved) before selecting write-path changes. Concurrency, cross-bio
   coalescing and caches are optional. Preserve authentication, fresh-IV
   coordination, error isolation and flush/completion semantics.

## Work following core implementation

- **Rekey/migration tooling — implemented (2026-10-20):** `pivstore migrate`
  (blocks.migrate) with a second pinned guest disk (`vm.py --second-blank-mib`,
  explicit `/dev/vdc` opt-in) and guest-migrate-test.py: AES v3 to a rekeyed,
  larger AEGIS v4 volume. Per-cipher budget guidance is still to write. Original
  plan: Offline copy into a freshly
  formatted volume: format the target (new primary key, chosen cipher, sector
  size and size), activate both paired stacks, copy decoy and hidden contents
  through their views, verify both independently (primary verification and
  hidden unpack hashes), then let the user retire the source. This one workflow
  provides primary rekey, cipher change and **offline resize** (hidden AAD binds
  geometry, so live resize stays unsupported). Tests need a second pinned guest
  disk; extend fixture guards only explicitly. Hidden-key change becomes a
  header rewrap once format v4 exists. Publish per-cipher lifetime-budget
  guidance; no on-disk ledger or online rekey.
- **Hidden-key KDF — implemented for v4 keyslots:** stdlib scrypt (N=2^17,
  r=8, p=1, salt = base context || "/kek") via `--hidden-passphrase-file`;
  Argon2id awaits the Rust port. Original plan: Argon2id (or stdlib scrypt meanwhile) from a passphrase in
  userspace setup. Before the header exists, use the LUKS UUID as salt with
  fixed or user-supplied parameters; the header then stores a random salt and
  parameters for wrapped keys.
- **Userspace setup port to Rust.** Zeroizing/mlocked key buffers, Argon2id and
  a static initramfs binary. Changes the current Python-standard-library setup
  rule; retain the independent Python diagnostics as a cross-check.
- Security/test expansion: active on-disk metadata/journal negative fixtures,
  broader interruption and scheduling/storage coverage, and a refreshed full
  profile matrix. Targeted versions move forward whenever a core change needs them.
- Independent cryptographic review of the whole encoding (including format v4)
  and per-cipher usage policy; findings override implementation order.
- General device deployment, packaging/signing, boot-time key provisioning and
  documentation consolidation. Actual RAM-root activation is already verified;
  production boot integration and unrestricted host deployment are not.

Out of scope (user, 2026-10-20): multi-snapshot observers, rollback resistance
(requires trusted external state) and coercion-resistant alternative hidden
openings (they only move the coercion to the next key).

Current evidence and limits remain in docs/security-review.md,
docs/read-performance.md, docs/detectability.md and the handoffs below. Broader
crash recovery, in-carrier redundancy, rollback resistance and deniability against
snapshot/workload observers remain outside the current scope. Neither this
priority change nor a larger volume authorizes stronger security/storage claims.

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


## Session handoff: original AEGIS-128

Standing user authorization: commit each completed verified update automatically;
do not push/publish without a separate request. ChaCha20-Poly1305 support was
committed as 8b83aef before this work began.

AEGIS-128 uses the ordinary aegis128-random/aead profile with a 16-byte key,
16-byte IV and 16-byte tag, at both primary sector sizes. The 576-byte v3 hidden
record is unchanged; group size is derived as 576/IV_bytes (36 for AEGIS, 48 for
AES/ChaCha). No external persistence or disk padding. Primary control ABI 2 widens
IV fields to 16 bytes and tuples to 4128, rejects nonzero unused padding and old
ABI requests. Native SETUP/STATUS remain ABI 3. Lower-table/journal/offset parsing
checks tuple-specific geometry against LUKS and the queried owner.

The optional independent SUPERCOP AES-NI diagnostic library is source/SHA pinned;
it is separate from the maintained Linux primary data path, stdlib-only setup
and hidden-record decoder. Do not substitute AEGIS-128L or treat the historical
reference as production crypto. See docs/development.md for its explicit build
and trusted library-path input. No new host installs/root/modules were required.

Stock aegis-control-4096-001 and aegis-control-512-001 passed full stock readback
and independent reference authentication. All 27 host tests passed separately
against all six stock profiles, no skips and ResourceWarning errors enabled.
Coverage includes both IV widths' torn-record boundaries, primary authentication,
geometry, CLI extraction/output counts, corruption and unsupported configurations.
Final review corrected inspect/extract-ivs counts that still assumed 12-byte IVs;
actual extraction was already geometry-aware. Native bootstrap dependency checks
still pass without site-packages.

Focused aegis-kernel-4096-001 and aegis-kernel-512-001 built the matched module
and passed PREPARE/APPLY, independent primary crypto/AAD comparison, primary
write/restore, padding/corruption rejection, lifecycle and stock final readback.
Independent host checks authenticated every final sector and matched kernel IVs
to raw offsets. Original AEGIS primary hashes:

- 4096: a9944fe4990d72988f91464b92ddb4ea25e80010bfdbcf27ec0d108c2921f199
- 512: 55ea5706557fe00c72c628e4480bfcc41f307eac5c755a143d432072dafa6029

artifacts/aegis-native-4096-001 and aegis-native-512-001 passed the full paired
writable-device/filesystem suite: absent/damaged/wrong-key isolation, encrypted
invalid markers and repair, actual boundary/tail mutations and restore, hidden
preservation/last-block rewrite, concurrent ext4/ext2, clean reopen and stock
full-primary readback. Independent host verification matched all 28,216 primary
sectors / 400,896 hidden bytes (4096) and 213,008 sectors / 3,028,992 hidden bytes
(512) against guest oracles; current IVs were distinct. Final primary hashes:

- 4096: 589e7dea3e01dffd206d19f84bc9451e868e3e19e5e5ab42a4e1daa312c21230
- 512: e42c7683a69cdfcf4bbf0fbca32de0f9bd6c15e950aaf2d79a714cc60054019a

artifacts/aegis-power-4096-001 observed 32/36 changed current/committed IVs before
SIGKILL. Stock replay preserved the original primary hash and all 782 other
hidden blocks; the affected block returned local EIO. Invalid-marker preservation
and repair passed. Stock and independent final primary/hidden verification passed
with distinct current IVs. Host page cache survived; no hardware power-loss,
whole-hidden-record recovery or rollback claim is added.

artifacts/aegis-aes-kernel-001 passed AES control regression, including nonzero
unused IV/expected-IV padding rejection. Stock/independent final readback retained
the original AES hash. aegis-aes-native-001 also passed the full paired-device
regression; independent host verification matched all 28,244 primary sectors and
301,056 hidden bytes to guest oracles, with distinct current IVs.

artifacts/aegis-early-4096-001 and aegis-early-512-001 passed actual RAM-root
activation and read/write/restore of both devices without persistent OS storage,
external metadata or a Python crypto package. Independent final primary/hidden
verification passed for both boot images, matching the native oracles with
distinct current IVs. Both sector sizes retain early-boot support.

Kernel stage vendor/kernel-build/aegis-001 and complete scaffold
artifacts/aegis-input-001/scaffold.tar exactly match current kernel files. Guest
is still pinned Debian 6.12.113+deb13-amd64 / source 6.12.113-1 / cryptsetup
2:2.7.5-2, with matching config/symbol checks. VM packages are frozen; later
changes affect only reporting, comments/indentation and an unused constant,
not executed native paths. Both initramfs builds include aegis128 explicitly.

Next priorities remain direct lower-device EIO/fail-stop/recreate coverage and
bounded batching. Cipher support adds no general-host, historical nonce-safety,
crash recovery or deniability guarantee. The long 512-byte suite still exposes
per-sector/full-volume setup and repeated carrier-refresh costs under QEMU TCG.

Python compilation, changed-shell syntax and git diff --check passed. Successful
guest logs contained no unexpected compiler warnings or kernel BUG/Oops/WARNING
diagnostics. All requested AEGIS-128 implementation and verification work is
complete; commit this update under the standing user authorization.


## Session handoff: separate renamed target

User selected coexistence with stock dm-crypt while retaining the private source
fork. Kbuild produces dm-piv.ko (kernel name dm_piv), registering piv-crypt and
piv-view with aliases dm-piv-crypt/dm-piv-view. Stock crypt stays untouched and
can remain mounted and busy. Module metadata lists only dm-mod as a dependency.
Private queues use kpiv_io/kpiv_crypt; the write thread uses piv_write and logs
use piv-crypt. No private symbols are exported to or imported from stock crypt.

Setup still unlocks with stock cryptsetup and delegates journal replay to Linux.
It then suspends the newly created private owner and reloads its table as
piv-crypt with piv_control. Reuse/validation require piv-crypt. Teardown uses
explicit DM removal because stock cryptsetup does not manage the custom target.
Public device names and all cipher profiles, crypto, control ABI and disk format
remain unchanged. Existing mounted stock volumes are not adopted or converted.
The setup guard still restricts activation to the pinned disposable QEMU disk.

Shared guest tests create an independent disposable stock-encrypted ext4 on a
guest-root-backed loop file before loading dm-piv. That stock volume remains
mounted/writable after custom-module teardown; loaded-targets.txt and
coexistence-result.txt record coexistence. No tests unload stock dm-crypt.
This sentinel is test data, never runtime metadata or an external-state dependency.

Initial separate-001 ordinary/control/native/power runs passed, but
separate-early-512-001 caught a real first-owner namespace bug: both modules' ID
allocators started at 1, producing the same kcryptd_io-253:1-1 sysfs name while
old/new tables coexisted during reload. Sysfs rejected the new queue. The final
separate-002 stage fixes queue/thread names; initial001 is not the release module.
Retain the actual first-owner RAM-root regression: earlier stock mappings can
advance IDs and mask this collision. No crypto or persistence change was needed.

Verified with corrected stage002:

- All 27 host tests passed separately against AES4096 and AEGIS512 stock fixtures,
  with ResourceWarning errors and no skips. Other codecs/formats are unchanged.
- artifacts/separate-kernel-512-002 built the matched module and passed the full
  AEGIS512 control/corruption/lifecycle suite, primary mutation/restore and stock
  full-primary readback. Independent host checks authenticated all 213,008 final
  sectors with the original hash and matched raw IV offsets. Stock crypt remained
  mounted/writable throughout load and unload.
- separate-native-4096-002 passed paired native read/write, carrier/metadata/tail
  mutations and restore, hidden preservation/repair/invalid markers/wrong-key
  isolation, concurrent ext4/ext2, clean reopen and stock final readback. Independent
  host decoding matched all 28,244 primary sectors and all 301,056 hidden bytes to
  guest oracles, with distinct current IVs. Final primary hash:
  e745a517d7eef8d46faa53fcdb9e732c0fe3da40e66e2bc228797eb40251065c.
  The unrelated stock encrypted filesystem stayed mounted and writable.
- separate-power-4096-002 cut at 32/36 AEGIS changed current/committed IVs. Stock
  replay preserved the primary and other hidden blocks; local EIO, invalid-marker
  preservation and repair passed. Stock and independent primary/hidden verification
  passed, and stock crypt stayed busy across custom load/unload on both boots.
  This is VM interruption with surviving host cache, not hardware power loss.

Corrected actual RAM-root boots passed as separate-early-512-002 (built in
separate-early-build-512-002 from the prior closed AEGIS512 fixture) and
separate-early-4096-002 (from the corrected AES native test). They loaded both
modules, required the owner target piv-crypt, tested both writable devices and
unloaded only dm_piv, leaving stock dm-crypt present. Independent final primary/
hidden verification matched both complete guest oracles, with distinct current
IVs. The first-owner collision regression passes without the original sysfs
error or kernel stack dump. Neither boot used a persistent OS filesystem.

The complete matched source stage is vendor/kernel-build/separate-002 and its
scaffold is artifacts/separate-input-002/scaffold.tar. Kernel/headers/config/symbol
pins remain unchanged. Source comparison confirms the private dm-crypt C differs
from the previous implementation only in target, workqueue/thread/log names and
module metadata; primary helpers/native records/control definitions are unchanged.
No host installs, host modules, host root or real-device access were used.

Next priorities remain lower-device EIO/fail-stop/recreate coverage, failed-setup
cleanup and bounded batching. Separation does not provide a stable cross-kernel
module ABI, upstream maintenance, generic deployment or new deniability/crash
claims. Commit completed updates under the user's standing authorization.

Python compilation, changed-shell syntax and git diff --check passed. A fresh
patch-only stage reproduced every tested source byte (the complete build stage
also supplies dm-audit.h). Corrected guest logs have no unexpected compiler or
kernel BUG/Oops/WARNING/kobject diagnostics. Separation is implemented and tested.


## Session handoff: failure handling and cleanup

Frontend exception cleanup now captures actual created mapping identities, even
when cryptsetup or public-view creation reports an error after kernel creation.
Public views receive volatile unique DM UUIDs. Cleanup removes only this attempt's
resources, preserves the original exception and reports cleanup failures as notes.
It skips an extra native checkpoint; stock lower teardown can still flush journal
state. Close validates BOTH public bindings before removing either, supports idle
owners, and refuses unrelated replacements. Open preserves existing idle/active
owners. No kernel, crypto, on-disk format or ABI change was necessary.

New scripts/guest-faults.sh and kernel/guest-fault-test.py use pinned dm-flakey
below dm-integrity. Coverage includes four conflicting setup names, post-cryptsetup
failure, before/during/after native setup, failures after each public creation,
existing owners and unrelated replacement at close. All four lower read/write
fault combinations exercise direct public I/O, sticky shared fail-stop after
restoring storage, teardown/recreation, full-primary and hidden verification.
Only the affected hidden block may require direct repair. Separate tests confirm
local hidden EIO, invalid-marker preservation and repair without global failure.
Final stock authentication and custom-module unload check compatibility/leaks;
an unrelated stock encrypted filesystem stays mounted and writable throughout.

Host suite: 30 tests passed without skips on AES4096 and AEGIS512, with
ResourceWarning errors enabled. New tests cover changed identities, partial view
creation and preservation of original errors when cleanup fails. Python compilation,
changed-shell syntax and git diff --check passed. Source pin now includes the
Linux 6.12.113 dm-flakey error feature definitions.

Executed AES4096 faults-4096-004 passed all cases. Read faults spent zero primary
encryptions; write faults spent 48 each. No hidden repairs were needed in these
four injected failures. Independent final verification authenticated all 28,244
primary sectors and matched all 301,056 hidden bytes; current IVs were distinct.
Primary hash: e745a517d7eef8d46faa53fcdb9e732c0fe3da40e66e2bc228797eb40251065c.
cleanup-early-build-001 packaged current stdlib-only setup; cleanup-early-001
passed actual RAM-root activation, both writable views and teardown/custom unload.
Independent full primary/hidden verification matched the same input oracles.
Neither early boot required a persistent OS disk.

AEGIS512 faults-512-002 also passed all setup, ownership, four lower-I/O and
local-repair cases. Read faults spent zero encryptions; each write fault spent
36. No hidden repairs were needed after the four storage faults. Independent
verification authenticated all 213,008 primary sectors and matched all 3,028,992
hidden bytes, with distinct current IVs. Primary hash:
e42c7683a69cdfcf4bbf0fbca32de0f9bd6c15e950aaf2d79a714cc60054019a.
Both final fault runs preserved the mounted writable stock encrypted sentinel
and unloaded dm_piv successfully. Final fault/early logs contained no unexpected
BUG/Oops/WARNING diagnostics. Expected injected EIO/journal errors and unsigned
out-of-tree module taint messages are not treated as unexpected failures.
This fault matrix covers AES4096 and AEGIS512, not every supported cipher/geometry.

Test development: faults-4096-001 exposed a missing test restore default;
faults-4096-002 raced a udev probe during manual foreign-view replacement. Retained
tests drain udev and retry removals. faults-4096-003 demonstrated that direct
sector 0 reads can be served from dm-integrity's cached setup checkpoint despite
a lower read fault. A lower fault alone is not an observed owner I/O error.
Final tests select cold carrier record 10, witness the raw read fault and require
failed writes to spend fresh encryptions. Obsolete faults-512-001 was stopped.
These failed/obsolete runs are not successful fixtures.

Remaining limits: cleanup is best effort under busy mappings, process death or
privileged external races; it is not rollback or atomic initialization. Tests
restore the fault source before teardown/recreation. Failures during a healthy
close checkpoint may require a close retry after fixing storage. This is injected
EIO coverage, not hardware power-loss/durability proof or hidden crash recovery.
Next: bounded batching/per-sector overhead, then broader lifecycle/debug-kernel
stress and matched-control detectability work. No host installs/modules, root or
real-device operations were used. Module/source pins remain separate-002.


## Session handoff: bounded decoy batching (2026-10-19)

Decoy bios now split at 16 KiB power-of-two boundaries, hidden bios remain 512
bytes. Each affected carrier group refreshes once per work item, using the
existing two-group/96-tuple preparation bound. Larger decoy reads use the same
bound and copy into the caller's bio only after authentication of the entire
work item. No cross-bio accumulation, delayed completion, new disk format, key
handling or ABI is introduced. Separate small writes can still repeat work.
WRITE|PREFLUSH explicitly drains the lower journal before the payload; ordered
work and the existing per-32-sector/final flushes preserve completion semantics.
A larger batch is not an atomic write and may damage either touched hidden
record if interrupted. Primary bytes outside the request must stay unchanged.

Source stage: vendor/kernel-build/batch-001; complete scaffold:
artifacts/batch-input-001/scaffold.tar. All three matched guest builds passed pinned
config/symbol checks without compiler warnings. Kernel/header/source/package
pins remain unchanged; the only runtime source change is kernel/piv-native.inc.
The reusable module is batch-native-4096-001/share/experimental-dm-piv.ko.
Current includes exactly match the staged/tested bytes. No host root, modules,
installations, full kernel build or real-device access was used.

New guest-batch-test/guest-batch measure direct O_DSYNC write/fsync counts and
timing, nontrivial write/read/restore, 4/16/32k, unaligned primary/batch/carrier
boundaries and incomplete tails. Complete primary/hidden checks, reopen, stock
readback and custom unload follow. Previous-module baselines (kernel unchanged
through 4f5ef60) and new outputs independently verify against the same oracles.

| Profile / request at offset 0 | Old encryptions | New encryptions |
| --- | ---: | ---: |
| AES4096 /4k |48|48|
| AES4096 /16k |192|48|
| AES4096 /32k |384|96|
| AEGIS512 /4k |288|36|
| AEGIS512 /16k |1152|36|
| AEGIS512 /32k |2304|108|

Executed benchmark runs: batch-baseline-4096-001, batch-baseline-512-001,
batch-native-4096-001, batch-native-512-001, batch-chacha-512-001. All passed.
The ChaCha512 carrier-boundary case reaches the full 96-tuple/two 48-sector bound;
AES4096 group alignment and AEGIS512's 36-sector groups cannot reach that in one
split. AEGIS32k uses 108 because its two 16k splits overlap 18k carrier groups.
AES16k measured 134ms old vs 40ms new; AEGIS16k 14ms new. Single QEMU TCG samples
with concurrent guests are diagnostic, not controlled throughput guarantees.
Each final image authenticated every primary sector, matched the complete hidden
oracle and had distinct current IVs. This does not establish lifetime uniqueness.

Regression results:
- Host 30 tests passed on AES4096 without skips (ResourceWarning errors, optional original
  AEGIS reference enabled). Compilation, changed-shell syntax and whitespace pass.
- batch-faults-4096-001 passed setup cleanup/foreign-name protection, 16k direct
  decoy and 512 hidden lower read/write errors, sticky shared failure after
  restoration, teardown/recreation, local hidden EIO/invalid-marker/direct repair,
  complete oracles, stock authentication and custom unload. Independent verification
  passed. Updated tests allow unavailable blocks only in the touched carrier range.
- batch-power-4096-001 cut at 32/48 changed committed/current IVs during the existing
  hidden-write interruption. Stock replay preserved the primary; the affected
  hidden block returned EIO, all other blocks matched, invalid-marker preservation
  and repair passed. Independent full verification passed. Host cache survived;
  this is not hardware power loss or new decoy-batch crash-atomicity evidence.
- batch-filesystems-4096-001 passed concurrent ext4/ext2, RMW, hidden preservation,
  setup exit, reopen, wrong-key/invalid-marker/repair and stock readback. Independent
  verification matched all 28,244 primary sectors and 301,056 hidden bytes. Its
  initramfs passed actual RAM-root boot as batch-early-4096-001: both writable
  views, standard-library-only setup, no persistent OS disk and custom unload.
  Independent full primary/hidden verification matched afterward.
- Stock crypt stayed loaded with a mounted writable encrypted sentinel in the
  normal guest runs. All completed run logs have no unexpected BUG/Oops/WARNING
  or compiler diagnostics; unsigned experimental module taint and injected EIO
  diagnostics are expected.

batch-faults-512-001 also passed every ownership/setup, larger decoy lower-I/O,
shared fail-stop/recreation and local-repair assertion. The 16 KiB decoy write
prepared 72 encryptions (two AEGIS carrier groups); the hidden write prepared 36.
Reads spent zero, no faulted record needed repair after recreation, and full
oracles/stock authentication/custom unload passed. Independent verification
matched all 213,008 primary sectors and 3,028,992 hidden bytes, with distinct
current IVs. No unexpected kernel diagnostics appeared. Both fault matrices
restore the lower device before teardown; this is not arbitrary failing-close
or hardware durability evidence.

All ten VM runs/boots completed successfully; every final output image has a
matching host-verification.json. This bounded milestone is complete. Next work
is concurrent lifecycle/flush stress and evidence-led profiling of read/setup
cost. No cross-bio coalescing, broader host deployment or new crash/deniability
claims follow from these results.


## Session handoff: concurrent lifecycle/flush stress (2026-10-19)

Added scripts/guest-lifecycle.sh, kernel/guest-lifecycle-test.py, the independent
kernel/lifecycle_trace.py evidence checker and three rejection tests. The
separate kernel/piv-io-test.c helper compiles only against pinned guest headers;
it is not part of dm-piv's Makefile or production interface. It accepts only two
public-view names, sector 0 and 512-byte same-data requests with exact plain/FUA/
PREFLUSH|FUA/flush modes, and wipes its temporary page. No keys, arbitrary paths,
offsets or plaintext are exposed through it. The production driver, disk format,
control ABI, cryptography and setup frontend are unchanged.

Kernel probes trace pn_worker, pn_write, blkdev_issue_flush and bio_endio on a
global trace clock. The checker rejects incomplete or overlapping workers,
unpaired/failed flushes, missing completion-after-flush and missing preflush
before payload. DM may split preflush into its own bio. Probe misses and trace
buffer overruns are failures. Tests wait for complete worker-return evidence
before stopping tracing, since upper completion can wake the submitting CPU
before the worker returns on another CPU. Probes and the helper are removed
before final production-module unload. Only metadata/results are traced.

Four writers own disjoint logical regions but deliberately share carriers:
two 16 KiB decoy regions and two 512-byte hidden blocks. Each performs eight
nontrivial write/read/fsync iterations and restores its original bytes (36 total
writes). Another thread performs eight public-view suspend/resume cycles;
recorded writer progress must demonstrate interleaving. Held public descriptors
must prevent remove/close/unload while retaining all mapping identities. Prepared
direct-write descriptors/buffers then prove actual pwritev/pwritev2 remains
blocked during public suspension, while the peer stays usable, and completes
after resume. Full primary/hidden checks, clean new-generation reopen, stock
readback and unload follow. Private owner/lower administrative mutation while
views are active remains unsupported; this tests the public lifecycle contract.

Host 33 tests passed without skips on AES4096 with ResourceWarning errors and
optional original AEGIS reference enabled. The three new checker tests reject
missing flush/completion/worker evidence, preflush after payload, errors and
missing worker entry. Python compilation, changed-shell syntax and whitespace
checks passed. No host installs/root/modules, physical-device access or full
kernel build was needed. The reused production module/source stage are
batch-native-4096-001/share/experimental-dm-piv.ko and vendor/kernel-build/batch-001.

AES4096 lifecycle-4096-004 PASSED. Both views each exercised four flag modes:
plain/FUA writes completed two lower flushes; preflush+FUA completed three
(one before payload); standalone flush completed one. Every trace had complete
ordered workers and zero missed/overrun events. Concurrent writer progress at
suspend/resume completion was [0,2,2,6,6,8,8,10], proving overlap. Busy operations,
blocked writes, new generation, stock readback and module unload passed. An
unrelated stock encrypted filesystem stayed mounted and writable. Independent
verification authenticated all 28,244 primary sectors and matched all 301,056
hidden bytes, with distinct current IVs. Primary hash:
e745a517d7eef8d46faa53fcdb9e732c0fe3da40e66e2bc228797eb40251065c.

AEGIS512 lifecycle-512-002 also PASSED using identical helper/parser/harness
bytes. All eight flag cases had the same successful worker/flush counts as AES,
zero missed probes and zero overruns. Concurrent suspend/resume progress was
[2,4,4,7,8,9,11,13]. Busy checks, witnessed blocked writes, complete oracles,
new-generation reopen, stock authentication and unload passed. Independent
verification authenticated all 213,008 primary sectors and matched all 3,028,992
hidden bytes, with distinct current IVs. Primary hash:
e42c7683a69cdfcf4bbf0fbca32de0f9bd6c15e950aaf2d79a714cc60054019a.
Both final guest logs contain no unexpected compiler warnings, kernel BUG/Oops/
WARNING or trace errors. Expected unsigned-module taint and udev probes of the
blocked private owner are not test failures. Frozen test inputs match current
sources; production includes match the previously verified batch-001 stage.
This bounded milestone is complete; no production-driver defect was found.

Failed experiments are not trusted fixtures: lifecycle-probe-001 established
tracefs/symbol availability; lifecycle-4096-001's helper used removed no_llseek;
lifecycle-4096-002 hit Python append's unsupported SEEK_END on tracefs seq_files.
Direct descriptor writes fix that. lifecycle-4096-003 passed flags, concurrent
oracles and busy checks but its blocked-write witness assumed syscall 296 and
opened after suspension. Final witnesses prepare descriptors first and accept
x86_64 pwritev 296 or pwritev2 328. Obsolete lifecycle-512-001 was stopped after
its flag traces passed. These were harness/API issues; no security guarantees
or error assertions were relaxed to turn them into passes.

Limits: bounded workload and pinned normal kernel, not lockdep/KASAN or broad
scheduler/hardware coverage. Successful ordered kernel flush returns do not
prove physical persistence, hidden-record atomicity or rollback resistance.


## Session handoff: matched ordinary controls (2026-10-19)

Implemented scripts/guest-controls.sh, kernel/guest-controls-test.py, shared
read-only scripts/control_metrics.py and scripts/analyze_controls.py. Three
sequential arms restore one pristine stock fixture only to guest /dev/vdb with
all holders closed. Stock writes and stock whole-group same-data refresh never
load/use dm-piv. Native initializes hidden zeros before its own closed baseline,
then applies the same primary-sector/4k/16k/same-data requests. The second stock
control encodes no hidden data and tests whether extra reencryption uniquely
implies payload existence. Fresh evolving CRNG state is never reset despite
intentionally reused synthetic key/UUID; these are not independent samples.

Both controls-4096-001 (original control-003 stock fixture) and controls-512-001
(original AEGIS512 stock fixture) PASSED. Complete stock Linux authentication,
equal primary outputs and preserved native hidden zeros passed in each. Reused
production module/source stage remain batch-native-4096-001 and batch-001. No
runtime driver, format, key handling or persistent state changes were made.

Host analysis independently authenticated all six closed before/after images
per profile, checked every plaintext byte against the deterministic workload,
matched supported geometry and exact LUKS prefixes, and verified native hidden
records. Each AES image had 28,244 sectors; each AEGIS image had 213,008. Native
hidden checks covered 301,056 / 3,028,992 bytes. Current IVs were distinct in every
after image; no historical uniqueness claim follows. Final reports are ignored
artifacts/controls-4096-001/analysis.json and controls-512-001/analysis.json.

Snapshot evidence:
- AES4096: all arms changed 6 plaintext sectors; stock changed 7 IVs, native 192.
  Stock-refresh matched the EXACT 192 native IV positions. Same-plaintext
  reencryption was 1 stock versus 186 native/stock-refresh sectors.
- AEGIS512: all arms changed 41 plaintext sectors; stock changed 42 IVs, native 144.
  Stock-refresh matched the EXACT 144 native IV positions. Same-plaintext
  reencryption was 1 stock versus 103 native/stock-refresh sectors.

Physical-vdb traces had no overruns. Journal queued-write bytes (stock /
stock-refresh / native) were 540,672 / 1,216,512 / 2,973,696 for AES and
180,224 / 405,504 / 585,728 for AEGIS. These are bounded-window submissions, not
media bytes or exact amplification; background propagation may occur at close.
Non-atomic live journal samples contained 7/192/67 entries for AES, 42/180/253 for
AEGIS; all 7/23 sections were commit-ID-consistent. Earlier journal history,
repeated writes and setup/checkpoint activity affect those counts. The observer
never replays or treats its samples as authenticated/atomic recovery information.

Full-IV and 32/528/16 encoding-position byte summaries report bit frequency,
empirical entropy, chi-square and compression with NO p-values or security
acceptance threshold. See docs/detectability.md for numerical results, observer
capabilities, scope and reproduction. The README now states the measured
known-workload snapshot distinction. Ordinary whole-group refresh matching one
feature does not make the native workload identical to ordinary requested writes,
nor does it show that hidden data can be uniquely detected. No broad single-image
or multi-snapshot deniability claim is warranted by this experiment.

Host 37 tests passed without skips (AES4096 fixture, optional AEGIS reference,
ResourceWarning errors). Four new tests cover statistics, trace device/region
classification, primary alignment and torn/truncated journal exclusion. Python
compilation, shell syntax and git diff --check passed. Both final guest logs had
no unexpected kernel BUG/Oops/WARNING or compiler diagnostics. Native inputs and
shared metric source match the frozen runs; the analyzed images were read-only.
No host installs/root/modules, real disks, large toolchains or new kernel build.
This bounded assessment is complete. Next: source-led security/threat-model
review, with independent cryptographic review still explicitly outstanding.


## Session handoff: security and threat-model review (2026-10-19)

Completed the bounded internal source review of runtime/format revision 1f4c94f.
docs/security-review.md records assets, observer capabilities, trusted components,
encoding assumptions, primary/hidden nonce domains, kernel/setup boundaries and
open work. Primary references are RFC 5869, RFC 8439, NIST SP 800-38D and Linux
dm-integrity documentation; actual AAD/layout and mutation gates were checked
against the pinned staged dm-crypt helper and current includes. No new concrete
implementation defect requiring a runtime/format change was identified. This is
not an exhaustive memory-safety audit or independent cryptographic assessment.

Clarifications now carried into README/format/agent instructions:
- A single raw image can retain journal history; current-IV pseudorandomness
  alone does not imply full-disk indistinguishability. Known-workload/snapshot
  distinctions from matched controls remain explicit.
- Hidden records provide an offline guessing oracle. Direct hidden keys require
  independent high entropy; HKDF does not make passwords safe. No key commitment,
  alternative-opening protocol or protection from a live administrator is claimed.
- Random-IV GCM's 2^32 invocation bound is across ALL instances using a key. The
  resetting owner counter cannot enforce it. ChaCha/original-AEGIS aggregate
  policies have not been established merely by using the same diagnostic cap.
- Context/address binding is not freshness, primary-key/cipher binding or clone
  prevention. Old valid blocks and mixed valid block epochs remain accepted.
  Reusing a salt at one context/address reuses a ChaCha stream/one-time MAC key.
- Un-MACed journal commit IDs do not authenticate hostile replay ordering; primary
  AEAD does not authenticate all disk metadata. Activation delegates replay to
  Linux before the native full scan. Active malicious metadata/journal experiments
  and forensic reconstruction of older hidden records remain unperformed.

Added three executable limitation regressions: whole-record rollback acceptance,
mixed valid block epochs, and plaintext-XOR leakage under deliberately repeated
salt. All 40 host tests passed without skips, with ResourceWarning errors, the
AES4096 fixture and optional original-AEGIS reference enabled. Python compilation
and git diff --check passed. Current production includes still match the verified
batch-001 source stage. No kernel/runtime, ABI, record bytes or persistent state
changed; no new VM run, host installation, module load or physical-device access
was needed. Existing VM evidence is retained, not represented as newly executed.

Next bounded implementation work: profile authenticated primary/hidden reads and
full activation cost before selecting a measured optimization. Independent
cryptographic review of the joint encoding distribution remains an external
requirement for stronger concealment claims. Debug-kernel testing, active journal
fixtures and explicit per-cipher lifetime/rekey policy remain separate open items.


## Session handoff: authenticated read/setup profiling (2026-10-19)

Added scripts/guest-profile.sh and kernel/guest-profile-test.py, using the shared
guarded guest scaffold and unchanged batch-native-4096-001 module. Timings run
without instrumentation; a separate entry-probe pass verifies exact primary
authentication load/record/write/checkpoint counts with zero missed hits. Setup
is delimited at the ioctl because pn_setup is inlined; piv_load's unique non-cold
compiler specialization is resolved from the loaded module. Public read counters
start after udev settles. Cumulative totals include discovery, deltas do not.

Sequential QEMU TCG runs profile-4096-003 and profile-512-001 both passed. Complete
primary/hidden oracles, zero read-phase encryption use, close/module unload and
stock Linux readback passed. Host check_stateless independently authenticated
all 28,244 AES4096 / 213,008 original-AEGIS512 primary sectors and matched all
301,056 / 3,028,992 hidden bytes. Both have host-verification.json. Current IVs
were distinct, not a lifetime uniqueness result. Frozen harnesses match current
sources; runtime includes match batch-001. No unexpected kernel diagnostics.

Median stock/native activation: AES 0.266/5.826 s, AEGIS 0.254/35.336 s. The native
setup ioctl took 5.146/34.647 s, with exactly primary_sectors+1 authenticated loads
(full scan plus checkpoint). At 16 KiB requests, reading 1 MiB through stock/native
decoy took 24.705/60.182 ms for AES and 22.346/321.641 ms for AEGIS. Reading 64 KiB
hidden took 1.122/0.706 s; larger requests barely helped. A 4 KiB hidden request
authenticated 384/288 primary sectors and decoded eight records. Full samples,
method, caveats, module hash and reproduction are in docs/read-performance.md,
linked from README. These are warm-cache TCG diagnostics with Python comparisons,
not physical-media throughput or a controlled cipher comparison.

Host 40 tests passed with ResourceWarning errors, AES4096 fixture and optional
AEGIS reference enabled; Python compilation, shell syntax and git diff --check
passed. No new runtime/format/ABI change, host installation/module load, physical
device access or full kernel build. profile-4096-001 failed on invalid stock
512-byte direct reads; profile-4096-002 was stopped when compiler symbol details
were identified. Neither is a successful fixture. Final runs do not weaken
alignment or counter assertions.

Next bounded task: prototype a shared authenticated range-read helper, gathering
at most 16 KiB of primary ciphertext/tag/IV tuples per lower read, authenticating
every sector with unchanged Linux AAD before copying requested bytes. Use for
setup scans, decoy reads and carrier reads without lazy verification, persistent
caches or cross-bio writeback. Retain per-sector crypto checks; measure fewer
lower submissions and repeated timings rather than assuming a speedup. Keep the
old module/results as the baseline. Recheck complete oracles and corruption/
lower-fault isolation, lifecycle/flush behavior and other affected guest suites
before accepting the optimization. This profile identifies a candidate path;
it does not separate CPU crypto, allocation, scheduling and lower-I/O costs.


## Session handoff: bounded authenticated range reads (2026-10-19)

Implemented piv_read_range in kernel/piv-control.inc. Each call gathers at most
16 KiB of primary ciphertext plus tag/IV metadata through one dm-integrity bio,
then invokes the original Linux AEAD helper once per sector with its own tag
offset and address/IV AAD. One request is reused sequentially. No plaintext or
IVs are published until the entire range verifies; pages and metadata are wiped
on all exits. Native setup scans, decoy reads and carrier collection use it.
Scalar privileged mutation controls, write preparation/application semantics,
flush ordering, format and ABI are unchanged. There is no persistent cache, lazy
verification, external state or cross-bio accumulation. Native reads still copy
to the public bio only on complete work-item success.

Source stage: vendor/kernel-build/read-range-001; complete scaffold:
artifacts/read-range-input-001/scaffold.tar. read-range-4096-001 built the matched
module with pinned config/symbol checks and no compiler warnings. Includes match
the stage exactly. Reusable module:
artifacts/read-range-4096-001/share/experimental-dm-piv.ko, SHA-256
c6424fc6e94be964affc4ee7cc4406170f54bb487bc0e4d80cc54bdc49f8a79e.
Kernel/header/compiler/cryptsetup pins are unchanged. scripts/guest-profile-build.sh
adds a shared-scaffold build-and-profile entry point. No full kernel build, host
installation/module loading, host root requirement or real-device access was used.

Uninstrumented profiles ran sequentially without competing benchmark VMs.
read-range-4096-001 and read-range-512-001 both passed complete view oracles,
zero read-phase primary encryptions, close/unload, stock authentication and
independent host checks. Against profile-4096-003 / profile-512-001 baselines:
- Median native activation AES4096 5.826 → 2.390 s; AEGIS512 35.336 → 2.416 s.
  Setup ioctl 5.146 → 1.699 s / 34.647 → 1.686 s.
- 1 MiB decoy read in 16 KiB requests 60.182 → 32.036 ms / 321.641 → 33.179 ms.
  64 KiB hidden read in 16 KiB requests 1.122 → 0.391 s / 0.706 → 0.063 s.
- Separate module-qualified probes assert unchanged primary AEAD invocations:
  setup 28,245 / 213,009 including checkpoint, 16 KiB decoy 4 / 32, and 4 KiB
  hidden 384 / 288. Read submissions to dm-integrity drop to 7,062 / 6,658 for
  setup, 1 / 1 for that decoy read, and 96 / 16 for that hidden read. Zero missed
  probes. These are logical submissions, not physical-media reads.

Full method, samples/comparison tables and reproduction are in
docs/read-performance.md. Warm-cache TCG/Python timing is diagnostic, not a
production/cipher benchmark or isolated CPU profile. Historical write/journal
detectability traces were not remeasured; their scope is now explicit. No new
deniability, crash atomicity or physical durability claim follows.

Regression results (all passed, with independent host-verification.json):
- read-range-faults-4096-001 and read-range-faults-512-001: existing setup failure
  cleanup, foreign-name preservation, lower read/write EIO, shared fail-stop,
  recreation, local hidden EIO/invalid marker/repair. Added one-sector read-only
  dm-flakey corruption at the last sector of a 16 KiB decoy item and hidden
  record 10. Direct caller buffers remained untouched on EIO, both views stayed
  failed after restoration, and complete oracles matched after recreation.
  Setup also rejected late-sector corruption and cleaned its own mappings.
- read-range-lifecycle-4096-001: exact plain/FUA/PREFLUSH/flush completion traces
  with zero missed/overrun events, concurrent writes to shared carriers, reads,
  fsync, public suspend/resume, busy mapping/unload protection and new generation.
- read-range-batch-4096-001, read-range-batch-512-001 and
  read-range-batch-chacha-512-001: nontrivial direct read/write/restore, exact
  encryption counts, unaligned/batch/carrier boundaries, incomplete tails and
  full oracles. ChaCha512 reaches the two-group/96-tuple bound. The current
  harness now assumes the documented 16 KiB split rather than inferring target
  behavior from the presence of a build archive; old baselines retain frozen
  harnesses at historical revisions.
- read-range-filesystems-4096-001: concurrent writable ext4/ext2, partial I/O,
  absent/damaged/wrong-key isolation, invalid-marker preservation, direct repair,
  clean reopen and stock readback. Its generated private initramfs passed
  read-range-early-4096-001: actual RAM-root activation with no persistent OS
  filesystem, stdlib-only setup, both writable views and custom unload. The
  post-boot image independently matches both complete expected views.

Nine standard VM runs plus one RAM-root boot completed; every output has full
independent primary/hidden verification. Profiles/faults used AES4096 and
original-AEGIS512, with ChaCha512 additionally covered by the boundary suite.
This is not a new six-profile matrix, debug-kernel audit or power-cut experiment.
The unchanged persistence protocol retains earlier interruption evidence; no
new crash/durability guarantee is inferred. All normal guests kept stock crypt
loaded with a writable unrelated encrypted filesystem. No unexpected kernel
BUG/Oops/WARNING or compiler diagnostics; injected I/O/auth errors and unsigned
module taint are expected. Host 40 tests passed without skips with ResourceWarning
errors, AES4096 fixture and optional original-AEGIS reference; changed Python
compilation, shell syntax and git diff --check passed.

This bounded optimization is complete. Next: active on-disk metadata/journal
negative fixtures using disposable copies and stock replay/native activation.
Record both rejection and accepted valid replay, preserve explicit availability/
freshness limits, and never claim activation cannot modify hostile storage before
the full scan. Independent crypto review, debug-kernel memory/lifecycle stress,
per-cipher lifetime/rekey policy and broader deployment remain open.


## Session handoff: core-first priorities (2026-10-19)

Reordered remaining work at the user's request. The next implementation is
larger native geometry, followed by cancellable/scalable setup, evidence-led
resource/lifecycle hardening, deliberate kernel porting and optional measured
performance work. Standalone journal/metadata assessment, deployment tooling and
documentation consolidation follow core changes; required tests/docs ship with
each change, and concrete security defects always take priority. The previous
handoffs' historical "next" entries are superseded by the top-level order.
No module or runtime change was made in this prioritization update. Existing
stateless-format, nonce, crash and threat-model limitations remain in force.
Verification: reviewed current kernel cap/setup path and userspace guest guard;
git diff --check passed. Runtime tests were not rerun for a documentation change.


## Session handoff: larger native geometry (2026-10-19)

Completed the next core-first milestone. Replaced pn_setup's 256 MiB primary cap
with primary_sectors <= MAX_LFS_FILESIZE / sector_size, and checked the public
map's 512-byte sector offset before converting it to bytes. Reviewed primary/
hidden capacities, address/AAD conversions, record-group products, range ends,
request counters and initialization indices: whole-volume arithmetic is 64-bit,
while allocations and small counters remain bounded to individual requests.
No AEAD, hidden record bytes, ABI, journal protocol or persistent state changed.

GuestOwner now uses the actual guarded raw size for extent parsing. Python and
shared shell guards allow exactly 128 or 512 MiB in the pinned QEMU /dev/vdb
workflow, retaining explicit test-wrapper opt-in. vm.py adds --blank-mib 512;
blank size and copied input are mutually exclusive, and copied inputs must be
regular files at an approved size. No arbitrary host device or generic deployment
was enabled. Added guest-large.sh/guest-large-512.sh and guest-large-test.py to
format fresh guest-owned synthetic fixtures through stock Linux before testing.

Source stage vendor/kernel-build/large-001 and scaffold
artifacts/large-input-001/scaffold.tar exactly match current production includes.
large-4096-001 built the module with matching config/symbol pins and no compiler
warnings; the other two runs reused it. Module:
artifacts/large-4096-001/share/experimental-dm-piv.ko, SHA-256
0a97560fd0df8a9709619725689eb9baaf128da4fd6cf7e2830387242bc95948.
No new host installation/module load/root access, real disk or full kernel build.

Both 512 MiB runs PASSED all exit criteria:
- large-4096-001 AES-GCM/4096: primary 512,344,064 bytes / 125,084 sectors,
  hidden 1,333,760 bytes, incomplete carrier tail 44 sectors.
- large-512-001 original AEGIS-128/512: primary 485,490,688 bytes / 948,224
  sectors, hidden 13,485,568 bytes, incomplete carrier tail 20 sectors.
- Full hidden initialization retained the stock primary hash; seeded nonzero
  hidden records at low/high/end addresses survived coordinated decoy writes.
  Nontrivial read/write/restore crossed the old cap, high unaligned addresses,
  integrity interleaves, carrier boundaries, actual incomplete tails and ends.
  EOF reads/past-end writes did not wrap or fail-stop a healthy owner.
- High-address lower read EIO and witnessed last-carrier ciphertext read corruption
  returned EIO without changing caller buffers. Failure stayed shared/sticky after
  fault restoration; recreate recovered complete expected views without repair.
- Clean reopen, custom unload, unrelated mounted stock crypt and stock full-primary
  authentication passed. Independent host verification authenticated every primary
  sector and matched every hidden byte for both large-final.img outputs. Current
  IVs were distinct; historical usage is still unknown.

large-lifecycle-128-001 additionally passed the original AES4096 fixture: exact
plain/FUA/PREFLUSH/flush ordering with complete traces and zero missed/overrun
events, concurrent writes/reads/fsync to shared carriers, public suspend/resume,
busy mapping/unload protection, new generation, full oracles and stock readback.
Its independent host verification also passed. All three runs have
host-verification.json and no unexpected kernel BUG/Oops/WARNING; injected errors
and unsigned module taint are expected.

Host 43 tests passed without skips with ResourceWarning errors, AES4096 fixture
and original-AEGIS reference enabled. Three new tests cover approved-size/identity
guards and synthetic 8 GiB layout arithmetic above 32-bit byte offsets across
both sector/tuple sizes, including truncated extents. No actual 8 GiB kernel run
is claimed. Changed Python compilation, shell syntax, VM CLI help and
git diff --check passed. New documentation is docs/large-volumes.md, linked from
README and deployment/development notes.

Initialization/activation took 93.25 s AES4096 and 507.53 s AEGIS512; subsequent
activation without initialization took 9.83 / 7.89 s. These are concurrent TCG
samples including frontend/udev work, not controlled performance guarantees.
The long initialization is evidence for the next core task: cancellable/scalable
setup and initialization with explicit cleanup, while retaining full verification.
The lifetime diagnostic cap remains; sufficiently large initialization can fail
after partial changes. Geometry-bound hidden AAD means live resize/migration is
unsupported. Only 128/512 MiB guest deployment is enabled; the arithmetic bound
is not a claim of arbitrary-size support or stronger security/crash guarantees.


## Session handoff: cancellable native setup (2026-10-19)

Completed the second core-first milestone. PIV_NATIVE_SETUP takes the owner
mutex interruptibly; setup calls cond_resched and checks pending signals before
each bounded authenticated scan range and whole initialization record, and around
the final checkpoint. Cancellation returns EINTR and frees unfinished native
state. There is no interruption inside pn_write: completed healthy records stay
committed. Retry performs full verification again; initialization restarts rather
than resumes. No ABI, encoding or persistent metadata changed.

The controlled SIGINT test uses a default Python KeyboardInterrupt handler and
unwinds frontend ownership. Default terminating signals/process death, repeated
interruption of cleanup and arbitrary clients do not inherit this guarantee.
Lower I/O, flushes, allocation and checkpoints can delay cancellation indefinitely;
a cancelled contended SETUP caller's subsequent fd close can wait for the owner
mutex. No hard latency, crash atomicity or memory-erasure guarantee is claimed.

The first two AES runs (cancel-4096-001/002) exposed a real cleanup defect:
udev probes could hold the suspended private mapping open after interrupted
setup. They FAILED and are not accepted fixtures. Failed-attempt cleanup now
replaces only its newly created, identity-checked private owner's table with an
error target (dmsetup wipe_table --noflush), draining those probes before normal
removal. It does not erase backing storage. Existing owners, foreign names and
public views are never forced; normal close retains busy protection. Tests reject
cleanup exception notes and check absence before settling udev.

Successful disposable QEMU runs, all with independent host verification:

- artifacts/cancel-4096-003: AES-GCM/4096, 128 MiB raw disk. Witnessed scan
  cancellation plus cleanup 0.339049 s, zero encryptions; initialization 0.450311 s,
  96 encryptions/two complete hidden records. Healthy reopen verified the zeroed
  prefix and unchanged remainder, then ordinary full initialization completed.
  Final host verification authenticated 28,244 primary sectors and matched all
  301,056 hidden bytes (zeros).
- artifacts/cancel-512-001: original AEGIS-128/512, 512 MiB raw disk. Scan
  cancellation plus cleanup 0.305701 s, zero encryptions; initialization 0.463972 s,
  72 encryptions/two complete records. Final verification authenticated 948,224
  primary sectors and all 13,485,568 hidden bytes: a 1,024-byte zero prefix and
  the original remainder. Full initialization was not repeated on this fixture.
- Both cancellation runs witnessed a second SETUP ioctl blocked on the owner
  mutex, then its EINTR marker while the first still scanned (0.008352/0.008960 s
  after SIGINT). These markers precede fd close, not full cleanup. Phase witnesses
  use filtered kernel probes plus the actual ioctl syscall; traces had no missed
  probes or overruns. Delay-target timing is observed evidence, not a deadline.
- artifacts/cancel-faults-4096-001: existing failure/ownership suite passed after
  the cleanup change, including setup/view failures, foreign/existing ownership,
  shared sticky lower-I/O failure, authentication rejection and local hidden
  damage/repair. Independent verification matched all 28,244 primary sectors and
  301,056 original hidden bytes.

All three passed full guest oracles, stock primary readback, custom module unload
and stock crypt coexistence. Each has result.txt and host-verification.json;
no unexpected kernel BUG/Oops/WARNING occurred. Injected errors and unsigned
module taint are expected. Current IVs were distinct; lifetime history remains
unknown.

Source stage vendor/kernel-build/cancel-001 and scaffold
artifacts/cancel-input-001/scaffold.tar match the production includes. Pinned
Linux 6.12.113+deb13-amd64/source 6.12.113-1, GCC 14.2.0-19 and cryptsetup
2:2.7.5-2; module built without compiler warnings or config/symbol mismatches.
All successful runs used experimental-dm-piv.ko SHA-256
aee864c71a5e75442a800484ef722a86a2f79df4393f4792bf9d5f08006c68c4
from cancel-4096-003/share. Their frozen production/harness snapshots match the
current sources. No host root/module operation or new system dependency needed.

Host suite: 47 tests passed, no skips, with ResourceWarning errors, stock fixture
and optional original-AEGIS reference enabled. Four new tests cover interruption
unwind, setup-buffer wiping, identity-before-discard ordering and abort scope.
Changed Python compilation, shell syntax and git diff --check passed. See
docs/cancellation.md for semantics and reproduction.

Next: evidence-led core resource/lifecycle review, especially allocation failures,
queue bounds and teardown concurrency. Select a bounded reproducible defect or
invariant test before changing production code; do not build another kernel
speculatively. Broader security review, six-profile refresh and deployment remain
later work; this milestone does not strengthen deniability or crash guarantees.

## Session handoff: production-readiness review follow-ups (2026-10-19)

Documentation/roadmap-only update from a user review of production blockers. No
kernel, setup, encoding or test code changed; no guest or host test run was
needed. README now states write-amplification throughput/wear costs (unmeasured),
concrete RNG-repeat consequences and the trust boundary. docs/security-review.md
records single-image journal history visible to a decoy-key holder, from layout
reasoning without a forensic experiment. The core-first list gains finer error
isolation and a stateless wrong-key guard; porting names the host kernel series
and a standalone-target evaluation; later work promotes rekey/migration and adds
journal mitigation, a UUID-salted KDF, write profiling and a Rust setup port.
Design choices awaiting the user are listed above the handoffs. Next remains the
evidence-led core resource/lifecycle work, now including the two follow-ups.

## Session handoff: user design decisions (2026-10-20)

Documentation/roadmap-only update recording the user's decisions on the review.
Approved: scoped error isolation and the standalone target as top priorities;
format v4 (fragment-local re-randomization, encrypted in-IV header with fast
key check/key wrapping/version flags but no counter, optional A/B slots,
`--integrity-no-journal` support); AEGIS-128 as recommended profile; concrete
rekey/migration including offline resize; hidden-key KDF; write profiling; Rust
setup port; investigating aes-xts-random + hmac-sha256. Out of scope: coercion
alternative openings, rollback, multi-snapshot observers. AGENTS.md now lists
these as planned changes; existing rules apply until each lands with tests. No
code changed; no tests run. Next: roadmap item 3, starting with a fault-class
inventory of the current fail-stop path and its injection tests.

## Session handoff: scoped error isolation and wrong-key guard (2026-10-20)

Completed roadmap item 3's two follow-ups on a new development host (no KVM;
all guest runs under QEMU TCG, the same pinned Debian 6.12.113 guest).

Kernel (piv-native.inc, piv-control.h):
- pn_write reports whether its APPLY loop began. pn_worker stops the shared
  owner only for negative errors after that point or for failed flushes
  (standalone, PREFLUSH, batch). Reads, request validation, carrier/primary
  authentication, allocation, nonce retries, the encryption cap and PREPARE
  failures now fail only that bio. Preparation can still spend encryptions.
- PN_INVALID distinguishes an authenticated invalid marker from an
  unauthenticated record; both remain local EIO.
- Wrong-key guard: setup collects carrier IVs from the mandatory primary scan
  and decrypts groups until one record authenticates (data or invalid marker).
  Without PIV_SETUP_INITIALIZE (1) or the new PIV_SETUP_UNINITIALIZED (2) flag,
  setup returns EKEYREJECTED. ABI 3 struct size unchanged; unknown flags still
  rejected. No extra I/O or primary crypto: the profile run measured exactly one
  record decrypt with unchanged range/crypto counts on an initialized volume.

Userspace: open_blocks(uninitialized=...) and `open-blocks --uninitialized`; an
EKEYREJECTED note explains the cause; failed setup unwinds as before.

Evidence (fresh fixture artifacts/control-001, AES-GCM/4096, 128 MiB; module
experimental-dm-piv.ko SHA-256
a26931bfacf5faef0b8784125920d639f618b113df1e50207ec313fb2259247c, built in-guest
without warnings or config/symbol mismatches; cryptsetup 2:2.7.5-2):
- guard-native-001 (dual test): stock carrier rejected without --uninitialized
  with no mappings left, opened with it; wrong hidden key rejected with
  EKEYREJECTED and no mappings, decoy still openable with --uninitialized;
  existing isolation, RMW, filesystem, reopen and stock readback checks passed.
- guard-early-001: RAM-root initramfs activation passed (guard accepts the
  initialized volume).
- guard-faults-001: error_reads on decoy and hidden: EIO, zero encryptions, a
  write needing the same carrier also EIO with zero encryptions, owner healthy;
  after restoration the SAME generation read/rewrote the range and passed full
  oracles without repair. error_writes: 48 encryptions spent, owner failed,
  dm-integrity logged "Error on writing journal: -5", recreation and oracles
  passed. Late-sector corruption: sentinel buffer untouched, owner healthy,
  overlapping write rejected before any encryption, unrelated requests on both
  views succeeded during the fault, same-owner oracles passed afterwards.
  Setup-scan corruption, setup-phase cleanup and invalid-marker checks passed.
- guard-profile-001 and guard-cancel-001 passed with the updated expectation
  (setup record=1).
- Host: 49 tests (2 new) pass with PIV_FIXTURE=artifacts/control-001; only the
  optional AEGIS reference test skipped. Independent host verification
  authenticated all 28,244 primary sectors of dual-final, fault-final,
  profile-final and cancel-final (identical primary hash), and hidden unpack of
  dual-final and fault-final matched the oracle byte-for-byte.

Not tested this session: 512-byte, ChaCha and AEGIS profiles; lifecycle, batch,
power-cut, large-volume and controls suites (no code paths they assert on
changed except setup flags, which they do not use without initialize on stock
carriers). An invalid-marker-only volume passing the guard is covered by code
path review, not a dedicated test. TCG timings are not comparable with earlier
handoffs from different hardware.

Next: roadmap item 4 (standalone target replacing the dm-crypt fork). Test
throughput on this host is TCG-bound; caching a provisioned guest image and
running independent suites in parallel are candidate harness improvements.

## Session handoff: harness, standalone target, format v4, migration (2026-10-20)

All guest runs used QEMU TCG (no KVM on this host) with the cached provisioned
image and scripts/suite.py. Fixtures: control-001 (AES-GCM/4096) and
suite-generated AES/512, AEGIS/4096, AEGIS/512 and ChaCha/4096 controls.

Changes:
- **Harness** (commit 4ca9321): vm.py provision/--provisioned, offline
  guest_packages, virtio-rng, scripts/suite.py, guest-build.sh. suite-001: 29 VMs
  passed with host verification in about 20 minutes.
- **Standalone target (item 4):** kernel/dm-piv.c replaces the vendored dm-crypt
  fork and kernel/dm-crypt-piv.patch. It accepts only the pinned profiles' stock
  table syntax plus piv_control; hex keys only, wiped after setkey; status never
  prints the key; it supports "key wipe" while suspended. The owner serves
  bounded authenticated reads before native ownership and never accepts
  ordinary writes. Staging copies five source files; no kernel source archive
  is needed.
- **Format v4 phases 1-3 (item 5):** fragments, SIV records, keyslots, directory,
  passphrase KEKs (scrypt), the keyslot add/remove ioctl and A/B slots. 16-byte-IV
  profiles detect the format at open; initialization defaults to v3.
  pn_write is noinline for the kprobe-based tests.
- **Migration:** `pivstore migrate` plus `vm.py --second-blank-mib` and an
  explicit /dev/vdc opt-in in the guest guard.
- **Docs:** format-v4.md, journal-atomicity.md (item 6 answered), README,
  native-blocks, security-review, kernel/README, AGENTS.md rules.

Evidence:
- suite-006 (module from artifacts/v4ks-input-002, all five profiles): native,
  faults, batch, early, power, controls, sector and v4 passed (40 VMs) with
  independent host verification of every closed image. The 20 failures were
  profile, cancel and lifecycle (kprobes could not find the inlined pn_write)
  and migrate (the test wrongly required a bit-identical source raw image).
- suite-007 (noinline fix, artifacts/v4ks-input-003, experimental-dm-piv.ko
  SHA-256 b09eafb8a5f76aaf793abc4699e04ee0bb6c662db0c18f192dfc7d2e20d68423, built
  in-guest without warnings): profile, cancel and lifecycle passed on all five
  profiles; migrate passed for AES/4096, AEGIS/4096 and ChaCha/4096. On 512-byte
  sources it correctly refused a 4096-byte AEGIS v4 target whose hidden view
  would be smaller; the test now keeps the source sector size (rerun:
  suite-008).
- v4 results (guest-v4-test.py, independently decoded on the host via keyslot
  unlock): 1 primary encryption per 4 KiB decoy write versus 36 for v3; hidden
  writes 90; A/B falls back after the newest slot is damaged. Keyslot add/remove,
  passphrase slots, the last-keyslot protection and keyslot preservation across
  a decoy rewrite of the keyslot area all passed. Capacity on 128 MiB AEGIS:
  158,720 bytes (4096-byte sectors).
- Host: 61 unit tests, including the v4 codec, keyslots and directory, pass with
  the fixture and the AEGIS reference.

Remaining:
- No-journal (phase 4) needs your decision on the torn-sector policy.
- Porting to a newer public kernel series is not done.
- The xts/hmac profile needs 32-byte tag ABI work.
- Rust setup port.
- Per-cipher lifetime-budget guidance.
- External cryptographic review of v4.
- Initialization defaults to v3. Switching AEGIS to v4 by default would require
  updating dual/fault/other suite expectations.

## Session handoff: v4 landed and full KVM matrix (2026-10-21)

The previous session was interrupted before committing; its work was applied
from a saved diff (one malformed suite.py hunk line fixed) on top of
726a35a/feb6d6f. Also removed: kernel/dm-crypt-piv.patch and
environment/kernel-sources.json, both obsolete with the standalone dm-piv.c
(fetch_kernel.py no longer downloads Debian source archives). The suite-008
migrate rerun noted above was never recorded; suite-004 below supersedes it.

Harness (726a35a): suite.py/early_vm.py take `--accel`, defaulting to KVM when
/dev/kvm is usable; host checks no longer pass `--format` for v3 images (that
bug made every host verification fail).

Evidence (this host has KVM; all runs `accel=kvm`, cached provisioned image):
- suite-003 (pre-v4 tree with the fork patch): 66 VMs, six profiles, all suites
  except v4/migrate passed; 36/36 closed images host-verified.
- suite-004 (this tree, artifacts/v4-input-001 scaffold): 78/78 VMs passed in
  about 23 minutes for all six profiles (AES/ChaCha/AEGIS at 512/4096) and the
  suites faults, profile, cancel, lifecycle, batch, early, power, controls,
  sector, v4 and migrate. 44 host checks (including v4 decoding via keyslot
  unlock) verified; no failures. v4 ran on both AEGIS profiles and correctly
  skipped on 12-byte-IV profiles. Migrate passed from every source profile
  into a rekeyed, larger AEGIS v4 target with the source's sector size.
  experimental-dm-piv.ko SHA-256 (AEGIS/4096 native run)
  b09eafb8a5f76aaf793abc4699e04ee0bb6c662db0c18f192dfc7d2e20d68423, identical
  to suite-007's; no compiler warnings, BUG or Oops (only unsigned-module taint).
- AEGIS/4096 v4 write profile under KVM: 48 random 4 KiB O_DSYNC decoy writes,
  v3 36 encryptions/write (0.749 s) vs v4 exactly 1 (0.448 s); A/B fallback and
  keyslot add/remove/last-slot protection passed.
- Host: 61 unit tests pass against fresh fixtures with the AEGIS reference.

Remaining items are unchanged from the previous handoff.
