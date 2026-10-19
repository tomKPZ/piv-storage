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

## Next bounded work

Failure handling and mapping cleanup are implemented; see the final handoff
for direct-I/O fault, ownership and boot regression evidence. Preserve that
coverage when changing the I/O path.

Next assess bounded batching to reduce repeated full-carrier-group rewrites
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
