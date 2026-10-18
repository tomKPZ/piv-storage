# Implementation roadmap

This is a revisable research plan. Update it when evidence changes the best
approach. The user has narrowed the offline prototype to make room for an
online implementation; the active priorities below supersede historical next
steps in the session notes.

## Scope decision

The offline compatibility baseline is sufficient: pack/unpack works on one
4096-byte AES-GCM/random profile, stock Linux authenticated a packed image with
unchanged primary plaintext, and 22 tests passed. Keep this implementation and
its tests as a reference; fix regressions and blockers, but stop expanding it
into a hardened standalone offline product.

Defer systematic steganalysis, broad benchmarks, 512-byte/alternative cipher
profiles, complete guest dependency pinning, exhaustive offline fault injection,
independent distro patch reconstruction, password UX, and production key-lifetime
management. Independent cryptographic review remains outstanding; it is not a
prerequisite for a disposable online experiment. No security claim is established
by deferring that review.

Do not defer primary authentication, nonce freshness, ownership/cache coherence,
or the minimum recovery behavior needed by actual online writes. Keep the
single-image threat model and known snapshot distinguisher explicit.

## First online demonstration (implemented)

Here online means a running service exposing a writable auxiliary file, with a
read-only primary view available through a coordinated path. The regular-file
implementation now passes the mounted demo, including simultaneous primary reads
and hidden updates. Its shared-codec offline regressions and nine new online
tests pass (31 total). See docs/online-implementation.md for actual limitations.

Keep one supported format, supplied high-entropy keys, one process, one hidden
file, and disposable VM disks. Reuse the whole-carrier v1 blob: buffer edits and
commit the whole blob on fsync/unmount. Incremental records, arbitrary primary
writes, multiple clients, a general hidden filesystem and a kernel driver are
not required. See [online design](docs/online-prototype.md).

### 1. Establish one owner and frontend contracts

Status: implemented and tested with a stable path lock plus inode locks,
authenticated read-only NBD, and a direct-I/O single-file FUSE adapter.

- Separate storage access/sector crypto from the CLI enough to reuse them in a
  long-running service, keeping the offline regression tests passing.
- Give one backend exclusive ownership of the backing image/device. Do not
  permit an independent dm-crypt/loop mapping to access it during online writes.
- First expose primary plaintext read-only and authenticated through an NBD
  adapter in the VM. Never acknowledge primary writes. Expose hidden content as
  one FUSE file, with clear read/write/truncate/fsync/unmount behavior.
- Stage adapters independently if useful, but settle how reads are paused during
  commits and how errors stop further access before implementing mutations.

Exit: primary reads match the offline verifier, write requests are rejected,
frontend operations have testable contracts, and the backend has one owner.
The frontend choices are provisional; revise if an alternative is simpler while
preserving those properties.

### 2. Add the minimum online commit/recovery path

Status: implemented for local regular files. Prepare/verify/fsync a whole-image
copy, atomically replace its canonical path under the owner lock, and fsync the
parent directory before acknowledgment. This simpler path needs no new in-place
journal. Backend SIGKILL tests reopen the complete old/new canonical image.

- Keep edits in memory until an explicit flush; initially serialize every commit
  and pause primary reads during it. Full-volume rewrites are acceptable.
- Authenticate affected primary data, generate fresh carrier IVs, and use the
  exact already-tested primary encryption/AAD path.
- Implement a bounded, documented transaction/recovery scheme before mutating
  the sole online backing image. A private external recovery journal is allowed
  for the VM prototype; it weakens deniability and is not an on-disk-format claim.
- Establish required persistence ordering and fail-stop behavior. After an
  interrupted commit, recover a complete old/new state before serving either
  view. Never replay old IVs by reencrypting changed primary plaintext.
- Use disposable known-lineage test keys, count encryption work in tests, and
  keep historical nonce/rollback limitations explicit.

Exit: fsync commits survive service restart, interrupted updates recover before
access resumes, and no primary read returns unauthenticated or mixed data.
Caught errors and selected process-crash boundaries are sufficient at this stage;
physical power-loss guarantees are deferred.

### 3. Demonstrate the mounted workflow in QEMU

Status: artifacts/online-002 passed the mounted ext4/FUSE/NBD workflow, clean
restart/remount, actual primary-write rejection, concurrent uncached primary
reads, full primary hashes and final independent stock-Linux authentication.

- Mount the hidden file and primary filesystem read-only inside the guest. Use
  synthetic data; do not require host root or host physical disks.
- Add a cleanly initialized primary-filesystem fixture for the mounted demo;
  retain the existing deterministic sector-pattern fixture for codec regressions.
- Edit/truncate the hidden file, fsync, unmount/restart/remount, and verify its
  contents. Exercise primary reads during commits and rejection of primary writes.
- Check unchanged full primary plaintext and all-sector authentication after
  commits/recovery, including a final stock-Linux readback with the service closed.
- Inject corruption and a few commit interruptions; document blocking latency,
  write amplification, and recovery limits without building a benchmark framework.
- Record any additional guest dependencies and reproducible commands.

Exit: a repeatable online demo, passing offline regressions and focused online
integration tests, with honest durability/security limitations.

## Kernel backend phase (K0 complete; K1 next)

Recommendation: start with an opt-in extension to the pinned dm-crypt source,
keeping hidden crypto/FUSE in userspace and reusing the current mapping's primary
key, AEAD/AAD and integrity-bio machinery. A custom target is a fallback if that
extension cannot remain contained; do not duplicate the driver before testing
the smaller path. See [investigation and design gates](docs/kernel-backend.md).

This phase targets disposable guest block devices and native primary reads,
without the userspace NBD path or full-image rename. It does not make v1 hidden
updates incremental, or make an entire blob atomic merely by using dm-integrity.
Keep the regular-file backend as the working fallback.

### K0. Matching module build and query-only control scaffold

Status: implemented and tested in artifacts/kernel-008. Exact guest module
build/load, query authorization/lifetime, primary mutation rejection and stock
readback passed. See kernel/README.md for reproduction and limits.

- Obtain exact Debian guest source/headers, config and Module.symvers; compare
  relevant distro patches to our reviewed Linux 6.12.113 files. Build/load only
  inside the disposable guest. If an exact module build is not viable, use a
  matched test kernel/modules build; never force ABI-mismatched modules to load.
- Add an explicit opt-in mode and bounded binary query endpoint tied to a live
  target. The reviewed IV hooks are private and are not a loadable plugin API;
  the existing text DM message API is not a bulk carrier transport.
- Prove primary mutation rejection and lower dm-integrity write access can
  coexist. Prototype a write-capable filtered owner with read-only presentation
  if needed; ordinary --readonly activation is not assumed sufficient.

Exit: unmodified behavior with the feature disabled, correct read-only primary
behavior with it enabled, working metadata queries, and verified build provenance.

### K1. One-sector IV replacement through the native integrity path

- Authenticate/read a complete old sector tuple through the lower integrity
  device, apply a request-local supplied IV, and reencrypt identical plaintext.
- Submit ciphertext plus metadata through that same journaled dm-integrity
  instance. Do not edit raw layout offsets or use global "next IV" state.
- Use bounded requests, validate indices/expected old IVs, and establish actual
  flush/FUA completion semantics. Reuse loaded key state without key-read APIs.
- Test first/last/interleave-boundary sectors, malformed requests and corrupted
  old tuples, then close the patched stack and verify with stock Linux/Python.

Exit: paired sector updates with identical full primary plaintext, native
integrity handling and no whole-image replacement. No whole-record commit claim.

### K2. Concurrency, target lifetime and whole-record recovery gate

- Serialize updates with primary I/O initially. Test controller death, stale
  generations, suspend/remove/reload/key-wipe, workqueue/allocation/I/O failures
  and invalid requests; use lockdep/KASAN configurations where available.
- Inject device/VM failures around actual journal commit/replay, not just kill
  the controller while kernel work continues. Record virtual cache assumptions.
- Design and test recoverable multi-sector blob commits before enabling hidden
  fsync through this backend. An external private recovery journal is allowed
  for experiments, with identity/integrity/ordering and explicit exposure limits.
  Recovery may need exact tuple replay; it must not reencrypt with stale IVs.

Exit: bounded concurrency/lifetime behavior and an explicit, tested record-level
recovery decision. If this is too large, retain the kernel work as a sector proof
and keep payload commits on the working userspace backend.

### K3. Connect the existing FUSE service to the optional kernel backend

- Keep the hidden codec and file interface; add a capability-checked kernel
  adapter and use the same extended dm-crypt owner for native read-only primary
  access. No separate raw writer or independently active primary mapping.
- Repeat mounted write/truncate/fsync, recovery and concurrent-read tests on
  disposable guest disks. Preserve stock-kernel readback and the existing backend.
- Add explicit setup/teardown tooling or cryptsetup integration: its stock
  active-table parser rejects the experimental piv_control flag. Keep correct
  table status rather than hiding the flag to bypass old parsers.
- Resolve mounted frontend crash cleanup as part of this integrated lifecycle.

Exit: a working optional device-backed demo with honest record-recovery limits;
no claim of general kernel ABI compatibility, production durability or deniability.

## Later, only if the experiments justify it

Incremental hidden records, reduced write amplification, in-device whole-record
transactions, broad upstream/cryptsetup integration, broader configurations, production
nonce/key policy, stronger crash testing, and systematic detectability evaluation.
These are not prerequisites for the first mounted demonstration.

## Next focused task

Begin K1 with authenticated lower-integrity tuple reads before adding any
replacement operation. Validate the lower journal mode/recovery state explicitly;
K0 validates crypto/profile shape, not LUKS metadata or journal configuration. The current kernel code has no carrier read/write command; keep FUSE
on the working regular-file backend until the record-recovery gate is satisfied.

Mounted-service crash cleanup remains a bounded integration task before K3:
stale FUSE mounts, NBD connections and Unix sockets need explicit cleanup after
process death. Do not delete the stable owner lock or recover from staging images.
It need not block the K0/K1 kernel experiments. Avoid resuming deferred broad
offline hardening instead of these focused online/kernel tasks.

## Session handoff

At the end of implementation sessions update this file with completed work,
commands/checks and results, known failures, blockers, and the next concrete task.
Add focused design notes when decisions become substantial. Never include keys,
passwords, real-data images, or sensitive host information.

### 2026-10-18: kernel backend investigation

- User requested investigation and roadmap integration, not implementation in
  this turn. Recommended a small opt-in dm-crypt patch first; separate target is
  a fallback with explicit refactoring/maintenance tradeoffs.
- Inspected pinned dm-crypt/dm-integrity source, DM target callback definitions
  and ioctl dispatch. Added three SHA-256-pinned source references to the fetch
  manifest and docs/kernel-backend.md with evidence, hypotheses and test gates.
- Important findings: IV hooks are private; caller-supplied IV updates need an
  explicit request path; read-only primary presentation must coexist with a
  write-capable lower integrity target; sector tuple journaling is not whole-blob
  atomicity. Bulk/control transport and table lifetime need a deliberate design.
- Confirmed host build tools (make, cc/ld, bison, flex, bc, pahole) and guest config
  DM_CRYPT=m, DM_INTEGRITY=m, BLK_DEV_INTEGRITY=y, KEYS=y, MODVERSIONS=y.
  Exact headers/Module.symvers and distro-source compatibility are not verified.
- No package installation, full checkout, kernel build, module load or runtime
  implementation change. Validate this revision with source checksums, JSON and
  documentation consistency/whitespace, not a claim of new runtime test coverage.
- Next concrete task: K0 build-provenance and query/control/access-mode spike
  in QEMU. Retain regular-file atomic replacement as a working fallback; do not
  wire full-carrier FUSE commits into sector writes before K2 recovery is solved.

### 2026-10-18: first online implementation

- Committed the requested scope revision as fbb7ff3. The user subsequently
  authorized committing the online implementation described below.
- Extracted SectorCodec and a held-image copy writer shared by offline and online
  paths. The offline 22-test baseline still passes. Exclusive inspection suppresses
  cryptsetup's secondary metadata lock while retaining our own held inode lock;
  otherwise the child process would block against its owner's exclusive lock.
- Added OnlineStore, Unix-socket read-only NBD and one-file pyfuse3 adapters, plus
  the serve CLI. Writes/truncation buffer in memory; fsync/flush commits the whole
  record. One owner serializes reads/commits and fails closed after uncertainty.
- Chose local regular-file atomic replacement instead of in-place transactions:
  leave the current image intact until a verified/fsynced replacement is ready,
  lock it, rename it, and fsync the parent. Raw devices are unsupported. This
  avoids inventing an external undo/redo journal for the first mounted demo.
- Added in-process IV history and a conservative per-session sector-encryption
  ceiling. Neither is persistent lifetime accounting; previous sessions, clones
  and rollback remain outside the trusted disposable-lineage assumptions.
- Added nine host online tests: ownership across replacement, buffered sparse
  write/truncate/reopen, read/write bounds, budget rejection, concurrent reads
  waiting for commit, authentication fail-stop, post-publication errors, SIGKILL
  at prepared/published/durable boundaries, and NBD protocol/write rejection.
  Full suite passed: PIV_FIXTURE=artifacts/control-003 python3 -W
  error::ResourceWarning -m unittest discover -v (31 tests).
- Added scripts/guest-online.sh and vm.py --code read-only package export. Guest
  backing files live on local ext4. FUSE/NBD/crypto dependencies were installed
  only inside the disposable guest; no new host packages or host root were needed.
- artifacts/online-001 mounted and committed successfully, then failed a test
  assumption that writable open itself must fail. Linux allowed that open while
  maintaining read-only state. Revised the test to attempt an actual write.
- artifacts/online-002 passed: hidden write/truncate/fsync during concurrent
  primary file and uncached block reads; actual primary-write rejection; clean
  service restart and hidden recovery; independent stock mapper verification.
  All four full primary hashes match:
  0f9245ced1686784b11da37e8bdb60d02aaa7d4a76f9152d35831652b6402eef.
  Host verification authenticated all 28,244 exported final-image sectors and
  recovered the same 20-byte synthetic hidden payload.
- Tested guest additions: pyfuse3 3.4.0, Trio 0.29.0, cryptography 43.0.0,
  nbd-client 3.26.1 and fuse3 3.17.2. Exact Debian package versions are recorded in
  artifacts/online-002/share/packages.tsv. Host crypto remains 46.0.5.
- See docs/online-implementation.md for ordering, capacity, process-crash versus
  power-loss scope, lock/staging exposure and manual use. Next focused task is
  mounted crash cleanup/reconnection, not another format or kernel driver.

### Scope revision: prioritize the online demonstration

- User requested a smaller remaining offline prototype scope to make room for
  online implementation. Existing code and tests are retained; this revision
  changes planning/instructions only and adds docs/online-prototype.md.
- Active milestones above supersede historical offline-hardening next steps.
  Keep one format and whole-carrier encoding, defer broad evaluation/production
  hardening, and build one mounted hidden file with coordinated read-only primary
  access. Single-owner coherence and minimum online recovery are not deferred.
- Next concrete task: inspect/refactor the storage/sector-codec boundaries for
  a single-owner service, then prototype its primary read-only adapter in the VM.
  Verify the guest NBD/FUSE dependencies when reaching their adapters. Do not
  edit a backing disk behind an independent active dm-crypt mapping.
- Validation for this revision is documentation consistency and whitespace;
  implementation behavior is unchanged, so the existing tests were not rerun.

### 2026-10-18: control volume and read-only implementation

- Created initial documentation commit 55d4074 as requested. The user subsequently
  authorized committing the implementation described below.
- Added SHA-512-pinned Debian guest download, unprivileged QEMU TCG orchestration,
  disposable OS overlay and a 128 MiB virtio data disk. Guest kernel is Debian
  6.12.113+deb13-amd64; cryptsetup/libcryptsetup are pinned to 2:2.7.5-2.
  Guest dependencies otherwise resolve from live APT and are recorded per run.
- Added SHA-256-pinned upstream dm-crypt/dm-integrity/cryptsetup source subset
  fetcher. Source subset is upstream, not a full Debian source reconstruction.
- Run artifacts/control-001 failed with a kernel fault involving loopback over
  9p. Revised harness uses a dedicated virtio data disk. Run control-002 reached
  format/write successfully but failed at unsupported integritysetup --offset.
  Fixed the diagnostic to inspect a copied superblock.
- Clean run artifacts/control-003 passed stock-kernel full-volume readback.
  It has 28,244 primary sectors (115,687,424 bytes). Do not use failed runs as
  trusted fixtures. Generated artifacts/keys remain ignored and private.
- Implemented Python package pivstore: inspect, extract-ivs, verify. Delegates
  LUKS2 header validation to cryptsetup; independently maps integrity extents,
  rejects nonempty/torn or unsupported journals, and authenticates primary data
  with the cryptography library. Subsequent work below adds copy-output writes
  and hidden encoding.
- Validation: PIV_FIXTURE=artifacts/control-003 python3 -W error::ResourceWarning
  -m unittest discover -v passed 10 tests, including 12 corruption placements
  across ciphertext/tag/IV and interleave boundaries. Full userspace plaintext
  hash matches the independently generated stock-kernel hash. Python compilation,
  shell syntax checks, source checksums and git diff --check also passed.

### 2026-10-18: first complete offline payload experiment

- Implemented copy-output randomize-ivs: selected fresh IVs, recomputed primary
  ciphertext/tags, validated the entire result, and published with exclusive
  hard-link/fsync semantics. Current/new IV collisions are rejected; history is
  not knowable locally and external lifetime budgets remain unenforced.
- artifacts/verify-001 passed stock-Linux read-only authentication after changing
  sectors 0, 4095, 4096 and 28243. Complete primary hashes agree and raw-image
  digests before/after stock verification match.
- Added experimental pack/unpack and keygen CLI commands. V1 is one full-carrier
  record using random 32-byte salt, HKDF-SHA256 and ChaCha20-Poly1305; framing and
  padding are encrypted and UUID/size bound in AAD. Every pack rewrites every
  primary sector; incremental records are deliberately deferred. See
  docs/hidden-format.md for rationale, assumptions and outstanding crypto review.
- Packed/recovered a synthetic 4300-byte blob. artifacts/verify-packed-001 passed
  full stock-kernel primary readback and unchanged raw-image checks. All 28,244
  IVs changed; old/new IV sets were disjoint. Primary plaintext remained identical.
  This explicitly demonstrates a multiple-snapshot distinguisher with the primary
  key; no single-image indistinguishability claim follows.
- Added tests for empty/maximum/repeated payloads, wrong hidden key, corruption,
  tampering that preserves primary authentication, current-IV reuse rejection,
  selected write extents, short writes, failed publication, and SIGKILL during
  copying, before fsync publication, and immediately after publication.
  Interrupted runs can leave private .partial files; published-but-unacknowledged
  images can exist. These are process-crash tests, not physical power-loss tests.
- No further host packages were needed.
- Final validation: PIV_FIXTURE=artifacts/control-003 python3 -W
  error::ResourceWarning -m unittest discover -v passed all 22 tests. CLI keygen
  created a 32-byte mode-0600 file and rejected overwrite without changing it.
  Compileall, both guest shell syntax checks, pinned source checksums, and
  whitespace checks covering tracked and new files passed.
- Next concrete task: add deterministic ENOSPC/fsync-error/source-change coverage
  and a tracked matched-control comparison/benchmark command. Review the v1 crypto
  composition and conservative primary-key lifetime policy before expanding use.
  Also consider snapshot-pinned guest APT dependencies and independent review of
  the Debian source patch equivalence. Keep unknown/recoverable journals rejected.

### 2026-10-18: kernel K0 implementation started

- Committed the preceding investigation/roadmap as 5eadf73 at the user's request.
  Added an opt-in dm-crypt patch, fixed-layout query UAPI, refcounted misc control
  device, primary bio mutation filter and guest-only build/test harness. No
  carrier read/replacement command or kernel-backed FUSE commit exists yet.
- Pinned Debian 6.12.113-1 source archives. The orig dm-crypt matches our reviewed
  upstream source byte-for-byte; distro patches do not mention dm-crypt.c or its
  dm-audit.h dependency. The reproducible staging script checks these facts.
- Build dependencies are installed only inside fresh QEMU TCG guests. Use exact
  Debian headers/Module.symvers and GCC 14; never force-load or install on host.
- artifacts/kernel-001 stopped at compilation because no_llseek was removed;
  removed that obsolete callback. artifacts/kernel-002 compiled the module, then
  stopped at an overly strict boot/header config comparison. Debian headers add
  exactly four salt/signing entries absent from /boot/config. Added an exact
  allowlist check; a deliberate unrelated config change is correctly rejected.
- The primary needs a read-only wrapper above the write-capable private owner.
  The owner's bio filter alone cannot stop buffered writes dirtying its page
  cache before bio rejection. The guest test uses aligned direct writes against
  the owner and buffered writes against the read-only wrapper separately.
- Existing userspace regressions passed all 31 tests, with ResourceWarnings
  treated as errors. Source staging/reconstruction, Python compilation, shell
  syntax and whitespace checks passed. Guest execution results follow below.
- artifacts/kernel-003 built and loaded successfully and passed the ordinary-mode
  full read/write/hash checks. Its table-reload harness then failed ENOKEY:
  cryptsetup's keyring reference was unavailable in the separate dmsetup process.
  Use --disable-keyring for this disposable test activation and keep table/key
  bytes in process memory and stdin, never argv/logs. The control exposes no keys.
  Require the read-only-owner negative test to fail with EINVAL, not just any
  unrelated error, so this provisioning failure cannot masquerade as success.
- artifacts/kernel-004 was invalidated by editing its 9p-shared task.sh while Bash
  was executing it; it stopped with a malformed command before compilation.
  Do not modify a running guest's task file. Subsequent runs use frozen inputs.
- artifacts/kernel-005 passed profile/query authorization, bad-command/pointer,
  lower write-mode and direct-write rejection checks. Its read-only wrapper
  correctly returned EPERM for a buffered write; adjusted the harness to accept
  EPERM or EROFS and explicitly verify the wrapper's read-only flag.
- Further pinned-source review found stock cryptsetup 2.7.5 rejects unknown
  active-table tokens. The opted-in stack uses explicit dmsetup owner/lower
  teardown; K3 now includes setup-tool integration. This does not change the
  stopped volume's stock-readable format. Do not omit the opt-in token from
  kernel table status merely to bypass that parser.
- artifacts/kernel-006 reached read-only wrapper teardown, where removal raced
  a temporary device opener and returned EBUSY. Use dmsetup's bounded --retry
  removal for owner/wrapper/lower teardown (as opposed to forced or deferred
  removal); keep open-control lifetime assertions and stock readback afterward.
- artifacts/kernel-007 reproduced the transient wrapper EBUSY without retry.
- artifacts/kernel-008 passed the complete frozen-input guest workflow: matched
  module build/load; ordinary-mode primary write/read/hash; EINVAL on read-only
  owner setup; 48-byte profile queries; 0600/CAP_SYS_ADMIN checks including a
  privilege-dropped inherited fd; bad command/pointer rejection; writable lower
  device plus primary direct-write/discard/zero rejection; read-only wrapper
  buffered-write rejection; bounded teardown retry; ENODEV on an open control
  after target removal; module unload blocked until control close; stock module
  restoration and full primary hash/authentication readback. QEMU exited zero.
- Guest kernel remains 6.12.113+deb13-amd64, headers/kbuild 6.12.113-1, GCC
  14.2.0-19. Module.symvers SHA-256 is
  3422bf655efdd33b193614b1f081f50932e9952d539bd8b6c4888f4ccf815b5a.
  Configs, module info/binary, packages, dmesg and result are in the private run
  share. No BUG/Oops/WARNING was found; unsigned-module taint is expected. This
  was not a KASAN/lockdep run, concurrency stress or power-loss test.
- All kernel implementation changes after 5eadf73 remain uncommitted. No new host
  packages/privileges were needed. Next: K1 bounded authenticated tuple/IV reads,
  then one-sector replacement through that same lower integrity target; do not
  connect FUSE commits before K2 whole-record recovery.
