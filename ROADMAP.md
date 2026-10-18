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

## Kernel backend phase (K0–K3 prototype complete)

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

Status: complete in artifacts/kernel-update-002. PREPARE authenticates the old
sector and returns a request-local native encryption; APPLY authenticates both
versions, checks identical primary plaintext, and submits exact tuples through
the same integrity target. Independent Python and stock-kernel readback passed,
including boundary sectors and corrupt-original refusal.

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

Status: prototype gate passed. Persistent encrypted nonce reservations precede
encryption; a sealed external exact-tuple journal precedes mutation. Controller
adoption, idempotent replay, suspend/resume/key gates, actual VM interruption with
nonempty native journal replay, and journal-write EIO recovery were exercised.
The supported concurrency model serializes primary access across commits.
KASAN/lockdep, allocation injection and exhaustive race testing remain deferred;
this milestone does not claim general kernel hardening.

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

Status: complete in artifacts/kernel-online-002. serve-kernel provides strict
guest setup, native read-only primary access and the existing hidden FUSE file.
Mounted write/truncate/fsync, controller death during fsync, stale-mount restart,
concurrent primary reads, primary write rejection and stock readback passed.

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

## Completion and future work

The requested offline, online and native kernel prototype is implemented and
verified within its documented disposable-guest scope. No required implementation
milestone remains. Reproduce the native tests with kernel/README.md before
changing its protocol or persistence ordering. Future work should choose a
specific deferred research/hardening question rather than expand scope silently.
The regular-file backend retains its separately documented cleanup limitations;
these do not block the completed native demonstration.

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

### 2026-10-18: K1 authenticated-read milestone

- Committed K0 as 81ff43c at the user's request. This session's new read operation
  and accompanying documentation/tests remain uncommitted.
- Added PIV_READ_IV: one 48-byte fixed-layout request with version/size, generation,
  encryption-sector index, zero input IV and zero reserved words. Validate all
  fields/bounds before I/O; return only IV12 after successful native AEAD auth.
  No primary key/plaintext export and no control write operation exists.
- Read ciphertext plus tuple through the existing lower target, using native
  dm_crypt_integrity_io_alloc and crypt_convert_block_aead with the already-loaded
  transform. Wait for asynchronous crypto completion, wipe the private data page,
  and release buffers. Use GFP_NOIO, a memalloc_noio scope and stock crypto flags.
- Control holds its lifecycle mutex while borrowing cc for synchronous I/O. New
  presuspend hooks drain/block reads; resume/undo unblock. Key wiping occurs only
  after suspension and cannot race admitted reads. Dtr invalidates the pointer
  before freeing crypto state. Userspace copies occur outside this mutex. Query
  remains an immutable snapshot. This does not solve future mutation concurrency.
- artifacts/kernel-read-001 built/loaded and passed the first read implementation.
  artifacts/kernel-read-002 passed the refined version with deterministic overlap
  between a continuous reader and three suspend/resume cycles. Both passed clean
  reads at 0, 1, 4095, 4096 and 28243; repeated reads; malformed version/size/IV/
  reserved fields; stale generations; oversized indices; bad pointers; dropped
  privilege; suspended/key-wiped rejection; removed-fd behavior and module pins.
- Both runs rejected separately corrupted ciphertext, tag and IV on sector4096.
  Raw flips/restores happened only on the CLOSED guest-owned disk, never behind
  an active mapping. A healthy neighbor authenticated after each failed request;
  failed ioctls left their output buffers unchanged. Restored disks passed full
  stock dm-crypt readback with the original expected primary SHA-256. No control
  write was tested or implemented.
- kernel/read-fixture.py generates nonsecret corruption offsets and independently
  compares returned IVs afterward via pivstore's offline layout parser. Both
  runs' returned IVs matched; final source/archive/input comparisons passed.
  The first run needed scaffold.tar added to its share before the task started
  because the initial archive basename was scaffold-k1.tar. The final run uses
  the documented scaffold.tar basename and frozen inputs.
- Final guest dmesg had no BUG/Oops/WARNING/KASAN diagnostics; unsigned-module
  taint and deliberately rejected key-wiped resume were expected. No lockdep,
  KASAN, allocation/device fault injection or active-I/O removal stress was run.
  The 31 existing Python tests passed with ResourceWarnings treated as errors;
  compilation, shell syntax and whitespace checks passed. No host installation,
  kernel load, root access or additional tools were needed.
- Next concrete task: validate the lower journal configuration and recovery
  assumptions, then add request-local one-sector IV replacement with expected-old
  IV/owner checks and native data+metadata submission/flush. Preserve current
  authenticated-read/lifecycle regressions. K1 is incomplete until that update
  passes independent stock readback; K2 still gates all kernel-backed FUSE fsync.

### 2026-10-18: native update, recovery and mounted prototype completed

- Committed the preceding authenticated-read slice as 9d2295f. Implemented
  bounded PREPARE/APPLY, BEGIN/END/SYNC, request-local nonce override, exact-tuple
  replay, fail-stop device errors and pending-transaction resume/key gates.
  Lower writes carry integrity metadata through the existing target; no raw
  active-stack edits, full-image replacement, host modules or forced loads.
- Added kernel_api/owner/store and encrypted recovery.py. Setup validates the
  pinned profile, static superblock, lower journal table, device identities and
  holders. Stable UUID/state locks exclude other controllers. Only the RO wrapper
  exposes primary data. Native state must live on private guest root ext4.
- External nonce reservations are persisted BEFORE encryption; sealed exact-tuple
  journals are published BEFORE writes. Recovery authenticates the complete
  immutable journal before parsing metadata or applying anything. Sync every32
  sectors and final END precede acknowledgment. Orphan staging files are ignored;
  publication uses atomic rename, avoiding the earlier two-hardlink crash gap.
  Missing/corrupt state fails closed. Historical pre-adoption nonce use remains
  unknown; the 2^20 reservation limit is not a total primary-key lifetime proof.
- artifacts/kernel-update-002 passed native boundary/negative/lifecycle tests,
  including refusal of separately corrupted original ciphertext/tag/IV for reads,
  PREPARE and APPLY. Stock and host authenticated all28,244 primary sectors;
  original SHA256 b54b4937b0a9539574c7525d1634b3052cbb3836ca8d46211bb1cf03e4aaf1c4.
- artifacts/kernel-online-002 passed direct and mounted updates, controller kill
  during mounted fsync, restart roll-forward, idle stale-FUSE cleanup, concurrent
  read-only primary file/block reads and primary write rejection. Stock and host
  full primary SHA256 was
  3f2dac5061b1febe70c35742fcc287c8672634cd72a637469a4c5b0508b6bb44;
  host unpack matched the expected23-byte synthetic payload. The earlier online-001
  was stopped after an invalid mount-ID readiness test waited despite service
  restart; readiness now requires a successful payload read. It is not a passing run.
- artifacts/kernel-power-002 passed actual QEMU SIGKILL with a delayed write in
  flight after at least96 applied entries and durable external WAL. Before replay,
  the offline parser rejected the nonempty integrity journal. Reboot replayed
  stock dm-integrity and the external journal. A subsequent dm-flakey journal-write
  EIO failed closed, then repair/recreation/replay recovered the35-byte payload.
  Stock and host full authentication/hash and hidden-payload comparison passed.
  power-001 also passed the experiment. Host page cache survives QEMU death;
  these are not host-power-loss or exhaustive torn-write tests. Device-error
  recovery requires stack recreation; automatic rebuild under a mounted primary
  filesystem is outside scope. Healthy controller-death recovery reuses its stack.
- Builds retain the exact Debian6.12.113-1 source/headers/symbol provenance and
  6.12.113+deb13-amd64 guest from K0. No unexpected BUG/Oops/WARNING/KASAN
  diagnostics were found in final online/power logs; unsigned-module taint,
  deliberately blocked resume and injected EIO are expected.
- Final host suite:41 tests passed with ResourceWarning errors enabled using
  PIV_FIXTURE=artifacts/control-003. New tests cover crash boundaries, replay
  without reencryption, corrupted/wrong-key state, reservation budgets/abandonment,
  ownership, strict lower tables and state filesystem policy. Final validation-only
  refinements (UUID canonicalization, authenticate-before-metadata parsing and
  root-ext4 state policy) followed the frozen VM snapshots and passed host tests;
  the final streaming journal also authenticated/validated all28,244 real native
  tuples at full fixture size on the host;
  do not describe those snapshots as byte-identical to the final Python package.
- See docs/kernel-implementation.md for actual protocol/order/limitations and
  kernel/README.md for reproduction. No new host installation, root privileges
  or additional tools are needed. All disks/keys/downloads remain ignored.
  Prototype complete; independent crypto review, systematic deniability analysis,
  production rollback/key policy, incremental records and exhaustive kernel/crash
  hardening remain deliberately deferred, not implied by the successful demo.
