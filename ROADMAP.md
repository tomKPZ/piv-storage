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

## Next target: a small online demonstration

Here online means a running service exposing a writable auxiliary file, with a
read-only primary view available through a coordinated path. No online code is
implemented yet. The first writable mount may run with the primary view closed;
completion of the demo includes simultaneous primary reads and hidden updates.

Keep one supported format, supplied high-entropy keys, one process, one hidden
file, and disposable VM disks. Reuse the whole-carrier v1 blob: buffer edits and
commit the whole blob on fsync/unmount. Incremental records, arbitrary primary
writes, multiple clients, a general hidden filesystem and a kernel driver are
not required. See [online design](docs/online-prototype.md).

### 1. Establish one owner and frontend contracts

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

## Later, only if the online experiment justifies it

Incremental hidden records, reduced write amplification, in-device transactions,
ordinary dm-crypt integration, kernel work, broader configurations, production
nonce/key policy, stronger crash testing, and systematic detectability evaluation.
These are not prerequisites for the first mounted demonstration.

## Session handoff

At the end of implementation sessions update this file with completed work,
commands/checks and results, known failures, blockers, and the next concrete task.
Add focused design notes when decisions become substantial. Never include keys,
passwords, real-data images, or sensitive host information.

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
