# Implementation roadmap

This is a revisable research plan. Milestones express evidence to obtain, not
commitments to a particular architecture. Update status and decisions as work
progresses. A discovery that invalidates the mechanism is a useful result:
document it and pursue a justified alternative rather than forcing this plan.

Current status: milestones 0-3 have initial working implementations for the
narrow tested profile, including stock-kernel verification of a packed image.
Milestone 4 has caught-error and process-crash tests; stronger persistence work
and independent crypto review remain. Milestone 5 has an observed snapshot
distinguisher but no systematic single-image steganalysis or benchmark suite.
Next: strengthen persistence/error coverage and reproducible comparative analysis;
do not broaden profiles or build a filesystem before reviewing these limits.

Environment preflight (2026-10-18): QEMU/qemu-img 10.2.1 installed; unprivileged
TCG startup and QMP shutdown passed. KVM access is denied to the current user,
but is optional. Python cryptography 46.0.5 and OpenSSL 3.5.5 are available;
a C AES-GCM compile/link/run smoke test passed. cryptsetup/integritysetup 2.8.4
are installed. No additional host package is currently required for the first
userspace/VM workflow. Guest image/kernel acquisition and guest DM/AEAD support
subsequently passed; see the session handoff below.
Use the ignored vendor/, downloads/, artifacts/, work/ and secrets/ directories
for local dependencies and generated data. Initial repository commit 55d4074
contains documentation and ignore rules only.

## 0. Establish a reproducible environment

- Inventory host capabilities and choose a userspace implementation language and
  maintained crypto library. Favor reproducibility and format correctness.
- Set up a small disposable Linux VM for privileged integration. Pin guest image,
  kernel, cryptsetup, crypto library, and relevant source revisions.
- Create scripts to generate an ordinary authenticated control volume, fully
  initialize it, cleanly close it, and collect nonsensitive configuration data.
- Record actual cipher, IV/tag sizes, sector size, integrity mode and layout.

Exit: another session can reproduce the control image and stock-kernel readback
from documented commands. Identify unsupported capabilities instead of silently
substituting a different cipher or format.

## 1. Prove the carrier and sector codec

- Inspect pinned source and format documentation; document address units, AAD,
  tuple order, interleaving, padding, offsets, and clean-journal detection.
- Implement read-only image inspection with strict bounds/version validation.
- Use a supplied disposable primary volume key; defer password/keyslot support.
- Extract IVs and authenticate/decrypt selected sectors in userspace.
- Cross-check against kernel-generated fixtures, then scan all sectors.

Exit: userspace primary plaintext exactly matches the stock mapper, and deliberate
IV/tag/ciphertext corruption fails correctly. Unsupported layouts fail closed.

## 2. Demonstrate compatible IV replacement

- Choose fresh random replacement IVs for a small set of sectors.
- Recompute ciphertext/tags into a separate output image; input stays unchanged.
- Open the result with unmodified Linux and compare the entire primary plaintext.
- Exercise beginning/end boundaries, metadata interleave transitions, offsets,
  multiple sectors, malformed images, and clean/dirty journal cases.

Exit: full-volume kernel authentication and identical primary plaintext, with
only intended data/metadata regions changed. No in-place update claim yet.

## 3. Define and implement the auxiliary blob

- Write a short design decision for hidden crypto and its complete serialized
  output, record dimensions, encrypted metadata, initialization, key input, and
  capacity calculation. Document the pseudorandomness argument and assumptions.
- Start with high-entropy hidden keys; defer password bootstrap if necessary.
- Specify global primary-nonce budgets, repeated-plaintext behavior, retries,
  snapshot restoration, and clone limitations before implementing hidden writes.
- Add pack/unpack operations on copies and authenticated record validation.
- Test empty/max-size blobs, wrong keys, corruption, record swaps, repetition,
  and hidden-record version reversion. Track nonce histories in test harnesses.

Exit: randomized hidden round trips preserve stock-kernel primary readback;
capacity/overhead and unsupported workflows are explicit. No visible hidden
format signature is introduced. Crypto/design review findings are recorded.

## 4. Make copy-output operations recoverable

- Specify output creation, exclusive access, flush/fsync, validation, publication,
  cleanup, and recovery semantics. Avoid implicit replacement of the input.
- Inject interrupted writes, short writes, disk-full errors and process crashes
  at persistence boundaries. Keep partial output clearly distinguishable to the
  operator without placing a signature in the completed IV carrier.
- Test that failures preserve the input and cannot be reported as successful.

Exit: repeatable crash tests support a precisely scoped durability claim for
copy-output operation. Document host/guest filesystem assumptions.

## 5. Evaluate detectability and tradeoffs

- Compare against matched ordinary control images, with and without primary keys.
- Analyze carrier repetitions/correlations, complete image diffs, journal history,
  and multiple snapshots. Include unchanged primary plaintext after reencrypting.
- Measure 4096 versus 512-byte capacity, update latency, write amplification,
  metadata overhead, and GCM lifetime-budget consumption.
- Publish observed distinguishers and limitations; randomness tests are diagnostic
  only. Reconsider the design if the target threat model is not met.

Exit: reproducible evaluation with bounded claims and a justified supported
profile, not an assertion of universal plausible deniability.

## 6. Optional extensions, selected by evidence

- In-place transactions: review supported dm-integrity write paths versus a
  custom transaction protocol; solve primary tuple and multi-record atomicity.
- Mounted auxiliary filesystem: FUSE over the established record engine.
- Auxiliary block interface: NBD/ublk if block semantics are actually useful.
- Kernel integration: narrowly scoped dm-crypt IV selection or a custom target
  only if userspace cannot satisfy justified requirements.
- More profiles, password-derived keys, redundancy, controlled primary writes,
  or alternative nonce/mode designs, each with explicit security analysis.

Do not make these prerequisites for completing the offline experiment.

## Session handoff

At the end of implementation sessions update this file with completed work,
commands/checks and results, known failures, blockers, and the next concrete task.
Add focused design notes when decisions become substantial. Never include keys,
passwords, real-data images, or sensitive host information.

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
