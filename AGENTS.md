# Agent instructions

## Mission and authorization

Continue this project autonomously toward a small online prototype that
stores an independently encrypted auxiliary payload in persistent IVs while
preserving stock-Linux authentication and primary plaintext. The existing offline
prototype is the compatibility baseline; the user has reduced further offline
scope to prioritize a mounted demonstration. The user intends
future sessions to implement it without significant human direction. Unless the
user gives a different task, inspect current state and advance the next useful
milestone in ROADMAP.md; do not stop after merely proposing work.

README.md and ROADMAP.md are provisional. Verify assumptions against pinned
sources and experiments. Change architecture, sequencing, or scope when evidence
justifies it, and record the reason. Do not treat unverified design prose as a
security specification. Respect tool/sandbox approval requirements.

## Start and finish each session

1. Read README.md, ROADMAP.md, applicable nested instructions, and existing design
   notes (especially docs/development.md, docs/observed-layout.md and
   docs/hidden-format.md, docs/online-prototype.md and
   docs/online-implementation.md). Inspect git status and
   relevant code before changing anything.
2. Determine what is actually implemented and tested. Recheck environmental
   assumptions as needed; the initial host is WSL2 without visible DM/KVM nodes.
3. Select a bounded task with observable exit criteria. Continue through its
   implementation and appropriate verification without routine design questions.
4. Update roadmap status and handoff notes with results, remaining uncertainties,
   blockers and next steps. Report what changed and what was actually tested.

Do not overwrite unrelated changes or claim tests passed when they were skipped.
If dependencies or privileges are missing, perform useful independent work and
request only the concrete access needed. Do not install large toolchains or build
a kernel speculatively. Ask the user when a consequential choice cannot be
resolved from context/evidence, not for routine implementation decisions.

## Implementation priorities

- Preserve the offline CLI and regression tests, but advance the online milestones
  in ROADMAP.md instead of expanding offline hardening or evaluation. Defer
  unrelated benchmarks, alternative profiles and complete environment pinning.
- Target one writable hidden file and a read-only primary view on disposable VM
  storage. Reuse the whole-carrier v1 format and serialize commits initially.
  A kernel driver, general hidden filesystem and primary writes are not required.
- One backend must own the backing storage and coordinate both views. Never edit
  raw metadata behind an independently active dm-crypt mapping. Authentication,
  nonce freshness, cache coherence and minimum commit recovery remain required.
- A private external recovery journal is allowed for the VM experiment, with
  explicit deniability limitations. It is not permission to use real disks or
  claim crash safety without tests. Prefer userspace frontends before kernel work.
- The first online backend uses regular-file image replacement, not in-place
  writes: prepare/verify/fsync a copy, hold old/new inode locks plus a stable path
  lock, replace the canonical path, and fsync its parent. Reuse this simpler path
  before considering block-device transactions. Never delete the stable
  .pivstore.lock sidecar on shutdown or recover from orphan staging copies.
- Pin one ordinary supported LUKS2/dm-integrity profile before broadening support.
  Confirm actual IV/tag lengths, sector/address units, AAD, tuple layout, padding,
  offsets, journal state and replay behavior from sources and kernel fixtures.
- Use maintained crypto libraries. Keep format parsing, sector crypto, carrier
  mapping, hidden records and persistence logic independently understandable.
- Reject unsupported/dirty formats and malformed metadata explicitly. Validate
  all offsets, sizes and arithmetic before reading or writing.
- Prefer supplied high-entropy keys initially; avoid implementing keyslot or
  password bootstrap machinery before the mechanism is established.
- Current implementation is Python with cryptography and the host cryptsetup CLI.
  Reproduce integration with scripts/vm.py and scripts/guest-control.sh; use
  scripts/guest-verify.sh for an existing output image. Read the documented 9p
  failure before changing the VM storage path. Tests use PIV_FIXTURE pointing
  to a successful control run; never use failed runs as trusted fixtures.
- The v1 hidden blob rewrites the entire carrier using a fresh salted derived
  ChaCha20-Poly1305 key. Do not interpret its design argument as independent
  cryptographic review. Primary nonce history/budgets are not enforced by the CLI;
  preserve and make explicit the disposable-lineage limitation.

## Invariants to preserve

- All primary plaintext remains byte-for-byte identical after a hidden update,
  and unmodified Linux verifies every supported primary sector.
- Authenticate the original primary data before modifying it. A replacement IV
  requires recomputed primary ciphertext and tag with exact Linux AAD.
- GCM nonce uniqueness is per primary key across sectors and time. Different
  addresses/AAD do not permit reuse. Repeated hidden data must be freshly
  randomized on rewrite. Specify retries, rollback, clones and lifetime budgets.
- An authenticated current image cannot reveal its full historical nonce usage;
  do not claim that a local collision scan solves lifetime nonce safety.
- Raw edits bypass dm-integrity journaling. Never assume its atomicity protects
  them; reject unrecovered journal state until a supported workflow is proven.
- Existing offline updates require a closed mapping. Online updates must pass
  through a single coordinated owner with a defined commit/recovery path;
  the primary view remains read-only. Ordinary primary writes are unsupported
  and may destroy hidden data.
- Hidden-record authentication, whole-record transactions, primary-sector
  atomicity and rollback resistance are separate properties.
- No public hidden magic/header or assumed-random padding. Review pseudorandomness
  of the entire stored encoding, not merely the selected encryption primitive.

## Verification and claims

Use small reproducible fixtures and pure userspace checks first, then stock Linux
inside a disposable VM. Cross-check crypto against independently generated kernel
data. Verify full primary hashes/authentication, corruption rejection, hidden
round trips and nonce behavior. Add meaningful boundary/error/crash tests as
features require them. Compare against matched ordinary controls for detectability.

Keep correctness, crash safety and deniability claims separate. Multiple snapshots,
journals, memory and host artifacts are explicit limitations. Statistical tests
cannot prove indistinguishability. If experiments contradict the intended threat
model, document the result candidly and revise the plan.

## Data and operational hygiene

Use only disposable synthetic data and test keys. Never put keys in argv, logs,
commits, fixtures, or documentation. Keep generated disks, VM images, secrets and
large downloaded sources out of git; add scoped ignore rules when creating them.
Do not touch real disks or erase/format unrelated storage. Default destructive
experiments to guest-owned disposable images. Do not commit or publish unless
requested. Keep source revision and test-environment provenance reproducible.
