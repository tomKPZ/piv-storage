# Agent instructions

## Mission and authorization

Continue this project autonomously toward a small online prototype, now including coordinated primary writes, that
stores an independently encrypted auxiliary payload in persistent IVs while
preserving stock-Linux authentication and primary plaintext. Independent
read-only userspace diagnostics remain the compatibility reference;
the old offline mutation and FUSE/NBD services have been retired. The user intends
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
   docs/hidden-format.md, docs/native-blocks.md and docs/kernel-backend.md). Inspect
   git status and relevant code before changing anything.
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

- Maintain the paired native block interface, standalone bootstrap and independent
  read-only verification/extraction tools. The user authorized retiring FUSE/NBD,
  regular-file online service and offline mutation commands. Do not restore them
  as regression baselines; their history and prior results remain in Git.
- The user's intended interface is now TWO writable native block devices, hidden
  and decoy, supporting independent filesystems without NBD/FUSE in the data path.
  Read docs/native-blocks.md and the newest roadmap handoff first. Keep setup,
  persistence, nonce reservations, hidden crypto and both views under one shared
  kernel owner. External recovery state on the independent guest root filesystem
  is retained for the prototype; do not claim a self-contained deniable disk.
- NativeBootstrap initializes/replays unfinished fixed-volume adoption using the
  existing ledger/pending-v2 encoding. After native READY, kernel native.log owns
  history. Never rebuild missing adopted history from bootstrap state. Keep
  independent v1/v2 decoders for historical fixtures and native cross-checks.
- One backend must own the backing storage and coordinate both views. Never edit
  raw metadata behind an independently active dm-crypt mapping. Authentication,
  nonce freshness, cache coherence and minimum commit recovery remain required.
- A private external recovery journal is allowed for the VM experiment, with
  explicit deniability limitations. It is not permission to use real disks or
  claim crash safety without tests. Retain the independent hidden codec and image
  verifier as test references.
- The native backend extends dm-crypt and registers paired piv-view DM targets
  in the same experimental module.
  Preserve authenticated PREPARE, exact-tuple APPLY and suspend/controller lifetime
  gates. The new primary preparation/application controls deliberately permit
  requested plaintext changes, while the original APPLY must still reject them.
  Persist nonce reservations before encryption and the complete encrypted
  recovery journal before mutation. Authenticate all recovery ciphertext before
  parsing metadata or replay. Never regenerate tuples on uncertain completion.
  Use kernel/README.md to reproduce the K0–K3 tests. Do not claim the external
  state provides deniability or detects disk-and-state rollback.
- Build/load experimental kernel code only in disposable guests with matched
  source/config/symbol versions. Do not install host modules or force-load an
  ABI-mismatched module. Keep private owner bios rejected while the paired views
  coordinate writes. Sector journaling alone does not make hidden transactions
  atomic; preserve the native reservation/WAL/completion protocol.
- Pin one ordinary supported LUKS2/dm-integrity profile before broadening support.
  Confirm actual IV/tag lengths, sector/address units, AAD, tuple layout, padding,
  offsets, journal state and replay behavior from sources and kernel fixtures.
- Use maintained crypto libraries. Keep format parsing, sector crypto, carrier
  mapping, hidden records and persistence logic independently understandable.
- Reject unsupported/dirty formats and malformed metadata explicitly. Validate
  all offsets, sizes and arithmetic before reading or writing.
- Prefer supplied high-entropy keys initially; avoid implementing keyslot or
  password bootstrap machinery before the mechanism is established.
- Setup/diagnostics use Python with cryptography and cryptsetup; the data path
  is the experimental kernel module.
  Reproduce integration with scripts/vm.py and scripts/guest-control.sh; use
  scripts/guest-verify.sh for an existing output image. Read the documented 9p
  failure before changing the VM storage path. Tests use PIV_FIXTURE pointing
  to a successful control run; never use failed runs as trusted fixtures.
- The v2 hidden records use fresh salted derived ChaCha20-Poly1305 keys. Do not
  interpret this as independent cryptographic review. Bootstrap/kernel history
  cannot establish nonce usage before adoption; preserve the known synthetic
  lineage and external-state/rollback limitations.

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
- All writes pass through one coordinated native owner. Refresh every intersecting
  hidden record, reserve fresh IVs before encryption and journal exact tuples
  before mutation. Stock/uncoordinated writes can destroy hidden data. Only
  requested primary bytes may change; hidden-only updates preserve all primary
  plaintext. Never expose an independently cached bypass of the paired views.
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
