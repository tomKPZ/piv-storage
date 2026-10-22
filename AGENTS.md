# Agent instructions

## Mission and authorization

Continue this project autonomously as a small online prototype that stores an
independently encrypted auxiliary (hidden) payload in the persistent random IVs
of a stock LUKS2 + dm-integrity volume while preserving stock-Linux
authentication and primary plaintext. Independent read-only userspace
diagnostics remain the compatibility reference. The user intends
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
   docs/format-v5.md, docs/native-blocks.md, docs/native-faults.md and
   docs/security-review.md, docs/journal-atomicity.md, docs/read-performance.md,
   docs/large-volumes.md, docs/cancellation.md and packaging/README.md). Inspect
   git status and relevant code before changing anything.
2. Determine what is actually implemented and tested. Recheck environmental
   assumptions as needed (the current host has KVM; see docs/development.md).
3. Select a bounded task with observable exit criteria. Continue through its
   implementation and appropriate verification without routine design questions.
4. Keep ROADMAP.md to what remains (no session history: git keeps it); record
   executed runs and evidence in commit messages and the relevant docs. Report
   what changed and what was actually tested.

Do not overwrite unrelated changes or claim tests passed when they were skipped.
If dependencies or privileges are missing, perform useful independent work and
request only the concrete access needed. Do not install large toolchains or build
a kernel speculatively. Ask the user when a consequential choice cannot be
resolved from context/evidence, not for routine implementation decisions.

## Implementation priorities

- The user prioritizes remaining work that requires core module changes. Follow
  ROADMAP.md's order; include necessary tests/docs with each change.
  Do not fabricate kernel features to defer useful validation. Concrete security
  defects override feature ordering; standalone tooling/assessment comes later.
- Maintain the paired native writable decoy/hidden block devices, one coordinated
  kernel owner and independent read-only image/record decoders. No FUSE/NBD,
  offline writer or external history/WAL.
- The user explicitly selected a stateless design. Persist only ordinary stock
  LUKS/dm-integrity structures and encrypted records inside IVs. No separate
  partition, root-ext4 file or hidden-volume metadata dependency. /run ownership
  locks are volatile. Early activation must be possible from an initramfs.
- Format v5 (docs/format-v5.md, design user-approved 2026-10-22) is the only
  hidden format; it replaced format v4 outright (no migration, no dual
  support). v5: LRW-randomized fragments (10 random + 6 payload bytes per
  16-byte IV), 4 KiB SIV records of 687 fragments plus optional Reed–Solomon
  parity (3p fragments, p ∈ {4, 8, 16}, off by default), encrypted keyslots (no
  public magic) carrying the layout parameters, a directory, Argon2id
  passphrase KEKs with cost tiers 1–4 (default 3, recorded nowhere) and
  optional A/B slots. Never add a persistent encryption counter. Formats v3
  and v4, v3's invalid markers and the 12-byte-IV AES-GCM/ChaCha20-Poly1305
  profiles were removed (v3/12-byte IVs by user decision 2026-10-21, "option
  A"; they cannot carry v5); do not reintroduce them. The "AEGIS-128 only"
  part of option A was reversed on 2026-10-22.
  To reduce maintenance (user decision 2026-10-22, after the suite-072 bench)
  stock no-journal volumes (refused: little dm-piv gain, torn decoy sectors on
  a crash; docs/journal-atomicity.md), the scrypt KDF and the Serpent/Twofish
  and HMAC-SHA1/SHA512 profiles were removed; do not reintroduce them without
  a user decision.
  Multi-snapshot observers, rollback resistance and alternative hidden openings
  under coercion are out of scope. Never put host-specific (e.g. corporate
  kernel) identifiers in the repository.
- One authenticated record covers exactly one hidden 4096-byte logical block in
  G = 687 + 3p primary IVs (A/B: two records per block); the hidden view's
  logical block size is 4096. Full-block authentication prevents old/new
  fragment mixing; RS parity only adds availability and never accepts a
  record without its SIV tag;
  cross-block transactions, hidden crash recovery and rollback resistance are
  NOT goals. Interrupted updates may leave hidden blocks returning EIO.
- Decoy access must not depend on hidden-record authentication. A decoy write
  re-randomizes only the written sectors' IVs and preserves their fragments
  (damage stays damage). Never turn corruption into authenticated zeros. Full hidden writes may repair a block after primary authentication.
- Fresh seeded CRNG entropy is mandatory. Local proposed/replaced IV collision
  rejection is only a small check, not lifetime nonce history. Any volatile
  per-owner encryption cap (currently 2^40) is an implementation choice that
  may be raised or removed; it does not enforce the per-key lifetime budget.
  Document probabilistic collisions, amplification, retries, rollback and
  clones. Do not resurrect an observable nonce ledger.
- IVs and metadata tuples are generated, authenticated and written only inside
  the kernel owner. The control device exposes only QUERY, DEVICES, BEGIN/END,
  SETUP, DETACH, STATUS and KEYSLOT; never re-add userspace IV or tuple access.
  Write through the ordinary lower dm-integrity journal; its per-sector atomicity
  does not make a hidden record atomic. Failure scope follows mutation: errors
  before the first lower write of a request (reads, authentication, allocation,
  preparation) fail only that bio; errors once writing has begun, and flush
  errors, stop the shared owner. Local hidden unavailability must not stop the
  decoy.
- Wrong-key guard: setup without initialize requires a keyslot to
  authenticate, using IVs from the keyslot-area scan, and refuses without the
  keyslot directory. There is no
  uninitialized-carrier mode (removed with v3); stock carriers must be
  initialized.
- Bio size bounds, preparation batch sizes, worker topology and cross-bio
  concurrency or batching are implementation choices that may change for
  performance (user decision 2026-10-22: the earlier one-bio-at-a-time ordered
  worker rule was removed). Any design must still serialize updates that touch
  the same hidden record, keep stock PREFLUSH/FUA/flush semantics and the
  failure-scope rules above. Tail primary sectors have no hidden record.
- Setup polls pending signals and yields between authenticated ranges and
  complete initialization records, never inside a record write: completed
  records stay committed, the keyslot-area scan repeats on retry, and
  cancellation is not rollback. Failed-attempt cleanup may errorize only its newly created,
  identity-checked private owner to drain probes; never force public views or
  existing/foreign mappings. Normal close retains busy-device protection.
- Larger geometry uses checked kernel file-offset bounds rather than a 256 MiB
  primary cap. pivsetup's activation guards (pinned QEMU guest, 128/512 MiB
  /dev/vdb, --allow-test-stack/--allow-second-disk) were removed by user
  approval (2026-10-22): `--device` is required and any block device or
  partition is accepted. Keep the user-protecting checks: root, block devices
  only, no partitioned whole disk, busy-device refusal (holders, exclusive
  openers), the exclusive /run lock, mapping identity checks, refusal of
  foreign/unexpected stacks and tables, profile validation and checked
  geometry. Agent testing must still use only disposable guests and synthetic
  disks (the harness guards in scripts/guest-common.sh stay; they protect the
  host); never touch real disks. packaging/ (DKMS, initramfs-tools hook,
  install.sh) is verified by the `deploy` suite. The actual validated raw size
  must reach extent parsing. Live resize, rekey and cipher
  change are out of scope (stock cryptsetup refuses them on integrity volumes;
  user decision 2026-10-22); `pivsetup migrate` is the offline path.
- Read sizes for setup, decoy reads and carrier collection are implementation
  choices (bounded memory). Authenticate every sector with unchanged Linux
  AAD/tag offsets before publishing any range bytes or IVs. Keep per-sector
  crypto counts and late-sector corruption/no-output regressions; fewer
  submissions must never skip checks.
- Build dm-piv.ko as a standalone module (dm-piv.c, no dm-crypt fork)
  registering piv-crypt/piv-view. Keep stock dm-crypt/crypt loaded and
  independent; never unload it to activate ours. Keep workqueue names distinct
  from stock kcryptd names (piv-native/kpiv_io). The owner never accepts
  ordinary writes and never prints its key. Build/load experimental kernel code
  only in disposable guests with exact header/config/symbol matches. Never
  install host modules or touch real disks. scripts/fetch_kernel.py (or
  kernel/prepare.py) stages the complete module source.
- Supported profiles (stock, 16-byte random IVs): LUKS2 original
  aegis128-random (integrity aead; not AEGIS-128L; default) and aes-xts-random
  with integrity hmac-sha256 (dm-crypt authenc; 32- or 64-byte XTS key plus
  the 32-byte HMAC key; 32-byte tags), 512/4096-byte sectors. Integrity v4
  fixed padding and the ordinary journal are required. Validate geometry,
  AAD, extents and arithmetic. Offline diagnostics reject dirty journals; native
  setup delegates replay to Linux before authenticated access.
- Use maintained crypto primitives. Setup is the static Rust `pivsetup` binary
  (rust/; keep dependencies few, maintained and pinned by Cargo.lock) plus
  cryptsetup, built rootlessly by scripts/build_pivsetup.py. Keys stay in
  mlocked, zeroized buffers and never reach argv. Python keeps only diagnostics
  and guest test instrumentation. Test hooks are explicit PIVSETUP_TEST_*
  variables, never monkeypatching. Diagnostics use cryptography (AES-XTS, HMAC) plus the
  optional pinned SUPERCOP AES-NI reference for original AEGIS-128 (not 128L);
  actual crypto/I/O runs in the experimental kernel module. Retain the independent
  codec and complete primary verifier as cross-checks. Only synthetic test keys.

## Invariants to preserve

- All primary plaintext remains byte-for-byte identical after a hidden update,
  and unmodified Linux verifies every supported primary sector.
- Authenticate the original primary data before modifying it. A replacement IV
  requires recomputed primary ciphertext and tag with exact Linux AAD. Sole
  exception (user decision 2026-10-21): a decoy write covering an entire primary
  sector that fails authentication replaces it, refreshing its raw stored
  fragment; the record's SIV tag still decides hidden validity.
- Setup scans only the 112-sector keyslot area by default (user decision
  2026-10-21); every request authenticates what it touches. `--verify`
  (PIV_SETUP_VERIFY) is the strict full audit. Never publish unauthenticated
  bytes or IVs; raw IVs of failing sectors may feed only SIV-checked decoding.
- Primary AEAD nonce uniqueness is per key across sectors and time. Different
  addresses/AAD do not permit reuse. Repeated hidden data must be freshly
  randomized on rewrite. Specify retries, rollback, clones and lifetime budgets.
- An authenticated current image cannot reveal its full historical nonce usage;
  do not claim that a local collision scan solves lifetime nonce safety.
- Raw edits bypass dm-integrity journaling. Never assume its atomicity protects
  them; reject unrecovered journal state until a supported workflow is proven.
- All writes pass through one coordinated native owner. Refresh every intersecting
  hidden record with fresh randomness before primary encryption.
  Stock/uncoordinated writes can destroy hidden data. Only
  requested primary bytes may change; hidden-only updates preserve all primary
  plaintext. Never expose an independently cached bypass of the paired views.
- Hidden-record authentication, whole-record transactions, primary-sector
  atomicity and rollback resistance are separate properties.
- No public hidden magic/header or assumed-random padding. Review pseudorandomness
  of the entire stored encoding, not merely the selected encryption primitive.

## Verification and claims

Guest test scaffolding lives in scripts/guest-common.sh, automatically frozen by
vm.py. Reuse it rather than duplicating guards, builds and package setup.
kernel/piv-io-test.c is a separate guest-only exact-bio-flags test helper; never
link it into dm-piv or load it on the host. Lifecycle traces must show the
flush/completion ordering the design promises, with zero missed/overrun events;
absent evidence is a test failure (update the expected ordering when the worker
design changes). Private owner/lower administrative mutations while views are
active are outside the supported public-view lifecycle.

Use small reproducible fixtures and pure userspace checks first, then stock Linux
inside a disposable VM. Cross-check crypto against independently generated kernel
data. Verify full primary hashes/authentication, corruption rejection, hidden
round trips and nonce behavior. Add meaningful boundary/error/crash tests as
features require them. Compare against matched ordinary controls for detectability.

Matched controls live in scripts/guest-controls.sh and scripts/analyze_controls.py
(stock and native arms over the same workload). Use pristine stock fixtures and
exclude native initialization only explicitly.
Live journal samples are not atomic; byte statistics are descriptive, not a
security acceptance test. Retain observed snapshot/I/O distinctions in claims.

Retain the observer boundaries in docs/security-review.md. A single raw image
can include journal history; high-entropy hidden keys are preferred because
keyslots provide an offline guessing oracle (passphrases rely on the KDF cost).
The owner counter does not enforce any per-key lifetime budget. Internal source
review is not external crypto review.

Keep correctness, crash safety and deniability claims separate. Multiple snapshots,
journals, memory and host artifacts are explicit limitations. Statistical tests
cannot prove indistinguishability. If experiments contradict the intended threat
model, document the result candidly and revise the plan.

## Data and operational hygiene

Use only disposable synthetic data and test keys. Never put keys in argv, logs,
commits, fixtures, or documentation. Keep generated disks, VM images, secrets and
large downloaded sources out of git; add scoped ignore rules when creating them.
Do not touch real disks or erase/format unrelated storage. Default destructive
experiments to guest-owned disposable images. Commit each completed, verified update automatically (standing user authorization).
Do not publish or push unless requested. Keep source revision and test-environment provenance reproducible.
