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
   docs/hidden-format.md, docs/native-blocks.md, docs/native-faults.md and
   docs/security-review.md, docs/read-performance.md and docs/large-volumes.md and docs/cancellation.md). Inspect
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

- The user prioritizes remaining work that requires core module changes. Follow
  ROADMAP.md's core-first order; include necessary tests/docs with each change.
  Do not fabricate kernel features to defer useful validation. Concrete security
  defects override feature ordering; standalone tooling/assessment comes later.
- Maintain the paired native writable decoy/hidden block devices, one coordinated
  kernel owner and independent read-only image/record decoders. No FUSE/NBD,
  offline writer, legacy decoding, external history/WAL, bootstrap or compaction.
- The user explicitly selected a stateless design. Persist only ordinary stock
  LUKS/dm-integrity structures and encrypted records inside IVs. No separate
  partition, root-ext4 file or hidden-volume metadata dependency. /run ownership
  locks are volatile. Early activation must be possible from an initramfs.
- User-approved planned changes (2026-10-20; see ROADMAP.md items 3-8). Until
  each lands with tests, the current rules below remain in force:
  - Scoped error isolation replaces whole-owner fail-stop where nothing was
    mutated; a stateless wrong-key activation guard.
  - A standalone AEAD-sector target replaces the vendored dm-crypt fork.
  - Format v4: fragment-local re-randomization of touched IVs; an encrypted
    in-IV hidden header (indistinguishable, no public magic; fast key check,
    key wrapping, version/flags) without any persistent encryption counter;
    optional A/B record slots; support for stock `--integrity-no-journal`
    (default decided after the journal-atomicity experiment).
  - AEGIS-128 becomes the recommended default profile.
  - Setup userspace may later be ported to Rust; Python diagnostics remain.
  Multi-snapshot observers, rollback resistance and alternative hidden openings
  under coercion are out of scope. Never put host-specific (e.g. corporate
  kernel) identifiers in the repository.
- One authenticated record covers exactly one hidden 512-byte logical block in
  48 primary IVs for AES/ChaCha or 36 for original AEGIS-128. Full-block authentication prevents old/new fragment mixing;
  cross-block transactions, hidden crash recovery and rollback resistance are
  NOT goals. Interrupted updates may leave hidden blocks returning EIO.
- Decoy access must not depend on hidden-record authentication. A decoy write
  refreshes valid hidden records, or writes a fresh encrypted invalid marker for
  absent/damaged/wrong-key records. Never turn corruption into authenticated
  zeros. Full hidden writes may repair a block after primary authentication.
- Fresh seeded CRNG entropy is mandatory. Local proposed/replaced IV collision
  rejection is only a small check, not lifetime nonce history. The 2^32 per-owner
  encryption counter resets at recreation and does not enforce the per-key
  lifetime budget. Document probabilistic collisions, amplification, retries,
  rollback and clones. Do not resurrect an observable nonce ledger.
- Preserve authenticated PREPARE/exact-tuple APPLY and owner lifetime gates.
  Apply through the ordinary lower dm-integrity journal; its per-sector atomicity
  does not make a hidden record atomic. Storage/primary-auth errors stop the
  shared owner. Local hidden unavailability must not stop the decoy.
- Decoy bios are bounded to 16 KiB at power-of-two DM split boundaries, hidden
  bios to 512 bytes. Retain the two-carrier-group/96-tuple preparation bound,
  ordered work and lower preflush/completion-flush semantics. Batching is within
  one bio, not cross-bio writeback. Tail primary sectors have no hidden record.
- Setup polls pending signals and yields between authenticated ranges and
  complete initialization records. Keep cancellation outside pn_write: completed
  records stay committed, full scan is mandatory on retry, and cancellation is
  not rollback. Failed-attempt cleanup may errorize only its newly created,
  identity-checked private owner to drain probes; never force public views or
  existing/foreign mappings. Normal close retains busy-device protection.
- Larger geometry uses checked kernel file-offset bounds rather than a 256 MiB
  primary cap. Frontend/VM fixtures allow only pinned QEMU /dev/vdb at 128 or
  512 MiB, plus explicitly opted-in test wrappers. Never broaden this into
  arbitrary host-device activation as a side effect of geometry work. The actual
  validated raw size must reach extent parsing. Live resize is unsupported.
- Native setup, decoy reads and carrier collection use bounded 16 KiB range
  reads. Authenticate every sector with unchanged Linux AAD/tag offsets before
  publishing any range bytes or IVs. Keep per-sector crypto counts and late-sector
  corruption/no-output regressions; fewer submissions must never skip checks.
- Build dm-piv.ko as a separate module registering piv-crypt/piv-view. Keep
  stock dm-crypt/crypt loaded and independent; never unload it to activate ours.
  Keep private sysfs workqueue names distinct (kpiv_io/kpiv_crypt): independent
  stock/fork ID allocators can collide during a suspended table reload.
  Build/load experimental kernel code only in disposable guests with exact
  source/config/symbol matches. Never install host modules or touch real disks.
  scripts/fetch_kernel.py stages the COMPLETE module including dm-audit.h;
  kernel/prepare.py alone stages only the patch and is insufficient for a build.
- Supported profiles: LUKS2 AES-GCM/random (integrity aead) or ChaCha20-Poly1305
  via chacha20-random (integrity poly1305), or original aegis128-random
  (integrity aead). All support 512/4096-byte sectors and 16-byte tags; AES/ChaCha
  use 32-byte keys and 12-byte IVs, AEGIS uses 16-byte keys and 16-byte IVs.
  Integrity v4 fixed padding and the ordinary journal are required. Validate geometry,
  AAD, extents and arithmetic. Offline diagnostics reject dirty journals; native
  setup delegates replay to Linux before authenticated access.
- Use maintained crypto primitives. Setup uses Python standard library/cryptsetup; diagnostics use cryptography plus the optional pinned
  SUPERCOP AES-NI reference for original AEGIS-128 (not 128L);
  actual crypto/I/O runs in the experimental kernel module. Retain the independent
  codec and complete primary verifier as cross-checks. Only synthetic test keys.

## Invariants to preserve

- All primary plaintext remains byte-for-byte identical after a hidden update,
  and unmodified Linux verifies every supported primary sector.
- Authenticate the original primary data before modifying it. A replacement IV
  requires recomputed primary ciphertext and tag with exact Linux AAD.
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
link it into dm-piv or load it on the host. Lifecycle traces must have complete
worker/flush/completion ordering and zero missed/overrun events; absent evidence
is a test failure. Private owner/lower administrative mutations while views are
active are outside the supported public-view lifecycle.

Use small reproducible fixtures and pure userspace checks first, then stock Linux
inside a disposable VM. Cross-check crypto against independently generated kernel
data. Verify full primary hashes/authentication, corruption rejection, hidden
round trips and nonce behavior. Add meaningful boundary/error/crash tests as
features require them. Compare against matched ordinary controls for detectability.

Matched controls live in scripts/guest-controls.sh and scripts/analyze_controls.py.
Use pristine stock fixtures, distinguish same-workload writes from deliberate
ordinary reencryption controls, and exclude native initialization only explicitly.
Live journal samples are not atomic; byte statistics are descriptive, not a
security acceptance test. Retain observed snapshot/I/O distinctions in claims.

Retain the observer boundaries in docs/security-review.md. A single raw image
can include journal history; high-entropy hidden keys are required because records
provide an offline guessing oracle. The owner counter does not enforce the GCM
per-key lifetime requirement. Internal source review is not external crypto review.

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
