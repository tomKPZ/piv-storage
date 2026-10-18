# Implementation roadmap

This is a revisable research plan. Milestones express evidence to obtain, not
commitments to a particular architecture. Update status and decisions as work
progresses. A discovery that invalidates the mechanism is a useful result:
document it and pursue a justified alternative rather than forcing this plan.

Current status: documentation only; no milestones completed.

Environment preflight (2026-10-18): QEMU/qemu-img 10.2.1 installed; unprivileged
TCG startup and QMP shutdown passed. KVM access is denied to the current user,
but is optional. Python cryptography 46.0.5 and OpenSSL 3.5.5 are available;
a C AES-GCM compile/link/run smoke test passed. cryptsetup/integritysetup 2.8.4
are installed. No additional host package is currently required for the first
userspace/VM workflow. Guest image/kernel acquisition and an actual guest boot
are the next environment tasks; guest DM/AEAD support is not yet verified.
Use the ignored vendor/, downloads/, artifacts/, work/ and secrets/ directories
for local dependencies and generated data. Initial repository commit contains
documentation and ignore rules only; implementation has not begun.

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
