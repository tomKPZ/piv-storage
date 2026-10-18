# Small online prototype

Status: a single-owner backend, read-only NBD export and one-file FUSE frontend
are implemented. The user reduced further offline scope to prioritize this demo.
The working offline codec, whole-carrier format and stock-Linux tests remain the
reference. This plan is provisional; see docs/online-implementation.md for the
actual regular-file commit/recovery contract.

## User-visible target

Run one service on disposable VM storage. Expose one writable auxiliary file and
a read-only primary block view suitable for mounting a primary filesystem. Edit,
truncate, fsync, restart and recover the auxiliary file while preserving every
primary plaintext byte and its authentication. An initial hidden-only mount may
keep primary access closed; the finished demo includes simultaneous primary reads.

Keep supplied high-entropy keys, the existing AES-GCM/random profile, a single
process/client and v1 whole-carrier encoding. Buffer auxiliary edits in memory;
fsync/unmount commits the complete record. Returning from write means buffered,
not durable. Full-volume rewrite cost and pausing reads during commits are
acceptable prototype limitations. No incremental allocator or general filesystem
format is required.

## Provisional architecture

One userspace backend exclusively owns a regular-file backing image and holds
both keys while serving updates. The implemented frontends are NBD for
authenticated primary reads and FUSE for one hidden file. Test them in the guest; do not
require host root or physical devices. Confirm actual guest dependencies during
implementation rather than installing toolchains speculatively.

Do not open an independent dm-crypt mapping over storage being mutated by the
service. A filesystem mounted read-only does not solve underlying metadata-cache
or racing-I/O problems. Route all active primary reads through the owner; pause
them while committing and resume only after a complete consistent state exists.
Reject primary writes at the block frontend. Perform stock dm-crypt compatibility
checks after stopping the service and closing its backing storage.

The shared sector codec and held-image copy writer now support a distinct owned
online path while preserving strict offline behavior. The owner uses a stable
path lock plus inode locks and serializes commits/reads. Block devices remain
deferred: whole-image preparation followed by atomic rename is the simpler first
commit mechanism. The image must live on the guest's local filesystem, not 9p.

## Minimum mutation/recovery contract

In-place tuple updates would need a new transaction protocol. The implemented
regular-file prototype instead leaves the current image intact until a fully
authenticated/fsynced replacement is ready, atomically replaces its path, then
fsyncs the parent directory before acknowledging. Restart authenticates the
canonical old/new complete image, never a staging copy. Do not assume
dm-integrity journaling covers userspace writes.

A private external recovery journal remains permitted if later device-backed work
requires it; the current regular-file approach does not need one. Specify its contents,
identity binding, persistence ordering, commit marker, startup recovery and error
behavior. It must not store keys or primary plaintext. It can contain encrypted
sector tuples and reveal update history; its presence weakens deniability. A
hidden/in-device journal is deferred, and no online deniability claim follows.

On interruption, restore or finish one complete record transaction before serving
either view. Restoring an old ciphertext/IV/tag tuple is distinct from performing
a new encryption with that IV; the latter can violate nonce safety. Primary
plaintext is frozen, but previous-image branches and unknown nonce histories
remain unsupported. Fail closed on uncertain recovery state or authentication
failure. Do not acknowledge fsync before the documented commit boundary.

## What is deferred

- Production durability and real hardware power-loss guarantees.
- Exhaustive offline fault coverage and performance/steganalysis frameworks.
- Password/keyslot UX, primary writes, multiple writers and alternative profiles.
- Incremental records, efficient small writes, a general hidden filesystem,
  transparent ordinary dm-crypt coexistence, and custom kernel integration.
- Fully pinned guest package repositories and complete distro source analysis.
- Formal deniability claims and independent crypto review as a launch gate for
  this disposable experiment; those remain necessary work before stronger claims.

## Focused success checks

Keep existing offline regressions passing. Demonstrate hidden write/truncate,
fsync and remount/restart; primary read rejection of corruption and primary write
rejection; serialized reads/commits; recovery at selected interruption points;
identical full primary hashes before/after; and final stock-Linux authentication
with the service stopped. Document write amplification, blocking, external-journal
exposure and untested durability rather than constructing a broad evaluation suite.
