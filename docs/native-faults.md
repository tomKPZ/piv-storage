# Stateless failure semantics and fault tests

The design keeps no private recovery plan, WAL or history. Primary
ciphertext/tag/IV updates go through the ordinary dm-integrity journal (the
only supported mode; see [journal-atomicity.md](journal-atomicity.md)). An interrupted hidden write may
leave that one 4096-byte hidden block unreadable (unless RS parity recovers it).
A record's whole plaintext must authenticate (SIV tag over all 687 data
fragments, after any RS correction) before it is returned, so old and
new carrier fragments are never mixed into a valid block. Independently valid
blocks can still represent different times; there is no cross-block
transaction, hidden crash recovery or rollback resistance.

## Failure scope

- **Hidden authentication failure** is local: that hidden request returns EIO;
  the owner stays healthy and decoy access is unaffected. Hidden reads use the
  raw stored IVs of carrier sectors that fail primary authentication, so
  data-area damage alone does not make a hidden block unavailable; IV damage does
  (the SIV tag rejects the wrong fragment).
- **Decoy writes over damaged hidden blocks** re-randomize only the written
  sectors' IVs and preserve their fragments, so damage stays damage. Nothing
  fabricates authenticated zeros. A full 4096-byte hidden write repairs the
  block; it needs authenticated plaintext of all G carrier sectors.
- **Unreadable or damaged carrier sectors with parity** (`--parity p`): up to p
  per lane (erasures: unreadable or failing authentication) or p/2 per lane
  (foreign fragments in authenticating sectors) are corrected on read; beyond
  that the block returns EIO, never other data. An unreadable carrier whose
  record still fails returns EIO and never falls back to an older A/B slot.
  Hidden writes stay strict. The v5 suite injects dm `error` segments over
  chosen carrier sectors and stock rewrites, and restores old raw tuples to
  emulate an interrupted rewrite (mixed versions).
- **Primary sectors failing authentication**: reads and partial writes return
  EIO. A decoy write covering the entire sector replaces it with a fresh IV and
  refreshed raw fragment (user decision 2026-10-21); the record's SIV tag still
  decides hidden validity.
- **Errors before the first lower write** (lower read error, primary
  authentication failure, allocation, nonce-collision retry exhaustion,
  encryption cap, encryption, request validation) fail only that bio. Every
  request reads, authenticates and encrypts all its sectors before submitting
  any write ([write path](native-blocks.md#write-path)); encryption
  invocations may already have been spent.
- **Errors once writing began and flush errors** (any of a request's write
  bios, standalone flush, PREFLUSH, FUA completion flush or the flush before an
  A/B slot rewrite) stop the shared owner and both views: storage may be
  partial or durability unknown. dm-integrity also enters its own sticky failed
  state on journal/metadata write errors. Unmount, remove and recreate the
  stack after correcting the underlying problem; there is no error-clearing
  control. An EIO write may have partially changed the disk.
- **Setup-time fill** (`--fill`) applies the same split per block: a block
  whose carrier cannot be read or authenticated, before anything of it was
  written, is left as it was and counted as failed while the fill continues;
  a write error, a flush error or a non-local error (allocation, encryption
  cap, nonce retries) fails the whole setup, which removes the attempt's
  private owner like a failed `--initialize`. Records completed earlier stay.
- **Concurrent requests at a fail-stop.** Requests run concurrently
  ([concurrency](native-blocks.md#concurrency)). One that has not yet started
  writing when the owner stops writes nothing and fails with EIO (it checks
  before encrypting and again before its first write bio); a write or flush
  still in flight completes with EIO, since whether it reached storage is
  unknown; requests waiting for a range lock proceed and fail the same way, so
  nothing hangs. Reads that already authenticated their data may still return
  it.
- **Plain writes are not flushed** (stock dm-crypt semantics). dm-integrity
  completes a journaled write before committing it, so a lower write error
  often surfaces only at the next commit: a flush, FUA, journal watermark or
  commit timer. The failing request is then the flush (or a later write once
  dm-integrity has entered its failed state), and earlier writes that reported
  success may be lost, as with stock dm-crypt.

Fault tests use only disposable synthetic guest disks. VM SIGKILL preserves the
host page cache and is not hardware power-loss evidence. Primary sector
authentication says nothing about hidden filesystem consistency or rollback.
All fault suites run per profile through `scripts/suite.py`; executed runs are
recorded in commit messages.

## Partial-record interruption (`power` suite)

scripts/guest-stateless-power.sh with kernel/guest-stateless-power.py
initializes the stock fixture, then reopens it through a dm-delay wrapper
(1 s write delay) and writes hidden block 0 followed by fsync. A record is
written as a few multi-sector bios and committed at the latest by that flush,
so at 512-byte sectors (a record fits below dm-integrity's 50% journal
watermark) the stock journal would commit it in one write: the test first
commits a few identical-plaintext decoy rewrites (each followed by fsync, since
plain writes are not flushed) so the record crosses the watermark part way and
dm-integrity commits its first part alone (4096-byte records exceed the watermark anyway; the prefill is recorded
in `cut-boundary.json`). An O_DIRECT raw observer reads the
record's 687 current tag/IV tuples and the dm-integrity journal (whole-section
commit IDs, pinned no-MAC entry layout) and cuts QEMU once some but not all of
the 687 carrier IVs have changed (`cut-boundary.json`; a run without the cut
fails). The observer never writes or bypasses the native owner; journal
inspection is test instrumentation, not a recovery implementation.

After reboot, scripts/guest-stateless-recover.sh lets stock cryptsetup replay
the journal and requires block 0 to be complete-old, complete-new or EIO, every
other hidden block unchanged and the full primary hash unchanged. A decoy write
must not silently repair an EIO block; a full hidden write then repairs it.
Stock full-primary readback and a stock dm-crypt coexistence check follow (this
suite produces no host-verified output image).

## Lower-device errors and setup cleanup (`faults` suite)

scripts/guest-faults.sh and kernel/guest-fault-test.py place a disposable
linear wrapper below stock dm-integrity and reload it as
[dm-flakey](https://docs.kernel.org/admin-guide/device-mapper/dm-flakey.html)
(`error_reads`, `error_writes` or one-sector `corrupt_bio_byte`) after
activation and once udev probes drain. Targets lie in hidden record 10, away
from the keyslot area, whose setup checkpoint may be served from
dm-integrity's journal cache (sector 0 has its own test below). Decoy requests use one aligned 128 KiB span (a whole decoy work item),
hidden requests one 4096-byte block. A direct raw read witnesses each injected
fault first.

- **Setup**: pivsetup's `PIVSETUP_TEST_FAIL` hook fails after cryptsetup open,
  before/after native setup and after each public view; a lower read error is
  injected during the kernel SETUP ioctl via `PIVSETUP_TEST_GATE`. Every
  attempt must remove exactly what it created. Conflicting lower/public names,
  existing owners and an unrelated replacement at close are preserved; both view
  names are validated before either is removed.
- **error_reads** (both views): the read and an overlapping write fail with EIO,
  spend no encryption and leave the owner healthy; after restoration the same
  owner generation reads and rewrites the range and passes the complete
  primary/hidden oracles without repair.
- **error_writes** (both views): encryption is spent, the request's writes hit
  the failing device (at its write bios or, since dm-integrity completes
  journaled writes before committing them, at the fsync's flush), the owner
  reports failure and both views keep rejecting I/O
  after the wrapper is restored. Only teardown/recreation clears it. Hidden
  blocks must match the oracle, with local EIO/repair allowed only for records
  intersecting the failed request (and, without the journal, torn sectors only
  within the request's span, restored by full-sector writes).
- **Late-sector corruption**: the corrupted sector is the last of one 128 KiB
  decoy work item or the last carrier sector of record 10. A decoy read must
  leave a sentinel-filled direct-I/O buffer unchanged (earlier sectors may have
  decrypted privately). A hidden read of record 10 still succeeds, because only
  primary data was corrupted and the raw IV feeds SIV-checked decoding. A
  hidden write needing the failing sector fails before encrypting (a
  sub-sector decoy write on a 4096-byte volume never reaches the module: the
  decoy view's logical block size is the sector size, so the block layer
  returns EINVAL); a full-sector decoy write replaces it. Unrelated requests on both views continue and the same
  owner passes the oracles afterwards.
- **Setup audit**: with the same corruption, `--verify` refuses and cleans up,
  while the default keyslot-area setup opens and returns local EIO only for the
  damaged decoy sector. A corrupted keyslot sector does not block default setup
  (raw IV, keyslot SIV or the other replica decides); `--verify` refuses.
- **IV damage**: a flipped stored IV byte makes that hidden block and decoy
  sector EIO while neighbours stay intact.
- **Sector 0 damage** (keyslot 0, replica 0): its fragment destroyed by a stock
  rewrite and its data failing authentication. Default setup unlocks through
  replica 1, `--verify` refuses, and setup, END (on an idle owner) and DETACH
  all succeed: their journal checkpoint copies the first keyslot-area sector
  that reads and authenticates instead of requiring sector 0.
- **Setup write faults**: lower writes fail for exactly the SETUP ioctl of an
  `--initialize` (its first write revokes keyslot area 1) and of a `--fill`
  after a quick initialization. Setup returns EIO, STATUS reports the owner
  failed (sticky, with no native state left), pivsetup removes what it
  created, the failed initialization leaves the previous volume intact, and a
  later fill completes and the contents are restored. Inside setup, a work item
  whose write began and failed stops the owner at once, so the other blocks of
  its round write nothing more; a failed flush stops it too. Cancellation
  (EINTR) is not a failure.
- **Uncoordinated stock rewrite** of one carrier sector (same plaintext, fresh
  IV) destroys only that hidden block; a decoy rewrite preserves the damage; a
  full hidden write repairs it.

The test finishes with stock full-primary readback, a closed image for host
verification, and custom-module unload while stock crypt stays busy. The
test harness keeps its fixtures on the guest's disposable /dev/vdb (128 or 512
MiB; scripts/guest-common.sh); pivsetup itself accepts the dm-delay/dm-flakey
wrappers like any other block device. Cleanup is best effort, not hidden recovery, rollback, atomic
initialization or protection against hardware that acknowledges writes without
persisting them. These synthetic faults test authenticated-read withholding and
scoped failure, not adversarial journal replay or physical durability.

## Concurrent lifecycle and flush/FUA ordering (`lifecycle` suite)

scripts/guest-lifecycle.sh builds a separate test-only piv-io-test.ko
(kernel/piv-io-test.c) against the pinned guest headers and loads it beside
dm-piv.ko. Never link it into the production module or load it on the host. Its
root-only interface accepts two integers (public view, request mode), reads 4096
bytes at sector 0 (the hidden view's logical block) and writes the same bytes
with plain, FUA or PREFLUSH|FUA flags, or submits a flush. It accepts no keys, paths, offsets or payload and is
unloaded before stress begins.

Dynamic kprobe entry/return events around pn_worker, pn_write,
blkdev_issue_flush and pn_endio (module-qualified, resolving compiler suffixes
such as `.constprop`; pn_endio is the worker's public-bio completion; a
bio_endio probe also caught about 20,000 interrupt-context lower completions
per v5 run, a few of which nested in another probe's handler and were counted
as misses) record function metadata and results, never plaintext or keys.
Workers run concurrently, so kernel/lifecycle_trace.py groups events per
kworker PID (one kworker runs one work item at a time) and uses the globally
ordered trace for cross-worker order. It requires complete workers (entry,
completion, return), successful paired non-nested lower flushes, no flush inside
pn_write, a plain write completing without any flush, a FUA write completing
only after a successful flush that follows its write, a completed flush before
a PREFLUSH payload starts (possibly in a separate DM-split flush bio), and a
standalone flush reaching a native worker. Probe misses, ring-buffer overruns,
missing events and negative results fail the test. See the [kprobe tracing documentation](https://docs.kernel.org/trace/kprobetrace.html).

Concurrent writers own disjoint logical regions sharing carrier groups and mix
direct and O_DSYNC writes with fsync while another thread suspends/resumes the
public views (the stress suite adds heavier concurrency, overlapping writes and
a fault under load; [native-blocks.md](native-blocks.md#reproduce)). Held descriptors must block removal, close and unload without
changing mapping identities; a request queued on a suspended view waits for
resume while its peer stays usable. Complete oracles are checked afterwards and
after a new owner generation, followed by stock full-primary readback and
unload.

This is a public-view lifecycle contract. Administrative suspension or
replacement of the private owner/lower mappings while views are active is
unsupported. Kernel flush return/order does not prove that hardware honoured
persistence or that a hidden record is atomic. Sanitizer runs are described in
[sanitizer.md](sanitizer.md).

## Running

```sh
python3 scripts/suite.py --prefix artifacts/faults-next --profile aegis-4096 \
  --scaffold artifacts/stage-next/scaffold.tar --suites faults,power,lifecycle
```

Use `--reuse-native PREFIX` to start from a previous matrix's verified native
run. suite.py verifies every closed output image on the host with
scripts/check_stateless.py; see [development.md](development.md).
