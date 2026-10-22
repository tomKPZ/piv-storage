# Stateless failure semantics and fault tests

The design keeps no private recovery plan, WAL or history. Primary
ciphertext/tag/IV updates go through the ordinary dm-integrity journal (or, with
the opted-in `--allow-no-journal`, stock direct mode; see
[journal-atomicity.md](journal-atomicity.md)). An interrupted hidden write may
leave that one 512-byte hidden block unreadable. A record's whole plaintext must
authenticate (SIV tag over all 90 fragments) before it is returned, so old and
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
  fabricates authenticated zeros. A full 512-byte hidden write repairs the block;
  it needs authenticated plaintext of all 90 carrier sectors.
- **Primary sectors failing authentication**: reads and partial writes return
  EIO. A decoy write covering the entire sector replaces it with a fresh IV and
  refreshed raw fragment (user decision 2026-10-21); the record's SIV tag still
  decides hidden validity.
- **Errors before the first APPLY** (lower read error, primary authentication
  failure, allocation, nonce-collision retry exhaustion, encryption cap, request
  validation) fail only that bio. Preparation may already have spent encryption
  invocations.
- **APPLY-time and flush errors** (standalone flush, PREFLUSH or completion
  flush) stop the shared owner and both views: storage may be partial or
  durability unknown. dm-integrity also enters its own sticky failed state on
  journal/metadata write errors. Unmount, remove and recreate the stack after
  correcting the underlying problem; there is no error-clearing control. An EIO
  write may have partially changed the disk.

Fault tests use only disposable synthetic guest disks. VM SIGKILL preserves the
host page cache and is not hardware power-loss evidence. Primary sector
authentication says nothing about hidden filesystem consistency or rollback.
All fault suites run per profile through `scripts/suite.py`; executed runs are
recorded in commit messages.

## Partial-record interruption (`power` suite)

scripts/guest-stateless-power.sh with kernel/guest-stateless-power.py
initializes the stock fixture, then reopens it through a dm-delay wrapper
(1 s write delay) and writes hidden block 0. An O_DIRECT raw observer reads the
record's 90 current tag/IV tuples and the dm-integrity journal (whole-section
commit IDs, pinned no-MAC entry layout) and cuts QEMU once some but not all of
the 90 carrier IVs have changed (`cut-boundary.json`; a run without the cut
fails). The observer never writes or bypasses the native owner; journal
inspection is test instrumentation, not a recovery implementation.

After reboot, scripts/guest-stateless-recover.sh lets stock cryptsetup replay
the journal and requires block 0 to be complete-old, complete-new or EIO, every
other hidden block unchanged and the full primary hash unchanged. A decoy write
must not silently repair an EIO block; a full hidden write then repairs it.
Stock full-primary readback and a stock dm-crypt coexistence check follow (this
suite produces no host-verified output image). On `*-nojournal` profiles torn primary sectors are allowed only inside
that record's carrier and are restored by full-sector decoy writes (the measured
hazard in journal-atomicity.md).

## Lower-device errors and setup cleanup (`faults` suite)

scripts/guest-faults.sh and kernel/guest-fault-test.py place a disposable
linear wrapper below stock dm-integrity and reload it as
[dm-flakey](https://docs.kernel.org/admin-guide/device-mapper/dm-flakey.html)
(`error_reads`, `error_writes` or one-sector `corrupt_bio_byte`) after
activation and once udev probes drain. Targets lie in hidden record 10, away
from sector 0, whose setup checkpoint may be served from dm-integrity's journal
cache. Decoy requests use an aligned 16 KiB span, hidden requests one 512-byte
block. A direct raw read witnesses each injected fault first.

- **Setup**: pivsetup's `PIVSETUP_TEST_FAIL` hook fails after cryptsetup open,
  before/after native setup and after each public view; a lower read error is
  injected during the kernel SETUP ioctl via `PIVSETUP_TEST_GATE`. Every
  attempt must remove exactly what it created. Conflicting lower/public names,
  existing owners and an unrelated replacement at close are preserved; both view
  names are validated before either is removed. On `*-nojournal` fixtures,
  opening without `--allow-no-journal` is refused and cleaned up.
- **error_reads** (both views): the read and an overlapping write fail with EIO,
  spend no encryption and leave the owner healthy; after restoration the same
  owner generation reads and rewrites the range and passes the complete
  primary/hidden oracles without repair.
- **error_writes** (both views): preparation spends encryptions, APPLY hits the
  failing write, the owner reports failure and both views keep rejecting I/O
  after the wrapper is restored. Only teardown/recreation clears it. Hidden
  blocks must match the oracle, with local EIO/repair allowed only for records
  intersecting the failed request (and, without the journal, torn sectors only
  within the request's span, restored by full-sector writes).
- **Late-sector corruption**: the corrupted sector is the last of one 16 KiB
  decoy work item or the last carrier sector of record 10. A decoy read must
  leave a sentinel-filled direct-I/O buffer unchanged (earlier sectors may have
  decrypted privately). A hidden read of record 10 still succeeds, because only
  primary data was corrupted and the raw IV feeds SIV-checked decoding. Partial
  writes into the failing sector fail before encrypting; a full-sector decoy
  write replaces it. Unrelated requests on both views continue and the same
  owner passes the oracles afterwards.
- **Setup audit**: with the same corruption, `--verify` refuses and cleans up,
  while the default keyslot-area setup opens and returns local EIO only for the
  damaged decoy sector. A corrupted keyslot sector does not block default setup
  (raw IV, keyslot SIV or the other replica decides); `--verify` refuses.
- **IV damage**: a flipped stored IV byte makes that hidden block and decoy
  sector EIO while neighbours stay intact.
- **Uncoordinated stock rewrite** of one carrier sector (same plaintext, fresh
  IV) destroys only that hidden block; a decoy rewrite preserves the damage; a
  full hidden write repairs it.

The test finishes with stock full-primary readback, a closed image for host
verification, and custom-module unload while stock crypt stays busy. Fixture
guards stay limited to QEMU /dev/vdb (128 or 512 MiB) plus the named test
wrappers. Cleanup is best effort, not hidden recovery, rollback, atomic
initialization or protection against hardware that acknowledges writes without
persisting them. These synthetic faults test authenticated-read withholding and
scoped failure, not adversarial journal replay or physical durability.

## Concurrent lifecycle and flush/FUA ordering (`lifecycle` suite)

scripts/guest-lifecycle.sh builds a separate test-only piv-io-test.ko
(kernel/piv-io-test.c) against the pinned guest headers and loads it beside
dm-piv.ko. Never link it into the production module or load it on the host. Its
root-only interface accepts two integers (public view, request mode), reads 512
bytes at sector 0 and writes the same bytes with plain, FUA or PREFLUSH|FUA
flags, or submits a flush. It accepts no keys, paths, offsets or payload and is
unloaded before stress begins.

Dynamic kprobe entry/return events around pn_worker, pn_write,
blkdev_issue_flush and bio_endio record function metadata and results, never
plaintext or keys. kernel/lifecycle_trace.py requires complete non-overlapping
ordered workers, successful paired lower flushes, a completed flush before write
return and public completion, and a preflush before a PREFLUSH payload (possibly
in a separate DM-split flush bio); a standalone flush must reach a native
worker. Probe misses, ring-buffer overruns, missing events and negative results
fail the test. See the [kprobe tracing documentation](https://docs.kernel.org/trace/kprobetrace.html).

Concurrent writers own disjoint logical regions sharing carrier groups and mix
direct and O_DSYNC writes with fsync while another thread suspends/resumes the
public views. Held descriptors must block removal, close and unload without
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
