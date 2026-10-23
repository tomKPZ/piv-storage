# Stateless failure semantics and fault tests

The design keeps no private recovery plan, WAL or history. Primary
ciphertext/tag/IV updates go through the ordinary lower dm-integrity device:
journaled, or direct on stock persistent no-journal volumes (recommended for
deniability; see [journal-atomicity.md](journal-atomicity.md#no-journal-mode)).
An interrupted hidden write may leave that one 4096-byte hidden block
unreadable (unless RS parity recovers it); without the journal it can also
tear (EIO) the primary sectors it was rewriting (its record's
[shaped extent](native-blocks.md#write-shaping)), never others, and the
neighbouring records whose edge sectors it refreshed stay readable.
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
  block; it needs authenticated plaintext of all G carrier sectors and of the
  neighbouring sectors up to the 4 KiB edges of its shaped extent (a failing
  neighbour sector fails the write locally, before anything is written; the v5
  suite checks this with an unreadable first sector of the next record).
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
  bios, standalone flush, PREFLUSH, FUA completion flush, a hidden write's
  completion flush or the flush before an A/B slot rewrite) stop the shared
  owner and both views: storage may be
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
- **Plain decoy writes are not flushed** (stock dm-crypt semantics; hidden
  writes are). dm-integrity
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

## Status, scrub and repair

Two read-only, keyless pivsetup commands make failures visible beyond EIO and
dmesg. Both need root and bind the owner's control device (STATUS only);
`--device D` optionally checks that the owner belongs to that LUKS volume.

- **`pivsetup status [--name N]`** prints the owner state as JSON: `state`
  `active`, `failed` (the sticky fail-stop above, also after a failed setup),
  `idle` (a bare owner without native state) or `absent`, plus views, hidden
  size and blocks, parity, A/B, encryptions since setup and
  `rs_corrected_reads` (hidden-view block reads that authenticated only after
  RS correction). Exit 0 active, 2 failed, 3 absent or idle.
- **`pivsetup scrub [--name N] [--limit L] [--decoy]`** reads every hidden
  block once through the hidden view (one 4096-byte O_DIRECT read per block,
  so the kernel authenticates each record as for any read) and counts it as
  `valid`, `recovered` (its chosen record authenticated only after RS
  correction, attributed by the STATUS counter around each read) or
  `unavailable` (EIO). It lists up to L (default 64) recovered and unavailable
  block indices and, for each listed unavailable block, the decoy sectors of
  its record's shaped carrier (both slots with A/B) that read EIO. `--decoy`
  also reads the whole decoy view and lists every run of EIO sectors with the
  hidden blocks whose shaped carrier it intersects. Exit 0 clean, 4 recovered
  blocks only, 5 unavailable blocks or decoy EIO, 2 owner failed, 3 inactive,
  130 cancelled (SIGINT/SIGTERM stop it between blocks; the partial report has
  `complete: false`).

The scrub writes nothing: no encryption, no lower write (the v5 suite checks
both through STATUS and the lower device's block statistics), and its reads
follow the ordinary failure scope (a failing block fails only its read). It
runs on active, possibly mounted views. Limits: a concurrent reader of an
RS-corrected block can make a valid block count as recovered (never the other
way; `unavailable` is exact EIO), and concurrent writers can change blocks
after they were read (`encryptions_during_scrub` shows writes during the
scan). With A/B a damaged newest slot whose older slot authenticates reads as
valid (the older version), exactly as the hidden view returns it. It reads one
block at a time, at about the hidden read speed
([configuration.md](configuration.md#monitoring-and-repair-status-and-scrub)).

**Repair after damage** (a tear on a no-journal volume, media errors, a stock
read-write open):

1. `pivsetup status`. If the owner failed (exit 2), unmount both views, run
   `close-blocks`, correct the cause and reopen; a failed owner refuses all I/O.
2. `pivsetup scrub --decoy`. Decoy sectors that read EIO lost their plaintext
   (a torn sector cannot be read back). Restore them with whole-sector writes
   through the decoy view: restore the decoy files that own them, or, for
   sectors no decoy file uses, write any whole sectors there. A whole-sector
   decoy write replaces a failing sector (the documented exception) and keeps
   its hidden fragment, so it never changes which hidden blocks authenticate.
3. Rewrite each unavailable hidden block with a complete 4096-byte write (from
   a backup, or let the hidden filesystem's fsck rewrite what it needs). A
   hidden write needs every sector of the block's shaped carrier to
   authenticate, so step 2 must cover the sectors listed for that block first.
   Never use `--fill` for this: it turns unavailable blocks into zeros.
4. Recovered blocks still decode but have used part of their parity margin;
   rewriting a block with its own contents (read 4096 bytes, write them back)
   re-encodes all G carrier sectors once its carrier authenticates.
5. Run `pivsetup scrub --decoy` again; exit 0 means every hidden block reads
   without correction and no decoy sector reads EIO.

The faults suite checks this on journaled and no-journal fixtures: after a
lower write failure (fail-stop; `status` and `scrub` exit 2) and recreation,
`scrub --decoy` lists exactly the torn sectors, only blocks of the failed
request are unavailable and their listed carrier sectors are torn ones; after
restoring the sectors and rewriting the blocks the scrub is clean. The v5
suite covers quick-initialized blocks (unavailable, no decoy EIO), a stock
rewrite (unavailable, no decoy EIO), parity erasures and errors (recovered,
exit 4), erasures beyond the bound (unavailable, the unreadable sectors
listed) and A/B; devices covers loop, dm-linear and partition volumes and
the `--device` ownership check; cancel interrupts a scrub over a slowed
lower device.

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

The `powerab` suite runs the same test on a volume initialized with `--ab`
(block 0's slots are groups 2 and 3). On no-journal fixtures there is no
journal to observe: the observer also reads the carrier's data sectors and
cuts as soon as any data or tag byte of the span changed while the writer's
fsync is outstanding (results in
[journal-atomicity.md](journal-atomicity.md#no-journal-mode)).

After reboot, scripts/guest-stateless-recover.sh lets stock cryptsetup replay
the journal (journaled fixtures) and requires block 0 to be complete-old,
complete-new or EIO (A/B: never EIO), every
other hidden block unchanged and the full primary hash unchanged. Journaled
fixtures must show no torn primary sector. On no-journal fixtures every torn
sector must lie in the record span (the shaped extent); the test records them
(`power-results.json`), checks that a hidden rewrite fails with EIO while they
remain, and restores them by full-sector decoy writes of the pre-cut
plaintext before the remaining checks. A decoy write
must not silently repair an EIO block; a full hidden write then repairs it.
Stock full-primary readback and a stock dm-crypt coexistence check follow (this
suite produces no host-verified output image).

## ext4 on the hidden view (`ext4power` suite)

The `ext4power` suite (opt-in, in `--suites all`; scripts/guest-ext4-power.sh,
kernel/guest-ext4-power.py, scripts/guest-ext4-recover.sh) checks the
filesystem-level effect of the crash semantics above. vm.py's 4 GiB second
disk is split into two 2 GiB dm-linear halves, each luksFormatted with the
fixture's cipher and 512-byte sectors; one is initialized single-slot (5,488
hidden blocks) and one with `--ab` (2,744). Each hidden view gets ext4 (4 KiB
blocks, a 1,024-block journal, `commit=5`) and 64 synced baseline files, then
a 20–25 s concurrent workload on both: file creation, every fourth file
fsync'ed together with its directory (recorded on the host share only after
the fsyncs), unlinks and renames of older unsynced files. vm.py then kills QEMU
while writes are in flight. After the reboot the suite scans every hidden
block for EIO, mounts (journal replay), checks every baseline and recorded
file, unmounts and runs `e2fsck -fn`, checks both decoy hashes through dm-piv
and, after `rmmod`, through stock read-only cryptsetup. A/B must show no EIO
block, a clean replay, every recorded file intact and a clean fsck;
single-slot outcomes are recorded, not asserted (`ext4-power-results.json`).
On `*-nojournal` profiles both volumes persist stock no-journal; the recovery
first scans the decoy, requires torn sectors to lie in hidden record carriers
and restores them (the luksFormat-wiped zeros) before the hidden checks.

Results (2026-10-23, 16 cuts: suite-121 and suites 124–126, each with the four
fixture ciphers/profiles, 512-byte-sector ext4 volumes):

| Mode | Cuts | Cuts with EIO blocks | Mount and replay | Recorded files intact | `e2fsck -fn` clean |
| --- | ---: | ---: | ---: | ---: | ---: |
| `--ab` | 16 | 0 | 16 | 16 (127–300 files each) | 16 |
| single slot | 16 | 1 (one block, suite-125 aegis-512) | 16 | 16 (139–373 files each) | 16 |

The single-slot EIO block was a block the replay and fsck never read (an
unsynced or freed block): the mechanism the A/B recommendation addresses is
real, but in these 16 cuts it never hit journal or metadata blocks. That is
not evidence that single-slot ext4 is safe: a cut that leaves a journal,
metadata or synced-file block mid-rewrite would return EIO there, and jbd2
cannot replay through a read error. The cut is a QEMU SIGKILL with the host
page cache intact (writes QEMU completed survive; only guest-side state such as
dm-integrity's in-memory journal is lost), not a hardware power loss, and the
small sample says nothing about rare interleavings. Use `--ab` for hidden
filesystems ([configuration.md](configuration.md#ab-record-slots)).

No-journal before hidden writes flushed (suite-125 and suite-128, three
profiles, 12 volumes: 6 single-slot and 6 A/B): no hidden block read EIO,
every mount replayed, every recorded file was intact and fsck was clean; 5
volumes had torn sectors, all whole records at record boundaries (1 to 12
records, 687 sectors each), repaired by decoy writes before mounting. With
the completion flush (suites 137, 140 and 141, 18 volumes): no torn sector, no EIO block, every mount
replayed, every recorded file intact, fsck clean.

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
  intersecting the failed request. Journaled fixtures must show no torn
  sector; on no-journal fixtures torn sectors must lie within the request's
  span and are restored by full-sector decoy writes. Lower write faults during
  `--initialize` and `--fill` follow the same rule with the setup's write
  scope (the revocation's keyslot areas 1–3 and directory group 1, or the
  hidden-block records): on no-journal volumes dm-integrity's buffered tags
  can reach the disk at deactivation after their data writes failed.
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
[development.md](development.md#sanitizer-kernel).

## Cancelling activation, initialization and fill (`cancel` suite)

Native SETUP yields to the scheduler and checks pending signals between
authenticated primary read ranges (up to 1024 sectors each), between rounds of
complete hidden-record initialization or fill writes (8 blocks handled
concurrently per round), and around the final checkpoint before marking the native state
ready. Waiting for the setup lifecycle mutex is interruptible. The
ioctl returns EINTR when cancellation wins at one of these boundaries. There is
no abort ioctl, flag, on-disk marker or resume file; `--fill` resumes by
checking which records already authenticate.

The `pivsetup` frontend installs SIGINT and SIGTERM handlers without
SA_RESTART that only set a flag, so the interruptible SETUP ioctl returns EINTR.
pivsetup then removes the mappings its own attempt created and exits with
status 130. The ioctl request buffer holding the key is wiped after the call
either way.

### Guarantees and limits

By default setup scans only the 112-sector keyslot area, which is too short to
cancel reliably; `--verify` scans the whole primary. Cancelling either scan
leaves no ready native state or public views and spends no primary encryption.
Reopening repeats the scan; an incomplete scan is never adopted.

Cancellation during `--initialize` waits for the current round of up to 8
concurrent record writes to finish; every round is flushed before the next
one starts, and cancellation is polled only then, so the completed records
are as durable as after an uncancelled initialization. Initialization first
writes a new master key into keyslot 0 and the directory, then the zero
records in rounds: within each run of 16 blocks the 8 even blocks, then the 8
odd ones (adjacent blocks' shaped rewrites share a 4 KiB unit and would
serialize). The completed blocks are therefore whole rounds, not always a
prefix: they read as authenticated zeros and every other block returns EIO,
because its old record no longer authenticates under the new master key (the
cancel suite derives the completed rounds from the encryption count). Setup does not poll between the keyslot
and directory writes; only a crash there could leave a keyslot without a
directory, which later opens refuse until `--initialize` is retried.

This is destructive partial initialization, not rollback or persistent
progress. Reopening without `--initialize` exposes the mixed content. Retrying
`--initialize` starts from block zero with a fresh master key and random
encodings and consumes additional primary encryptions. To resume instead,
open with `--fill`: blocks completed before the cancellation authenticate and
are skipped; every other block receives a zero record. A cancelled fill
behaves the same way (whole rounds of up to 8 blocks completed, flushed before
returning) and another `--fill` resumes it. A quick initialization
(`--initialize --quick`) writes no records at all; its only uninterruptible
writes are keyslot 0 and the directory.
Storage errors and power loss keep the existing torn-record/EIO limitations;
cancellation is not a crash transaction.

On cancellation the kernel frees temporary native state, crypto transforms and
its copied setup request; the frontend removes its own device stack and closes
its ownership lock. This is resource cleanup in the tested paths, not
physical-memory key-erasure assurance: dumps, privileged memory access and
external artifacts remain outside that claim. pivsetup reports any cleanup that
could not complete.

There is no hard latency deadline. An in-flight lower read, record write, flush,
allocation or checkpoint must finish, so a stalled device delays cancellation.
Closing a raw control descriptor can wait for another operation's mutex, even
after its own SETUP ioctl was interrupted while waiting for it. Other control
commands are not generally interruptible.

SIGKILL, process death and repeated interruption of cleanup bypass the
frontend's cleanup; private mappings may then need manual removal, especially
if a probe is blocked on a suspended device. SIGINT is the regression-tested
path; SIGTERM uses the same handler without a dedicated test. Activation steps
before the native ioctl, including cryptsetup journal replay, are not made
transactional or mutation-free. These limits also apply to early-boot use;
service shutdown needs a caller that delivers one of these signals.

### Draining failed private setup

A cancelled setup can leave udev probing a suspended private owner, so a plain
`dmsetup remove --retry` can fail while the probe holds it open. Failed-setup
cleanup therefore closes its control descriptor, checks the captured device
identity, and replaces the newly created private owner's table with an error
target (`dmsetup wipe_table --noflush`) before removing it. Deferred probes get
EIO, the private target releases its state and the lower integrity device is
then removed normally. Only the transient mapping changes, not the stored
ciphertext.

This applies only to an owner created by the failed attempt. Public views must
be removed normally first; a busy view stops cleanup. Existing owners,
foreign/replaced identities and normal close keep the ordinary refusal rules.
There is no promise of atomic cleanup against privileged external table races,
busy public views or hardware that never completes a request.

### Test procedure

scripts/guest-cancel.sh runs kernel/guest-cancel-test.py over a dm-delay
wrapper on the closed 128 MiB native fixture. The harness runs pivsetup as the
child setup client; its `PIVSETUP_TEST_GATE` hook provides a handshake before
the native ioctl and reports the kernel status after it. Module-qualified
kprobes witness actual range reads (filtered to the child's PID) or pn_write
calls (which run on the module's workqueue; nothing else writes during the
test), and `/proc/PID/syscall` must show the SETUP ioctl before a signal is
sent; a signal delivered before entering the kernel does not count. While the
task is on a CPU that file reads `running` even inside the ioctl (a single
such sample once failed the scan check on aes-sha256-512), so the checks
resample until the task is observed blocked.

- **Scan** (`--verify`, 25 ms lower read delay, at least three range reads
  witnessed): a second raw SETUP caller is interrupted while the first holds the
  setup mutex and must report EINTR before the first scan is cancelled. The
  encryption counter must stay zero.
- **Initialize** (2 ms lower write delay, short enough that one round of
  records finishes within the signal-to-exit timeout; at least two pn_write
  entries witnessed): the retained counter must equal 28 keyslot + 687
  directory + 687 per completed record, with at least two and fewer than 64
  records completed (whole rounds of 8, except a shorter last round).
- **Fill** (after a quick initialization; same delay and witness): the counter
  must equal 687 per completed record (a fill writes no keyslot or directory),
  with the same bounds.

After each initialize/fill cancellation the reopened views are checked as
below, then `--fill` must report exactly the completed records as valid
(skipped), every other block as written and none failed, and the whole hidden
view must then read as zeros.

Each cancellation must report EINTR with inactive status, no views, zero hidden
capacity and no failure, exit 130 without cleanup notes, leave no mappings or
control nodes, keep the wrapper identity, and have no missed probes or trace
overruns. Reopened views must match the full primary hash and, for the
initialization and fill cases, zeros in the completed rounds and EIO elsewhere. A
normal full initialization then runs to completion, followed by close, custom
unload, stock full-primary readback and host verification of `cancel-final.img`
against `expected-cancel-hidden`.

The `faults` suite covers the related setup-phase failures and ownership rules
([above](#lower-device-errors-and-setup-cleanup-faults-suite)).

```sh
python3 scripts/suite.py --prefix artifacts/cancel-next --profile aegis-4096 \
  --scaffold artifacts/stage-next/scaffold.tar --suites cancel
```

Executed results are recorded in commit messages; a trace or interrupted
process alone is not a successful run.

## Running

```sh
python3 scripts/suite.py --prefix artifacts/faults-next --profile aegis-4096 \
  --scaffold artifacts/stage-next/scaffold.tar --suites faults,power,lifecycle
```

Use `--reuse-native PREFIX` to start from a previous matrix's verified native
run. suite.py verifies every closed output image on the host with
scripts/check_stateless.py; see [development.md](development.md).
