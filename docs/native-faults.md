# Stateless failure semantics and experiments

The external recovery/history protocol and its root-ext4 ENOSPC/compaction tests
were removed with the stateless architecture. Historical results in Git do not
establish the current crash behavior.

Primary ciphertext/tag/IV updates go through the ordinary dm-integrity journal.
No private cross-sector recovery plan is written. Interrupted hidden writes may
leave one 512-byte logical block unreadable. A record's entire plaintext must
authenticate before return; its old/new carrier fragments cannot be returned as
valid fragments. Independently valid blocks can still represent different times.

A hidden authentication failure means local EIO, not global fail-stop. Decoy
reads remain available. A decoy write overlapping an unavailable hidden block
stores a fresh encrypted invalid marker, never fabricated valid zeros. A full
512-byte hidden write repairs the block after authenticating the primary carrier.
A primary authentication or storage I/O failure stops both views. Unmount/remove
and recreate after correcting the underlying problem; do not clear an error flag
on a mounted stack. An EIO write may have partially changed the disk.

Fault tests use only disposable synthetic guest disks. VM SIGKILL preserves the
host page cache and is not hardware power-loss evidence. Never infer hidden
filesystem consistency or rollback resistance from primary sector authentication.
See ROADMAP.md for current executed tests and artifacts.

## Reproduce the partial-record interruption

First build the exact module with the native test. Use fresh output directories:

```sh
python3 scripts/vm.py run --code \
  --script scripts/guest-stateless-power.sh \
  --power-cut-script scripts/guest-stateless-recover.sh \
  --run-dir artifacts/stateless-power-next \
  --data-image artifacts/control-003/control.img \
  --share-file artifacts/stateless-next/share/experimental-dm-piv.ko \
  --share-file kernel/guest-stateless-power.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key --timeout 3600
```

The guest initializes zeros on the stock fixture before introducing dm-delay.
An O_DIRECT raw observer validates whole journal-section commit IDs, parses the
pinned 48-byte (512-byte primary) or 104-byte (4096-byte primary) entries and
combines new committed/current IV addresses. It cuts
QEMU when some but not all carrier slots (48 for AES/ChaCha, 36 for AEGIS-128) have changed. The observer never
writes metadata or bypasses the native owner for mutations. Journal inspection
is test instrumentation, not a second native recovery implementation.

The reboot test accepts a complete old/new authenticated block or local EIO,
checks all other blocks and the entire primary hash, verifies invalid-marker
preservation and repairs the affected block. artifacts/stateless-power-003
observed exactly 32 changed slots and EIO afterward. Stock and independent full
primary/hidden verification passed after repair. Check cut-boundary.json,
power-results.json and result.txt; a run without the requested cut is a failure.


## Direct lower-device errors and setup cleanup

scripts/guest-faults.sh and kernel/guest-fault-test.py use a disposable linear
wrapper below stock dm-integrity. The test reloads it as dm-flakey with up=0,
down=3600 and either error_reads or error_writes, after activation and after udev
probes drain. Carrier record 10 avoids sector 0, whose checkpoint can still be served from
dm-integrity's journal cache. Decoy requests use a 16 KiB-aligned 16 KiB span
at or beyond carrier record 10; hidden requests use one 512-byte block.
A direct raw read witnesses error_reads before the
selected public read, and failing writes must have spent fresh encryptions.
These features return errors; no silently dropped writes are used.
Their definitions were checked against the pinned v6.12.113 source in
environment/sources.json and the [kernel documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-flakey.html).

For each view, direct reads and writes trigger the corresponding lower error.
Once an operation actually reaches a failing lower I/O, the owner must report
failure and both views must keep rejecting direct reads and writes after the
wrapper is restored. Only teardown/recreation clears the
fail-stop. Stock journal replay and full-primary verification follow; hidden
blocks must match the original oracle, with local EIO/whole-block repair allowed
only for carrier records intersecting the failed request. A separate fresh-IV primary rewrite tests local
hidden EIO, invalid-marker preservation and direct repair without global failure.

Setup tests fail after cryptsetup creates mappings, before native setup, during
kernel authentication, after native setup and after each public-view creation.
They also preserve conflicting lower/public names, existing idle/active owners,
and an unrelated replacement at close. Both view names are validated before any
is removed. Runtime DM UUIDs/device numbers identify resources; no new disk or
external persistent state is introduced. A final custom-module unload checks
that descriptors/target references were released while stock crypt stays busy.

Use a CLOSED native output with its complete expected views, not an uninitialized
control image:

```sh
python3 scripts/vm.py run --code --script scripts/guest-faults.sh \
  --run-dir artifacts/faults-next \
  --data-image artifacts/separate-native-4096-002/share/dual-final.img \
  --share-file artifacts/separate-kernel-512-002/share/experimental-dm-piv.ko \
  --share-file kernel/guest-fault-test.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key \
  --share-file artifacts/separate-native-4096-002/share/expected-hidden-volume \
  --share-file artifacts/separate-native-4096-002/share/expected-primary.sha256 \
  --timeout 3600
```

The wrapper guard remains QEMU-only /dev/vdb at 128 MiB. The test never mounts
filesystems on a failed project stack. Restore the fault source and unmount both
views before teardown in normal use. Resource cleanup is best effort and is not
hidden recovery, rollback, atomic initialization or a guarantee against hardware
that acknowledges writes without persisting them.


## Concurrent lifecycle and explicit flush/FUA evidence

scripts/guest-lifecycle.sh builds a SEPARATE test-only piv-io-test.ko against the
pinned guest headers and loads it alongside the previously verified dm-piv.ko.
Never link this helper into the production module or load it on the host. Its
root-only write interface accepts two integers (public view and request mode),
reads 512 bytes at sector 0 and writes those SAME bytes with plain, FUA or
PREFLUSH|FUA flags, or submits a flush. It accepts no keys, paths, offsets or user
payload. The helper is unloaded before lifecycle stress begins.

Dynamic kprobe entry/return events around pn_worker, pn_write,
blkdev_issue_flush and bio_endio record function metadata and results, not
plaintext or keys. Trace parsing requires complete non-overlapping ordered
workers, successful paired lower flush returns, a completed flush before write
return and public completion, and a preflush before a PREFLUSH payload (possibly
in a separate DM-split flush bio). A standalone flush must also reach a native
worker. Probe misses, ring-buffer overruns, missing events and negative results
are failures, not skipped coverage. See the [kernel kprobe tracing documentation](https://docs.kernel.org/trace/kprobetrace.html)
for the event/profile interface. Probes are removed before module unload.

Concurrent writers own disjoint logical regions that share carrier groups,
change/read/restore their data, and interleave direct and O_DSYNC writes with
fsync. Another thread suspends/resumes public views during that workload. Held
public descriptors must prevent removal, close and unload without changing
mapping identities. A request queued while a public view is suspended must wait
for resume while its peer remains usable. Complete primary/hidden oracles are
checked afterward and after a new owner generation. Stock full-primary readback
and custom unload finish the test.

This is a public-view lifecycle contract. Direct administrative suspension or
replacement of the PRIVATE owner/lower mappings while views are active remains
outside the supported workflow. Successful kernel flush return/order is not
proof that physical hardware honored persistence, hidden-record atomicity, or a
debug-kernel/lockdep audit. See ROADMAP.md for executed results.

Example using a CLOSED native fixture and a matched module (fresh run directory):

```sh
python3 scripts/vm.py run --code --script scripts/guest-lifecycle.sh \
  --run-dir artifacts/lifecycle-next \
  --data-image artifacts/separate-native-4096-002/share/dual-final.img \
  --share-file artifacts/batch-native-4096-001/share/experimental-dm-piv.ko \
  --share-file kernel/piv-io-test.c --share-file kernel/guest-lifecycle-test.py \
  --share-file kernel/lifecycle_trace.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key \
  --share-file artifacts/separate-native-4096-002/share/expected-hidden-volume \
  --share-file artifacts/separate-native-4096-002/share/expected-primary.sha256 \
  --timeout 2400
```

## Late-sector corruption in batched reads

The range-read regression extends guest-fault-test.py with a one-sector
`dm-flakey` read replacement below dm-integrity. It uses the documented
[corrupt_bio_byte feature](https://docs.kernel.org/admin-guide/device-mapper/dm-flakey.html)
to flip the first byte of a selected ciphertext sector on reads only, leaving
backing bytes and writes unchanged. A direct raw read witnesses the replacement
before testing authentication. The chosen sector is the last in one aligned
16 KiB decoy work item or the last carrier sector of hidden record 10, away from
the setup checkpoint's journal cache.

Earlier sectors may have decrypted into private pages when this last sector
fails. A direct-I/O caller buffer prefilled with a sentinel must remain entirely
unchanged on EIO. Both views must then remain failed after fault removal until
teardown/recreation. Complete primary/hidden oracles must match afterward with
no repair. A separate setup attempt with the same later-sector corruption must
fail, remove its own mappings and permit a healthy full reopen after restoration.
These synthetic faults test authenticated-read withholding and shared failure,
not adversarial journal replay, physical corruption durability or atomicity of
application requests spanning multiple public bios. Results are in ROADMAP.md.
