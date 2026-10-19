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
  --share-file artifacts/stateless-next/share/experimental-dm-crypt.ko \
  --share-file kernel/guest-stateless-power.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key --timeout 3600
```

The guest initializes zeros on the stock fixture before introducing dm-delay.
An O_DIRECT raw observer validates whole journal-section commit IDs, parses the
pinned 48-byte (512-byte primary) or 104-byte (4096-byte primary) entries and
combines new committed/current IV addresses. It cuts
QEMU when some but not all 48 carrier slots have changed. The observer never
writes metadata or bypasses the native owner for mutations. Journal inspection
is test instrumentation, not a second native recovery implementation.

The reboot test accepts a complete old/new authenticated block or local EIO,
checks all other blocks and the entire primary hash, verifies invalid-marker
preservation and repairs the affected block. artifacts/stateless-power-003
observed exactly 32 changed slots and EIO afterward. Stock and independent full
primary/hidden verification passed after repair. Check cut-boundary.json,
power-results.json and result.txt; a run without the requested cut is a failure.
