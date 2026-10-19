# Closed-volume native log compaction

compact-state is an explicit maintenance operation for the pinned guest backend.
Unmount both filesystems and run close-blocks first. Supply the same backing
device, LUKS credential and hidden-key files, and the existing state directory:

```sh
python3 -m pivstore close-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key
python3 -m pivstore compact-state --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key \
  --hidden-key-file /mnt/piv-work/hidden.key
python3 -m pivstore open-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key \
  --hidden-key-file /mnt/piv-work/hidden.key
```

If setup used --state-directory, pass that same directory to maintenance and
reopen. The default remains /var/lib/pivstore/<UUID>. Do not pass --initialize.
Active native contexts are refused, including unmounted-but-still-open views.
The command reports nonce count, previous bytes and compacted bytes. Both public
views stay absent during maintenance. Arbitrary host devices remain prohibited.

## Ordering and invariants

1. Hold the existing exclusive volume ownership lock; validate private state and
   the ordinary native stack. Refuse active native contexts without detaching or
   removing their devices.
2. Suspend the private owner and invoke native setup with NO bootstrap seeds.
   The kernel authenticates/replays any pending exact-tuple WAL, checks every
   primary sector/hidden record and current IV membership, and checkpoints.
3. Detach the native context while no public views exist. This closes its log
   file descriptor BEFORE replacing the pathname. Keep the private owner
   suspended and the ownership lock held.
4. Authenticate the completed log independently. Write ALL historical reserved
   IVs, including obsolete and abandoned reservations, into encrypted NONCES
   batches of at most 512, followed by READY. Use the unchanged PIVNLOG1 format,
   historical log KDF domain, fresh random salts, sequence from zero and a fresh
   hash chain. Only completed tuple WALs are omitted.
5. Write a private temporary file on the SAME root ext4 filesystem, fsync it and
   authenticate its actual contents. Require exact nonce-set equality with the
   recovered original, READY, no pending WAL and no trailing bytes.
6. Atomically replace native.log and fsync its parent directory. The old canonical
   file stays authoritative until replacement. Before/after replacement, either
   complete canonical file contains the same full nonce history.
7. Let a fresh kernel native context load the published file and authenticate
   the complete volume again. Detach and remove the private stack. Reopening
   ordinary native views is a separate explicit operation.

No primary data is reencrypted for compaction. Kernel journal checkpoints can
copy an unchanged current tuple. A pending failed request can be rolled forward
before compaction, as during normal recovery; EIO never promised rollback.
Compaction does NOT reset the per-key 2^20 nonce budget or discard old IVs. A
future primary rekey/lineage transition requires a separate design.

## Failure behavior and limits

Before publication, write/fsync/validation/rename failure leaves the original log
canonical. After publication, directory-fsync failure is reported; the newly
published complete file remains canonical, and the code never blindly restores
an older log. A process/VM interruption can leave the old or new complete log;
both have identical history. Never choose an orphan .piv-compacting-* temporary
as recovery authority. Only native.log is opened. Normal exceptions remove the
temporary file; abrupt process death can leave one for later manual cleanup.

This depends on the tested ext4 rename/fsync and virtual-device assumptions, not
arbitrary hardware power-loss behavior. Full-length log corruption, rollback,
clones and loss of trusted private state remain outside these guarantees. Both
old/new logs are observable metadata, and deleted copies can remain in storage.
This does not establish deniability or erase evidence.

Compaction needs temporary free space for the snapshot (up to about 13 MiB at
2^20 reservations), alongside the old log. A full filesystem must have space
freed first. It does not automatically run under mounted filesystems or prevent
write amplification. Startup still scans all primary sectors/hidden records.
Snapshot size is 12 bytes per reserved nonce plus 108 bytes per batch and a
104-byte READY frame. All 148,372 reservations of a closed 383,732,268-byte test
log were retained in 1,811,888 bytes (6,880 frames reduced to 291).

## Verification

Host tests cover abandoned reservations, multiple batches, repeated fresh salts,
active-owner refusal, malformed/wrong-key/pending/partial input, write/fsync/
rename/directory-fsync errors and SIGKILL at four publication boundaries. The
helper is private; its file-only tests use disposable synthetic logs. The public
maintenance command always applies the native ownership and kernel verification
policy above.

The VM test uses the closed output of native-fault-002, including its REAL spent
reservations from failed WAL appends. It checks active refusal, ordinary/CLI
maintenance, recovery of an already-applied WAL with its final DONE omitted,
real root-ext4 ENOSPC and a QEMU cut after rename before explicit parent fsync.
Reboot must recover both full logical views with the EXACT original nonce set,
then pass stock Linux and independent host authentication. See ROADMAP.md for
actual outcomes; do not infer a passing run merely from this intended test plan.

```sh
python3 scripts/fetch_kernel.py vendor/kernel-build/compaction-next
mkdir -p artifacts/compaction-input-next
tar -cf artifacts/compaction-input-next/scaffold.tar -C vendor/kernel-build/compaction-next .
python3 scripts/vm.py run --code --script scripts/guest-compaction.sh \
  --power-cut-script scripts/guest-compaction-recover.sh \
  --run-dir artifacts/compaction-next \
  --data-image artifacts/native-fault-002/share/fault-final.img \
  --share-file artifacts/compaction-input-next/scaffold.tar \
  --share-file kernel/guest-compaction-test.py --share-file kernel/check-config.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key \
  --share-file artifacts/native-fault-002/share/native-fault.log \
  --share-file artifacts/native-fault-002/share/expected-fault-primary.sha256 \
  --share-file artifacts/native-fault-002/share/expected-fault-hidden --timeout 3600
```

Use a fresh staged scaffold matching current kernel sources as in native-blocks.md;
that pinned unchanged scaffold was used for the recorded compaction experiment.

Independent verification after the runner succeeds:

```sh
python3 scripts/check_compaction.py \
  artifacts/native-fault-002/share/fault-final.img \
  artifacts/native-fault-002/share/native-fault.log artifacts/compaction-next \
  --volume-key-file artifacts/control-003/share/volume.key \
  --hidden-key-file artifacts/control-003/hidden.key
```

artifacts/compaction-001 passed the full VM/reboot run. Independent checks found
all 28,244 primary ciphertext/tag/IV tuples and all 281,600 hidden bytes unchanged,
with all 57,396 reservations retained. The log shrank from 4,156,356 to 701,060
bytes (153 frames to 114). A separate host-only closed-fixture check produced
the larger 383.7 MB to 1.81 MB reduction above. These are distinct experiments.
