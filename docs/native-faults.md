# Native storage error experiments

These tests run only inside the pinned disposable guest. They do not install a
host module or touch host block devices. Both kernel views use O_DIRECT reads and
writes to exercise the target rather than successful page-cache reads after
fail-stop. Test data and keys remain synthetic and ignored.

The matrix injects dm-flakey error_writes underneath the SAME dm-integrity
mapping for one decoy and one hidden transaction. A durable kernel WAL must
remain pending; after repairing the test device, explicitly destroy/recreate the
failed owner/lower stack and replay exact tuples. A failed request can be rolled
forward on reopen: EIO does not mean that its requested changes were rolled back.
Never clear an error flag and silently continue a mounted failed stack.

The log cases allocate a temporary unwritten-extent file on independent guest
root ext4 until even a 4 KiB allocation returns ENOSPC. Filesystem-internal
reserves can still appear in statvfs free-block counts; those counts are evidence,
not an assertion that every nominal free block is allocatable. The kernel's real log append then encounters
ENOSPC. The filler is removed in finally, including on assertion failure. Compare
all primary ciphertext/tag/IV tuples before/after the failed request to establish
that an unpersisted WAL did not authorize mutation. Inspect authenticated nonce
history and partial tail before reopen; reservations that became durable remain
spent, even when no primary write occurred. Both views must fail-stop, then recover
after space is restored and the stack is recreated.

The independent host verifier decrypts the entire original primary and computes
the exact expected result (one 4 KiB decoy replacement). It compares every final
primary byte through its full hash, the entire expected hidden volume, native-log
authentication/history and current IV uniqueness/membership. The guest checks
that recovery spends no nonce and that a subsequent same-data hidden write spends
64 fresh nonces while preserving decoy plaintext.

## Reproduce

Use a coherent CLOSED disk/log pair from the fresh-initialization fixture, not a
mutable disk from an interrupted run. Create fresh staging/artifact names:

```sh
python3 scripts/fetch_kernel.py vendor/kernel-build/fault-next
mkdir -p artifacts/fault-input-next
tar -cf artifacts/fault-input-next/scaffold.tar -C vendor/kernel-build/fault-next .
python3 scripts/vm.py run --code --script scripts/guest-dual-fault.sh \
  --run-dir artifacts/native-fault-next \
  --data-image artifacts/dual-final-007/share/dual-final.img \
  --share-file artifacts/fault-input-next/scaffold.tar \
  --share-file kernel/guest-dual-fault.py --share-file kernel/check-config.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key \
  --share-file artifacts/dual-final-007/share/native.log \
  --share-file artifacts/dual-final-007/share/expected-primary.sha256 \
  --share-file artifacts/dual-final-007/share/expected-hidden-volume --timeout 3600
python3 scripts/check_native_fault.py \
  artifacts/dual-final-007/share/dual-final.img artifacts/native-fault-next \
  --volume-key-file artifacts/control-003/share/volume.key \
  --hidden-key-file artifacts/control-003/hidden.key
```

Kernel/header/source/config provenance is unchanged from native-blocks.md; the
ordinary module is tested with no special failure hooks. Expected failed-device
and ENOSPC diagnostics must be distinguished from unexpected kernel faults.
See ROADMAP.md for actual run results. This is not arbitrary fsync failure,
hardware power-loss, lifecycle-race or rollback testing.

## Observed results

artifacts/native-fault-002 passed all four cases on the ordinary unmodified
experimental module. Both device EIO cases retained complete WALs; both ENOSPC
cases left primary tuples unchanged and incomplete WAL tails (2,600/1,404 bytes).
Those tails were removed on reopen; the 32/64 durable reservations remained spent.
Every replay preserved its exact nonce count; every later successful same-data
hidden write spent 64 fresh nonces. Stock Linux and the independent host checker
agreed on all primary bytes and the full hidden volume. See the roadmap handoff
for hashes, counts, source/environment matching and the failed first harness run.

These ENOSPC cases exercise incomplete append recovery. They do not establish
recovery for a full-length bad frame, an arbitrary fsync error, a failure after
applying data but before DONE durability, or loss/corruption of private state.
Complete unauthentic frames remain refused; no corruption check was relaxed.
