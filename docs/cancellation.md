# Cancelling native activation and initialization

Native SETUP yields to the scheduler and checks pending signals between 16 KiB
authenticated primary read ranges, between complete hidden-record
initialization writes, and around the final checkpoint before marking the
native state ready. Waiting for the setup lifecycle mutex is interruptible. The
ioctl returns EINTR when cancellation wins at one of these boundaries. There is
no abort ioctl, flag, on-disk marker or resume file.

The `pivsetup` frontend installs SIGINT and SIGTERM handlers without
SA_RESTART that only set a flag, so the interruptible SETUP ioctl returns EINTR.
pivsetup then removes the mappings its own attempt created and exits with
status 130. The ioctl request buffer holding the key is wiped after the call
either way.

## Guarantees and limits

By default setup scans only the 112-sector keyslot area, which is too short to
cancel reliably; `--verify` scans the whole primary. Cancelling either scan
leaves no ready native state or public views and spends no primary encryption.
Reopening repeats the scan; an incomplete scan is never adopted.

Cancellation during `--initialize` waits for the current pn_write call to
finish, then stops before the next record. Initialization first writes a new
master key into keyslot 0 and the directory, then the zero records in block
order. After cancellation the completed leading blocks read as authenticated
zeros and every later block returns EIO, because its old record no longer
authenticates under the new master key. Setup does not poll between the keyslot
and directory writes; only a crash there could leave a keyslot without a
directory, which later opens refuse until `--initialize` is retried.

This is destructive partial initialization, not rollback or persistent
progress. Reopening without `--initialize` exposes the mixed content. Retrying
`--initialize` starts from block zero with a fresh master key and random
encodings; it is not resume and consumes additional primary encryptions.
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

## Draining failed private setup

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

## `cancel` suite

scripts/guest-cancel.sh runs kernel/guest-cancel-test.py over a dm-delay
wrapper on the closed 128 MiB native fixture. The harness runs pivsetup as the
child setup client; its `PIVSETUP_TEST_GATE` hook provides a handshake before
the native ioctl and reports the kernel status after it. Module-qualified
kprobes, filtered to the child's PID, witness actual range reads or pn_write
calls, and `/proc/PID/syscall` must show the SETUP ioctl before a signal is
sent; a signal delivered before entering the kernel does not count.

- **Scan** (`--verify`, 25 ms lower read delay, at least three range reads
  witnessed): a second raw SETUP caller is interrupted while the first holds the
  setup mutex and must report EINTR before the first scan is cancelled. The
  encryption counter must stay zero.
- **Initialize** (25 ms lower write delay, at least two pn_write entries
  witnessed): the retained counter must equal 28 keyslot + 90 directory + 90 per
  completed record, with at least two and fewer than 64 records completed.

Each cancellation must report EINTR with inactive status, no views, zero hidden
capacity and no failure, exit 130 without cleanup notes, leave no mappings or
control nodes, keep the wrapper identity, and have no missed probes or trace
overruns. Reopened views must match the full primary hash and, for the
initialization case, zeros up to the completed prefix and EIO beyond it. A
normal full initialization then runs to completion, followed by close, custom
unload, stock full-primary readback and host verification of `cancel-final.img`
against `expected-cancel-hidden`.

The `faults` suite covers the related setup-phase failures and ownership rules
([native-faults.md](native-faults.md)).

```sh
python3 scripts/suite.py --prefix artifacts/cancel-next --profile aegis-4096 \
  --scaffold artifacts/stage-next/scaffold.tar --suites cancel
```

Executed results are recorded in commit messages; a trace or interrupted
process alone is not a successful run.
