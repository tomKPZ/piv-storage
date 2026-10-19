# Cancelling native activation and initialization

Native SETUP now yields to the scheduler and checks pending signals between
16 KiB authenticated primary read ranges and between complete hidden-record
initialization writes. It checks again around the final checkpoint before marking
the native state ready. Waiting for the setup lifecycle mutex is interruptible.
The ioctl returns EINTR when cancellation wins at one of these boundaries.
No new ABI, flag, on-disk marker, resume file or record encoding is introduced.

For the existing Python frontend, use Ctrl-C/SIGINT with its default handler.
That handler raises KeyboardInterrupt, allowing open_blocks to unwind and remove
its own mappings. The ioctl key buffer is wiped in a finally block. Library users
must likewise use a handler that unwinds the operation: Python's fcntl.ioctl can
automatically retry EINTR if a handler simply returns. There is no separate abort
ioctl or process-wide signal-handler installation in the library.

## Guarantees and limits

Cancelling the authentication scan leaves no ready native state or public views.
Healthy scan cancellation performs no primary encryption. Successful reopening
still authenticates the entire primary; it does not adopt an incomplete scan.

Cancellation during --initialize waits for the current pn_write call to finish,
then stops before another record starts. Under healthy I/O, completed leading
records contain authenticated zeros and the remainder retains its earlier state.
This is destructive partial initialization, not rollback or persistent progress.
Reopening without --initialize exposes that mixed content. Retrying --initialize
starts from block zero with fresh random encodings; it is not resume and consumes
additional primary encryptions. Normal storage errors and power loss retain the
existing torn-record/EIO limitations; this is not a new crash transaction.

The kernel frees temporary native state and crypto transforms on cancellation,
and frees its copied setup request. Successful frontend cleanup removes its
owned device stack and closes its ownership lock. This establishes resource
cleanup in the tested paths, not physical-memory key-erasure assurance: Python
key objects, dumps, privileged memory access and external artifacts remain outside
that claim. Inspect error notes if cleanup cannot complete.

There is no hard latency deadline. An in-flight lower read, record write, flush,
allocation or checkpoint must finish; a stalled device can delay cancellation.
Closing a raw control descriptor can also wait for another operation's mutex,
even after its own SETUP ioctl was interrupted while waiting for that mutex.
Other control commands are not made universally interruptible by this change.

SIGKILL, a default terminating SIGTERM, process death and repeated interruption
of cleanup do not run Python exception cleanup. Private mappings may need manual
administrative cleanup in those cases, especially if a probe is blocked on a
suspended device. SIGINT is the verified cooperative frontend path. Activation
steps before the native ioctl, including cryptsetup journal replay, are not made
transactional or mutation-free by cancellation. These limits also apply to early
boot integration; graceful service shutdown needs an appropriate caller handler.

## Draining failed private setup

A cancelled setup can leave udev probing a suspended private owner. A plain
remove --retry can fail because that probe holds the device open. Failed-setup
cleanup now closes its control descriptor, checks the captured device identity,
and replaces the newly created private owner's table with an error target using
dmsetup wipe_table --noflush before removal. Deferred probes receive EIO, the
private crypto target releases its state, and lower integrity removal can finish.
This changes the transient mapping, not the backing ciphertext layout or payload.

This path is limited to an owner created by that failed attempt. Public views
must first be removed normally; a busy view stops cleanup. Existing owners,
foreign/replaced identities and normal close retain the original refusal rules.
The lower integrity device is removed normally. This does not promise atomic
cleanup against privileged external table races, busy public views or hardware
that never completes an outstanding request.

## Regression method

scripts/guest-cancel.sh uses the existing shared pinned-guest scaffold. The
Python harness runs child setup clients with the default SIGINT handler. A
handshake occurs before the native ioctl, then module-qualified kprobes witness
actual primary range reads or initialization writes in that child's context.
/proc/PID/syscall must identify the native SETUP ioctl before a signal is sent.
It does not count a signal delivered before entering the kernel as a pass.

The scan uses 25 ms synthetic lower read delay. A second raw SETUP caller is
interrupted while the first still holds the setup mutex. Its interruption marker
must arrive before the first scan is cancelled; descriptor close may wait for
the first to unwind. Initialization uses healthy reads and 25 ms lower write
delay. At least two pn_write entries are witnessed before interruption, proving
initialization has begun and a previous record has completed.

After cancellation the child captures inactive native status, zero views/capacity
and the retained encryption counter before frontend cleanup. The scan counter
must be zero. For initialization, the counter must represent a small whole-number
prefix of complete carrier groups. The harness independently constructs the
expected zeroed prefix and checks every primary/hidden byte through the reopened
views. It rejects cleanup error notes, leftover mappings/control nodes, changed
wrapper identity, missed probes and trace overruns. Normal full initialization
also runs on the 128 MiB fixture. Final close, custom unload, stock full-primary
readback and independent host image verification follow.

The existing guest fault/ownership matrix additionally covers foreign names,
failed setup at each creation phase, lower read/write errors, local hidden damage
and repair, and close ownership rules. It is rerun because private abort cleanup
changed; normal close must not acquire the discard behavior.

## Reproduce

Stage a complete module as described in native-blocks.md. To build and run:

```sh
python3 scripts/fetch_kernel.py vendor/kernel-build/cancel-next
mkdir -p artifacts/cancel-input-next
tar -cf artifacts/cancel-input-next/scaffold.tar -C vendor/kernel-build/cancel-next .
python3 scripts/vm.py run --code --script scripts/guest-cancel.sh \
  --run-dir artifacts/cancel-4096-next \
  --data-image artifacts/separate-native-4096-002/share/dual-final.img \
  --share-file artifacts/cancel-input-next/scaffold.tar \
  --share-file kernel/check-config.py --share-file kernel/guest-cancel-test.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key \
  --share-file artifacts/separate-native-4096-002/share/expected-hidden-volume \
  --share-file artifacts/separate-native-4096-002/share/expected-primary.sha256 \
  --timeout 900
```

For the 512 MiB original-AEGIS512 run, use large-512-001/share/large-final.img and
that run's keys/oracles; supply the built experimental-dm-piv.ko instead of the
build archive. Full initialization is interrupted, not repeated to completion
on the large fixture. Verify cancel-final.img with scripts/check_stateless.py,
using expected-cancel-hidden from the cancellation run and the original primary
key/hash. Original-AEGIS verification needs the optional diagnostic reference
library; native activation does not. See ROADMAP.md for executed results and
failed experiments; a trace or interrupted process alone is not a successful run.
