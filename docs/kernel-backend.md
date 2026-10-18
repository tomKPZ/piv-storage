# Kernel backend investigation and proposed next phase

Status: the K0–K3 prototype is implemented and tested. This document preserves
the investigation and original design gates; current protocol, ordering and
limitations are in [implementation notes](kernel-implementation.md), with
[reproduction instructions](../kernel/README.md) and evidence in ROADMAP.md.
The selected extension remained contained, so a separate target was unnecessary.

## Recommendation

Start with a small opt-in extension to dm-crypt in a pinned experimental kernel
tree. Keep FUSE, hidden encryption, v1 framing and transaction policy in userspace.
The extension owns primary crypto and exposes bounded persistent-IV operations;
primary reads use that same dm-crypt instance instead of our NBD adapter.

Do not start a separate crypto implementation or full dm-crypt fork. A new
device-mapper target is a fallback if the extension cannot remain reasonably
contained; first consider sharing internal helpers in-tree. There is no current
promise of an upstreamable ABI or compatibility across arbitrary kernels.

| Approach | Assessment |
| --- | --- |
| Opt-in dm-crypt extension | Preferred: reuse its key, AEAD/AAD, persistent-IV and integrity-bio machinery; coordinate updates with its reads. |
| Independent target that does primary crypto | Possible, but duplicates/refactors AEAD setup, request lifetime, error handling and block integrity integration. Reconsider only with evidence. |
| IV-rewriting shim under stock dm-crypt | Insufficient alone: changing an IV also changes ciphertext/tag; coordinating a second crypto/key owner adds complexity. |
| Module registering another IV generator | The reviewed IV hooks are private static dm-crypt machinery, not a public registration API. A crypto algorithm module alone cannot supply the complete update path. |

Expected utility is direct-device updates, reuse of the real integrity journal,
and native primary reads. Kernel execution alone does not make v1 incremental,
solve whole-record recovery, track lifetime nonces, or improve snapshot deniability.

## Findings from pinned Linux 6.12.113

The reviewed upstream files are SHA-256 pinned in environment/sources.json.
The K0 source staging also checks Debian 6.12.113-1 orig equality and rejects
distro patches mentioning either compiled source file. Exact guest headers and
symbol versions, rather than only the upstream version string, are used for builds.

- `crypt_iv_random_gen` generates fresh bytes on normal writes. The private
  `crypt_iv_operations` table is selected inside dm-crypt; ordinary write syscalls
  do not carry caller-selected per-sector IVs into it.
- `crypt_convert_block_aead` loads persistent IVs on reads, writes the generated
  IV on encryption, and authenticates sector_LE64 plus the IV. It couples the
  tag and IV to the ciphertext. Reusing this path is preferable to independently
  reimplementing its address/offset rules.
- `crypt_integrity_ctr` checks the lower device's metadata profile, tuple size
  and sector interval. Internal I/O must preserve those checks.
- `dm_integrity_map` accepts metadata supplied through `bio_integrity_payload`,
  checks its length, and sends journaled writes through `dm_integrity_map_continue`.
  Direct raw writes under that target would bypass its metadata cache/journal.
- `crypt_map` has early flush/discard handling. A primary write prohibition must
  precede bypass paths and cover all mutating operations, not just ordinary WRITE.
- `crypt_message` currently handles key operations, not an IV transport. The DM
  target `prepare_ioctl` callback routes ioctls toward a lower block device; it
  is not a generic per-target binary command dispatcher with a userspace buffer.

These observations do not establish a working carrier-update path.
The documented dm-integrity journal couples data and integrity metadata, but
does not expose a general transaction spanning our full auxiliary record.
The current fixture has seven journal sections with 32 encryption-sector entries
each, versus 28,244 sectors in the carrier. Even fitting a request in a journal
would not itself establish multi-request atomicity.

## Proposed ownership and I/O path

One opted-in crypt instance owns the primary key and all carrier updates. A
restricted binary control endpoint refers to that exact live target with a
generation/refcounted lifetime. Hidden encryption stays in userspace; only
already-encrypted carrier bytes enter the kernel. Keep existing LUKS metadata,
`aes-gcm-random`, sector size and 28-byte tuple layout unchanged so the stopped
volume remains readable by stock Linux.

Prototype stack:

    primary filesystem, read-only
        -> read-only presentation of the extended dm-crypt owner
        -> the one shared dm-integrity target, journaled and write-capable
        -> disposable guest block device

    userspace hidden codec/FUSE -> privileged binary control -> same crypt owner

Read-only presentation must not accidentally make the lower integrity device
unwritable for authorized internal operations. Current dm-crypt obtains its
lower-device access mode from its table. Resolve this explicitly in the first
spike: a write-capable owner with a hard primary-mutation filter and read-only
upper wrapper is a candidate. Reject primary write bios inside the owner even if an administrator changes the upper
read-only flag. Keep the writable owner private: its bio filter cannot prevent
buffered writes from first dirtying its page cache. The read-only wrapper is
required for the primary interface, independently of read-only filesystem mounts. Ordinary cryptsetup --readonly activation is not yet assumed to
create the required lower stack.

For an internal replacement: read ciphertext and its entire metadata tuple
through the lower integrity target, authenticate/decrypt it, choose the supplied
IV for this specific request/sector, reencrypt identical plaintext, and submit
ciphertext plus the new tuple back through that same lower target. Never update
raw interleaved metadata or keep a global "next IV" variable shared by writes.

## Control interface and synchronization

Use a private, versioned, bounded binary endpoint (a misc/character device is the
initial candidate). Do not pass keys or carrier blobs through shell arguments,
sysfs, logs or text dmsetup messages. Any text DM configuration only enables or
identifies the feature. Reuse the owner's loaded key; key provisioning should use
protected file input/keyring references, never hexadecimal command-line keys.

Candidate operations, not a frozen UAPI:

- Query profile/owner generation and read a bounded range of persistent IVs.
- Replace IVs for a bounded list of encryption-sector indices, with expected
  old-IV/generation checks and precise completion/failure reporting.
- Serialize, flush, and report whether recovery or operator action is required.

Validate indices, lengths, integer overflow, profile, authorization and owner
identity. Begin with one controller and one sector per operation. Restrict access
to guest administrator privileges and private device permissions; a valid IV
update does not authorize changing primary plaintext. Provide no key-read API.

Schedule work in an appropriate sleepable context with bounded buffers and
no-I/O allocation discipline. Drain active reads and prevent new ones during
updates initially. Do not sleep under spinlocks or wait on work that needs a lock
held by the caller. Internal bios must go to the lower device rather than recurse
through the primary target. Test controller exit, target suspend/remove/reload,
key wipe, pending work and module lifetime together. Hold target references until
all control I/O completes; do not assume an open fd keeps a DM table alive.

## Implemented authenticated-read slice of K1

PIV_READ_IV now reads one ciphertext sector and its complete tuple through the
existing lower target, then calls the same native AEAD conversion helper used
by ordinary reads. It returns only an authenticated IV, with fixed request sizes,
owner/index validation and no write in that initial read-only slice. Native writes were subsequently added as PREPARE/APPLY. The final guest experiment
passed boundary reads, ciphertext/tag/IV corruption rejection, coordinated reads
with suspend/resume, key-wipe rejection, removal lifetime checks, stock full-volume
readback and independent offline IV comparison. See kernel/README.md and the
roadmap handoff for exact commands and remaining test limits.

Unlike the original query-only snapshot, this operation borrows crypt_config
under a mutex for the duration of synchronous I/O. Presuspend drains/blocks it;
dtr invalidates the pointer under that same mutex before freeing native state.
This is not a design for asynchronous mutation workqueues or whole-record commits.
Those subsequent mutation gates now pass the selected prototype tests; see the
implementation notes for lower validation, exclusion and durable completion.

## Userspace setup compatibility

The pinned cryptsetup 2.7.5 `_dm_target_query_crypt` parser rejects unknown
optional table tokens, including our experimental `piv_control`. Consequently
stock status/close/reload workflows cannot be assumed to manage the opted-in
stack. The harness uses dmsetup to remove the owner and its known lower mapping,
then restores stock dm-crypt for ordinary cryptsetup activation. This is a runtime
tooling limitation, not an on-disk format change. Add opt-in setup/teardown
integration (now implemented for K3); do not hide the flag in table status to fool old parsers.
The reviewed libdevmapper.c/setup.c files are now pinned in the source manifest.

## Atomicity and recovery gates

Separate three promises:

1. Primary ciphertext/IV/tag must remain paired per encryption sector.
2. A control request must report partial progress and durable completion honestly.
3. A v1 hidden blob spanning the carrier needs complete-old-or-new record recovery.

The first can use journaled dm-integrity I/O; the other two need explicit design
and testing. A bio completion without suitable flush/FUA ordering is not our
durability acknowledgment. Verify the lower journal's actual completion behavior.

The first kernel experiment only rewrites a disposable sector with random carrier
bytes and makes no hidden-record commit claim. Do not attach FUSE writes to a
batch of sector operations until a recoverable whole-record protocol exists.
A private external recovery journal is acceptable for the VM prototype, but
must precede mutations, bind volume/ranges/operation identity, detect corruption,
and define commit/rollback ordering. Preserve exact ciphertext/IV/tag tuples for
recovery where needed; do not recreate old tuples by reencrypting changed data
with old IVs. Never blindly retry an uncertain operation or reuse cached plans.
The exact recovery/transport ABI is intentionally a later decision gate.

If that protocol is too large, retain the current regular-file backend for
payload commits and report the kernel result as a sector-update proof. Do not
silently downgrade hidden fsync to a collection of independently durable writes.

## Experiments and exit criteria

**K0 — matching build and control scaffold.** Acquire exact guest Debian source,
headers/config and Module.symvers, review relevant distro changes, and build/load
an opt-in patched dm-crypt module in a fresh VM. CONFIG_MODVERSIONS is enabled;
upstream source plus a matching version string is insufficient. If a matching
module build cannot be established, build a matched test kernel/modules from one
pinned tree. Never force-load an ABI-mismatched module. First expose query only,
prove read-only primary policy/lower write access, and test ordinary mode unchanged.

**K1 — one-sector update.** Add one bounded replacement operation, verify old
authentication and unchanged primary plaintext, flush it, then close the patched
stack and read it with unmodified Linux and the userspace codec. Repeat at sector
0, both sides of the metadata interleave boundary, and the final sector. Corrupt
old ciphertext/tag/IV and confirm refusal before a write. Exit: paired updates
through dm-integrity with no raw layout writes and no full-image replacement.

**K2 — concurrency and record-recovery decision.** Run primary reads with updates;
test malformed control requests, repeated/current IVs, stale owner generations,
allocation/I/O failures, controller death and mapping lifetime operations. Use
lockdep/KASAN builds where available. Inject VM/device failures around lower
journal commit/replay, not merely kill userspace while the kernel keeps running.
Record QEMU cache/flush behavior and scope crash claims accordingly. Select and
test a whole-record recovery protocol before declaring payload fsync supported.

**K3 — optional kernel adapter under the existing service.** Keep FUSE and the
hidden codec, replace the primary NBD path with the extended mapping, and put a
small adapter behind backend capability checks. Repeat the mounted demo and
selected crash/recovery checks on disposable VM disks. Keep the regular-file
backend available as a working fallback and retain stock-kernel readback tests.

## Tools and boundaries

Host make, C compiler/linker, bison, flex, bc and pahole were found during this
investigation. The guest config has DM_CRYPT=m, DM_INTEGRITY=m,
BLK_DEV_INTEGRITY=y, KEYS=y, and MODVERSIONS=y. Matching Debian headers,
Module.symvers and the guest build/load path were verified in K0. The config
comparison permits only four exact Debian packaging additions; no forced load
or full kernel build was needed.
Download source/build artifacts into ignored vendor/, downloads/ and artifacts/.
The investigation itself installed no packages. K0 now installs build dependencies
inside the disposable guest; see kernel/README.md for source/build provenance.
Load/test only inside disposable QEMU guests; no host module installation or real
device access. Do not make either backend claim production safety or deniability.

## References

- [Pinned dm-crypt source](https://github.com/gregkh/linux/blob/v6.12.113/drivers/md/dm-crypt.c)
- [Pinned dm-integrity source](https://github.com/gregkh/linux/blob/v6.12.113/drivers/md/dm-integrity.c)
- [Pinned target API](https://github.com/gregkh/linux/blob/v6.12.113/include/linux/device-mapper.h)
- [Pinned DM ioctl dispatch](https://github.com/gregkh/linux/blob/v6.12.113/drivers/md/dm.c)
- [dm-crypt documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html)
- [dm-integrity documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html)
- [Block integrity documentation](https://docs.kernel.org/block/data-integrity.html)
- [Pinned cryptsetup active-table parser](https://github.com/mbroz/cryptsetup/blob/v2.7.5/lib/libdevmapper.c)
- [Pinned cryptsetup lifecycle code](https://github.com/mbroz/cryptsetup/blob/v2.7.5/lib/setup.c)
