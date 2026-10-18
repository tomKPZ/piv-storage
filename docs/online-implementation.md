# Online implementation and recovery contract

The first online backend supports regular-file images on a local filesystem.
It reuses the existing 4096-byte profile and v1 whole-carrier hidden blob. Direct
block-device commits, in-place tuple journals and kernel modifications are deferred.

## Ownership and views

OnlineStore holds an exclusive advisory lock on the backing inode and on a stable
`<image>.pivstore.lock` sidecar. Keep that empty sidecar in place, including after
shutdown: deleting it can create two different lock inodes. Cooperating owners
cannot open the same current image concurrently. Advisory locking does not stop
another process deliberately bypassing locks; never attach the backing file to
an independent dm-crypt, loop or QEMU mapping while serving it.

The service authenticates the complete primary at startup. NBD reads authenticate
every touched primary sector before returning any plaintext for the request.
The export advertises read-only and independently rejects write requests. It
uses a mode-0600 Unix socket, fixed-newstyle negotiation and simple replies;
requests are bounded to 1 MiB. It does not provide a public TCP endpoint, TLS,
structured replies, trim, or primary write support.

FUSE exposes one pre-existing mode-0600 file named `payload`, with direct I/O and
no writeback cache. Reads/writes/truncation operate on the owner's in-memory
buffer. Fsync and close/flush commit dirty content; normal service exit after
unmount also attempts a final flush. Use explicit fsync when acknowledgment
matters. Backend close alone does not commit unflushed edits. Creating, deleting,
renaming and changing file ownership/mode are unsupported; editors that require
temporary-file/rename workflows will not work.

One lock serializes backend operations. Primary reads and hidden operations wait
during a commit. Primary plaintext never changes, so the mounted primary view's
cached plaintext remains valid across backing inode replacement. The backend
checks held-inode metadata and path identity for unexpected changes and stops
serving on detected changes or authentication failures.

## Commit ordering

1. Reserve the per-session sector-encryption budget, encode a fresh complete
   hidden blob, and reject IVs seen in the current image or this process's history.
2. In a private staging directory beside the image, use the shared offline writer
   to authenticate the input, copy it, reencrypt the carrier, authenticate/hash the
   complete candidate and fsync it. No bytes in the current image are modified.
3. Open and exclusively lock the candidate. Keep the old inode and stable path
   lock held. Atomically replace the canonical image path with the candidate.
4. Switch the owner's read descriptor while the backend lock excludes reads,
   release the old descriptor, and fsync the canonical parent directory.
5. Only then clear dirty state and acknowledge the flush.

This avoids a new recovery journal: after process death, only the canonical image
is reopened, fully authenticated, and decoded. Before replacement it contains
the previous record; after replacement it contains the complete new record. Never
resume a staging copy or reuse a cached IV plan. Caught commit errors fail-stop
the owner; restart is required even if a complete unacknowledged new image exists.

SIGKILL tests cover prepared, published and directory-synced boundaries. These
are process-crash checks, not proof of hardware power-loss guarantees. The
contract assumes local atomic rename, hard-link and fsync semantics. Network
filesystems, unusual storage stacks and directory fsync failures may not provide
the claimed acknowledgment semantics. A failed flush can leave a valid new image
without acknowledgment; an unflushed edit can be lost.

A killed mounted service can leave a dead FUSE mount, NBD connection and Unix
socket. Disconnect/unmount those before restarting, and remove only a confirmed
stale socket or select a fresh private socket path. The server deliberately does
not unlink an existing socket on startup. Never delete the stable owner lock.
Automated mounted-crash cleanup is a next task; data publication crash tests do
not imply that frontend reconnection is automatic.

## Limits and exposure

- Every commit copies the full encrypted image and rewrites every primary sector;
  it needs roughly one additional image's worth of free disk space and blocks reads.
- Staging directories/images may survive a crash. They contain ciphertext and
  visible update history, and are not used for automatic recovery. Old filesystem
  extents and the lock/socket artifacts weaken operational deniability.
- The session ceiling defaults to 2^20 sector encryptions, counting an attempted
  whole-carrier commit conservatively. It is not persistent key-lifetime accounting.
  This process remembers planned IVs during its lifetime; prior sessions, cloned
  images and rollback still require a trusted disposable lineage and external
  lifetime limits. A restart does not establish a fresh primary key.
- `--initialize` explicitly starts with an empty hidden buffer and replaces any
  prior hidden payload on flush. It cannot distinguish an absent payload from
  the wrong hidden key. Without this flag, hidden authentication must succeed.
- Keys/plaintext remain in Python memory without guaranteed erasure. Hidden
  capacity, crypto-review and multiple-snapshot limitations are unchanged.

## Development and reproduction

No new host package is required. The QEMU integration installs guest-only
`python3-pyfuse3`, `python3-trio`, `python3-cryptography`, `fuse3`, `nbd-client`
and filesystem tools. It exports package source read-only with `--code`; the
backing file lives on guest ext4, not 9p. Only after the service stops does the
test attach that file to an independent stock-Linux mapper.

```sh
python3 scripts/vm.py run --code --script scripts/guest-online.sh --data-image artifacts/control-003/control.img --share-file artifacts/control-003/share/passphrase.key --share-file artifacts/control-003/share/volume.key --share-file artifacts/control-003/hidden.key --run-dir artifacts/online-002 --timeout 1500
PIV_FIXTURE=artifacts/control-003 python3 -W error::ResourceWarning -m unittest discover -v
```

The hidden key is a disposable runtime key; create one with `pivstore keygen` if
the example fixture's hidden.key does not exist. Choose a new run directory each
time. This test deliberately reformats the copied volume's primary filesystem
and discards any incoming hidden payload; never use non-disposable input data.

For manual guest use, first close all other mappings and create empty private
mount/socket directories. Start the foreground service with key-file paths:

```sh
python3 -m pivstore serve current.img --volume-key-file volume.key --hidden-key-file hidden.key --socket /run/piv/primary.sock --mountpoint /run/piv/hidden --initialize
```

In a second guest shell connect `nbd-client -unix /run/piv/primary.sock -N primary
/dev/nbd0`, then mount `/dev/nbd0` read-only (for the clean ext4 demo use `ro,noload`).
Edit `/run/piv/hidden/payload` and explicitly fsync it. Unmount the primary,
disconnect NBD, unmount FUSE, and wait for the service before running offline
tools. On later starts omit `--initialize` to authenticate/recover existing data.

Protocol/API references used during implementation:

- [Official NBD protocol](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md)
- [pyfuse3 examples](https://pyfuse3.readthedocs.io/en/latest/example.html)

## Recorded result

artifacts/online-002 passed the complete mounted test on the pinned Debian guest:
pyfuse3 3.4.0, Trio 0.29.0, cryptography 43.0.0, nbd-client 3.26.1, fuse3 3.17.2.
The host suite passes 31 tests. Primary hashes before updates, before/after restart
and through the final stock Linux mapper all matched. Host cryptography 46.0.5
also authenticated all 28,244 final-image sectors and unpacked the matching
20-byte synthetic payload. See ROADMAP.md for full provenance and handoff.
