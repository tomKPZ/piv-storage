# Roadmap

What remains. History lives in git (the previous long-form roadmap with every
session handoff is in commits up to 2026-10-22); current behaviour, evidence
and limits are in README.md and docs/.

## Current state (2026-10-22)

- One coordinated native owner (`kernel/dm-piv.c`, standalone, no dm-crypt fork)
  exposes paired writable decoy/hidden block devices over a stock LUKS2 +
  dm-integrity volume with 16-byte random IVs (AEGIS-128 default, or AES-XTS + HMAC-SHA256
  authenc). Hidden format v5 (4 KiB records, keyslot parameters, Argon2id
  cost tiers, optional Reed–Solomon parity) is the only format.
- Setup is the static Rust `pivsetup` (open/close, keyslots, migrate, keygen);
  Python keeps only independent read-only diagnostics and guest test
  instrumentation.
- Tested on the pinned Debian 6.12.113 guest kernel, its KASAN/UBSAN/lockdep
  build and the Debian backports 7.2.9 kernel; journaled
  volumes; 128 and 512 MiB fixtures. Test tiers and rerun policy:
  docs/development.md.

## Remaining work

1. **Faster record writes** (core module, no format change). Every write
   (decoy, hidden, keyslot, initialization) goes through `pn_commit` /
   `piv_update`, which per sector reads and authenticates three times (range
   read, prepare, apply), self-decrypts, submits one synchronous write and
   flushes every 32 sectors: about 2,000 serial round trips per 687-sector v5
   record (5–8 hidden 4 KiB blocks/s; initialization at 4,600–5,500 primary
   sectors/s extrapolates to 16 h for 1 TiB at 4096-byte sectors and 4–5 days
   at 512; suite-077). A hidden write also allocates one prepared tuple per
   carrier sector (about 3 MiB per record). Reuse the range read's authenticated plaintext
   (drop the prepare/apply re-reads; a per-record lock replaces the old
   userspace-era ESTALE recheck), submit each record as a few multi-sector bios
   with integrity metadata and wait once, flush once per record (initialization:
   every N records and before returning at a cancellation point). Keep the
   failure-scope rules and per-sector authentication before publishing.
   Exit: bench shows the gain for hidden writes, initialization and decoy
   writes; faults, power, cancel, batch and lifecycle suites updated and
   passing on the stock and sanitizer images; docs updated.
2. **Concurrent bios and larger reads** (core module). The single ordered
   `piv-native` worker handles one bio at a time, so decoy writes run 12–45×
   slower than stock dm-crypt and sequential reads 3–5× slower
   (docs/configuration.md, suite-077). Process independent bios and
   initialization records concurrently and/or batch across bios while
   serializing updates that touch the same hidden record, keeping stock
   PREFLUSH/FUA/flush semantics, per-sector authentication before publishing
   and the failure-scope rules (a failure after writing begins still stops the
   owner). Revisit the 16 KiB range-read and DM split bounds and the 2^32
   per-owner cap. Exit as item 1, plus the lifecycle expected ordering updated
   for the new design. Initialization's floor is then disk bandwidth: it reads
   every carrier sector once and writes it about twice (journal).
3. **Quick and resumable initialization** (pivsetup + module, no format change).
   `--initialize --quick` (non-default, user decision 2026-10-22) writes only
   keyslot 0 and the directory; never-written hidden blocks return EIO until
   first written (each hidden write replaces a whole record), which breaks
   tools that read unwritten blocks; document that. A separate fill operation
   on an open volume writes zero records only into blocks whose record does not
   authenticate under the current master key, skipping authenticated ones; it
   completes a quick or cancelled initialization and resumes after
   interruption. It also rewrites damaged blocks as zeros, so it must be an
   explicit, documented destructive command, never automatic. Exit: v5/cancel
   suites cover quick init, EIO on unwritten blocks, fill after cancellation
   and skipping of written blocks; host decoder verifies the result.
4. **Lift the activation guards and deploy beyond test guests** (user
   approval 2026-10-22). Remove pivsetup's restriction to the pinned QEMU guest
   and 128/512 MiB `/dev/vdb` (and the test-only `--allow-test-stack` /
   `--allow-second-disk` escape hatches once unneeded), keeping the safety
   checks that are not about test confinement: exclusive /run locks, identity
   checks on mappings, busy-device protection and refusal of foreign stacks.
   Then packaging and module signing and boot integration beyond the test
   initramfs. Agent testing still uses only disposable guests and synthetic
   disks. Exit: activation works on an arbitrary block device inside a guest
   (e.g. a non-vdb disk of another size), guard tests replaced by tests of the
   remaining safety checks, docs updated.

## Standing decisions (binding for autonomous sessions)

- One hidden format at a time: v5 (it replaced v4 without migration; a future
  format would do the same unless the user decides otherwise). Primary profiles: AEGIS-128 (default) and aes-xts-random +
  hmac-sha256. v3, the 12-byte-IV profiles, Serpent/Twofish-XTS and
  HMAC-SHA1/SHA512 stay removed (the last four by user decision 2026-10-22,
  for maintenance).
- Setup scans only the keyslot area; `--verify` is the full audit. A decoy write
  covering a whole sector that fails authentication replaces it; raw IVs of such
  sectors feed only SIV-checked decoding (keyslots, directory, hidden reads).
- Journaled dm-integrity is required; stock no-journal volumes are refused
  (user decision 2026-10-22: little dm-piv gain, torn decoy sectors on a
  crash). Hidden passphrases use Argon2id only (scrypt removed).
- No persistent counter, history, WAL or ledger. Multi-snapshot observers,
  rollback resistance and coercion-resistant alternative openings are out of
  scope.
- The control device exposes only QUERY, DEVICES, BEGIN/END, SETUP, DETACH,
  STATUS and KEYSLOT; no userspace IV or tuple access.
- Migration (`pivsetup migrate`) is the rekey/resize/cipher-change path. Live
  resize, rekey and cipher change are not supported (user decision 2026-10-22):
  stock cryptsetup refuses them on integrity volumes, so the prototype does not
  add features the stock stack lacks.
- Background initialization (reads above a progress mark return zeros while a
  kernel worker fills records) is not planned: it is not low maintenance
  (user condition 2026-10-22). It needs a persistent mark, a rule separating
  never-written from damaged blocks above it so corruption never becomes
  zeros, interaction with concurrent writes, and worker lifecycle across
  close/cancel. Quick init plus explicit fill covers the need.
