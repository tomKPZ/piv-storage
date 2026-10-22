# Roadmap

What remains. History lives in git (the previous long-form roadmap with every
session handoff is in commits up to 2026-10-22); current behaviour, evidence
and limits are in README.md and docs/.

## Current state (2026-10-22)

- One coordinated native owner (`kernel/dm-piv.c`, standalone, no dm-crypt fork)
  exposes paired writable decoy/hidden block devices over a stock LUKS2 +
  dm-integrity volume with 16-byte random IVs (AEGIS-128 default, or AES-XTS + HMAC-SHA256
  authenc). Hidden format v5 (4 KiB records, keyslot parameters, Argon2id
  cost tiers, optional Reed–Solomon parity) is the only format. View bios run
  concurrently (range locks per sector range/record, stock flush semantics,
  batched 1024-sector authenticated reads).
- Setup is the static Rust `pivsetup` (open/close, keyslots, migrate, keygen;
  full or `--quick` initialization and the explicit, destructive `--fill`);
  Python keeps only independent read-only diagnostics and guest test
  instrumentation.
- Tested on the pinned Debian 6.12.113 guest kernel, its KASAN/UBSAN/lockdep
  build and the Debian backports 7.2.9 kernel; journaled
  volumes; 128 and 512 MiB fixtures. Test tiers and rerun policy:
  docs/development.md.

## Remaining work

1. **Lift the activation guards and deploy beyond test guests** (user
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
