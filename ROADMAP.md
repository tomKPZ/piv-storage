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
  build and the Debian backports 7.2.9 kernel; journaled volumes; 128 and
  512 MiB fixtures plus arbitrary devices (300 MiB disk, loop, dm-linear
  offset, GPT partition) and 2–3 GiB volumes. Test tiers and rerun policy:
  docs/development.md.
- Activation is no longer confined to the test guest (user approval
  2026-10-22): `--device` is required and any block device or partition is
  accepted, with the user-protecting checks kept. packaging/ provides DKMS,
  install.sh and an initramfs-tools hook, verified by the `deploy` suite
  (packaging/README.md).

## Remaining work

No implementation items remain. Open, unverified deployment areas (pick up
only with a concrete need; each needs a disposable-guest test first):

- Boot-time `ask` prompts (initramfs askpass), a root filesystem on a view,
  Secure Boot enrollment/enforcement of the DKMS-signed module, dracut and
  non-Debian distributions (packaging/README.md lists what was verified).

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
