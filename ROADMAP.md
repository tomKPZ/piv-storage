# Roadmap

What remains. History lives in git (the previous long-form roadmap with every
session handoff is in commits up to 2026-10-22); current behaviour, evidence
and limits are in README.md and docs/.

## Current state (2026-10-22)

- One coordinated native owner (`kernel/dm-piv.c`, standalone, no dm-crypt fork)
  exposes paired writable decoy/hidden block devices over a stock LUKS2 +
  dm-integrity volume with 16-byte random IVs (AEGIS-128 default, or XTS + HMAC
  authenc). Hidden format v4 is the only format.
- Setup is the static Rust `pivsetup` (open/close, keyslots, migrate, keygen);
  Python keeps only independent read-only diagnostics and guest test
  instrumentation.
- Tested on the pinned Debian 6.12.113 guest kernel, its KASAN/UBSAN/lockdep
  build and the Debian backports 7.2.9 kernel; journaled and opt-in no-journal
  volumes; 128 and 512 MiB fixtures. Test tiers and rerun policy:
  docs/development.md.

## Remaining work

1. **External cryptographic review** of the whole stored encoding (format v4:
   LRW-AES fragments, SIV records, keyslots/directory, KDFs) and of the
   AEGIS-128 and XTS + HMAC primary profiles' usage and the nonce-budget guidance in docs/security-review.md. Needs an
   outside reviewer; findings override everything below.
2. **Sanitizer build of the 7.2 port kernel** (optional; the KASAN image is
   6.12 only). docs/kernel-port.md.
3. **Kernels between 6.12 and 7.2 and other distributions** (optional). The
   API shims in dm-piv.c use believed-but-unverified version thresholds; a wrong
   one fails the build rather than misbehaving.
4. **Deployment beyond test guests** — packaging and module signing, boot
   integration beyond the test initramfs, and real-device activation. The guards
   deliberately restrict activation to the pinned disposable QEMU guests; lifting
   that is a scope change that needs the user.

## Standing decisions (binding for autonomous sessions)

- Format v4 only. Primary profiles: AEGIS-128 (default) and aes-/serpent-/
  twofish-xts-random with hmac-sha1/256/512 (2026-10-22); v3 and the 12-byte-IV
  profiles stay removed.
- Setup scans only the keyslot area; `--verify` is the full audit. A decoy write
  covering a whole sector that fails authentication replaces it; raw IVs of such
  sectors feed only SIV-checked decoding (keyslots, directory, hidden reads).
- Journaled dm-integrity is the default. Stock no-journal is accepted only with
  `--allow-no-journal`; its torn-decoy-sector hazard is accepted by the user.
- No persistent counter, history, WAL or ledger. Multi-snapshot observers,
  rollback resistance and coercion-resistant alternative openings are out of
  scope.
- The control device exposes only QUERY, DEVICES, BEGIN/END, SETUP, DETACH,
  STATUS and KEYSLOT; no userspace IV or tuple access.
- Migration (`pivsetup migrate`) is the rekey/resize path; no online rekey.
