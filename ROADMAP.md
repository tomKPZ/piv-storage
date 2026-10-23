# Roadmap

What remains. History lives in git (the previous long-form roadmap with every
session handoff is in commits up to 2026-10-22); current behaviour, evidence
and limits are in README.md and docs/.

## Current state (2026-10-23)

- One coordinated native owner (`kernel/dm-piv.c`, standalone, no dm-crypt fork)
  exposes paired writable decoy/hidden block devices over a stock LUKS2 +
  dm-integrity volume with 16-byte random IVs (AES-XTS + HMAC-SHA256 authenc,
  the recommended profile, or AEGIS-128). Hidden format v5 (4 KiB records, keyslot parameters, Argon2id
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
  offset, GPT partition) and 2–8 GiB volumes. Test tiers and rerun policy:
  docs/development.md.
- Activation is no longer confined to the test guest (user approval
  2026-10-22): `--device` is required and any block device or partition is
  accepted, with the user-protecting checks kept. packaging/ provides DKMS,
  install.sh and an initramfs-tools hook, verified by the `deploy` suite
  (packaging/README.md).

## Remaining work

1. **No-journal mode for deniability** (user decision 2026-10-23; reverses the
   2026-10-22 removal). Stock dm-integrity keeps every recent write (target
   sector, full ciphertext, tag and IV; no journal encryption) in its circular
   journal while the volume is active and after a crash; only a clean
   deactivation wipes it (`init_journal()` in postsuspend). A hidden write
   journals a whole 687-sector record, so a crash or seizure image shows a
   decoy-key holder recent record-shaped runs re-encrypted with identical
   plaintext (up to ~190 hidden writes in a 64 MiB journal at 512-byte
   sectors). Re-add support for stock `--integrity-no-journal --persistent`
   volumes (direct-mode lower table) in pivsetup, the Python diagnostics,
   fixtures (`*-nojournal` profiles) and the fault/power/recover tests, and
   make it the **recommended** mode for deniability; journaled mode stays
   supported as the integrity-first choice. Re-measure the torn-sector
   behaviour under v5 and the current batched/concurrent write path (which
   decoy and carrier sectors a crash can tear; power suite with and without
   `--ab`; ext4power on no-journal), document the residual single-record tear
   signature, and recommend `--ab` for hidden data on no-journal volumes.
   Update configuration.md, journal-atomicity.md, security-review.md, README
   (before-production section) and AGENTS.md. Exit: all suites pass on
   journaled and no-journal fixtures (stock and sanitizer), host checks
   verify, docs updated.
2. **Shape hidden writes for keyless observers** (kernel, no format change).
   A hidden write rewrites exactly the record's G sectors starting at
   `112 + G·g`; at 512-byte sectors that is a 351,744-byte run (not a 4 KiB
   multiple) at unaligned offsets, a shape ordinary filesystems do not
   produce and that any address trace (journal, I/O tracing, multiple
   snapshots) reveals without keys. Extend each record rewrite to 4 KiB
   (consider larger, e.g. 64 KiB) aligned edges by refreshing the neighbouring
   sectors' IVs with the decoy-write rule (fragments kept, fresh random bytes,
   plaintext unchanged, same authentication and collision rules), inside the
   same range lock. Measure the amplification cost with `bench` and choose
   the alignment; document what it does not hide (a decoy-key holder still
   sees unchanged-plaintext rewrites). Exit: profile/v5 counts updated, a test
   asserting every hidden-write lower bio set is aligned, docs updated.
3. **Parallel Argon2 lanes** (pivsetup). Tiers use 4 lanes, but the vendored
   `argon2` 0.5.3 computes them sequentially (no `parallel` feature; its
   block-filling routine is private), so an attacker gains up to ~4× in time
   per guess versus the defender's open time. Thread the lanes (argon2 ≥ 0.6
   with rayon, or a small in-tree lane scheduler on maintained primitives),
   keeping outputs byte-identical (existing KEK vectors in rust/tests must
   still match; no format change). Then decide whether to raise tier passes so
   tier 3 stays ≈ 2 s. Exit: vectors unchanged, tier timings re-measured with
   `bench`, docs updated.
4. **`pivsetup status` and a non-destructive hidden scrub.** Today fail-stop
   is visible only as EIO plus dmesg, and `--fill` is the only whole-volume
   hidden pass (destructive). Add `pivsetup status` (owner active/failed,
   encryptions, hidden size, views, via the existing STATUS ioctl; no new
   control commands) and a read-only scrub that reads every hidden block and
   reports valid / RS-recovered / unavailable counts without writing (in
   pivsetup over the hidden view, or as a read-only setup flag if
   RS-recovered blocks need kernel reporting). Exit: devices/v5 suites cover
   status on healthy and failed owners and scrub counts on damaged blocks
   (with and without parity); docs (README before-production section,
   configuration.md) updated.

Open, unverified deployment areas (pick up only with a concrete need; each
needs a disposable-guest test first):

- Boot-time `ask` prompts (initramfs askpass), a root filesystem on a view,
  Secure Boot enrollment/enforcement of the DKMS-signed module, dracut and
  non-Debian distributions (packaging/README.md lists what was verified).

## Standing decisions (binding for autonomous sessions)

- One hidden format at a time: v5 (it replaced v4 without migration; a future
  format would do the same unless the user decides otherwise). Primary profiles: aes-xts-random +
  hmac-sha256 (recommended since 2026-10-23, with 512-byte sectors and `--ab`
  for hidden filesystems) and AEGIS-128. v3, the 12-byte-IV profiles, Serpent/Twofish-XTS and
  HMAC-SHA1/SHA512 stay removed (the last four by user decision 2026-10-22,
  for maintenance).
- Format v5 is frozen (2026-10-22, after the final-review format fixes; see
  docs/format-v5.md). Only directory-listed keyslots are authoritative,
  initialization revokes earlier keyslots, and keyslot changes need the
  current hidden credential.
- Setup scans only the keyslot area; `--verify` is the full audit. A decoy write
  covering a whole sector that fails authentication replaces it; raw IVs of such
  sectors feed only SIV-checked decoding (keyslots, directory, hidden reads).
- Priorities (user, 2026-10-23): deniability > integrity > performance and
  storage overhead.
- Stock no-journal volumes are currently refused, but the user decided on
  2026-10-23 to re-add them as the recommended deniability mode (item 1).
  Hidden passphrases use Argon2id only (scrypt removed).
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
