# Journal atomicity and the no-journal option

Question: can the stock dm-integrity journal make one hidden record (90 primary
sectors) atomic across power loss? Answer: no. The journal gives per-sector
primary atomicity only; per-block hidden atomicity comes from the optional A/B
record slots ([format-v4.md](format-v4.md)), which work with or without a journal.

## Evidence

**Source** (pinned Linux 6.12.113 `drivers/md/dm-integrity.c`, fetched for
review only):

- `integrity_commit` stamps commit IDs on every uncommitted section, then
  `write_journal` writes that contiguous section range with one FUA I/O (two
  if it wraps). Replay validates each section independently by its per-sector
  commit IDs. A commit spanning several sections is therefore only as atomic as
  the device makes a multi-sector write; storage gives no such guarantee.
- `dm_integrity_map_continue` limits a journal reservation to the free journal
  space (`free_sectors`). Under journal pressure one bio is copied in several
  reservations, which can land in different commits.
- A journal section holds at most 80 entries in every supported profile (32 for
  AEGIS at 4096-byte sectors, 80 at 512; 24–72 for XTS + HMAC; see
  [observed-layout.md](observed-layout.md)), so a 90-sector record always spans
  more than one section even if it were submitted as one bio.
- The native owner applies one tuple per lower write and flushes every 32
  tuples and at the end of the request.

**Experiment** (guest power test, `kernel/guest-stateless-power.py` and
`scripts/guest-stateless-recover.sh`): a hidden write (no A/B) runs over a
dm-delay test stack and QEMU is killed mid-write; the volume is then replayed by
stock Linux. With the journal (AEGIS 4096 and 512), 32 of the record's 90
carrier IVs were changed in committed journal or current state, the block
returned EIO after replay, no primary sector was torn, other hidden blocks and
all primary plaintext were unchanged, a decoy write did not make the damaged
block valid, and a later full hidden write repaired it. This kills the VM, not
the device: it does not model a torn device write or hardware power loss.

## Conclusions

1. The journal does not make a hidden record atomic, and cannot without changes
   to dm-integrity. Without A/B an interrupted hidden write leaves its block
   unavailable (EIO); with A/B the previous version stays readable. There is no
   cross-block ordering.
2. The journal does provide per-sector primary atomicity (data, tag and IV
   together). Without it, a crash can tear a primary sector, which then fails
   authentication (EIO), as for any stock `--integrity-no-journal` user.
3. The design tolerates failing sectors: setup scans only the keyslot area by
   default (`--verify` keeps the strict full audit), keyslot, directory and
   hidden decoding take raw IVs of failing carrier sectors (only the SIV tag can
   accept them), and a decoy write covering a whole failing sector replaces it.
   A torn sector therefore does not block activation; it returns EIO until
   overwritten.

## No-journal support

Stock `--integrity-no-journal` is persisted by cryptsetup as the LUKS2 config
flag `"no-journal"` (`cryptsetup open --integrity-no-journal --persistent`); the
superblock is unchanged and every later open builds a direct-mode (`D`) lower
table without `journal_watermark`/`commit_time`. pivsetup and the Python
instrumentation accept exactly that flag (any other persistent flag is refused)
and validate the D table; the offline diagnostics read such images unchanged.

**Hazard (measured, accepted by the user).** Without the journal a hidden write
is non-atomic not only for its record but also for the primary sectors it
rewrites: it re-encrypts all 90 carrier sectors with unchanged plaintext, and a
crash can leave a sector with mismatched data and tag/IV. In the same power
test on the `aegis-4096-nojournal` and `aegis-512-nojournal` profiles, primary
sector 303 (inside the interrupted record's carrier) was left failing
authentication (4096 in every run; 512 in some runs, while others tore none);
12 of 90 carrier IVs had changed. Its decoy plaintext is lost unless the user
has a copy (the test restores it from a pre-cut copy to show the damage is
confined to that carrier). Stock no-journal users lose only sectors they were
writing; here a crash can also damage decoy sectors the user never wrote, which
is also an observable anomaly. Decoy writes have only the stock exposure.

**Policy.** pivsetup refuses a no-journal volume unless `--allow-no-journal` is
given (the error explains the hazard). The journal stays the default. With
no-journal, A/B records are recommended; a decoy-write tear leaves the hidden
block readable (both IVs carry the same fragment, and hidden reads use the raw
IV), while an interrupted hidden write mixes old and new fragments and fails its
SIV tag (A/B keeps the previous version). Torn sectors return EIO until a
full-sector decoy write replaces them.

The no-journal profiles run the routine guest suites (faults including the
opt-in refusal and torn-sector confinement, profile, cancel, lifecycle, batch,
early, power, v4) plus fuzz and migrate; executed runs are recorded in commit
messages.
