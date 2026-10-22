# Journal atomicity

Question: can the stock dm-integrity journal make one hidden record (90 primary
sectors) atomic across power loss? Answer: no. The journal gives per-sector
primary atomicity only; per-block hidden atomicity comes from the optional A/B
record slots ([format-v4.md](format-v4.md)).

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
  AEGIS at 4096-byte sectors, 80 at 512; 32 and 56 for XTS + HMAC-SHA256; see
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
   authentication (EIO). This is why no-journal volumes are unsupported
   ([below](#no-journal-mode-is-unsupported)).
3. The design tolerates failing sectors: setup scans only the keyslot area by
   default (`--verify` keeps the strict full audit), keyslot, directory and
   hidden decoding take raw IVs of failing carrier sectors (only the SIV tag can
   accept them), and a decoy write covering a whole failing sector replaces it.
   A torn sector therefore does not block activation; it returns EIO until
   overwritten.

## No-journal mode is unsupported

pivsetup refuses a LUKS2 header persisting the stock `"no-journal"` flag
(`cryptsetup open --integrity-no-journal --persistent`) and any non-journal
(direct-mode `D`) lower table. Earlier opt-in support showed the hazard: in the
same power test on 4096- and 512-byte AEGIS no-journal volumes, an interrupted
hidden write left a carrier sector it re-encrypted with unchanged plaintext
failing authentication (every 4096 run, some 512 runs), so a crash could
destroy decoy sectors the user never wrote, an observable anomaly that stock
no-journal users do not have. The measured dm-piv write gain was at most about
17%, and none at 512-byte sectors ([configuration.md](configuration.md#integrity-journal)),
so support was removed.
