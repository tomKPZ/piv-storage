# Journal atomicity

Question: can the stock dm-integrity journal make one hidden record (687 + 3p
primary sectors) atomic across power loss? Answer: no. The journal gives
per-sector primary atomicity only; per-block hidden atomicity comes from the
optional A/B record slots ([format-v5.md](format-v5.md)), and optional RS
parity may recover a record with few mixed-version sectors.

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
  [observed-layout.md](observed-layout.md)), so a 687-sector record always spans
  more than one section even if it were submitted as one bio.
- The native owner writes a record as a few multi-sector bios (all in flight
  together) and, like stock dm-crypt, does not flush after a plain write.
  dm-integrity commits on the next flush or FUA request, or earlier,
  asynchronously, once free journal entries fall to the 50% watermark
  (`journal_watermark:50`) or its commit timer fires. A 4096-byte record exceeds the
  whole journal and is always committed in parts; a 512-byte record fits below
  the watermark and is usually committed by one journal write. That is not a
  guarantee (journal pressure from earlier writes splits it), so the
  conclusions below do not change.

**Experiment** (guest power test, `kernel/guest-stateless-power.py` and
`scripts/guest-stateless-recover.sh`): a hidden write (no A/B) runs over a
dm-delay test stack and QEMU is killed mid-write; the volume is then replayed by
stock Linux. At 512-byte sectors the test first commits identical-plaintext
decoy rewrites so the record crosses the watermark part way (otherwise the
record would usually be committed whole). With the journal (format v5, all four
supported profiles, batched record writes, suite-081/082), 96 (4096-byte
sectors), 640 (AEGIS 512) and 400 (XTS + HMAC 512) of the record's 687 carrier
IVs were changed in committed journal or current state when the VM was cut,
the block
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

## Unflushed writes

View writes follow stock flush semantics
([write path](native-blocks.md#write-path)): a plain decoy or hidden write
completes when its lower write bios complete, and is durable only after a
later flush or FUA request (a FUA write flushes before completing). Each
primary sector stays old or new across a crash, as with stock dm-crypt. A
hidden block written since the last flush is in the same position as one whose
write was interrupted: after a crash it reads as the old block, the new block
or, without A/B, EIO until rewritten. Before completion flushes were dropped
only a write in flight at the crash could do that; now any write not yet
covered by a flush can. Filesystems on the hidden view already issue flush/FUA
where they need durability (for example ext4 journal commits), so this matches
the stock contract that unflushed writes may be lost, except that a lost
single-slot hidden block becomes unavailable rather than old.

A/B keeps its guarantee: before rewriting a slot, an A/B hidden write flushes
the lower device, so the slot holding the newest version is committed before
the other slot is overwritten. Without that flush, two successive unflushed
writes of one block could leave both slots torn by one crash. Writes of the
same block are serialized by its range lock, so the flush covers the previous
write of the block. A failure of that flush stops the owner like any flush
error.

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
