# Journal atomicity and the no-journal option (roadmap item 6)

Question: can the stock dm-integrity journal make one hidden record (a carrier
group of 36/48/90 primary sectors) atomic across power loss? If it could,
journaled mode would give atomic hidden writes at no capacity cost, which
would weigh against `--integrity-no-journal`.

## Evidence

**Source** (pinned Linux 6.12.113 `drivers/md/dm-integrity.c`, fetched for
review only):

- `integrity_commit` stamps commit IDs on every uncommitted section, then
  `write_journal` writes that contiguous section range with one FUA I/O (two
  if it wraps). Replay validates each section independently by its per-sector
  commit IDs. A commit spanning several sections is therefore only as atomic as
  the device makes a multi-sector write. Storage gives no such guarantee.
- `dm_integrity_map_continue` limits a journal reservation to the free journal
  space (`free_sectors`). Under journal pressure one bio is therefore copied in
  several reservations, which can land in different commits.
- With the pinned layouts, one section holds 32 entries at 4096-byte sectors
  (104-byte entries, 264-sector sections). Every carrier group (36, 48 or 90
  sectors) needs at least two sections, even if it were submitted as one bio.

**Experiment:** `artifacts/stateless-power-003` (an earlier handoff) cut power
during a hidden write and observed exactly 32 of 48 carrier slots changed. The
block returned EIO after replay. The native owner applies one tuple per bio
and flushes every 32 tuples, so non-atomicity is observed, not hypothetical.

**Not done:** a QEMU SIGKILL experiment of a single multi-section bio. The host
page cache survives SIGKILL, and QEMU usually completes or drops a whole
guest request, so such a test would overstate atomicity. It would not model a
torn device write.

## Conclusions

1. The journal does not make a hidden record atomic, and it cannot without
   changes to dm-integrity. Per-block hidden atomicity comes from format v4
   A/B slots, which work with or without a journal.
2. The journal does provide per-sector primary atomicity (data, tag and IV
   together). Without a journal, a crash can tear one primary sector, which
   then fails authentication. Stock users of `--integrity-no-journal` accept
   EIO on that sector.
3. Native setup authenticates every primary sector and refuses a volume with
   any failing sector. Combined with no-journal, one torn sector would block
   activation until it is repaired outside the stack (for example, overwriting
   that sector through stock dm-crypt, which also destroys the hidden fragment
   it carried). This is the main cost of no-journal for this design.
4. Recommendation: keep the journaled default for now. Offer no-journal as an
   explicit option (format v4 phase 4) only together with a documented repair
   path, or with a setup policy that tolerates and reports torn sectors. That
   policy needs a decision: it relaxes "authenticate every sector before
   exposing", although per-request authentication still prevents serving or
   modifying unauthenticated data.
