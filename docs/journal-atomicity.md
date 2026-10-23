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
block valid, and a later full hidden write repaired it. The same test passed on all
four profiles with concurrent requests and no completion flush (suite-090: 96,
256, 96 and 160 changed carrier IVs at the cut, first attempt each; the
hidden writer's fsync and the prefill's fsyncs provide the commits). This kills
the VM, not the device: it does not model a torn device write or hardware
power loss.

## Conclusions

1. The journal does not make a hidden record atomic, and cannot without changes
   to dm-integrity. Without A/B an interrupted hidden write leaves its block
   unavailable (EIO); with A/B the previous version stays readable. There is no
   cross-block ordering.
2. The journal does provide per-sector primary atomicity (data, tag and IV
   together). Without it, a crash can tear a primary sector, which then fails
   authentication (EIO); no-journal volumes accept that for deniability
   ([below](#no-journal-mode)).
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

## No-journal mode

Stock persistent no-journal volumes (`cryptsetup open --integrity-no-journal
--persistent`, direct-mode `D` lower table) are supported and recommended for
deniability (user decision 2026-10-23, reversing the 2026-10-22 removal): the
journal keeps recent hidden writes readable to a decoy-key holder after a
crash or while active ([security review](security-review.md#journal-history-and-the-decoy-key-holder)).
pivsetup accepts the `no-journal` flag alone and exactly the stock direct-mode
options (the journaled ones minus `journal_watermark` and `commit_time`).

**Mechanism** (pinned 6.12 source): in direct mode dm-integrity submits the
data bio in place and updates the tags in its dm-bufio metadata cache; dirty
metadata reaches the disk at the next flush or FUA (or bufio writeback, or
deactivation). Nothing orders the two, so a crash in between leaves sectors
whose data and tag/IV come from different writes: they fail authentication.

**Power test** (suite-125, reproduced identically in suite-128, on the
sanitizer kernel in suite-129 and on the 7.2.9 port kernel in suite-131; the
same dm-delay test with a 1 s write delay; on
no-journal fixtures the cut lands as soon as any data or tag byte of the
carrier changed on disk while the writer's fsync is outstanding):

| Profile | Mode | Carrier at the cut | Torn sectors after reboot | Block 0 | Hidden write before decoy repair |
| --- | --- | --- | --- | --- | --- |
| AES-XTS + HMAC 512 | single, `--ab` | data of all 687 sectors new, no tag yet | 687: exactly the record (sectors 1,486–2,172; A/B: slot 1, 2,173–2,859) | old | EIO |
| AES-XTS + HMAC 4096 | single, `--ab` | same | same | old | EIO |
| AEGIS-128 512 | single, `--ab` | same | same | old | EIO |

Every cut caught the record's data written and its tags still buffered, the
widest window: it lasts until the next flush, so an unflushed hidden write
leaves its carrier exposed this long. The block read its **old** contents
because the stored IVs (with the old fragments) were intact; the torn sectors'
raw IVs feed SIV-checked decoding. Hidden writes stay strict, so rewriting
that block failed locally (EIO, no fail-stop) until full-sector decoy writes
replaced the torn sectors; afterwards the hidden rewrite and stock read-only
verification of every primary sector passed. The decoy plaintext of torn
sectors is lost (the test restores it from a pre-cut copy). Torn sectors never
left the in-flight record's carrier. A cut after the tag flush leaves the new
block and no tears; tags reaching the disk before data (not observed here)
would tear the same sectors.

Other no-journal runs: the ext4power suite (ext4 on single-slot and A/B
hidden views, 512-byte sectors; suite-125 and suite-128, 12 volumes) left torn
sectors in 5 of 12 volumes, always whole records at record boundaries: 1, 1,
6 and 12 records in A/B or single-slot volumes (one single-slot cut tore 11
consecutive records, a burst of unflushed hidden writes). No hidden block read
EIO before or after the decoy repair (the stored IVs still held the old
fragments), every mount replayed, every fsync'ed file survived and fsck was
clean. In the stress suite's concurrent lower-write-error phase, 2
to 1,377 decoy sectors were torn, all inside the region that phase wrote.
Lower write errors (fault suite, suite-127) tore exactly the failed
request's sectors and nothing else: a 128 KiB decoy write (256 sectors at 512,
32 at 4096), a hidden write's 687-sector record, 14 sectors of the
initialization's keyslot revocation and 2,061 (512) or 5,496 (4096) sectors of
fill records, because tags buffered by dm-integrity reached the disk at
deactivation after their data writes had failed. Full-sector decoy writes
repaired all of them.

**Residual signature.** A crash image of a no-journal volume shows no journal
history, but each hidden write not yet covered by a flush can leave one run
of exactly G failing sectors starting at a record boundary (`112 + G·g`;
ext4power saw up to 12 such records after one cut); stock crash tears follow
the filesystem's write extents. ROADMAP's hidden-write shaping would
align such runs to ordinary block edges but not hide their length.

**Earlier result** (format v4): the same hazard was measured on
AEGIS no-journal volumes (every 4096 run, some 512 runs), and support was
removed for maintenance after the journal was judged the safer default.
