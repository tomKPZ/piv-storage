# Matched ordinary-Linux controls

> [!NOTE]
> 2026-10-21: format v3 and the AES-GCM / ChaCha20-Poly1305 profiles were
> removed (AEGIS-128 with [format v4](format-v4.md) is the only supported
> configuration). Results below that mention them are historical evidence for
> the code at that time; current runs are recorded in commit messages.

This experiment measures observable differences. It does not certify plausible
deniability or prove single-snapshot indistinguishability. The implementation
and on-disk encoding are unchanged.

## Controls and observer access

Each profile starts from one ordinary stock-Linux fixture. Three sequential arms
restore that fixture onto ONLY guest-owned /dev/vdb with every mapping closed:

- stock: unmodified cryptsetup/dm-crypt, ordinary requested writes.
- stock-refresh: unmodified cryptsetup/dm-crypt, application-level read/modify/
  rewrite of every complete carrier group intersecting each requested write.
  This control encodes no hidden records; unchanged primary bytes are simply
  rewritten through ordinary encryption.
- native: dm-piv, hidden zeros initialized before its own baseline, then exactly
  the same requested primary writes. Hidden zeros must survive the workload.

The custom module is loaded only for the last arm. Each arm gets a closed before
snapshot and a closed after snapshot. Key, UUID, geometry and primary plaintext
are deliberately matched; fresh CRNG state evolves through the experiment and is
never restored. These are sequential synthetic clones, not independently sampled
volumes. Native initialization is excluded from its workload trace, but would
itself be visible to an observer with earlier snapshots.

The workload is a primary-sector write at 0, 4 KiB ending at the first carrier
boundary, 16 KiB across the third carrier boundary, and a same-plaintext sector
rewrite in group 5. Nontrivial test bytes are deterministic. All requests satisfy
stock primary alignment. Both stock and native final primary plaintexts must
match exactly; host analysis independently authenticates every before/after
sector and verifies only the requested bytes changed. Native hidden records
must independently decode to the expected zeros.

Observer measurements are deliberately separated:

- Without keys: public geometry/header compatibility, changed IV/ciphertext
  extents between snapshots, descriptive IV byte statistics, public journal
  addresses and physical-vdb block submissions during the workload.
- With the primary key: authenticated plaintext changes versus same-plaintext
  reencryption. The hidden key is used only by correctness verification, never
  as a proposed detector.
- With host/runtime access: the installed module, process memory, tracing and
  operational artifacts remain outside any disk-only concealment claim.

## Measurements and limits

Closed images use the existing strict LUKS/integrity parser. The analysis checks
identical LUKS prefixes, identical supported layout, exact changed-IV support,
all primary plaintext bytes, current IV duplicates and native hidden contents.
It counts changed physical 512-byte units by header, superblock, journal,
metadata area and data area. Area labels include ordinary padding; they are not
claims that each changed byte is a live tag or ciphertext byte.

The block_bio_queue trace is filtered to /dev/vdb and rejects overruns. It counts
submissions and repeated submitted bytes, not SSD/media writes, completed bytes
or a fixed amplification ratio. Capture includes a non-atomic direct journal
read and one second after fsync. Some journal-to-data propagation can occur only
at close, outside the trace window; all after snapshots are taken after close.
Background journal scheduling and pre-baseline history affect these figures.

Live journal reads may race background updates. Only sections with consistent
pinned commit IDs are described, invalid sections are counted and no replay is
attempted. Even an accepted section is NOT an atomic or authenticated snapshot.
The supported stock journal is neither encrypted nor MACed.

Byte summaries include one-bit frequency, empirical byte entropy, byte-frequency
chi-square and zlib ratio for all IV bytes and corresponding 32/528/16-byte slices
of complete 576-byte groups in EVERY arm. Those slices are salt/ciphertext/tag
only in the native encoding; stock slices have no such meaning. No p-values,
classifier accuracy, acceptance threshold, statistical independence or security
proof is inferred. A small collection of synthetic samples cannot establish
pseudorandomness against arbitrary steganalysis.

## Executed results

AES-GCM with 4096-byte primary sectors, artifacts/controls-4096-001:

| Arm | Changed primary IVs | Changed plaintext sectors | Same-plaintext reencryption |
| --- | ---: | ---: | ---: |
| stock |7|6|1|
| stock-refresh |192|6|186|
| native |192|6|186|

All three arms authenticated and ended with the same primary hash. Native hidden
contents remained zero. Geometry and LUKS prefixes matched exactly. All current
IVs were distinct. All-IV empirical byte entropy was 7.99943 (stock), 7.99944
(stock-refresh), 7.99952 (native) bits/byte; these are observations, not a pass.

Observed queued journal bytes were 540,672 / 1,216,512 / 2,973,696 respectively.
Closed snapshots changed all 1,848 stock journal sectors but 792 native journal
sectors in this run. The live samples contained 7 / 192 / 67 entries respectively,
with all 7 sections commit-ID-consistent. These counts depend on timing, flushes
and earlier journal contents; neither larger nor smaller journal differences
uniquely identify hidden data.

The known primary workload is readily distinguishable from ordinary requested
writes using multiple snapshots or observed I/O. The ordinary whole-group
refresh control matches the native changed-IV positions EXACTLY, showing that
extra same-plaintext reencryption alone does not establish hidden payload
existence. It does not make the native workload identical to the ordinary one.
There is no basis here for a multi-snapshot/workload-observing deniability claim.

Original AEGIS-128 with 512-byte primary sectors,
artifacts/controls-512-001:

| Arm | Changed primary IVs | Changed plaintext sectors | Same-plaintext reencryption |
| --- | ---: | ---: | ---: |
| stock |42|41|1|
| stock-refresh |144|41|103|
| native |144|41|103|

Again, all complete primary outputs matched and native hidden contents remained
zero. Layout/header checks and current-IV uniqueness passed. All-IV empirical
byte entropy was 7.999928 (stock and stock-refresh) and 7.999951 (native).
Queued journal bytes were 180,224 / 405,504 / 585,728. All three closed journals
changed 2,024 physical 512-byte units. Live samples contained 42 / 180 / 253 entries,
with all 23 sections commit-ID-consistent. Repeated sector updates and the native
setup checkpoint can appear in live samples; entry counts are not unique-sector
counts or exact encryption counters. Trace differences remain observable even
when the native and stock-refresh closed changed-IV positions match.

All-IV descriptive summaries (no security acceptance rule):

| Profile / arm | One-bit fraction | Byte entropy | Byte chi-square | zlib ratio |
| --- | ---: | ---: | ---: | ---: |
| AES4096 / stock | 0.499461 | 7.999434 | 265.15 | 1.000328 |
| AES4096 / stock-refresh | 0.499543 | 7.999440 | 262.73 | 1.000328 |
| AES4096 / native | 0.500127 | 7.999523 | 223.61 | 1.000328 |
| AEGIS512 / stock | 0.499848 | 7.999928 | 339.92 | 1.000307 |
| AEGIS512 / stock-refresh | 0.499849 | 7.999928 | 339.65 | 1.000307 |
| AEGIS512 / native | 0.500059 | 7.999951 | 229.94 | 1.000307 |

Host analysis independently authenticated six before/after images per profile:
28,244 sectors per AES image and 213,008 per AEGIS image. Native hidden checks
covered 301,056 and 3,028,992 bytes. Full descriptive statistics, changed-index
lists, physical differences, trace counts and journal addresses are in each
ignored artifacts/controls-*/analysis.json. No unexpected kernel/compiler
warnings occurred in either successful guest experiment. The 37 host tests passed
with ResourceWarning errors and no skips.

## Reproduce

Use a pristine CLOSED ordinary fixture, not a previous native output. A fresh
run directory is mandatory; all restores happen inside the guarded guest.

```sh
python3 scripts/vm.py run --code --script scripts/guest-controls.sh \
  --run-dir artifacts/controls-next \
  --data-image artifacts/control-003/control.img \
  --share-file artifacts/batch-native-4096-001/share/experimental-dm-piv.ko \
  --share-file kernel/guest-controls-test.py --share-file scripts/control_metrics.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key --timeout 3600
python3 scripts/analyze_controls.py artifacts/controls-next/share \
  --volume-key-file artifacts/control-003/share/volume.key \
  --hidden-key-file artifacts/control-003/hidden.key > artifacts/controls-next/analysis.json
```

Use the AEGIS512 stock fixture and matching passphrase/primary key for that
profile. Its host authentication requires the pinned optional original AEGIS
reference described in development.md; guest/native crypto does not. The scripts
need no additional host packages. JSON, traces, snapshots, keys and large outputs
stay ignored. No hidden metadata, persistent ledger or driver mitigation is
introduced by this diagnostic experiment.

The numerical control runs above predate bounded primary read batching. That
optimization preserves record bytes, primary AEAD checks and prepared-tuple write
semantics, but can change scheduling and read traces. Journal timing/counts were
not remeasured after it; do not treat these historical transcripts as exact
current-runtime performance predictions. See read-performance.md for the new
read measurements. The existing known-workload distinctions still constrain
claims; a faster read path does not establish deniability.
