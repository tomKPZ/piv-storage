# Matched ordinary-Linux controls

This experiment measures observable differences between ordinary stock Linux
writes and the same writes through the native owner. It does not certify
plausible deniability or prove single-snapshot indistinguishability.

## Controls and observer access

Each profile starts from one ordinary stock-Linux fixture. Two sequential arms
(`kernel/guest-controls-test.py`) restore that fixture onto only the guest-owned
`/dev/vdb` with every mapping closed:

- **stock**: unmodified cryptsetup/dm-crypt, ordinary requested writes.
- **native**: dm-piv, hidden zeros initialized (format v5) before its own
  baseline, then exactly the same requested primary writes through the decoy
  view. Hidden zeros must survive the workload.

The custom module is loaded only for the native arm. Each arm gets a closed
before snapshot and a closed after snapshot. Key, UUID, geometry and primary
plaintext are deliberately matched; fresh CRNG state evolves and is never
restored. These are sequential synthetic clones, not independently sampled
volumes. Native initialization is excluded from the workload trace, but would
itself be visible to an observer with earlier snapshots (it rewrites keyslot 0,
the directory and every record carrier with unchanged plaintext).

The workload (`scripts/control_metrics.py`, `span` = 687 primary sectors, one
v5 record without parity) writes
one primary sector at offset 0, 4 KiB ending at `span`, 16 KiB straddling
`3·span`, and rewrites one sector at `5·span` with its own plaintext. Offsets
are decoy-view bytes, so the writes touch the keyslot area, the directory and a
record. Test bytes are deterministic. Both final primary plaintexts must match
exactly; host analysis (`scripts/analyze_controls.py`) independently
authenticates every before/after sector, verifies only the requested bytes
changed and decodes the native hidden contents with the hidden key (used only
for correctness, never as a detector). No hidden write occurs in the workload;
the hidden-write signature is discussed in
[security-review.md](security-review.md#journal-history-and-the-decoy-key-holder).

Observer measurements are separated:

- Without keys: public geometry/header compatibility, changed IV/ciphertext
  extents between snapshots, descriptive IV byte statistics, public journal
  addresses and `/dev/vdb` block submissions during the workload.
- With the primary key: authenticated plaintext changes versus same-plaintext
  reencryption.
- With host/runtime access: the installed module, process memory, tracing and
  operational artifacts remain outside any disk-only concealment claim.

## Measurements and limits

Closed images use the strict LUKS/integrity parser. The analysis checks
identical LUKS prefixes and layout, exact changed-IV positions, all primary
plaintext bytes, current-IV duplicates and native hidden contents. It counts
changed physical 512-byte units by superblock, journal, metadata area and data
area; area labels include ordinary padding.

The `block_bio_queue` trace is filtered to `/dev/vdb` and rejects overruns. It
counts submissions and queued bytes, not media writes or a fixed amplification
ratio. Capture includes a non-atomic direct journal read and one second after
fsync; some journal-to-data propagation happens only at close, outside the trace
window. Live journal reads may race background updates: only sections with
consistent commit IDs are described and none is an atomic or authenticated
snapshot. The stock journal is neither encrypted nor MACed.

Byte summaries (one-bit fraction, empirical byte entropy, byte chi-square, zlib
ratio over all IV bytes) are descriptive. No p-values, classifier accuracy,
acceptance threshold or security proof is inferred; a few synthetic samples
cannot establish pseudorandomness against arbitrary steganalysis.

## Executed results (format v5, all supported profiles)

The 2026-10-22 format v5 matrix (`artifacts/suite-076-v5`, controls suite on
the 128 MiB `aegis-4096`, `aegis-512`, `aes-sha256-4096` and `aes-sha256-512`
fixtures) repeated the experiment with the v5 workload span. In every profile
the native changed-IV positions equal the stock ones exactly (7 changed IVs, 6
changed plaintext sectors and 1 same-plaintext reencryption at 4096-byte
sectors; 42 / 41 / 1 at 512), both arms authenticated every primary sector and
ended with the same primary hash, and the native hidden zeros survived. The
byte statistics and live-I/O counts are in each run's `analysis.json` (not
committed); the interpretation below applies.

## Interpretation

For decoy writes, the closed-snapshot footprint (changed IVs and plaintext
sectors) matched stock. That does not make the native stack
indistinguishable: live I/O traces can differ (the native owner issues its own
bounded authenticated range reads instead of the stock read path; the counts
depend on timing, flushes and earlier journal contents and identify the use of
the native stack to an I/O observer, not hidden data), initialization and
hidden writes rewrite carriers with unchanged plaintext, and there is no basis
here for a multi-snapshot or workload-observing deniability claim.

## Reproduce

Run the `controls` suite on a pristine stock fixture through the suite runner
(see [development.md](development.md)); it restores the fixture inside the
guarded guest and writes `analysis.json` next to the run:

```sh
python3 scripts/suite.py --prefix artifacts/suite-next \
  --scaffold artifacts/scaffold-next.tar \
  --profile aegis-4096 --profile aegis-512 --suites controls
```

Host authentication of AEGIS images requires the pinned optional original
AEGIS-128 reference described in development.md. JSON, traces, snapshots, keys
and large outputs stay ignored.
