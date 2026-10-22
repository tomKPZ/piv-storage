# Matched ordinary-Linux controls

This experiment measures observable differences between ordinary stock Linux
writes and the same writes through the native owner. It does not certify
plausible deniability or prove single-snapshot indistinguishability.

## Controls and observer access

Each profile starts from one ordinary stock-Linux fixture. Two sequential arms
(`kernel/guest-controls-test.py`) restore that fixture onto only the guest-owned
`/dev/vdb` with every mapping closed:

- **stock**: unmodified cryptsetup/dm-crypt, ordinary requested writes.
- **native**: dm-piv, hidden zeros initialized (format v4) before its own
  baseline, then exactly the same requested primary writes through the decoy
  view. Hidden zeros must survive the workload.

The custom module is loaded only for the native arm. Each arm gets a closed
before snapshot and a closed after snapshot. Key, UUID, geometry and primary
plaintext are deliberately matched; fresh CRNG state evolves and is never
restored. These are sequential synthetic clones, not independently sampled
volumes. Native initialization is excluded from the workload trace, but would
itself be visible to an observer with earlier snapshots (it rewrites keyslot 0,
the directory and every record carrier with unchanged plaintext).

The workload (`scripts/control_metrics.py`, `span` = 90 primary sectors) writes
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

## Executed results (format v4, original AEGIS-128)

Measured on the 128 MiB `aegis-4096` and `aegis-512` fixtures (pinned Debian
6.12.113 guest, run `artifacts/suite-061` on 2026-10-22, before the XTS + HMAC
profiles were added; artifacts are not committed). The XTS + HMAC profiles have not been measured with
this experiment; the decoy-write rule is profile-independent, but no result is
claimed for them.

| Profile / arm | Changed primary IVs | Changed plaintext sectors | Same-plaintext reencryption | Changed journal / metadata / data 512 B units (closed) |
| --- | ---: | ---: | ---: | --- |
| AEGIS 4096 / stock | 7 | 6 | 1 | 1,848 / 4 / 56 |
| AEGIS 4096 / native | 7 | 6 | 1 | 1,848 / 4 / 56 |
| AEGIS 512 / stock | 42 | 41 | 1 | 2,024 / 6 / 42 |
| AEGIS 512 / native | 42 | 41 | 1 | 2,024 / 6 / 42 |

In both profiles the native changed-IV positions equal the stock ones exactly:
a v4 decoy write changes only the IVs of the sectors it writes. Both arms
authenticated every sector (28,216 / 213,008), ended with the same primary hash,
had no duplicate current IVs, and the native hidden contents (158,720 /
1,209,856 bytes) remained zero.

| Profile / arm | One-bit fraction | Byte entropy | Byte chi-square | zlib ratio |
| --- | ---: | ---: | ---: | ---: |
| AEGIS 4096 / stock | 0.499687 | 7.999631 | 231.60 | 1.000323 |
| AEGIS 4096 / native | 0.499990 | 7.999634 | 229.37 | 1.000323 |
| AEGIS 512 / stock | 0.500143 | 7.999943 | 268.06 | 1.000307 |
| AEGIS 512 / native | 0.499754 | 7.999947 | 251.23 | 1.000307 |

Live I/O still differs. Queued journal bytes were 540,672 (stock) / 540,672
(native) at 4096-byte sectors and 180,224 / 225,280 at 512. Submission counts
differ in shape: the stock arm shows read-ahead reads (92 and 94 events), the
native owner bounded synchronous range reads (36 and 171 events). Live journal
samples held 7 / 8 and 42 / 43 entries. These counts depend on timing, flushes
and earlier journal contents; they identify the use of the native stack to an
I/O observer, not hidden data.

Interpretation: for decoy writes, the closed-snapshot footprint (changed IVs,
plaintext and physical units) matched stock in this run. That does not make the
native stack indistinguishable: live I/O traces differ, initialization and
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
