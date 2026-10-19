# Authenticated read and activation profiling

The bounded profile separates uninstrumented elapsed time from kernel call counts.
It does not change the production driver, record format, ABI or failure policy.
Measurements use the pinned Debian 6.12.113 guest, QEMU TCG with two virtual CPUs
and 1 GiB RAM, the existing batch-native-4096-001 module and synthetic closed
fixtures. Stock dm-crypt stays loaded with an unrelated mounted encrypted
filesystem. Run the two profiles sequentially to avoid competing benchmark VMs.

## Method and limits

`scripts/guest-profile.sh` uses the shared guest guards and loads the existing
matched module. `kernel/guest-profile-test.py` first measures three stock opens,
then three native opens without initialization. It separately times the native
setup ioctl, which authenticates the entire primary and checkpoints sector zero.
Opening includes cryptsetup/keyslot work, private target conversion and public
view creation; the stock open does not include a full primary scan. Close is
outside these timing intervals. These are different activation contracts, not
interchangeable security/performance guarantees.

Stock primary plaintext is completely authenticated/hashed and kept only in
guest RAM as the read oracle. Native primary reads must match it; hidden reads
must match the complete fixture oracle. Direct reads use 512/4096/16384/65536-byte
application requests, three sequential samples each, covering 1 MiB of primary
or 64 KiB of hidden data. Thirty-two reproducible random reads per role
also check bytes. Stock reads obey its reported logical block size: AES/4096
uses 4096-byte random reads and omits the 512-byte sequential case. Native views
use 512-byte random reads for both profiles. Compare common sequential sizes
between stock/native rather than unlike random requests. Timings include Python loops, system calls and comparisons.
The request size is an application size: DM still splits native decoy bios at
16 KiB and hidden bios at 512 bytes. There is no cross-bio cache/coalescing.

These are warm-cache diagnostics. O_DIRECT bypasses the public block-device page
cache, not every lower, host or device cache. The stock run authenticates the
whole primary before timed native reads, and setup/read repetitions further warm
caches. We do not claim cold-start, physical-media, production throughput or a
controlled cipher comparison; the two profiles differ in cipher and geometry.
Medians summarize three samples, not confidence intervals or an extensive run.

A separate instrumented pass installs entry-only kprobes for `piv_load`,
`pn_record`, `pn_write` and `piv_checkpoint`. The compiler specializes
`piv_load` and inlines `pn_setup`; the harness resolves the unique non-cold
load specialization in the loaded module and delimits the setup ioctl in Python. Events contain no payload or key fields.
`tracing_on=0` avoids retaining event data; `kprobe_profile` hit counters still
count enabled handlers. The setup ioctl is counted separately from mapping creation/udev probes; read
counts are taken after udev settles. Saved cumulative probe totals may include
udev discovery reads between intervals; assertions use deltas for each delimited
operation, not those global totals. Missing events, nonzero missed hits and unexpected counts
fail the test. Probe counters establish calls, not time spent or lower physical
read submissions: `piv_load` includes allocation, lower bio setup/submission and
primary decryption. No probe is enabled during elapsed-time measurements.

After profiling, both complete plaintext views are checked, the native stack is
closed, the module unloads, and stock Linux authenticates/hashes the entire final
primary. The copied closed image is also independently verified on the host for
all primary sectors and hidden bytes. Reading spends zero primary encryptions;
activation/close checkpoints can write an existing tuple without new encryption.

## Recorded results (2026-10-19)

Successful sequential runs: artifacts/profile-4096-003 (AES/4096) and
artifacts/profile-512-001 (original AEGIS/512). The reused module SHA-256 is
91d424368e7e73e827afd74f4add8364e77af251b5ced96adc56499216ddfa52.
Both frozen harness copies match the committed source. The production includes
still match vendor/kernel-build/batch-001; no kernel rebuild was needed.

Median elapsed times, three samples per row:

| Operation | AES/4096 | AEGIS/512 |
| --- | ---: | ---: |
| Stock activation | 0.266 s | 0.254 s |
| Native activation | 5.826 s | 35.336 s |
| Native setup ioctl within activation | 5.146 s | 34.647 s |
| 1 MiB stock read, 4 KiB requests | 75.688 ms | 69.379 ms |
| 1 MiB native decoy read, 4 KiB requests | 84.307 ms | 350.137 ms |
| 1 MiB stock read, 16 KiB requests | 24.705 ms | 22.346 ms |
| 1 MiB native decoy read, 16 KiB requests | 60.182 ms | 321.641 ms |
| 1 MiB stock read, 64 KiB requests | 11.282 ms | 10.444 ms |
| 1 MiB native decoy read, 64 KiB requests | 55.337 ms | 311.938 ms |
| 64 KiB hidden read, 512-byte requests | 1.161 s | 0.724 s |
| 64 KiB hidden read, 16 KiB requests | 1.122 s | 0.706 s |
| 64 KiB hidden read, 64 KiB requests | 1.116 s | 0.719 s |

Exact measured `piv_load` call deltas, with zero missed probes:

| Operation | AES/4096 | AEGIS/512 |
| --- | ---: | ---: |
| Setup ioctl, including one checkpoint | 28,245 | 213,009 |
| 512-byte decoy read | 1 | 1 |
| 16 KiB decoy read | 4 | 32 |
| 512-byte hidden read | 48 | 36 |
| 4 KiB hidden read | 384 | 288 |

Setup called the checkpoint once and performed no record encoding or native
write. The read intervals called no checkpoint or write; hidden reads decoded
one record per 512 bytes. The timed read phase spent zero primary encryptions.
A 64 KiB hidden read at AES/4096 authenticates 24 MiB of primary data; at
AEGIS/512 it authenticates 2.25 MiB. Larger application requests barely improve
these hidden timings because record/carrier work is unchanged. Native decoy
reads benefit from larger application requests but remain sector-at-a-time
below each public bio. Setup's similar average cost per sector (about 182/163
microseconds, including the rest of the ioctl) is consistent with substantial
per-sector overhead; it is not a CPU-time decomposition or a cipher benchmark.

Both runs passed complete primary/hidden comparisons, close, custom-module
unload and stock full-primary authentication. Independent host verification
also authenticated all 28,244 / 213,008 primary sectors and matched all
301,056 / 3,028,992 hidden bytes. Current IVs were distinct; no lifetime nonce
claim follows. Guest logs contain no unexpected BUG/Oops/WARNING; unsigned
module taint and udev reads rejected by the private owner are expected.

Failed/obsolete attempts are not successful fixtures: profile-4096-001 tried
512-byte direct reads on a stock 4096-logical device. profile-4096-002 was stopped
before completion when inspection showed that compiler specialization/inlining
required different probe symbols. The final harness obeys stock logical sizes,
resolves the actual load symbol and delimits setup before public udev probes.

## Optimization direction

Retain authentication of every primary sector, including sectors whose IVs are
only being collected for a hidden read. The bounded next candidate is a shared
range-read helper: gather at most 16 KiB of primary data/tag/IV tuples in one
lower bio, then authenticate each sector with the unchanged Linux AAD before
returning any requested bytes. Use it for setup scans, decoy reads and carrier
collection, without persistent caches, lazy setup verification or cross-bio
transactions. Count reductions and repeat these timings before accepting it.

The current call-count evidence does not separate CPU crypto time, allocations,
lower bio latency and scheduling. It identifies repeated authenticated sector
loads as the path to investigate; it does not prove that any proposed batching
will achieve a particular speedup. Preserve corruption/fault isolation, bounded
memory, complete-or-error reads and the existing lifecycle/flush regressions.
A prototype that weakens those properties to improve timing should be rejected.

## Reproduce

Reuse a module built with [native-blocks.md](native-blocks.md), and a successful
closed native fixture with its complete oracles. From the repository root:

```sh
python3 scripts/vm.py run --code --script scripts/guest-profile.sh \
  --run-dir artifacts/profile-4096-next \
  --data-image artifacts/separate-native-4096-002/share/dual-final.img \
  --share-file artifacts/batch-native-4096-001/share/experimental-dm-piv.ko \
  --share-file kernel/guest-profile-test.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key \
  --share-file artifacts/separate-native-4096-002/share/expected-hidden-volume \
  --share-file artifacts/separate-native-4096-002/share/expected-primary.sha256 \
  --timeout 1800
python3 scripts/check_stateless.py \
  artifacts/profile-4096-next/share/profile-final.img \
  --volume-key-file artifacts/control-003/share/volume.key \
  --hidden-key-file artifacts/control-003/hidden.key \
  --expected-primary artifacts/separate-native-4096-002/share/expected-primary.sha256 \
  --expected-hidden artifacts/separate-native-4096-002/share/expected-hidden-volume
```

For original AEGIS/512 substitute the aegis-native-512-001 image/oracles and
corresponding aegis-control-512-001 primary/passphrase keys. Its independent
host primary verifier requires the optional original-AEGIS reference library
specified in [development.md](development.md). Native activation does not.
`profile-results.json` retains all timing samples and measured counts;
`profile-kprobe-counts.txt`, `result.txt` and host-verification.json are supporting
artifacts, not committed disk images or secrets.
