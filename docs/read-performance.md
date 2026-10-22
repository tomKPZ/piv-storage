# Authenticated reads and activation profiling

## Bounded range reads

`piv_read_range` reads at most 1024 primary sectors (a whole record; 4 MiB at
4096-byte sectors, 512 KiB at 512) plus their tag/IV metadata as one batch of
multi-sector bios to dm-integrity, all in flight together (up to 128 KiB of data
and one page of tuples per bio, the same batch code as writes). It invokes the
per-sector AEAD helper (`piv_aead`) once per sector, advancing the sector AAD
and tag offset, so per-sector authentication is identical to stock dm-crypt.
Plaintext or carrier IVs are copied out only after every sector in the range
verifies; for hidden carrier collection, sectors failing authentication
contribute only their raw IVs to SIV-checked decoding. Private pages and
metadata are bounded and wiped on release, including after a partial
authentication failure. Setup's keyslot/directory scan (and the `--verify` full
audit), decoy reads, hidden-read carrier collection and private owner reads
use it; writes read their sectors through the batch path
([write path](native-blocks.md#write-path)). There is no persistent cache,
lazy verification or cross-bio accumulation: DM splits decoy bios at 128 KiB
and hidden bios per 4096-byte block, and one hidden block read authenticates
its whole 687-sector carrier (G = 687 + 3p with parity) with one range call.
Concurrent requests overlap their reads ([concurrency](native-blocks.md#concurrency)).

One range call submits one batch of reads to dm-integrity; the lower target may
split them or serve them from its journal/cache, so call counts are not
physical-media read counts. Fewer submissions must never skip a per-sector
check; the profile and fault suites assert this (see
[native-faults.md](native-faults.md) for the late-sector corruption/no-output
regression).

## `profile` suite

scripts/guest-profile.sh loads the matched module and runs
kernel/guest-profile-test.py on the closed native fixture, with stock dm-crypt
loaded and an unrelated stock volume mounted.

**Timings (uninstrumented).** Three stock opens, then three native opens
without initialization; pivsetup's `PIVSETUP_TEST_GATE` hook reports the SETUP
ioctl time separately. Native opening includes cryptsetup/keyslot work, private
target conversion, the keyslot-area scan, directory load and view creation;
`--verify` would instead authenticate every primary sector. Close is not timed.
Stock primary plaintext is authenticated, hashed and kept in guest RAM as the
read oracle. Sequential O_DIRECT reads use 512/4096/16384/65536-byte
application requests (at least the stock logical block size), three samples
each, over 1 MiB of primary or 64 KiB of hidden data, plus 32 reproducible
random reads per role. All bytes are compared; timings include Python loops,
system calls and comparisons. Reading must spend zero primary encryptions.

**Call counts (separate pass).** Entry kprobes on module-qualified symbols
(`piv_load_mode`, `piv_read_range`, the private `piv_aead` helper, `pn_write`,
`piv_checkpoint`, `piv_batch_read`, `piv_batch_submit`) resolve the unique non-cold compiler specialization in
`[dm_piv]`, never the stock copy. `tracing_on=0` keeps no event data; only
`kprobe_profile` hit counters are used, and any missed hit fails. The SETUP
ioctl is bracketed by pivsetup's gate/hold hooks, reads are counted after udev
settles, and assertions use exact per-operation deltas. Each range read is one
batch submission:

| Operation | range reads | primary authentications | other |
| --- | ---: | ---: | --- |
| SETUP (keyslot area, directory, checkpoint) | 3 | 112 + 1374 + 1 | 1 checkpoint (one scalar load), 3 submissions, 0 writes |
| 512-byte decoy read | 1 | 1 | 1 submission |
| 16 KiB decoy read | 1 | 16384 / S | 1 submission |
| 128 KiB decoy read | 1 | 131072 / S | 1 submission |
| 4 KiB hidden read | 1 | 687 | 1 submission |
| 16 KiB hidden read | 4 | 2748 | 4 submissions |
| 16 KiB and 128 KiB decoy write (same bytes) | 0 | 2n (n checks + n encryptions, n = bytes / S) | 1 pn_write, 1 batch read, 2 submissions (read, write) |
| 4 KiB hidden write (same bytes) | 0 | 1374 (687 checks + 687 encryptions) | 1 pn_write, 1 batch read, 2 submissions |

S is the primary sector size. The write rows pin the [write path](native-blocks.md#write-path): one
authenticated read of every touched sector, one encryption each, no per-sector
loads, re-reads or self-decryption (the previous path made about five AEAD
calls per sector); the encryption counter must rise by exactly the sector
count. The write descriptor stays open across the counted window so udev's
re-probe after closing a written device is not counted.

Probe counts establish calls, not time spent. No probe is enabled during
timings.

Afterwards both complete views are checked, the stack closes, the module
unloads, stock Linux authenticates and hashes the full primary, and suite.py
verifies `profile-final.img` on the host. `profile-results.json` keeps all
timing samples and counts; `profile-kprobe-counts.txt` the raw counters.

## Limits

These are warm-cache diagnostics under QEMU: O_DIRECT bypasses only the public
page cache, and the stock pass plus repeated opens warm lower, host and device
caches. Medians of three samples are not confidence intervals. There is no
claim about cold start, physical media, production throughput or a controlled
cipher comparison (profiles differ in cipher, tag size and geometry). Hidden
reads cost 687 primary authentications per 4096-byte block regardless of
request size (no parity; RS decoding runs only after a failed tag).
Current results live in each run's `profile-results.json`; the sequential
`bench` suite's user-facing write/read/activation numbers are in
[configuration.md](configuration.md).

## Running

```sh
python3 scripts/suite.py --prefix artifacts/profile-next --profile aegis-4096 \
  --profile aegis-512 --scaffold artifacts/stage-next/scaffold.tar --suites profile
```

Run timing comparisons sequentially (`--jobs 1`) to avoid competing VMs.
Original AEGIS-128 host verification needs the optional reference library from
[development.md](development.md); native activation does not.
