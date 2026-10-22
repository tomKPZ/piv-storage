# Authenticated reads and activation profiling

## Bounded range reads

`piv_read_range` gathers at most 16 KiB of primary ciphertext plus its tag/IV
metadata in one bio to dm-integrity. It reuses one AEAD request and invokes the
unchanged Linux helper once per sector, advancing the sector AAD and tag offset,
so per-sector authentication is identical to stock dm-crypt. Plaintext or
carrier IVs are copied out only after every sector in the range verifies;
private pages and metadata are bounded and wiped on release, including after a
partial authentication failure. Setup's keyslot/directory scan (and the
`--verify` full audit), decoy reads and hidden carrier collection use it;
prepared-tuple application keeps the scalar path. There is no persistent cache,
lazy verification or cross-bio accumulation: DM still splits decoy bios at
16 KiB and hidden bios per 4096-byte block, and one hidden block read
authenticates its whole 687-sector carrier (G = 687 + 3p with parity).

One range call submits one read to dm-integrity; the lower target may split it
or serve it from its journal/cache, so call counts are not physical-media read
counts. Fewer submissions must never skip a per-sector check; the profile and
fault suites assert this (see [native-faults.md](native-faults.md) for the
late-sector corruption/no-output regression).

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
`piv_checkpoint`) resolve the unique non-cold compiler specialization in
`[dm_piv]`, never the stock copy. `tracing_on=0` keeps no event data; only
`kprobe_profile` hit counters are used, and any missed hit fails. The SETUP
ioctl is bracketed by pivsetup's gate/hold hooks, reads are counted after udev
settles, and assertions use exact per-operation deltas. With
`r = 16384 / sector_size` sectors per range:

| Operation | range reads | primary authentications | other |
| --- | ---: | ---: | --- |
| SETUP (keyslot area, directory, checkpoint) | ⌈112/r⌉ + 2·⌈687/r⌉ | 112 + 1374 + 1 | 1 checkpoint (one scalar load), 0 writes |
| 512-byte decoy read | 1 | 1 | |
| 16 KiB decoy read | 1 | r | |
| 4 KiB hidden read | ⌈687/r⌉ | 687 | |
| 16 KiB hidden read | 4·⌈687/r⌉ | 2748 | |

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
