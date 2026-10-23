# pivsetup

Static Rust setup binary for the dm-piv paired native views. It is the only
setup path; the Python `pivstore` package keeps independent read-only
diagnostics and guest test instrumentation (`pivstore/blocks.py` is a thin
client of this binary).

```sh
python3 scripts/build_pivsetup.py        # rootless; prints path and SHA-256
python3 scripts/build_pivsetup.py --test-hooks   # guest-test build (below)
```

The build uses the system rustc/cargo, a project-local `CARGO_HOME` under the
ignored `downloads/cargo`, the committed `Cargo.lock` (`--locked`, offline after
the first fetch) and static glibc (`-C target-feature=+crt-static`). Crates:
`libc`, `zeroize`, RustCrypto `argon2` 0.6 (its `parallel` feature) and
`rayon` (the four Argon2id lanes on a private four-thread pool) only (no
clap/serde; a minimal strict JSON reader parses `cryptsetup luksDump`).
Including transitive crates the lock has 21 dependencies; rayon brings
rayon-core, crossbeam-{deque,epoch,utils} and either. The version
(`pivsetup --version`, with the control ABI versions and whether test hooks
are compiled in) equals packaging/VERSION, the DKMS package version; a unit
test checks this. Host tests: `cargo test` with and without
`--features test-hooks`.

## Commands

Run as root (installation: [packaging/README.md](../packaging/README.md)).
Agent and CI testing still runs only in disposable guests
([development.md](../docs/development.md)).

```
pivsetup open-blocks --device D --key-file F (--hidden-key-file F | --hidden-passphrase-file F)
                     [--name piv-native]
                     [--initialize [--quick] [--ab] [--parity 4|8|16] | --fill]
                     [--verify] [--kdf-cost 1-4]
pivsetup close-blocks --device D --key-file F [--name piv-native]
pivsetup keyslot add|remove --device D --key-file F --slot 0-3
                     (--hidden-key-file F | --hidden-passphrase-file F [--kdf-cost 1-4])
                     [--new-key-file F | --new-passphrase-file F [--new-kdf-cost 1-4]]
                     [--name piv-native]
pivsetup migrate --source D --source-key-file F (--source-hidden-key-file F | --source-hidden-passphrase-file F)
                 --target D --target-key-file F
                 (--target-hidden-key-file F | --target-hidden-passphrase-file F)
                 [--ab] [--parity 4|8|16]
                 [--source-kdf-cost 1-4] [--target-kdf-cost 1-4]
pivsetup status [--name piv-native] [--device D]
pivsetup scrub [--name piv-native] [--device D] [--limit 64] [--decoy]
pivsetup keygen --output F
```

`--key-file` is the stock LUKS passphrase file; hidden key files hold 32 bytes
(`keygen` writes one). Option semantics are in the [README](../README.md#usage).
Passphrase KEKs use Argon2id (p = 4) at cost tier `--kdf-cost` (1: 64 MiB,
t = 10; 2: 256 MiB, t = 10; 3, the default: 1 GiB, t = 10; 4: 2 GiB, t = 22;
lanes computed in parallel, working memory zeroized after use), with
salt = base context ‖ "/kek/argon2id/" ‖ tier digit; a `*-kdf-cost` option is
refused without the matching passphrase option. Rust/Python KEK vectors for
tiers 1 and 3 live in `rust/tests/`. Only the two
supported primary profiles are accepted, on stock persistent no-journal
(direct-mode, recommended for deniability) or journaled dm-integrity volumes
([configuration.md](../docs/configuration.md)).

`--device`/`--source` are required (no default) and name any block device or
partition holding the LUKS2 volume (symlinks are followed once: the device is
resolved to the kernel's own /dev node, `DEVNAME` from sysfs with the same
device number, and every later step uses that node and re-checks the device
number of what it opens). Before reading a key file, privileged commands
require root. Key, passphrase and LUKS key files must be regular files owned
by root without group or other permissions. `open-blocks` then checks the
device (a block device of whole 512-byte sectors, not a whole disk with
partitions), validates the LUKS2/integrity profile, takes the exclusive
per-volume /run lock, and for a new owner refuses an existing lower mapping
name, any holder of the device and an exclusive opener (EBUSY: mounted, mapped
or open with O_EXCL) before reading the integrity superblock (checked geometry
bounds against the real device size). It continues with cryptsetup open and reload as `piv-crypt`, NATIVE_SETUP (ABI 6, with
the parity choice and the quick/fill flags; `--fill` prints the returned block
counts as `"fill": {"valid": N, "written": N, "failed": N}` and notes failed
blocks on stderr) and
view creation ([native-blocks.md](../docs/native-blocks.md)). Failed-attempt
cleanup is limited to its own identity-checked mappings; close validates both
views. `keyslot` uses NATIVE_KEYSLOT (version 2) on the active owner,
authorized by the current hidden key or passphrase of a listed keyslot.

`status` and `scrub` (src/health.rs) read no key and write nothing. They need
root, find the owner mapping by name (a `piv-crypt` table whose DM UUID is
`CRYPT-LUKS2-<uuid>-<name>`; with `--device`, the UUID of that LUKS volume) and
its one bound control device, and take no /run lock (they can run beside a
busy owner; while a scrub holds the views open, `close-blocks` fails as busy). `status` prints
NATIVE_STATUS (version 5) as JSON and exits 0 (active), 2 (failed) or 3
(absent or idle). `scrub` checks both view tables against the owner and
generation, reads every hidden block with O_DIRECT, attributes RS-recovered
blocks with a STATUS call around each read, probes the shaped carriers of the
listed unavailable blocks (and with `--decoy` the whole decoy view) for EIO
sectors, and prints counts, capped lists (`--limit`, default 64) and
`encryptions_during_scrub`; exit 0, 4 (recovered only), 5 (unavailable or
decoy EIO), 2 (failed), 3 (inactive) or 130 (cancelled, partial report).
Semantics and the repair procedure:
[native-faults.md](../docs/native-faults.md#status-scrub-and-repair).

`migrate` (src/migrate.rs) is the offline rekey/resize/sector-size-change path
(live resize and rekey are unsupported): it refuses a target that is the
source (same path, canonical path or device number), opens the source as `piv-src`,
initializes a freshly luksFormatted supported target as `piv-dst` (destroying
any target hidden contents), refuses a target view smaller than the source's,
copies both views in 1 MiB O_DIRECT chunks through an mlocked, zeroized buffer,
flushes, re-reads both devices and compares them byte for byte, then closes
both. It is neither atomic nor resumable: after a failure, reformat the target
and rerun. The source is only read (activation still writes ordinary integrity
metadata). The migrate suite copies the fixture source (AEGIS-128, or AES-XTS +
HMAC-SHA256 for the aes-sha256 profiles) into a rekeyed, larger,
512-byte-sector A/B AEGIS-128 target with `--parity 4`.

## Security properties

Keys are read from files only and live in mlocked, zeroized buffers; they never
reach argv. The process is non-dumpable. SIGINT and SIGTERM are cooperative
(exit 130 after cleanup; see [native-faults.md](../docs/native-faults.md#cancelling-activation-initialization-and-fill-cancel-suite)).
Errors print `pivsetup: [Errno N] message`; EKEYREJECTED adds a hint about the
key/passphrase and `--kdf-cost` tier. Tiers 2–4 check `MemAvailable` before
Argon2id. cryptsetup and dmsetup run with a cleared environment, `LC_ALL=C`
and the fixed `PATH` /usr/sbin:/usr/bin:/sbin:/bin; device sizes come from
`BLKGETSIZE64` (no `blockdev`).

## Test hooks

Compiled in only with the cargo feature `test-hooks` (`build_pivsetup.py
--test-hooks`, which scripts/suite.py shares into the guests); the default
release build, which packaging/install.sh requires and the deploy suite
installs, ignores every `PIVSETUP_TEST_*` variable. Explicit environment
variables, inert unless set: `PIVSETUP_TEST_GATE=PREFIX` (handshake files
around the SETUP ioctl, with `PIVSETUP_TEST_HOLD=1` to pause afterwards),
`PIVSETUP_TEST_FAIL=POINT` (after-cryptsetup-open, before-setup, after-setup,
first-view, second-view) and `PIVSETUP_TEST_LAX_KEY_FILES=1` (skip the
key-file permission check: guest test keys live on a 9p share). They can only
fail or pause setup, relax that check or write public context to the PREFIX
files. See src/hooks.rs. The former
test-confinement options `--allow-test-stack` and `--allow-second-disk` were
removed with the guest-only activation guard (2026-10-22).

`cargo test` runs unit tests, including cross-check vectors shared with the
Python code (Argon2id KEKs, profile/segment validation, superblock
geometry, ioctl numbers).
