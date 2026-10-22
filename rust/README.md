# pivsetup

Static Rust setup binary for the dm-piv paired native views. It is the only
setup path; the Python `pivstore` package keeps independent read-only
diagnostics and guest test instrumentation (`pivstore/blocks.py` is a thin
client of this binary).

```sh
python3 scripts/build_pivsetup.py        # rootless; prints path and SHA-256
```

The build uses the system rustc/cargo, a project-local `CARGO_HOME` under the
ignored `downloads/cargo`, the committed `Cargo.lock` (`--locked`, offline after
the first fetch) and static glibc (`-C target-feature=+crt-static`). Crates:
`libc`, `zeroize` and RustCrypto `argon2` only (no clap/serde; a
minimal strict JSON reader parses `cryptsetup luksDump`).

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
                     [--new-key-file F | --new-passphrase-file F [--kdf-cost 1-4]]
                     [--name piv-native]
pivsetup migrate --source D --source-key-file F (--source-hidden-key-file F | --source-hidden-passphrase-file F)
                 --target D --target-key-file F
                 (--target-hidden-key-file F | --target-hidden-passphrase-file F)
                 [--ab] [--parity 4|8|16]
                 [--source-kdf-cost 1-4] [--target-kdf-cost 1-4]
pivsetup keygen --output F
```

`--key-file` is the stock LUKS passphrase file; hidden key files hold 32 bytes
(`keygen` writes one). Option semantics are in the [README](../README.md#usage).
Passphrase KEKs use Argon2id (p = 4) at cost tier `--kdf-cost` (1: 64 MiB,
t = 3; 2: 256 MiB, t = 3; 3, the default: 1 GiB, t = 3; 4: 2 GiB, t = 6), with
salt = base context ‖ "/kek/argon2id/" ‖ tier digit; a `*-kdf-cost` option is
refused without the matching passphrase option. Rust/Python KEK vectors for
tiers 1 and 3 live in `rust/tests/`. Only the two
supported primary profiles and journaled dm-integrity volumes are accepted
([configuration.md](../docs/configuration.md)).

`--device`/`--source` are required (no default) and name any block device or
partition holding the LUKS2 volume (symlinks are followed). Before reading a
key file, privileged commands require root. `open-blocks` then checks the
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
views. `keyslot` uses NATIVE_KEYSLOT on the active owner.

`migrate` (src/migrate.rs) is the offline rekey/resize/sector-size-change path
(live resize and rekey are unsupported): it refuses a target that is the
source (same path, canonical path or device number), opens the source as `piv-src`,
initializes a freshly luksFormatted supported target as `piv-dst` (destroying
any target hidden contents), refuses a target view smaller than the source's,
copies both views in 1 MiB O_DIRECT chunks through an mlocked, zeroized buffer,
flushes, re-reads both devices and compares them byte for byte, then closes
both. It is neither atomic nor resumable: after a failure, reformat the target
and rerun. The source is only read (activation still writes ordinary journal
metadata). The migrate suite copies the fixture source (AEGIS-128, or AES-XTS +
HMAC-SHA256 for the aes-sha256 profiles) into a rekeyed, larger,
512-byte-sector A/B AEGIS-128 target with `--parity 4`.

## Security properties

Keys are read from files only and live in mlocked, zeroized buffers; they never
reach argv. The process is non-dumpable. SIGINT and SIGTERM are cooperative
(exit 130 after cleanup; see [cancellation.md](../docs/cancellation.md)).
Errors print `pivsetup: [Errno N] message`.

## Test hooks

Explicit environment variables, inert unless set:
`PIVSETUP_TEST_GATE=PREFIX` (handshake files around the SETUP ioctl, with
`PIVSETUP_TEST_HOLD=1` to pause afterwards) and `PIVSETUP_TEST_FAIL=POINT`
(after-cryptsetup-open, before-setup, after-setup, first-view, second-view).
They ship in the deployed binary (it is the tested binary); only whoever
controls root's environment can set them, and they can only fail or pause
setup or write public context to the PREFIX files. See src/hooks.rs. The former
test-confinement options `--allow-test-stack` and `--allow-second-disk` were
removed with the guest-only activation guard (2026-10-22).

`cargo test` runs unit tests, including cross-check vectors shared with the
Python code (Argon2id KEKs, profile/segment validation, superblock
geometry, ioctl numbers).
