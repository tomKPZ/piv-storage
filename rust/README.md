# pivsetup

Static Rust setup frontend for the experimental dm-piv paired native views. It
replaces the former Python setup path (`python3 -m pivstore open-blocks` etc.);
the Python package keeps the independent read-only diagnostics and the guest
test instrumentation.

```sh
python3 scripts/build_pivsetup.py        # rootless; prints path and SHA-256
```

The build uses the system rustc/cargo, a project-local `CARGO_HOME` under the
ignored `downloads/cargo`, the committed `Cargo.lock` (`--locked`, offline after
the first fetch) and static glibc (`-C target-feature=+crt-static`). Crates:
`libc`, `zeroize` and RustCrypto `scrypt` and `argon2` only (no clap/serde; a minimal strict
JSON reader parses `cryptsetup luksDump`).

Commands (inside the pinned disposable guest only, like the Python setup was):

```
pivsetup open-blocks --key-file F (--hidden-key-file F | --hidden-passphrase-file F)
                     [--device /dev/vdb] [--name piv-native] [--initialize]
                     [--ab] [--verify] [--kdf argon2id|scrypt]
pivsetup close-blocks --key-file F [--device /dev/vdb] [--name piv-native]
pivsetup keyslot add|remove --key-file F --slot 0-3 [--new-key-file F | --new-passphrase-file F [--kdf K]]
pivsetup migrate --source-key-file F (--source-hidden-key-file F | --source-hidden-passphrase-file F)
                 --target D --target-key-file F (--target-hidden-key-file F | --target-hidden-passphrase-file F)
                 [--source /dev/vdb] [--source-kdf K] [--target-kdf K] [--ab]
pivsetup keygen --output F
```

`migrate` (src/migrate.rs) is the offline rekey/resize/sector-size-change path:
it opens the source as `piv-src`, initializes a freshly luksFormatted supported
target as `piv-dst` (destroying any target hidden contents), refuses a target
view smaller than the source's, copies both views in 1 MiB O_DIRECT chunks
through an mlocked, zeroized buffer, flushes, re-reads both devices and compares
them byte for byte, then closes both. It is neither atomic nor resumable: after
a failure, reformat the target and rerun. The source is only read (activation
still writes ordinary journal metadata). In test guests `--allow-test-stack`
and `--allow-second-disk` (the second disposable disk `/dev/vdc`, used by the
migrate suite) are explicit opt-ins beyond `/dev/vdb`.

Behaviour is a port of pivstore/blocks.py and kernel_owner.py at commit
6e4e099: guest guard, LUKS/integrity validation, exclusive /run lock,
cryptsetup open and reload as piv-crypt, SETUP ABI 4 (format v4)/STATUS/KEYSLOT, wrong-key
guard note, failed-attempt cleanup limited to its own identity-checked mappings,
and close validation of both views. Differences: keys live in mlocked,
zeroized buffers; the process is non-dumpable; SIGTERM is cooperative like
SIGINT (exit 130 after cleanup); passphrase KEKs default to Argon2id
(m = 64 MiB, t = 3, p = 4; `--kdf scrypt` keeps the former derivation); errors print `pivsetup: [Errno N] message`.

Explicit test-only hooks (environment variables, inert unless set):
`PIVSETUP_TEST_GATE=PREFIX` (handshake files around the SETUP ioctl, with
`PIVSETUP_TEST_HOLD=1` to pause afterwards) and `PIVSETUP_TEST_FAIL=POINT`
(after-cryptsetup-open, before-setup, after-setup, first-view, second-view).
See src/hooks.rs.

`cargo test` runs unit tests, including cross-check vectors shared with the
Python code (scrypt and Argon2id KEKs, superblock geometry, ioctl numbers).
