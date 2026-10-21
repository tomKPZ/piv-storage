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
                     [--format 3|4] [--ab] [--uninitialized] [--kdf argon2id|scrypt]
pivsetup close-blocks --key-file F [--device /dev/vdb] [--name piv-native]
pivsetup keyslot add|remove --key-file F --slot 0-3 [--new-key-file F | --new-passphrase-file F [--kdf K]]
pivsetup keygen --output F
```

Behaviour is a port of pivstore/blocks.py and kernel_owner.py at commit
6e4e099: guest guard, LUKS/integrity validation, exclusive /run lock,
cryptsetup open and reload as piv-crypt, ABI 3 SETUP/STATUS/KEYSLOT, wrong-key
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
