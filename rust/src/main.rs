//! pivsetup: setup frontend for the experimental dm-piv paired native views.
//! A port of the Python pivstore setup path (open-blocks, close-blocks,
//! keyslot, keygen); independent diagnostics remain in Python.

mod blocks;
mod cmd;
mod error;
mod hooks;
mod ioctl;
mod json;
mod migrate;
mod owner;
mod profile;
mod secret;
mod signals;

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use blocks::{HiddenSecret, OpenOptions};
use error::{Error, Result};
use secret::Secret;

const USAGE: &str = "\
usage: pivsetup open-blocks --key-file F (--hidden-key-file F | --hidden-passphrase-file F)
                            [--device /dev/vdb] [--name piv-native] [--initialize]
                            [--ab] [--verify] [--allow-no-journal] [--kdf argon2id|scrypt]
       pivsetup close-blocks --key-file F [--device /dev/vdb] [--name piv-native]
       pivsetup keyslot add|remove --key-file F --slot 0-3
                            [--new-key-file F | --new-passphrase-file F [--kdf argon2id|scrypt]]
                            [--device /dev/vdb] [--name piv-native]
       pivsetup migrate --source-key-file F (--source-hidden-key-file F | --source-hidden-passphrase-file F)
                        --target D --target-key-file F
                        (--target-hidden-key-file F | --target-hidden-passphrase-file F)
                        [--source /dev/vdb] [--source-kdf K] [--target-kdf K] [--ab]
                        [--allow-no-journal]
       pivsetup keygen --output F

LUKS2 volumes with 16-byte random IVs (aegis128-random + aead, or aes-, serpent- or
twofish-xts-random + hmac-sha1/256/512) and hidden format v4.
--initialize destroys all existing hidden contents. Keys are read from files only.
Setup authenticates only the keyslot area; --verify first authenticates every
primary sector and refuses on any failure (a full audit, O(volume) time).
Volumes persisting stock --integrity-no-journal need --allow-no-journal: a crash
during a hidden write can then destroy decoy sectors of that record.
Passphrase KEKs use --kdf (default argon2id: 64 MiB, t=3, p=4); nothing records
which KDF a keyslot used, so open with the same one. migrate copies both views of
an opened source into a freshly luksFormatted supported target that it initializes
(rekey, resize or sector-size change), then re-reads and compares both views.";

const MAX_PASSPHRASE: usize = 4096;

struct Args {
    action: String,
    operation: Option<String>,
    values: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Args {
    fn parse(mut argv: impl Iterator<Item = String>) -> Result<Args> {
        let action = argv.next().ok_or_else(|| Error::new(USAGE))?;
        let mut args = Args { action, operation: None, values: Vec::new(), flags: Vec::new() };
        let valued = ["--device", "--key-file", "--name", "--hidden-key-file", "--hidden-passphrase-file",
                      "--slot", "--new-key-file", "--new-passphrase-file", "--output", "--kdf",
                      "--source", "--source-key-file", "--source-hidden-key-file",
                      "--source-hidden-passphrase-file", "--source-kdf", "--target", "--target-key-file",
                      "--target-hidden-key-file", "--target-hidden-passphrase-file", "--target-kdf"];
        let switches = ["--initialize", "--ab", "--verify", "--allow-no-journal", "--allow-test-stack",
                        "--allow-second-disk"];
        while let Some(word) = argv.next() {
            let (key, inline) = match word.split_once('=') {
                Some((k, v)) if k.starts_with("--") => (k.to_string(), Some(v.to_string())),
                _ => (word.clone(), None),
            };
            if valued.contains(&key.as_str()) {
                let value = match inline {
                    Some(v) => v,
                    None => argv.next().ok_or_else(|| Error::new(format!("{key} needs a value")))?,
                };
                if args.values.iter().any(|(k, _)| k == &key) {
                    return Err(Error::new(format!("{key} given more than once")));
                }
                args.values.push((key, value));
            } else if switches.contains(&key.as_str()) && inline.is_none() {
                args.flags.push(key);
            } else if word == "-h" || word == "--help" {
                return Err(Error::new(USAGE));
            } else if !word.starts_with('-') && args.operation.is_none() && args.action == "keyslot" {
                args.operation = Some(word);
            } else {
                return Err(Error::new(format!("Unrecognized argument: {word}\n{USAGE}")));
            }
        }
        Ok(args)
    }

    fn value(&self, key: &str) -> Option<&str> {
        self.values.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    fn path(&self, key: &str) -> Option<PathBuf> {
        self.value(key).map(PathBuf::from)
    }

    fn required(&self, key: &str) -> Result<PathBuf> {
        self.path(key).ok_or_else(|| Error::new(format!("{key} is required")))
    }

    fn flag(&self, key: &str) -> bool {
        self.flags.iter().any(|f| f == key)
    }

    fn only(&self, allowed: &[&str]) -> Result<()> {
        for key in self.values.iter().map(|(k, _)| k.as_str()).chain(self.flags.iter().map(String::as_str)) {
            if !allowed.contains(&key) {
                return Err(Error::new(format!("{key} is not valid for {}", self.action)));
            }
        }
        Ok(())
    }
}

fn read_key(path: &Path) -> Result<Secret> {
    Secret::read_file(path, 33)
}

/// Whole file without trailing newlines (Python: read().rstrip(b'\n')).
fn read_passphrase(path: &Path) -> Result<Secret> {
    let mut secret = Secret::read_file(path, MAX_PASSPHRASE + 1)?;
    if secret.len() > MAX_PASSPHRASE {
        return Err(Error::new("Passphrase file is too large"));
    }
    let trimmed = secret.iter().rposition(|&b| b != b'\n').map_or(0, |i| i + 1);
    secret.truncate(trimmed);
    Ok(secret)
}

fn kdf(args: &Args) -> Result<blocks::Kdf> {
    args.value("--kdf").map_or(Ok(blocks::Kdf::Argon2id), blocks::Kdf::parse)
}

/// Exactly one of `<prefix>-key-file` / `<prefix>-passphrase-file`; `kdf_key`
/// selects the passphrase KDF and is rejected for key files.
fn hidden_secret(args: &Args, prefix: &str, kdf_key: &str) -> Result<HiddenSecret> {
    let (key_opt, pass_opt) = (format!("{prefix}-key-file"), format!("{prefix}-passphrase-file"));
    match (args.path(&key_opt), args.path(&pass_opt)) {
        (Some(key), None) => {
            if args.value(kdf_key).is_some() {
                return Err(Error::new(format!("{kdf_key} applies only to {pass_opt}")));
            }
            Ok(HiddenSecret::Key(read_key(&key)?))
        }
        (None, Some(passphrase)) => {
            let kdf = args.value(kdf_key).map_or(Ok(blocks::Kdf::Argon2id), blocks::Kdf::parse)?;
            Ok(HiddenSecret::Passphrase(read_passphrase(&passphrase)?, kdf))
        }
        _ => Err(Error::new(format!("Give exactly one of {key_opt} or {pass_opt}"))),
    }
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn fill_random(buffer: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        // SAFETY: getrandom into the unfilled tail of a live buffer.
        let n = unsafe { libc::getrandom(buffer[filled..].as_mut_ptr().cast(), buffer.len() - filled, 0) };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        filled += n as usize;
    }
    Ok(())
}

fn run(args: Args) -> Result<()> {
    let device = args.path("--device").unwrap_or_else(|| PathBuf::from("/dev/vdb"));
    let name = args.value("--name").unwrap_or("piv-native").to_string();
    let allow = owner::Allow {
        test_stack: args.flag("--allow-test-stack"),
        second_disk: args.flag("--allow-second-disk"),
    };
    match args.action.as_str() {
        "open-blocks" => {
            args.only(&["--device", "--key-file", "--name", "--hidden-key-file", "--hidden-passphrase-file",
                        "--initialize", "--ab", "--verify", "--allow-no-journal", "--allow-test-stack",
                        "--allow-second-disk", "--kdf"])?;
            let secret = hidden_secret(&args, "--hidden", "--kdf")?;
            let options = OpenOptions {
                name: &name, initialize: args.flag("--initialize"), ab: args.flag("--ab"),
                verify: args.flag("--verify"), allow_no_journal: args.flag("--allow-no-journal"), allow,
            };
            let views = blocks::open_blocks(&device, &args.required("--key-file")?, secret, &options)?;
            println!("{{\n  \"decoy\": {},\n  \"hidden\": {},\n  \"hidden_bytes\": {}\n}}",
                     json_string(&views.decoy), json_string(&views.hidden), views.hidden_bytes);
            Ok(())
        }
        "close-blocks" => {
            args.only(&["--device", "--key-file", "--name", "--allow-test-stack", "--allow-second-disk"])?;
            blocks::close_blocks(&device, &args.required("--key-file")?, &name, allow)
        }
        "migrate" => {
            args.only(&["--source", "--source-key-file", "--source-hidden-key-file",
                        "--source-hidden-passphrase-file", "--source-kdf", "--target", "--target-key-file",
                        "--target-hidden-key-file", "--target-hidden-passphrase-file", "--target-kdf", "--ab",
                        "--allow-no-journal", "--allow-test-stack", "--allow-second-disk"])?;
            let source = args.path("--source").unwrap_or_else(|| PathBuf::from("/dev/vdb"));
            let source_secret = hidden_secret(&args, "--source-hidden", "--source-kdf")?;
            let target_secret = hidden_secret(&args, "--target-hidden", "--target-kdf")?;
            let report = migrate::migrate(&source, &args.required("--source-key-file")?, source_secret,
                                          &args.required("--target")?, &args.required("--target-key-file")?,
                                          target_secret, args.flag("--ab"), args.flag("--allow-no-journal"), allow)?;
            println!("{{\n  \"decoy\": {{\"bytes\": {}, \"target_bytes\": {}}},\n  \
                      \"hidden\": {{\"bytes\": {}, \"target_bytes\": {}}},\n  \"verified\": true\n}}",
                     report.decoy_bytes, report.decoy_target_bytes, report.hidden_bytes, report.hidden_target_bytes);
            Ok(())
        }
        "keyslot" => {
            args.only(&["--device", "--key-file", "--name", "--slot", "--new-key-file", "--new-passphrase-file",
                        "--allow-test-stack", "--allow-second-disk", "--kdf"])?;
            if args.value("--kdf").is_some() && args.path("--new-passphrase-file").is_none() {
                return Err(Error::new("--kdf applies only to --new-passphrase-file"));
            }
            let slot: u32 = args.value("--slot").and_then(|s| s.parse().ok()).filter(|&s| s < 4)
                .ok_or_else(|| Error::new("--slot must be 0, 1, 2 or 3"))?;
            let key_file = args.required("--key-file")?;
            let kek = match (args.operation.as_deref(), args.path("--new-key-file"), args.path("--new-passphrase-file")) {
                (Some("remove"), None, None) => None,
                (Some("add"), Some(key), None) => {
                    let kek = read_key(&key)?;
                    if kek.len() != 32 {
                        return Err(Error::new("Invalid keyslot request"));
                    }
                    Some(kek)
                }
                (Some("add"), None, Some(passphrase)) => {
                    let identity = {
                        let owner = owner::GuestOwner::open(&device, &key_file, &name, allow)?;
                        blocks::base_identity(&owner)
                    };
                    Some(blocks::passphrase_kek(&read_passphrase(&passphrase)?, &identity, kdf(&args)?)?)
                }
                (Some("add"), None, None) => {
                    return Err(Error::new("keyslot add needs --new-key-file or --new-passphrase-file"))
                }
                _ => return Err(Error::new(format!("Usage error\n{USAGE}"))),
            };
            blocks::keyslot(&device, &key_file, slot, kek.as_deref(), &name, allow)
        }
        "keygen" => {
            args.only(&["--output"])?;
            let output = args.required("--output")?;
            let mut key = Secret::with_capacity(32);
            key.push(&[0u8; 32])?;
            fill_random(&mut key)?;
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&output)?;
            file.write_all(&key)?;
            file.sync_all()?;
            println!("Created a private 32-byte key file");
            Ok(())
        }
        _ => Err(Error::new(USAGE)),
    }
}

fn main() {
    secret::harden_process();
    signals::install();
    let code = match Args::parse(std::env::args().skip(1)).and_then(run) {
        Ok(()) => 0,
        Err(error) => {
            // Python-compatible "[Errno N]" lets wrappers rebuild OSError subclasses.
            match error.errno {
                Some(errno) => eprintln!("pivsetup: [Errno {errno}] {}", error.message),
                None => eprintln!("pivsetup: {}", error.message),
            }
            for note in &error.notes {
                eprintln!("pivsetup: {note}");
            }
            if error.interrupted { 130 } else { 1 }
        }
    };
    std::process::exit(code);
}
