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
usage: pivsetup open-blocks --device D --key-file F (--hidden-key-file F | --hidden-passphrase-file F)
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
       pivsetup keygen --output F
       pivsetup --version

D is the block device (or partition) holding the LUKS2 volume; there is no
default. Research prototype without external cryptographic review. Key,
passphrase and LUKS key files must be regular files owned by root and not
accessible by group or others (chmod 600).
LUKS2 volumes with 16-byte random IVs (aegis128-random + aead, or aes-xts-random
+ hmac-sha256), the journaled integrity layer, and hidden format v5 (4096-byte
hidden blocks). --initialize destroys all existing hidden contents and writes
zeros into every hidden block; with --quick it writes only the keyslot and
directory, and every hidden block reads EIO until first written (tools that
read unwritten blocks fail). --fill (on an existing volume, destructive) writes
zeros into every hidden block whose record does not authenticate, skipping
valid ones: it completes a quick or interrupted --initialize, resumes itself,
and turns damaged blocks into zeros. --parity
adds Reed-Solomon parity fragments per lane (off by default). Keys are read
from files only. Setup authenticates only the keyslot area; --verify first
authenticates every primary sector and refuses on any failure (a full audit,
O(volume) time). Passphrase KEKs use Argon2id at cost tier --kdf-cost
(1: 64 MiB, 2: 256 MiB, 3: 1 GiB (default), 4: 2 GiB; 4 lanes). The tier is not
recorded: give the same tier on every open. migrate copies both views of
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
                      "--slot", "--new-key-file", "--new-passphrase-file", "--output",
                      "--source", "--source-key-file", "--source-hidden-key-file",
                      "--source-hidden-passphrase-file", "--target", "--target-key-file",
                      "--target-hidden-key-file", "--target-hidden-passphrase-file", "--parity",
                      "--kdf-cost", "--new-kdf-cost", "--source-kdf-cost", "--target-kdf-cost"];
        let switches = ["--initialize", "--quick", "--fill", "--ab", "--verify"];
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

    /// A required LUKS key-file path, after the key-file permission check
    /// (cryptsetup reads the file itself).
    fn key_file(&self, key: &str) -> Result<PathBuf> {
        let path = self.required(key)?;
        secret::check_key_file(&path)?;
        Ok(path)
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
    Secret::read_key_file(path, 33)
}

/// Whole file without trailing newlines (Python: read().rstrip(b'\n')).
fn read_passphrase(path: &Path) -> Result<Secret> {
    let mut secret = Secret::read_key_file(path, MAX_PASSPHRASE + 1)?;
    if secret.len() > MAX_PASSPHRASE {
        return Err(Error::new("Passphrase file is too large"));
    }
    let trimmed = secret.iter().rposition(|&b| b != b'\n').map_or(0, |i| i + 1);
    secret.truncate(trimmed);
    Ok(secret)
}

/// Exactly one of `<prefix>-key-file` / `<prefix>-passphrase-file`.
fn hidden_secret(args: &Args, prefix: &str) -> Result<HiddenSecret> {
    let (key_opt, pass_opt) = (format!("{prefix}-key-file"), format!("{prefix}-passphrase-file"));
    match (args.path(&key_opt), args.path(&pass_opt)) {
        (Some(key), None) => Ok(HiddenSecret::Key(read_key(&key)?)),
        (None, Some(passphrase)) => Ok(HiddenSecret::Passphrase(read_passphrase(&passphrase)?)),
        _ => Err(Error::new(format!("Give exactly one of {key_opt} or {pass_opt}"))),
    }
}

/// A `--*kdf-cost` value applies only to a passphrase (key files are KEKs).
fn kdf_cost_for(args: &Args, option: &str, passphrase_option: &str) -> Result<u8> {
    if args.value(option).is_some() && args.value(passphrase_option).is_none() {
        return Err(Error::new(format!("{option} applies only with {passphrase_option}")));
    }
    blocks::kdf_cost(args.value(option))
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
    let name = args.value("--name").unwrap_or("piv-native").to_string();
    if matches!(args.action.as_str(), "open-blocks" | "close-blocks" | "keyslot" | "migrate") {
        owner::require_root()?;
    }
    match args.action.as_str() {
        "open-blocks" => {
            args.only(&["--device", "--key-file", "--name", "--hidden-key-file", "--hidden-passphrase-file",
                        "--initialize", "--quick", "--fill", "--ab", "--parity", "--verify", "--kdf-cost"])?;
            let device = args.required("--device")?;
            let secret = hidden_secret(&args, "--hidden")?;
            let options = OpenOptions {
                name: &name, initialize: args.flag("--initialize"), quick: args.flag("--quick"),
                fill: args.flag("--fill"), ab: args.flag("--ab"),
                verify: args.flag("--verify"), parity: blocks::parity(args.value("--parity"))?,
                kdf_cost: kdf_cost_for(&args, "--kdf-cost", "--hidden-passphrase-file")?,
            };
            let views = blocks::open_blocks(&device, &args.key_file("--key-file")?, secret, &options)?;
            // --fill adds the block counts: already valid (skipped), written
            // as zeros, and failed (carrier unreadable or not authenticating).
            let fill = views.fill.map_or(String::new(), |c| format!(
                ",\n  \"fill\": {{\"valid\": {}, \"written\": {}, \"failed\": {}}}", c.valid, c.written, c.failed));
            println!("{{\n  \"decoy\": {},\n  \"hidden\": {},\n  \"hidden_bytes\": {}{fill}\n}}",
                     json_string(&views.decoy), json_string(&views.hidden), views.hidden_bytes);
            if let Some(counts) = views.fill.filter(|c| c.failed > 0) {
                eprintln!("pivsetup: --fill left {} hidden block(s) unchanged: their carrier could not be read or \
                           authenticated (they still read EIO)", counts.failed);
            }
            Ok(())
        }
        "close-blocks" => {
            args.only(&["--device", "--key-file", "--name"])?;
            blocks::close_blocks(&args.required("--device")?, &args.key_file("--key-file")?, &name)
        }
        "migrate" => {
            args.only(&["--source", "--source-key-file", "--source-hidden-key-file",
                        "--source-hidden-passphrase-file", "--target", "--target-key-file",
                        "--target-hidden-key-file", "--target-hidden-passphrase-file", "--ab", "--parity",
                        "--source-kdf-cost", "--target-kdf-cost"])?;
            let source = args.required("--source")?;
            let source_secret = hidden_secret(&args, "--source-hidden")?;
            let target_secret = hidden_secret(&args, "--target-hidden")?;
            let layout = migrate::MigrateOptions {
                ab: args.flag("--ab"),
                parity: blocks::parity(args.value("--parity"))?,
                source_kdf_cost: kdf_cost_for(&args, "--source-kdf-cost", "--source-hidden-passphrase-file")?,
                target_kdf_cost: kdf_cost_for(&args, "--target-kdf-cost", "--target-hidden-passphrase-file")?,
            };
            let report = migrate::migrate(&source, &args.key_file("--source-key-file")?, source_secret,
                                          &args.required("--target")?, &args.key_file("--target-key-file")?,
                                          target_secret, &layout)?;
            println!("{{\n  \"decoy\": {{\"bytes\": {}, \"target_bytes\": {}}},\n  \
                      \"hidden\": {{\"bytes\": {}, \"target_bytes\": {}}},\n  \"verified\": true\n}}",
                     report.decoy_bytes, report.decoy_target_bytes, report.hidden_bytes, report.hidden_target_bytes);
            Ok(())
        }
        "keyslot" => {
            args.only(&["--device", "--key-file", "--name", "--slot", "--new-key-file", "--new-passphrase-file",
                        "--hidden-key-file", "--hidden-passphrase-file", "--kdf-cost", "--new-kdf-cost"])?;
            let device = args.required("--device")?;
            // Authorization: the current hidden key or passphrase of a listed
            // keyslot (--kdf-cost is its tier, as for open-blocks).
            let auth = hidden_secret(&args, "--hidden")?;
            let auth_tier = kdf_cost_for(&args, "--kdf-cost", "--hidden-passphrase-file")?;
            let tier = kdf_cost_for(&args, "--new-kdf-cost", "--new-passphrase-file")?;
            let slot: u32 = args.value("--slot").and_then(|s| s.parse().ok()).filter(|&s| s < 4)
                .ok_or_else(|| Error::new("--slot must be 0, 1, 2 or 3"))?;
            let key_file = args.key_file("--key-file")?;
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
                        let owner = owner::Owner::open(&device, &key_file, &name)?;
                        blocks::base_identity(&owner)
                    };
                    Some(blocks::passphrase_kek(&read_passphrase(&passphrase)?, &identity, tier)?)
                }
                (Some("add"), None, None) => {
                    return Err(Error::new("keyslot add needs --new-key-file or --new-passphrase-file"))
                }
                _ => return Err(Error::new(format!("Usage error\n{USAGE}"))),
            };
            blocks::keyslot(&device, &key_file, slot, kek.as_deref(), auth, auth_tier, &name)
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

/// `pivsetup --version`: the package version (also the DKMS package version,
/// packaging/VERSION), the control ABI versions it speaks and whether the
/// PIVSETUP_TEST_* hooks are compiled in.
fn version() -> String {
    format!("pivsetup {}\ncontrol ABI: QUERY {}, request {}, SETUP {}, STATUS {}, KEYSLOT {}\ntest hooks: {}",
            env!("CARGO_PKG_VERSION"), ioctl::QUERY_VERSION, ioctl::REQUEST_VERSION, ioctl::SETUP_VERSION,
            ioctl::STATUS_VERSION, ioctl::KEYSLOT_VERSION, if hooks::ENABLED { "compiled in" } else { "no" })
}

fn main() {
    secret::harden_process();
    signals::install();
    if matches!(std::env::args().nth(1).as_deref(), Some("--version" | "version")) && std::env::args().len() == 2 {
        println!("{}", version());
        std::process::exit(0);
    }
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
            if error.errno == Some(libc::EKEYREJECTED) {
                eprintln!("pivsetup: hint: wrong hidden key or passphrase, or a passphrase given with another \
                           --kdf-cost tier than its keyslot was created with (the tier is not recorded)");
            }
            if error.interrupted { 130 } else { 1 }
        }
    };
    std::process::exit(code);
}
