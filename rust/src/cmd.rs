//! dmsetup/cryptsetup helpers. Keys and tuple data never appear in argv; a
//! key-containing table is read into and written from locked memory only.
//! Helpers run with a cleared environment and a fixed PATH (SAFE_PATH).

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::signals;

pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

fn describe(program: &str, args: &[&str]) -> String {
    let mut words = vec![format!("'{program}'")];
    words.extend(args.iter().map(|a| format!("'{a}'")));
    format!("[{}]", words.join(", "))
}

/// Search path for the helper programs (cryptsetup, dmsetup): fixed, never the
/// caller's PATH, so an inherited environment cannot substitute another
/// binary. The children get only PATH and LC_ALL=C (stable messages/output).
pub const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

fn spawn(program: &str, args: &[&str], input: Option<&[u8]>, secret_out: Option<&mut Secret>) -> Result<Output> {
    // With PATH set via env(), Command resolves the program in that PATH.
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::os(e.raw_os_error().unwrap_or(libc::ENOENT), format!("{program}: {e}")))?;
    if let Some(data) = input {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(data)?;
    }
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    // stderr is small diagnostics; drain it on a thread to avoid pipe deadlock.
    let stderr_thread = std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut text);
        text
    });
    let mut stdout = String::new();
    match secret_out {
        Some(secret) => {
            let mut chunk = [0u8; 512];
            loop {
                match stdout_pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => secret.push(&chunk[..n])?,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            zeroize::Zeroize::zeroize(&mut chunk);
        }
        None => {
            stdout_pipe.read_to_string(&mut stdout)?;
        }
    }
    let status = loop {
        match child.wait() {
            Ok(status) => break status,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    };
    let stderr = String::from_utf8_lossy(&stderr_thread.join().unwrap_or_default()).into_owned();
    Ok(Output { status: status.code().unwrap_or(-1), stdout, stderr })
}

fn checked(program: &str, args: &[&str], output: Output) -> Result<Output> {
    if output.status != 0 {
        let mut error = Error::new(format!(
            "Command '{}' returned non-zero exit status {}.", describe(program, args), output.status));
        let detail = output.stderr.trim();
        if !detail.is_empty() {
            error.note(detail.to_string());
        }
        return Err(error);
    }
    Ok(output)
}

/// dmsetup with --noudevsync; creates device nodes after create/resume like the
/// Python frontend. Never pass keys or tuple data as arguments.
pub fn dm(args: &[&str], input: Option<&[u8]>, check: bool) -> Result<Output> {
    let mut full = vec!["--noudevsync"];
    full.extend_from_slice(args);
    let output = spawn("dmsetup", &full, input, None)?;
    if output.status == 0 && matches!(args.first(), Some(&"create") | Some(&"resume")) {
        checked("dmsetup", &["--noudevsync", "mknodes", args[1]],
                spawn("dmsetup", &["--noudevsync", "mknodes", args[1]], None, None)?)?;
    }
    if check { checked("dmsetup", &full, output) } else { Ok(output) }
}

pub fn dm_ok(args: &[&str]) -> Result<String> {
    Ok(dm(args, None, true)?.stdout)
}

/// `dmsetup table --showkeys NAME` into locked memory.
pub fn dm_table_with_keys(name: &str) -> Result<Secret> {
    let args = ["--noudevsync", "table", "--showkeys", name];
    let mut secret = Secret::with_capacity(8192);
    let output = spawn("dmsetup", &args, None, Some(&mut secret))?;
    checked("dmsetup", &args, output)?;
    Ok(secret)
}

pub fn crypt(args: &[&str]) -> Result<String> {
    signals::check()?;
    let output = spawn("cryptsetup", args, None, None)?;
    Ok(checked("cryptsetup", args, output)?.stdout)
}
