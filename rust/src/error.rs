//! Error type with Python-frontend-compatible notes and errno reporting.

use std::fmt;

#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub errno: Option<i32>,
    pub notes: Vec<String>,
    /// Cooperative cancellation (SIGINT/SIGTERM) won; exit 130 after cleanup.
    pub interrupted: bool,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error { message: message.into(), errno: None, notes: Vec::new(), interrupted: false }
    }

    pub fn os(errno: i32, message: impl Into<String>) -> Self {
        Error { errno: Some(errno), ..Error::new(message) }
    }

    pub fn last_os(context: &str) -> Self {
        let error = std::io::Error::last_os_error();
        Error::os(error.raw_os_error().unwrap_or(libc::EIO), format!("{context}: {error}"))
    }

    pub fn interrupted() -> Self {
        Error { interrupted: true, ..Error::os(libc::EINTR, "Interrupted") }
    }

    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::os(error.raw_os_error().unwrap_or(libc::EIO), error.to_string())
    }
}

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => { return Err($crate::error::Error::new(format!($($arg)*))) };
}
