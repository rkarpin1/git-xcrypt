//! Logic behind the `git-xcrypt` binary.
//!
//! The crate is split into a library and a thin binary so integration tests can
//! drive the logic directly instead of only through a subprocess.
//!
//! Nothing here may write to `stdout`. On the filter path git treats our
//! `stdout` as the file content itself, so a stray `println!` silently corrupts
//! a user's file. Diagnostics go to `stderr`.

use thiserror::Error;

pub mod atomic;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod decide;
pub mod eol;
pub mod exit;
pub mod filter;
pub mod format;
pub mod gitattributes;
pub mod gitconfig;
pub mod gitindex;
pub mod history;
pub mod key;
pub mod keyfile;
pub mod pktline;
pub mod repo;

/// Errors returned by library operations.
///
/// The variants line up with the exit codes the binary reports, so a caller can
/// map an error to a code without inspecting its message.
#[derive(Debug, Error)]
pub enum Error {
    /// Reading the input or writing the output failed.
    #[error("i/o failure: {0}")]
    Io(#[from] std::io::Error),

    /// The operating system refused to provide randomness.
    #[error("could not draw randomness from the operating system: {0}")]
    Entropy(String),

    /// The content is not a file this build can read.
    #[error("format error: {0}")]
    Format(String),

    /// The file belongs to a different repository key.
    #[error(
        "this file was encrypted with key {}, but the repository holds key {}",
        hex(wanted),
        hex(have)
    )]
    KeyMismatch {
        /// Fingerprint the file asks for.
        wanted: [u8; format::KEY_ID_LEN],
        /// Fingerprint we actually hold.
        have: [u8; format::KEY_ID_LEN],
    },

    /// Authentication failed, or the cipher refused the input.
    #[error("{0}")]
    Crypto(String),

    /// The repository is not in a state this command can act on.
    #[error("{0}")]
    Config(String),

    /// No repository key is present.
    #[error("no repository key; run `git-xcrypt init`, `unlock` or `import-key`")]
    NoKey,

    /// The command line asked for something impossible.
    #[error("{0}")]
    Usage(String),
}

impl Error {
    /// The process exit code this error reports.
    ///
    /// Callers map errors to codes here rather than at each call site, so the
    /// set stays consistent across every command.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) | Self::Io(_) | Self::Entropy(_) => exit::USAGE,
            Self::Config(_) => exit::CONFIG,
            Self::NoKey => exit::NO_KEY,
            Self::Format(_) | Self::KeyMismatch { .. } | Self::Crypto(_) => exit::FORMAT,
        }
    }
}

/// Result alias for library operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Renders a key fingerprint the way every user-facing message shows it.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Formats a key fingerprint for display.
#[must_use]
pub fn format_key_id(key_id: &[u8; format::KEY_ID_LEN]) -> String {
    hex(key_id)
}
