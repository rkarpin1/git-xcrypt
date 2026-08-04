//! Logic behind the `git-xcrypt` binary.
//!
//! The crate is split into a library and a thin binary so integration tests can
//! drive the logic directly instead of only through a subprocess.
//!
//! Nothing here may write to `stdout`. On the filter path git treats our
//! `stdout` as the file content itself, so a stray `println!` silently corrupts
//! a user's file. Diagnostics go to `stderr`.

use std::io::{Read, Write};

use thiserror::Error;

pub mod crypto;
pub mod format;
pub mod key;

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

/// Placeholder transform standing in for the real cipher until S-01 phase 4.
///
/// Reversing the byte order is deterministic and its own inverse, so one
/// implementation serves both the clean and the smudge side of the filter.
/// Phase 4 removes it together with the hidden `__test-filter` command.
#[must_use]
pub fn transform(input: &[u8]) -> Vec<u8> {
    input.iter().rev().copied().collect()
}

/// Reads all of `input`, applies [`transform`] and writes the result to `output`.
///
/// # Errors
///
/// [`Error::Io`] when reading or writing fails.
pub fn run_filter(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;
    output.write_all(&transform(&buffer))?;
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transform_is_its_own_inverse() {
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        for input in [b"".as_slice(), b"a".as_slice(), all_bytes.as_slice()] {
            assert_eq!(transform(&transform(input)), input);
        }
    }

    #[test]
    fn empty_input_yields_empty_output() {
        let mut output = Vec::new();
        run_filter(&mut b"".as_slice(), &mut output).expect("empty input must succeed");
        assert!(output.is_empty());
    }

    #[test]
    fn key_ids_render_as_lowercase_hex() {
        assert_eq!(
            format_key_id(&[0x3f, 0xa9, 0x12, 0x0b, 0x7e, 0xc4, 0x55, 0x8a]),
            "3fa9120b7ec4558a"
        );
    }
}
