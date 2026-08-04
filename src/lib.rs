//! Logic behind the `git-crypt` binary.
//!
//! The crate is split into a library and a thin binary so integration tests can
//! drive the logic directly instead of only through a subprocess.

use std::io::{Read, Write};

use thiserror::Error;

/// Errors returned by library operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Reading the input or writing the output failed.
    #[error("i/o failure on the filter path: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias for library operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Placeholder transform standing in for the real cipher until S-01 lands.
///
/// Reversing the byte order is deterministic and its own inverse, so one
/// implementation serves both the clean and the smudge side of the filter.
#[must_use]
pub fn transform(input: &[u8]) -> Vec<u8> {
    input.iter().rev().copied().collect()
}

/// Reads all of `input`, applies [`transform`] and writes the result to `output`.
///
/// The whole input is buffered before anything is written. Reversing needs the
/// last byte first, and AES-SIV will need two passes over the data for the same
/// structural reason, so the buffering is not an accident of the placeholder.
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
    fn transform_is_deterministic() {
        let input = b"the same plaintext twice";
        assert_eq!(transform(input), transform(input));
    }

    #[test]
    fn empty_input_yields_empty_output() {
        let mut output = Vec::new();
        run_filter(&mut b"".as_slice(), &mut output).expect("empty input must succeed");
        assert!(output.is_empty());
    }

    #[test]
    fn run_filter_round_trips_binary_content() {
        let plaintext: Vec<u8> = (0u8..=255).collect();

        let mut cleaned = Vec::new();
        run_filter(&mut plaintext.as_slice(), &mut cleaned).expect("clean must succeed");
        let mut smudged = Vec::new();
        run_filter(&mut cleaned.as_slice(), &mut smudged).expect("smudge must succeed");

        assert_ne!(cleaned, plaintext);
        assert_eq!(smudged, plaintext);
    }
}
