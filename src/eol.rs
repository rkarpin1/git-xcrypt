//! Line endings — the part git normally does, which we have to do ourselves.
//!
//! Git converts on the far side of the filter, so for an encrypted path it would
//! always hit ciphertext rather than content. The conversion therefore moves
//! here, and it moves **asymmetrically**:
//!
//! * clean never reads git's configuration. The same file has to yield the same
//!   plaintext on every machine, or the ciphertext differs and determinism dies.
//! * smudge does read it. That is the one moment where machines are allowed to
//!   differ, and where they should.
//!
//! Whether a file was normalised at all is recorded in the header's flag bit, so
//! smudge never has to ask `.git-xcrypt` — which also removes a real race, since
//! git does not promise to write `.git-xcrypt` before the files it filters.

use crate::config::{EolMode, TextMode};

/// Whether git — and therefore we — would treat this content as binary.
///
/// Measured against git 2.55 rather than taken from documentation. Binary means
/// a NUL byte anywhere, or too many control characters below `0x20`. Bytes at
/// or above `0x80` count as printable, which is why UTF-8 text is recognised as
/// text. The whole content is scanned; the 8000-byte window belongs to a
/// different heuristic, the one `git diff` uses to print `Binary files differ`.
///
/// This rule is **frozen with the format**: changing it would move the
/// text/binary boundary and rewrite the ciphertext of existing files.
#[must_use]
pub fn looks_binary(content: &[u8]) -> bool {
    let mut printable = 0usize;
    let mut nonprintable = 0usize;

    for &byte in content {
        match byte {
            0 => return true,
            b'\t' | b'\n' | b'\r' | 0x0c | 0x08 | 0x1b => printable += 1,
            0x01..0x20 => nonprintable += 1,
            _ => printable += 1,
        }
    }

    (printable >> 7) < nonprintable
}

/// Whether the content should be normalised, given its declared mode.
///
/// Unlike git, the answer never depends on the index. Git keeps CRLF for a file
/// that entered the repository with it, even after `core.autocrlf` is switched
/// on — which makes its verdict a function of history, not content. Ours has to
/// be a pure function of content or the same file encrypts differently depending
/// on where it has been.
#[must_use]
pub fn should_normalise(mode: TextMode, content: &[u8]) -> bool {
    match mode {
        TextMode::Text => true,
        TextMode::Binary => false,
        TextMode::Auto => !looks_binary(content),
    }
}

/// Replaces every `CRLF` with `LF`.
///
/// A lone `CR` is left alone: it is not a line ending git would have produced,
/// and rewriting it would corrupt content that merely happens to contain the
/// byte. The function is idempotent, which matters because the round trip runs
/// it again on content it has already normalised.
#[must_use]
pub fn normalise_to_lf(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len());
    let mut index = 0;

    while index < content.len() {
        if content[index] == b'\r' && content.get(index + 1) == Some(&b'\n') {
            out.push(b'\n');
            index += 2;
        } else {
            out.push(content[index]);
            index += 1;
        }
    }

    out
}

/// Rewrites LF as CRLF.
#[must_use]
pub fn to_crlf(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + content.len() / 16);
    for (index, &byte) in content.iter().enumerate() {
        if byte == b'\n' && (index == 0 || content[index - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(byte);
    }
    out
}

/// What the working tree should receive, given the declaration and git's config.
///
/// The table is measured, not guessed: `autocrlf=true` yields CRLF and ignores
/// `core.eol`, `autocrlf=input` yields LF and ignores it too, and only
/// `autocrlf=false` lets `core.eol` decide.
#[must_use]
pub fn resolve_output(
    declared: Option<EolMode>,
    autocrlf: Option<&str>,
    eol: Option<&str>,
) -> EolMode {
    if let Some(mode) = declared {
        return mode;
    }

    match autocrlf.map(str::to_ascii_lowercase).as_deref() {
        Some("true") => EolMode::Crlf,
        Some("input") => EolMode::Lf,
        _ => match eol.map(str::to_ascii_lowercase).as_deref() {
            Some("crlf") => EolMode::Crlf,
            Some("lf") => EolMode::Lf,
            _ => EolMode::Native,
        },
    }
}

/// Applies a resolved line-ending mode to content that was normalised to LF.
#[must_use]
pub fn apply(content: &[u8], mode: EolMode) -> Vec<u8> {
    match mode {
        EolMode::Lf => content.to_vec(),
        EolMode::Crlf => to_crlf(content),
        EolMode::Native => {
            if cfg!(windows) {
                to_crlf(content)
            } else {
                content.to_vec()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nul_byte_anywhere_means_binary() {
        assert!(looks_binary(b"\0"));
        assert!(looks_binary(b"text then \0 a nul"));

        // Measured on git 2.55: a NUL a million bytes in still reads as binary,
        // because the CRLF path scans the whole content.
        let mut late = vec![b'A'; 1_000_000];
        late.push(0);
        assert!(looks_binary(&late));
    }

    #[test]
    fn high_bytes_count_as_printable() {
        // Measured: 2560 bytes of 0x80..0xff with CRLF inside was normalised by
        // git, so UTF-8 text must not be mistaken for binary.
        let content: Vec<u8> = (0x80u8..=0xff).cycle().take(2560).collect();
        assert!(!looks_binary(&content));
    }

    #[test]
    fn plenty_of_control_bytes_mean_binary() {
        // Measured: 2400 bytes of 0x01..0x08 was left untouched by git.
        let content: Vec<u8> = (1u8..=8).cycle().take(2400).collect();
        assert!(looks_binary(&content));
    }

    #[test]
    fn ordinary_text_is_text() {
        assert!(!looks_binary(b"api_key = do-not-commit-me\n"));
        assert!(!looks_binary(b""));
        assert!(!looks_binary(b"tabs\tand\nnewlines\r\n"));
    }

    #[test]
    fn normalising_is_idempotent() {
        let once = normalise_to_lf(b"a\r\nb\r\n");
        let twice = normalise_to_lf(&once);
        assert_eq!(once, b"a\nb\n");
        assert_eq!(once, twice);
    }

    #[test]
    fn a_lone_carriage_return_survives() {
        assert_eq!(normalise_to_lf(b"a\rb"), b"a\rb");
        assert_eq!(normalise_to_lf(b"trailing\r"), b"trailing\r");
    }

    #[test]
    fn crlf_conversion_round_trips_through_normalisation() {
        let original = b"one\ntwo\nthree\n";
        assert_eq!(normalise_to_lf(&to_crlf(original)), original);
    }

    #[test]
    fn crlf_conversion_does_not_double_existing_carriage_returns() {
        assert_eq!(to_crlf(b"a\r\nb\n"), b"a\r\nb\r\n");
    }

    #[test]
    fn the_declared_mode_wins_over_configuration() {
        assert_eq!(
            resolve_output(Some(EolMode::Lf), Some("true"), Some("crlf")),
            EolMode::Lf
        );
    }

    #[test]
    fn the_measured_configuration_table_is_reproduced() {
        assert_eq!(
            resolve_output(None, Some("true"), Some("lf")),
            EolMode::Crlf
        );
        assert_eq!(
            resolve_output(None, Some("input"), Some("crlf")),
            EolMode::Lf
        );
        assert_eq!(
            resolve_output(None, Some("false"), Some("crlf")),
            EolMode::Crlf
        );
        assert_eq!(resolve_output(None, Some("false"), Some("lf")), EolMode::Lf);
        assert_eq!(
            resolve_output(None, Some("false"), Some("native")),
            EolMode::Native
        );
        assert_eq!(resolve_output(None, None, None), EolMode::Native);
    }

    #[test]
    fn auto_decides_from_content_alone() {
        assert!(should_normalise(TextMode::Auto, b"plain text\r\n"));
        assert!(!should_normalise(TextMode::Auto, b"\0binary\r\n"));
        assert!(should_normalise(TextMode::Text, b"\0even binary\r\n"));
        assert!(!should_normalise(TextMode::Binary, b"plain text\r\n"));
    }
}
