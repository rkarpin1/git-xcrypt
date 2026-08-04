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
/// A byte-for-byte port of git's `gather_stats` plus `convert_is_binary`,
/// measured against git 2.55 rather than taken from documentation. Binary means
/// a NUL byte anywhere, a lone `CR` — one not followed by `LF` — or too many
/// disallowed control characters relative to printable ones.
///
/// The three details that make it a port rather than an approximation, each of
/// which git-xcrypt got wrong before and each of which moves real files across
/// the boundary:
///
/// * `CR` and `LF` are counted as line endings and go into **neither** bucket;
/// * `DEL` (`0x7f`) counts as non-printable, despite being above `0x20`;
/// * of the bytes below `0x20` only `BS`, `TAB`, `FF` and `ESC` are forgiven.
///
/// Bytes at or above `0x80` count as printable, which is why UTF-8 text is
/// recognised as text. The whole content is scanned; the 8000-byte window
/// belongs to a different heuristic, the one `git diff` uses to print
/// `Binary files differ`.
///
/// The lone-`CR` rule is not decoration. Without it, content such as
/// `a\r\r\nb` normalises to `a\r\nb`, which normalises again to `a\nb` — so the
/// conversion is not closed over its own output, the working tree comes back
/// different after a checkout and `git status` reports a file nobody edited.
/// Git avoids that the same way, by declining to convert at all.
///
/// This rule is **frozen with the format**: changing it would move the
/// text/binary boundary and rewrite the ciphertext of existing files.
#[must_use]
pub fn looks_binary(content: &[u8]) -> bool {
    let mut printable = 0usize;
    let mut nonprintable = 0usize;

    for (index, &byte) in content.iter().enumerate() {
        match byte {
            // CR and LF are counted as line endings and land in neither
            // bucket. Counting them as printable would inflate the left side
            // of the ratio below and call binary content text.
            b'\r' => {
                if content.get(index + 1) != Some(&b'\n') {
                    return true;
                }
            }
            b'\n' => {}
            0 => return true,
            // BS, TAB, FF and ESC are the control bytes git forgives.
            0x08 | b'\t' | 0x0c | 0x1b => printable += 1,
            // DEL counts against the content, same as the other controls.
            0x01..0x20 | 0x7f => nonprintable += 1,
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
/// byte.
///
/// **Not idempotent in general** — `\r\r\n` collapses to `\r\n` and would
/// collapse again to `\n` on a second pass, exactly as git's own conversion
/// does. Under `text=auto`, which is the default and so the mode almost every
/// path is in, that never happens: content carrying a lone `CR` is classified
/// binary by [`looks_binary`] and is never normalised at all.
///
/// **An explicit `text` bypasses that classifier**, so a path declared
/// `secrets/*.sh text` whose content holds `\r\r\n` does not round-trip: clean
/// stores `\r\n`, smudge writes it back, and the next clean collapses it again,
/// so `git status` reports the file as modified for good. Git does the same
/// thing with an explicit `text` attribute — this is what `core.safecrlf` warns
/// about, and whether to reproduce that warning is Open Decision 8 in
/// `context/foundation/zalozenia.md`. Recorded here rather than claimed away,
/// because an earlier version of this comment asserted the invariant held
/// everywhere.
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
        Some("input") => EolMode::Lf,
        // `core.autocrlf` is a git boolean plus the special value `input`, and
        // git accepts every boolean spelling here: `1`, `yes` and `on` are as
        // valid as `true`. Matching only `true` silently downgraded them to
        // `false` and wrote LF where the user asked for CRLF.
        Some(value) if is_git_true(value) => EolMode::Crlf,
        _ => match eol.map(str::to_ascii_lowercase).as_deref() {
            Some("crlf") => EolMode::Crlf,
            Some("lf") => EolMode::Lf,
            _ => EolMode::Native,
        },
    }
}

/// Whether a configuration value is one of git's spellings of true.
///
/// Shared with `status`, which has to read `filter.git-xcrypt.required` by the
/// same rule: two answers to "is this git boolean true" is one answer too many.
fn is_git_true(value: &str) -> bool {
    crate::gitconfig::is_true(value)
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
    fn a_lone_carriage_return_means_binary() {
        // Git's own `convert_is_binary` refuses these, and so must we: without
        // the rule, `a\r\r\nb` normalises to something that normalises again,
        // so a checked-out file comes back changed and `git status` never
        // settles.
        assert!(looks_binary(b"old mac\rline endings\r"));
        assert!(looks_binary(b"a\r\r\nb\r\n"));
        assert!(looks_binary(b"trailing\r"));
        assert!(looks_binary(b"\n\r"));
        assert!(!looks_binary(b"a\r\nb\r\n"), "plain CRLF is still text");
    }

    #[test]
    fn content_that_is_normalised_survives_a_second_pass() {
        // The invariant the lone-CR rule exists to protect: everything
        // `should_normalise` says yes to must be closed under normalisation.
        for content in [
            &b"a\r\nb\r\n"[..],
            b"a\r\r\nb\r\n",
            b"trailing\r",
            b"plain\n",
            b"\n\r",
            b"",
        ] {
            if !should_normalise(TextMode::Auto, content) {
                continue;
            }
            let once = normalise_to_lf(content);
            assert_eq!(
                normalise_to_lf(&once),
                once,
                "{content:?} was normalised into something that normalises again, \
                 so its round trip would never settle"
            );
        }
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
    fn every_git_spelling_of_true_means_crlf() {
        // `""` is deliberately absent from this list, and `true` stands in for
        // the value-less `[core]\n\tautocrlf` line — which is what
        // `gitconfig::get` now hands over for it. Measured on git 2.55 with a
        // repository whose file carries `* text`:
        //
        //   `autocrlf`     (no `=`)  → checkout writes CRLF
        //   `autocrlf = `  (empty)   → checkout writes LF
        //
        // The two used to arrive here as the same empty string, so the second
        // wrote CRLF where git writes LF — see the false half of this test.
        for spelling in ["true", "TRUE", "yes", "on", "1"] {
            assert_eq!(
                resolve_output(None, Some(spelling), None),
                EolMode::Crlf,
                "`core.autocrlf = {spelling}` is true to git and must be to us"
            );
        }
        for spelling in ["false", "no", "off", "0", ""] {
            assert_eq!(
                resolve_output(None, Some(spelling), Some("lf")),
                EolMode::Lf,
                "`core.autocrlf = {spelling}` is false to git, so core.eol decides"
            );
        }
    }

    #[test]
    fn auto_decides_from_content_alone() {
        assert!(should_normalise(TextMode::Auto, b"plain text\r\n"));
        assert!(!should_normalise(TextMode::Auto, b"\0binary\r\n"));
        assert!(should_normalise(TextMode::Text, b"\0even binary\r\n"));
        assert!(!should_normalise(TextMode::Binary, b"plain text\r\n"));
    }
}
