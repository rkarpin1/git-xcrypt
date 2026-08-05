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
/// * of the bytes below `0x20` only `BS`, `TAB`, `FF` and `ESC` are forgiven;
/// * a **trailing `SUB`** (`0x1a`, the DOS end-of-file marker) is taken back off
///   the non-printable count after the scan. One byte, only the last one.
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
/// This rule is **frozen with the format from 2026-08-04**, and not before: the
/// trailing-`SUB` correction landed on that date (roadmap S-08), deliberately
/// ahead of the first release. Changing it moves the text/binary boundary, so
/// every file that crosses the boundary encrypts differently — after a release
/// that stops being a fix and becomes a new `suite`.
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

    // git's `gather_stats` closes with this, verbatim:
    //
    //     /* If file ends with EOF then don't count this EOF as non-printable. */
    //     if (size >= 1 && buf[size-1] == '\032')
    //             stats->nonprintable--;
    //
    // A `SUB` is below 0x20 and is not one of the four forgiven bytes, so the
    // loop above has always counted it; this takes exactly one back. Measured on
    // git 2.55: with `* text=auto`, `a\r\n\x1a` is stored as `61 0a 1a` — git
    // normalised the CRLF, so it read the file as text. `saturating_sub` rather
    // than `-`: a debug build's overflow panic on the filter path would abort
    // every git operation in the repository, and a file that is nothing but a
    // `SUB` reaches zero here.
    if content.last() == Some(&0x1a) {
        nonprintable = nonprintable.saturating_sub(1);
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

/// Whether **git** would write `CRLF` into the working tree for a path it
/// converts itself.
///
/// Git's `text_eol_is_crlf`, which is the same table [`resolve_output`] already
/// reproduces for our own output — `core.autocrlf` first, `core.eol` only while
/// it is false, the platform only when neither says anything. It is asked about
/// a different subject: not "what should we write" but "is git about to expand
/// `LF` to `CRLF` in bytes it hands us".
///
/// That question only comes up on the smudge path, and only once an
/// authentication tag has already failed. Git's check-out order is blob, then
/// git's conversion, then smudge, so on a path some attribute line pulled out
/// from under the managed `-text`, the tag is handed bytes that were never
/// stored — and the file is fine while the message says it is not.
#[must_use]
pub fn git_writes_crlf(autocrlf: Option<&str>, core_eol: Option<&str>) -> bool {
    writes_crlf_where(autocrlf, core_eol, cfg!(windows))
}

/// The platform-independent core, for the same reason [`apply_where`] has one.
fn writes_crlf_where(autocrlf: Option<&str>, core_eol: Option<&str>, native_is_crlf: bool) -> bool {
    match resolve_output(None, autocrlf, core_eol) {
        EolMode::Crlf => true,
        EolMode::Lf => false,
        EolMode::Native => native_is_crlf,
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
    apply_where(content, mode, cfg!(windows))
}

/// The platform-independent core, so both arms are testable from either machine.
///
/// `native_is_crlf` is `cfg!(windows)` in production and an argument here for the
/// same reason `repo::with_separator` takes a separator: this arm decides the
/// bytes that land in a **Windows** working tree, and the development machine is
/// not Windows, so without the parameter it would be covered by CI alone.
///
/// It is the smudge half of the asymmetry this module exists for — clean never
/// reads the platform, smudge is the one place that may — so the invariant worth
/// pinning is that the two still meet: whatever this writes out has to normalise
/// back to exactly what came in, or the same file yields a different blob on
/// Windows and `git status` reports a file nobody edited.
#[must_use]
fn apply_where(content: &[u8], mode: EolMode, native_is_crlf: bool) -> Vec<u8> {
    match mode {
        EolMode::Lf => content.to_vec(),
        EolMode::Crlf => to_crlf(content),
        EolMode::Native => {
            if native_is_crlf {
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
    fn gits_own_check_out_conversion_follows_the_measured_table() {
        // Measured on git 2.55, 2026-08-05, in a throwaway repository: a blob
        // holding lone `LF` bytes, the path declared `text` so git's binary
        // detection is out of the way, `rm` and `git checkout --`.
        //
        //   autocrlf=true                  -> CRLF, the file came back expanded
        //   autocrlf=input                 -> LF, untouched
        //   autocrlf=false core.eol=crlf   -> CRLF, expanded
        //   autocrlf=false core.eol=native -> LF on macOS, untouched
        //
        // The third row is worth the ink: `core.eol` on its own reaches nothing
        // — with no `text` attribute in force git leaves even a plain text blob
        // alone — but once a foreign line sets `text`, `core.eol=crlf` expands
        // exactly as `autocrlf=true` does.
        for (autocrlf, core_eol, expected) in [
            (Some("true"), None, true),
            (Some("input"), None, false),
            (Some("input"), Some("crlf"), false),
            (Some("false"), Some("crlf"), true),
            (Some("false"), Some("lf"), false),
        ] {
            assert_eq!(
                git_writes_crlf(autocrlf, core_eol),
                expected,
                "autocrlf={autocrlf:?} eol={core_eol:?} disagrees with git 2.55"
            );
        }

        // The row whose answer is the machine's, pinned on both machines rather
        // than left to whichever one happens to run the suite.
        for core_eol in [None, Some("native"), Some("")] {
            assert!(
                writes_crlf_where(Some("false"), core_eol, true),
                "a Windows checkout expands, so a converted ciphertext breaks there"
            );
            assert!(
                !writes_crlf_where(Some("false"), core_eol, false),
                "a Unix checkout leaves the bytes alone"
            );
        }
    }

    #[test]
    fn the_native_mode_writes_what_each_platform_asks_for_and_still_round_trips() {
        // `EolMode::Native` is what `resolve_output` returns whenever
        // `core.autocrlf` is false and `core.eol` is unset or `native` — an
        // ordinary configuration — and its CRLF arm has never run on the
        // development machine. Parameterised rather than left to CI, the same
        // way `repo::with_separator` is. Verified to bite: forcing the arm to
        // the Unix answer fails the first assertion below.
        let stored = b"one\ntwo\nthree\n";

        assert_eq!(
            apply_where(stored, EolMode::Native, true),
            b"one\r\ntwo\r\nthree\r\n",
            "a Windows working tree must receive CRLF"
        );
        assert_eq!(
            apply_where(stored, EolMode::Native, false),
            stored,
            "a Unix working tree must receive the bytes unchanged"
        );

        // The other two modes do not consult the platform at all, which is what
        // makes the measured configuration table portable.
        for native_is_crlf in [true, false] {
            assert_eq!(apply_where(stored, EolMode::Lf, native_is_crlf), stored);
            assert_eq!(
                apply_where(stored, EolMode::Crlf, native_is_crlf),
                b"one\r\ntwo\r\nthree\r\n"
            );
        }

        // The invariant that spans the asymmetry: smudge may write CRLF, but the
        // next clean has to normalise back to exactly the plaintext that was
        // encrypted, or the same file gives a different blob on Windows and
        // `git status` reports a file nobody edited, for good.
        for content in [
            &b"one\ntwo\nthree\n"[..],
            b"",
            b"no trailing newline",
            b"\n",
            b"blank\n\nlines\n",
        ] {
            for native_is_crlf in [true, false] {
                let written = apply_where(content, EolMode::Native, native_is_crlf);
                assert_eq!(
                    normalise_to_lf(&written),
                    content,
                    "{content:?} did not survive the Windows round trip"
                );
            }
        }
    }
}
