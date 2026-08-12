//! Line endings — the part git normally does, which we have to do ourselves.
//!
//! Git converts on the far side of the filter, so for an encrypted path it would
//! always hit ciphertext rather than content. The conversion therefore moves
//! here, and it moves **asymmetrically**:
//!
//! * clean never reads git's configuration. The same file has to yield the same
//!   plaintext on every machine, or the ciphertext differs and determinism dies.
//! * smudge does read it. That is the one moment where machines are allowed to
//!   differ, and where they should — but only when the configuration asks. Since
//!   2026-08-11 the case where nothing asks writes the stored bytes back
//!   unchanged rather than the platform's own ending, so two machines differ
//!   because someone chose it and not by default; see [`resolve_output`].
//!
//! Whether a file was normalised at all is recorded in the header's flag bit, so
//! smudge never has to ask `.git-xcrypt` — which also removes a real race, since
//! git does not promise to write `.git-xcrypt` before the files it filters.

use crate::rules::declaration::{EolMode, TextMode};

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
/// so `git status` reports the file as modified until it is added again — which
/// stores the collapsed bytes. Git does the same thing with an explicit `text`
/// attribute, and measured on 2.55 it does **not** warn about it even with
/// `core.safecrlf=warn`.
///
/// That is not the only shape, and not the worst one. Mixed `CRLF` and lone `LF`
/// is normalised under plain `text=auto` too, so the default mode loses the
/// distinction as well — and there `git status` stays *clean* while the working
/// tree changes, because the new bytes normalise to the same plaintext.
/// [`normalisation_is_reversible`] answers for both, and the filter warns; Open
/// Decision 8 in `context/foundation/zalozenia.md` closed on 2026-08-06.
/// Recorded here rather than claimed away, because an earlier version of this
/// comment asserted the invariant held everywhere.
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
///
/// **One row deliberately departs from git's own table, since 2026-08-11: with
/// `core.autocrlf` false or unset and `core.eol` unset, this writes the stored
/// bytes back unchanged rather than the platform's own ending.** That is the
/// configuration in which git converts *nothing*, and until this change
/// declaring a path secret opted it into a conversion the same file would never
/// have received while stored in the clear. Measured on git 2.55, two throwaway
/// repositories, a declared path and an undeclared one holding identical bytes:
///
/// | config | undeclared, git decides | declared, we decided | agreed? |
/// | --- | --- | --- | --- |
/// | `autocrlf=true` | `LF` in, `CRLF` out | `CRLF` out | yes |
/// | `autocrlf=input` | `CRLF` in, `LF` out | `LF` out | yes |
/// | `autocrlf=false`, `eol` unset | `LF` in, `LF` out | **`CRLF` out** | **no** |
/// | `autocrlf=false`, `eol=lf` | `CRLF` in, `CRLF` out | **`LF` out** | **no** |
///
/// `git status` was clean in all four, so nothing signalled either mismatch. The
/// third row is what this arm fixes; the fourth is the check-in half — `clean`
/// normalises before the header can record which ending was there — and no
/// choice made here can bring that back, so it stays a documented limit rather
/// than a fixed one. What the change does buy for it is that the answer stops
/// depending on the platform: after this, a declared path on Windows and on
/// Linux receives identical bytes unless something explicitly asks otherwise,
/// which is what §Non-Functional Requirements means by no differences across
/// machines.
///
/// An explicit `core.eol=native` still selects the platform's ending, because
/// that is a user asking for it rather than a default nobody chose, and it is
/// the way back to the previous behaviour without editing `.git-xcrypt`. So is
/// `eol=native` on the pattern, which outranks all of this.
///
/// Nothing here touches a stored byte: `clean` never reads configuration, the
/// ciphertext is unchanged, and whatever this writes normalises back to the same
/// plaintext — so the repository stays clean across the change.
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
            Some("native") => EolMode::Native,
            // Unset, empty, or a value git would not recognise: nobody asked for
            // a conversion, so there is none. The stored plaintext is already
            // LF, so this is the same thing the binary path does — the header
            // decides whether the content was normalised, and the configuration
            // only ever converts when it says so out loud.
            _ => EolMode::Lf,
        },
    }
}

/// Whether **git** would write `CRLF` into the working tree for a path it
/// converts itself.
///
/// Git's `text_eol_is_crlf`: `core.autocrlf` first, `core.eol` only while it is
/// false, the platform when neither says anything. It is asked about a different
/// subject than [`resolve_output`] — not "what should we write" but "is git
/// about to expand `LF` to `CRLF` in bytes it hands us" — and since 2026-08-11
/// the two answers differ in one row, so it computes its own rather than
/// borrowing. With `core.eol` unset git's default *is* `native`, and a path some
/// foreign line declared `text` really does get expanded; reading our own
/// narrower answer here would have made this say "git left it alone" about a
/// checkout that had just eaten the `CR` bytes out of a ciphertext, which is the
/// one question this function exists to answer.
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
    match autocrlf.map(str::to_ascii_lowercase).as_deref() {
        Some("input") => false,
        Some(value) if is_git_true(value) => true,
        _ => match core_eol.map(str::to_ascii_lowercase).as_deref() {
            Some("crlf") => true,
            Some("lf") => false,
            // Git's documented default for `core.eol` is `native`, and unlike
            // our own output this must keep saying so: the subject here is a
            // path git converts, where the default really does apply.
            _ => native_is_crlf,
        },
    }
}

/// Whether a configuration value is one of git's spellings of true.
///
/// Shared with `status`, which has to read `filter.git-xcrypt.required` by the
/// same rule: two answers to "is this git boolean true" is one answer too many.
fn is_git_true(value: &str) -> bool {
    crate::git::config::is_true(value)
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

/// Whether the working tree's own bytes can still be recovered from what
/// `clean` is about to store.
///
/// Normalisation maps several working trees onto one plaintext, so for some
/// content the original is simply gone. This asks about *that* — whether the
/// information survives — and deliberately **not** whether the bytes change.
/// The distinction is the whole design of this predicate, and it is where we
/// part company with git's `core.safecrlf`.
///
/// Git asks the wider question: it counts `CRLF` and lone `LF` before and after
/// a simulated round trip, so on a machine with `core.autocrlf=true` an ordinary
/// LF-only file warns — measured on 2.55, `* text=auto` and `a\nb\nc\n` give
/// `LF will be replaced by CRLF the next time Git touches it`. Git can afford
/// that because `safecrlf` defaults to **false**; the warning is opt-in. Ours is
/// always on and has no knob, so the wider question would put a line on `stderr`
/// for every text file in every Windows checkout — and a warning that fires on
/// healthy content is worse than none, because it teaches the reader to skip the
/// two that mean something.
///
/// Recoverable means some line-ending mode reproduces the original, which is the
/// question a *uniform* file always answers yes to and the two lossy shapes
/// always answer no to. Measured on git 2.55, verdict = working tree compared
/// byte for byte after `add`, `commit`, `rm`, `checkout`:
///
/// | content | git, `safecrlf=warn` | this |
/// | --- | --- | --- |
/// | `a\nb\nc\n`, out `CRLF` | warns | quiet — comes back as uniform `CRLF`, stable from then on |
/// | `a\r\nb\r\nc\r\n`, out `LF` | warns | quiet — mirror image |
/// | `a\r\nb\nc\r\n` mixed | warns | **catches** |
/// | `a\r\r\nb` under `text` | **silent**, byte lost | **catches** |
/// | `a\r\r\nb` under `auto` | silent, untouched | quiet — agrees, [`looks_binary`] declines to convert |
///
/// Git misses the fourth row because its two counters cannot see a lone `CR`:
/// one `CRLF` goes in and one comes out, so the totals agree while a byte is
/// gone.
///
/// Being a question about information rather than bytes, the answer needs no
/// [`EolMode`] and reads no configuration — so it is the same on every machine,
/// which is what keeps it from being one more thing that behaves differently on
/// Windows.
///
/// The two lossy shapes fail differently and a caller must not promise either:
/// mixed endings come back changed with `git status` **clean**, because the next
/// clean normalises the new bytes to the plaintext already stored; `CR` before
/// `CRLF` collapses one byte further on each pass and does show up as modified.
#[must_use]
pub fn normalisation_is_reversible(text: TextMode, content: &[u8]) -> bool {
    if !should_normalise(text, content) {
        // Stored verbatim, so nothing can be lost. Asked first because it is the
        // answer for every binary file and for anything declared `-text`, which
        // is also the remedy the warning built on this recommends.
        return true;
    }

    let normalised = normalise_to_lf(content);
    // One of the two directions has to reproduce the original. `Lf` succeeds for
    // content that had no `CRLF` to begin with, `Crlf` for content whose every
    // `LF` was part of one — that is, for a file that is uniform either way.
    normalised == content || to_crlf(&normalised) == content
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

    /// The one row where our output and git's table are allowed to disagree.
    ///
    /// Both halves matter and they pull opposite ways, which is why they are
    /// asserted together: [`resolve_output`] must stop converting where nobody
    /// asked, and [`git_writes_crlf`] must keep saying that git converts there —
    /// it is asked about a path a foreign `text` line pulled out from under the
    /// managed `-text`, and answering "left alone" would blame a healthy
    /// configuration for a checkout that just ate the `CR` bytes out of a
    /// ciphertext.
    #[test]
    fn nothing_asked_for_a_conversion_so_we_write_none_where_git_still_would() {
        for autocrlf in [None, Some("false"), Some("0"), Some("off")] {
            for core_eol in [None, Some(""), Some("nonsense")] {
                assert_eq!(
                    resolve_output(None, autocrlf, core_eol),
                    EolMode::Lf,
                    "autocrlf={autocrlf:?} eol={core_eol:?}: git converts nothing \
                     here, so a declared path must come back as it was stored"
                );
                // Same inputs, the other question, the other answer.
                assert!(
                    writes_crlf_where(autocrlf, core_eol, true),
                    "autocrlf={autocrlf:?} eol={core_eol:?}: git's own default \
                     for core.eol is native, and a Windows checkout expands"
                );
            }
        }

        // Asking for the platform explicitly still gets it — that is the way
        // back to the old behaviour without touching `.git-xcrypt`, and the
        // pattern's own `eol=native` outranks the configuration entirely.
        assert_eq!(
            resolve_output(None, Some("false"), Some("native")),
            EolMode::Native
        );
        assert_eq!(
            resolve_output(Some(EolMode::Native), Some("false"), None),
            EolMode::Native
        );

        // And the rows that were never in question stay where they were.
        assert_eq!(resolve_output(None, Some("true"), None), EolMode::Crlf);
        assert_eq!(resolve_output(None, Some("input"), None), EolMode::Lf);
        assert_eq!(
            resolve_output(None, Some("false"), Some("crlf")),
            EolMode::Crlf
        );
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

    #[test]
    fn only_content_whose_original_is_unrecoverable_is_called_out() {
        // The quiet rows carry more weight than the loud ones. This question is
        // asked on every `git add` of every encrypted file and the answer has no
        // knob to turn it off, so a predicate that fires on healthy content is
        // worse than no predicate: it teaches the reader to skip the two lines
        // that mean something. Every row is measured against git 2.55, verdict
        // by byte-for-byte comparison after `add`, `commit`, `rm`, `checkout`.
        let mixed = &b"a\r\nb\nc\r\n"[..];
        let cr_before_crlf = &b"a\r\r\nb"[..];

        // Mixed endings lose the distinction between the two kinds, and the
        // default mode loses it as readily as an explicit `text`.
        for text in [TextMode::Auto, TextMode::Text] {
            assert!(
                !normalisation_is_reversible(text, mixed),
                "{text:?} must not promise mixed endings can come back"
            );
        }

        // A `CR` before `CRLF` is the shape git's own counters miss: measured on
        // 2.55, `* text` with `core.safecrlf=warn` stores `a\r\nb` in silence.
        assert!(should_normalise(TextMode::Text, cr_before_crlf));
        assert!(!normalisation_is_reversible(TextMode::Text, cr_before_crlf));

        // …and under `text=auto` it cannot arise, because the lone `CR` makes
        // `looks_binary` decline to convert at all — agreeing with git, which
        // also leaves the file untouched there.
        assert!(!should_normalise(TextMode::Auto, cr_before_crlf));
        assert!(normalisation_is_reversible(TextMode::Auto, cr_before_crlf));

        // The quiet side, and the row that made this predicate narrower than
        // git's: a uniform file is recoverable whichever ending it uses, so an
        // ordinary LF-only file must stay silent even though a Windows checkout
        // will hand it back as CRLF. Git warns there; we must not.
        for text in [TextMode::Auto, TextMode::Text] {
            for content in [
                &b"one\ntwo\n"[..],
                b"one\r\ntwo\r\n",
                b"",
                b"no trailing newline",
                b"\n",
                b"\r\n",
                b"blank\n\nlines\n",
                b"blank\r\n\r\nlines\r\n",
            ] {
                assert!(
                    normalisation_is_reversible(text, content),
                    "{text:?} must stay quiet about the uniform {content:?}"
                );
            }
        }

        // Verbatim storage cannot lose anything, so `binary` — the remedy the
        // warning recommends — had better answer yes to both lossy shapes.
        for content in [mixed, cr_before_crlf, &b"\0\r\nbinary\n"[..]] {
            assert!(
                normalisation_is_reversible(TextMode::Binary, content),
                "declaring {content:?} binary must make the round trip exact"
            );
        }
    }
}
