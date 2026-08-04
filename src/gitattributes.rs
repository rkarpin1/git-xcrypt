//! The managed section of `.gitattributes`.
//!
//! The section holds one static line, `* filter=git-xcrypt`, and the whole
//! security guarantee rests on it. It does not depend on the contents of
//! `.git-xcrypt`, so it cannot drift from it — that is the entire point of the
//! catch-all construction.
//!
//! Everything below that line is **cosmetic** in the sense that letting it go
//! stale never stores a secret in the clear. It is not cosmetic in the sense of
//! being optional: `-text` is what keeps git's own CRLF conversion off the
//! ciphertext. Git applies that conversion to the *output* of the clean filter,
//! so on a path where some other rule sets `text` — a user's own `*.env text`
//! line is entirely ordinary — the conversion eats the `CR` bytes inside the
//! ciphertext. `git add` still exits 0, the damaged blob is committed, and the
//! loss only surfaces at the next checkout as a failed authentication tag, with
//! the plaintext already gone.
//!
//! So the rendered lines have to cover **exactly** the set of paths the filter
//! encrypts. Neither direction is free: too narrow leaves the hole above, too
//! broad turns line-ending conversion off for files that are not encrypted at
//! all. The two syntaxes make that harder than it sounds — see [`translate`].

use std::fs;
use std::path::Path;

use crate::config::Config;
use crate::repo::DRIVER;
use crate::{Error, Result};

/// Opens the section this tool owns.
const BEGIN: &str = "# >>> git-xcrypt >>>";

/// Closes it. Everything outside the pair belongs to the user.
const END: &str = "# <<< git-xcrypt <<<";

/// The line the filter actually hangs on.
///
/// Static by design: it names no pattern, so changing `.git-xcrypt` never makes
/// it stale. The filter is invoked for every file and decides for itself.
const CATCH_ALL: &str = "* filter=git-xcrypt";

/// Renders the per-pattern lines for `config`.
///
/// An encrypted path gets `-text` plus `diff=git-xcrypt`, or `-text -diff` when
/// its pattern was declared `binary` — git's own `binary` macro means
/// `-text -diff`, and we reproduce it. A path a negation took back out gets
/// `!text !diff`, which restores git's defaults for it; leaving it alone would
/// keep `-text` on a file that is stored in the clear, so git would stop
/// managing its line endings.
///
/// Output order is three groups, each in the order of `.git-xcrypt`: patterns
/// that keep the diff driver, then patterns that drop it, then negations. The
/// grouping is what reconciles the two resolution rules — git takes the last
/// matching line, [`Config::decide`] merges every matching line — so anything
/// that takes an attribute away has to sit below everything that grants it.
/// Within that, the order is the input's, so the section is a pure function of
/// the configuration and two runs produce the same file.
#[must_use]
pub fn render_lines(config: &Config) -> Vec<String> {
    // A pattern may be spelled by several lines; `binary` on any of them
    // suppresses the diff driver for the path, so the spellings merge here
    // rather than fighting each other in the file.
    let mut encrypted: Vec<(String, bool)> = Vec::new();
    for (source, decision) in config.selecting_patterns() {
        for spelling in translate(source) {
            match encrypted
                .iter_mut()
                .find(|(existing, _)| *existing == spelling)
            {
                Some((_, suppress_diff)) => *suppress_diff |= decision.suppress_diff,
                None => encrypted.push((spelling, decision.suppress_diff)),
            }
        }
    }

    let mut excluded: Vec<String> = Vec::new();
    for source in config.negated_patterns() {
        for spelling in translate(source) {
            if !excluded.contains(&spelling) {
                excluded.push(spelling);
            }
        }
    }

    let mut lines = Vec::with_capacity(encrypted.len() + excluded.len());
    lines.extend(
        encrypted
            .iter()
            .filter(|(_, suppress_diff)| !suppress_diff)
            .map(|(pattern, _)| format!("{pattern} -text diff={DRIVER}")),
    );
    lines.extend(
        encrypted
            .iter()
            .filter(|(_, suppress_diff)| *suppress_diff)
            .map(|(pattern, _)| format!("{pattern} -text -diff")),
    );
    lines.extend(
        excluded
            .iter()
            .map(|pattern| format!("{pattern} !text !diff")),
    );
    lines
}

/// Spells one `.git-xcrypt` pattern the way `.gitattributes` needs it.
///
/// Returns every spelling the pattern needs — one or two lines, or none for a
/// pattern with nothing left to render. Four differences between the two
/// syntaxes matter, all measured against git 2.55:
///
/// * **A pattern with no slash floats; one with a slash is anchored.** That rule
///   is the same in both files, but the translation itself introduces slashes,
///   so it has to be undone deliberately: `secrets/` matches `app/secrets/x` in
///   `.gitignore`, while a bare `secrets/**` in `.gitattributes` reaches only
///   the root one. Hence the `**/` prefix on anything the trailing slash did not
///   already anchor. Getting this wrong is not cosmetic — see the module doc.
/// * **A trailing `/` matches a directory in `.gitignore` and nothing at all in
///   `.gitattributes`**, so the subtree has to be spelled `.../**`.
/// * **A pattern without a trailing slash can still match a directory**, and
///   this tool encrypts everything under a matched directory. That needs a
///   second line: `*.env` covers the file `a.env` and, separately, everything
///   inside a directory named `a.env`.
/// * **A leading `/` is kept.** It anchors in both files, and dropping it would
///   let `/build.env` float to every subdirectory — `-text` on files that are
///   not encrypted.
///
/// Whitespace ends a pattern in `.gitattributes` unless the whole pattern is
/// C-quoted; the `\ ` escape `.gitignore` uses is not understood there. A
/// pattern opening with `[attr]` is quoted for a different reason: git reads
/// that prefix as a macro definition before it looks at quoting at all.
fn translate(pattern: &str) -> Vec<String> {
    let directory_only = pattern.ends_with('/');
    let core = pattern.strip_suffix('/').unwrap_or(pattern);
    if core.trim_matches('/').is_empty() {
        return Vec::new();
    }

    // `.gitignore`: a slash anywhere but at the very end anchors the pattern to
    // the root; without one it matches at any depth.
    let anchored = core.contains('/');

    let mut spellings = Vec::with_capacity(2);
    if !directory_only {
        spellings.push(spell(core));
    }
    spellings.push(if anchored {
        spell(&format!("{core}/**"))
    } else {
        spell(&format!("**/{core}/**"))
    });
    spellings
}

/// One pattern, escaped and quoted the way git's attribute parser reads it.
fn spell(pattern: &str) -> String {
    // Undo only the escape that the two syntaxes disagree about. Every other
    // backslash is wildmatch's, and wildmatch is the same engine on both sides.
    let mut plain = String::with_capacity(pattern.len());
    let mut characters = pattern.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            plain.push(character);
            continue;
        }
        match characters.next() {
            Some(escaped) if escaped.is_whitespace() => plain.push(escaped),
            Some(escaped) => {
                plain.push('\\');
                plain.push(escaped);
            }
            None => plain.push('\\'),
        }
    }

    // A leading quote would send git into its C-quoting parser mid-pattern, and
    // a leading `[attr]` would make the line a macro definition instead of a
    // pattern. Quoting settles both.
    if !plain.contains(char::is_whitespace)
        && !plain.starts_with('"')
        && !plain.starts_with("[attr]")
    {
        return plain;
    }

    let mut quoted = String::with_capacity(plain.len() + 2);
    quoted.push('"');
    for character in plain.chars() {
        match character {
            '"' | '\\' => {
                quoted.push('\\');
                quoted.push(character);
            }
            '\t' => quoted.push_str("\\t"),
            '\r' => quoted.push_str("\\r"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// Renders the body of the managed section.
#[must_use]
pub fn render_section(extra_lines: &[String]) -> String {
    let mut out = String::new();
    out.push_str(BEGIN);
    out.push('\n');
    out.push_str(CATCH_ALL);
    out.push('\n');
    for line in extra_lines {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// Whether `contents` shows any sign of a managed section.
///
/// Deliberately looser than [`upsert`]'s boundary detection: this answer decides
/// whether `init` refuses to generate a second key, and there the safe direction
/// is to see a trace that is not there rather than to miss one that is.
#[must_use]
pub fn has_section(contents: &str) -> bool {
    contents.contains(BEGIN)
}

/// Where the line that is exactly `marker` starts, and where the line after it
/// begins.
///
/// Matching a marker as a whole line rather than as a substring is what keeps
/// `# >>> git-xcrypt >>> (legacy)` in a user's own comment from being taken for
/// the start of our section — which would put everything after it inside the
/// region the next write replaces.
fn marker_line(contents: &str, marker: &str) -> Option<(usize, usize)> {
    let mut offset = 0;
    for line in contents.split_inclusive('\n') {
        let text = line.strip_suffix('\n').unwrap_or(line);
        let text = text.strip_suffix('\r').unwrap_or(text);
        if text == marker {
            return Some((offset, offset + line.len()));
        }
        offset += line.len();
    }
    None
}

/// Replaces the managed section in `contents`, or appends one.
///
/// Everything outside the markers is preserved byte for byte. A file with an
/// opening marker and no closing one is refused rather than guessed at: guessing
/// the boundary would destroy the user's own attributes.
///
/// # Errors
///
/// [`Error::Config`] when the markers are unbalanced.
pub fn upsert(contents: &str, section: &str) -> Result<String> {
    let Some((begin, _)) = marker_line(contents, BEGIN) else {
        if marker_line(contents, END).is_some() {
            return Err(Error::Config(format!(
                "{ATTRIBUTES}: found the closing git-xcrypt marker without the opening one; \
                 fix it by hand so nothing of yours is lost",
                ATTRIBUTES = crate::repo::ATTRIBUTES_FILE
            )));
        }
        let mut out = contents.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(section);
        return Ok(out);
    };

    // The closing marker is looked for after the opening one, so a stray copy
    // above the section cannot shorten it.
    let Some((_, after_end)) = marker_line(&contents[begin..], END) else {
        return Err(Error::Config(format!(
            "{ATTRIBUTES}: the git-xcrypt section is opened but never closed; \
             fix it by hand so nothing of yours is lost",
            ATTRIBUTES = crate::repo::ATTRIBUTES_FILE
        )));
    };

    let mut out = String::with_capacity(contents.len() + section.len());
    out.push_str(&contents[..begin]);
    out.push_str(section);
    out.push_str(&contents[begin + after_end..]);
    Ok(out)
}

/// Reads the attributes file at `path`, treating an absent one as empty.
///
/// # Errors
///
/// [`Error::Io`] when the file exists but cannot be read, [`Error::Config`] when
/// it is not text. An unreadable file is never silently treated as an empty one:
/// that would replace the user's own attributes with a bare managed section.
pub fn read(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        // `read_to_string` reports "stream did not contain valid UTF-8" as an
        // I/O error, which tells a user nothing about which file is at fault.
        Err(err) if err.kind() == std::io::ErrorKind::InvalidData => Err(Error::Config(format!(
            "{}: not valid UTF-8, so the managed section cannot be edited safely; \
             fix the file by hand",
            path.display()
        ))),
        Err(err) => Err(Error::Io(err)),
    }
}

/// What the attributes file at `path` should contain for `extra_lines`.
///
/// Split out from [`write_section`] so `sync --check` can compare without
/// writing — the check and the write must never answer differently.
///
/// # Errors
///
/// [`Error::Io`] on a read failure, [`Error::Config`] on unbalanced markers.
pub fn desired(path: &Path, extra_lines: &[String]) -> Result<(String, String)> {
    let existing = read(path)?;
    let updated = upsert(&existing, &render_section(extra_lines))?;
    Ok((existing, updated))
}

/// Writes the managed section into the attributes file at `path`.
///
/// # Errors
///
/// [`Error::Io`] on a read or write failure, [`Error::Config`] on unbalanced
/// markers.
pub fn write_section(path: &Path, extra_lines: &[String]) -> Result<bool> {
    let (existing, updated) = desired(path, extra_lines)?;
    if updated == existing {
        return Ok(false);
    }
    // Never `fs::write`: truncating this file is what turns encryption off, and
    // it also loses whatever the user keeps outside our markers.
    crate::atomic::write(path, updated.as_bytes())?;
    Ok(true)
}

/// The configuration keys `init` writes, for `status` to check for completeness.
///
/// A clone that never ran `init` or `unlock` carries the catch-all attribute
/// through history but not `.git/config`, and git treats an undefined filter as
/// no filter at all — content passes through in the clear. `diff.git-xcrypt.*`
/// is absent on purpose: it arrives with S-05, and listing it here would make
/// every repository report itself incomplete until then.
#[must_use]
pub fn driver_keys() -> [String; 2] {
    [
        format!("filter.{DRIVER}.process"),
        format!("filter.{DRIVER}.required"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_section_is_appended() {
        let out = upsert("# mine\n*.png binary\n", &render_section(&[])).expect("valid input");
        assert!(out.starts_with("# mine\n*.png binary\n"));
        assert!(out.contains(CATCH_ALL));
    }

    #[test]
    fn an_empty_file_gains_only_the_section() {
        let out = upsert("", &render_section(&[])).expect("valid input");
        assert_eq!(out, render_section(&[]));
    }

    #[test]
    fn a_file_without_a_trailing_newline_still_gets_one() {
        let out = upsert("*.png binary", &render_section(&[])).expect("valid input");
        assert!(out.starts_with("*.png binary\n"));
    }

    #[test]
    fn replacing_the_section_is_idempotent() {
        let first = upsert("# mine\n", &render_section(&[])).expect("valid input");
        let second = upsert(&first, &render_section(&[])).expect("valid input");
        assert_eq!(first, second, "a second pass must not change the file");
    }

    #[test]
    fn user_content_around_the_section_survives() {
        let original =
            upsert("# above\n", &render_section(&[])).expect("valid input") + "# below\n";
        let updated =
            upsert(&original, &render_section(&["*.env -text".into()])).expect("valid input");

        assert!(updated.starts_with("# above\n"));
        assert!(updated.ends_with("# below\n"));
        assert!(updated.contains("*.env -text"));
    }

    #[test]
    fn an_unclosed_section_is_refused() {
        let broken = format!("{BEGIN}\n{CATCH_ALL}\n");
        assert!(upsert(&broken, &render_section(&[])).is_err());
    }

    #[test]
    fn a_stray_closing_marker_is_refused() {
        let broken = format!("# mine\n{END}\n");
        assert!(upsert(&broken, &render_section(&[])).is_err());
    }

    /// Parses a `.git-xcrypt` body and renders the cosmetic lines from it.
    fn lines(config: &str) -> Vec<String> {
        render_lines(&Config::parse(config).expect("the test configuration must parse"))
    }

    #[test]
    fn a_directory_pattern_covers_the_subtree_at_any_depth() {
        // Two mistakes are possible here and both were made once. A trailing
        // slash matches nothing in `.gitattributes`, so the subtree needs
        // `/**`; and `secrets/**` carries a slash, which anchors it to the root,
        // while `.gitignore`'s `secrets/` floats. The filter encrypts
        // `app/secrets/x`, so the line has to reach it.
        assert_eq!(lines("secrets/\n"), ["**/secrets/** -text diff=git-xcrypt"]);
    }

    #[test]
    fn a_file_pattern_also_covers_a_directory_of_that_name() {
        // `*.env` matches a directory called `a.env` in `.gitignore`, and this
        // tool encrypts everything under a matched directory, so the attributes
        // have to follow it there.
        assert_eq!(
            lines("*.env\n"),
            [
                "*.env -text diff=git-xcrypt",
                "**/*.env/** -text diff=git-xcrypt"
            ]
        );
    }

    #[test]
    fn binary_drops_the_diff_driver() {
        // `-diff` is written out, not merely left off: measured on git 2.55, a
        // later line overrides only the attributes it names, so a bare
        // `secrets/key.p12 -text` under a `secrets/**` line would keep the diff
        // driver the broader line set.
        assert_eq!(
            lines("secrets/key.p12 binary\n"),
            [
                "secrets/key.p12 -text -diff",
                "secrets/key.p12/** -text -diff"
            ]
        );
        assert_eq!(
            lines("secrets/key.p12 -text\n"),
            [
                "secrets/key.p12 -text diff=git-xcrypt",
                "secrets/key.p12/** -text diff=git-xcrypt"
            ],
            "-text alone is not the `binary` macro; only `binary` drops diff"
        );
    }

    #[test]
    fn a_line_that_takes_something_away_is_rendered_below_every_line_that_grants_it() {
        // git takes the last matching line, `Config::decide` merges them all, so
        // a `binary` pattern written above a broader one would otherwise have
        // its `-diff` overruled by the broader line's `diff=git-xcrypt`.
        assert_eq!(
            lines("secrets/key.p12 binary\nsecrets/\n"),
            [
                "**/secrets/** -text diff=git-xcrypt",
                "secrets/key.p12 -text -diff",
                "secrets/key.p12/** -text -diff",
            ]
        );
    }

    #[test]
    fn a_negation_restores_gits_defaults_for_the_path() {
        // Dropping the negated pattern would leave `-text` on a file that is
        // stored in the clear, so git would stop managing its line endings. The
        // line has to come last, because git takes the last match.
        assert_eq!(
            lines("secrets/\n!secrets/README.md\n"),
            [
                "**/secrets/** -text diff=git-xcrypt",
                "secrets/README.md !text !diff",
                "secrets/README.md/** !text !diff",
            ]
        );
    }

    #[test]
    fn a_leading_slash_is_kept_because_it_anchors() {
        // Dropping it would turn `/build.env` into `build.env`, which floats to
        // every subdirectory — `-text` applied to files that are not encrypted.
        assert_eq!(
            lines("/deploy/id_rsa\n"),
            [
                "/deploy/id_rsa -text diff=git-xcrypt",
                "/deploy/id_rsa/** -text diff=git-xcrypt"
            ]
        );
    }

    #[test]
    fn a_pattern_with_a_space_is_c_quoted() {
        // `.gitattributes` ends a pattern at the first blank unless the whole
        // pattern is quoted; the `\ ` escape `.gitignore` uses means nothing
        // there, so the line would parse as a pattern plus a stray attribute.
        assert_eq!(
            lines("docs/READ\\ ME.md\n"),
            [
                "\"docs/READ ME.md\" -text diff=git-xcrypt",
                "\"docs/READ ME.md/**\" -text diff=git-xcrypt"
            ]
        );
    }

    #[test]
    fn a_pattern_opening_with_attr_is_quoted_so_git_reads_it_as_a_pattern() {
        // Measured on git 2.55: `[attr]foo …` defines a macro named `foo` and
        // applies to nothing at all. The macro check runs before the quoting
        // one, so quoting is what keeps it a pattern.
        assert_eq!(
            lines("[attr]x\n"),
            [
                "\"[attr]x\" -text diff=git-xcrypt",
                // The subtree spelling opens with `**/`, so git never reaches
                // its macro branch and the quotes would be noise.
                "**/[attr]x/** -text diff=git-xcrypt"
            ]
        );
    }

    #[test]
    fn a_wildmatch_escape_survives_translation() {
        assert_eq!(
            lines("secrets/a\\*b\n")[0],
            "secrets/a\\*b -text diff=git-xcrypt",
            "only the whitespace escape differs between the two syntaxes"
        );
        assert_eq!(
            lines("secrets/a\\*b\\ c\n")[0],
            "\"secrets/a\\\\*b c\" -text diff=git-xcrypt",
            "inside C quotes the backslash has to be doubled to survive unquoting"
        );
    }

    #[test]
    fn a_repeated_pattern_collapses_into_one_line() {
        // git resolves attributes by last match, we resolve them by merging, so
        // two lines for one pattern would disagree with the filter's own answer.
        assert_eq!(
            lines("secrets/key.p12 binary\nsecrets/key.p12 eol=lf\n"),
            [
                "secrets/key.p12 -text -diff",
                "secrets/key.p12/** -text -diff"
            ]
        );
    }

    #[test]
    fn the_order_of_the_config_is_the_order_of_the_section() {
        assert_eq!(
            lines("*.env\nsecrets/\n*.pem\n"),
            [
                "*.env -text diff=git-xcrypt",
                "**/*.env/** -text diff=git-xcrypt",
                "**/secrets/** -text diff=git-xcrypt",
                "*.pem -text diff=git-xcrypt",
                "**/*.pem/** -text diff=git-xcrypt"
            ]
        );
    }

    #[test]
    fn a_marker_inside_a_user_comment_is_not_taken_for_the_section() {
        // Substring matching used to start the section at this comment, so the
        // next write replaced everything from there down.
        let original = format!("{BEGIN} (legacy, do not remove)\n# mine\n");
        let updated = upsert(&original, &render_section(&[])).expect("valid input");

        assert!(
            updated.starts_with(&original),
            "the user's own lines were swallowed by the section"
        );
        assert!(updated.contains(CATCH_ALL));
    }

    #[test]
    fn rendering_the_lines_twice_gives_the_same_file() {
        let config = Config::parse("secrets/\n*.env\n").expect("valid configuration");
        let section = render_section(&render_lines(&config));
        let first = upsert("# mine\n", &section).expect("valid input");
        let second = upsert(&first, &section).expect("valid input");
        assert_eq!(first, second, "a second pass must not change the file");
    }

    #[test]
    fn user_content_survives_a_section_that_gained_lines() {
        let original =
            upsert("# above\n", &render_section(&[])).expect("valid input") + "# below\n";
        let config = Config::parse("secrets/\n").expect("valid configuration");
        let updated =
            upsert(&original, &render_section(&render_lines(&config))).expect("valid input");

        assert!(updated.starts_with("# above\n"));
        assert!(updated.ends_with("# below\n"));
        assert!(updated.contains("**/secrets/** -text diff=git-xcrypt"));
    }

    #[test]
    fn broken_markers_report_the_configuration_exit_code() {
        // Guessing where the section ends would destroy the user's own
        // attributes, so the refusal has to reach the shell as code 2.
        let broken = format!("{BEGIN}\n{CATCH_ALL}\n");
        let error = upsert(&broken, &render_section(&[])).expect_err("must refuse");
        assert_eq!(error.exit_code(), crate::exit::CONFIG);
    }

    #[test]
    fn the_catch_all_line_names_no_pattern_from_the_config() {
        // If this line ever depended on `.git-xcrypt`, the drift this design
        // removes would come straight back.
        assert_eq!(CATCH_ALL, "* filter=git-xcrypt");
        assert!(has_section(&render_section(&[])));
    }
}
