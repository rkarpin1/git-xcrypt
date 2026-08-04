//! The managed section of `.gitattributes`.
//!
//! The section holds one static line, `* filter=git-xcrypt`, and the whole
//! security guarantee rests on it. It does not depend on the contents of
//! `.git-xcrypt`, so it cannot drift from it — that is the entire point of the
//! catch-all construction.
//!
//! Everything below that line is **cosmetic**: `-text` keeps git's own CRLF
//! machinery off the ciphertext, `diff=git-xcrypt` points `git diff` at the
//! plaintext. Letting them go stale costs a worse diff, never a secret — which
//! is why translating `.gitignore` patterns into `.gitattributes` spelling is
//! allowed to be an approximation, and why the approximation errs narrow: a line
//! that is too broad would turn git's line-ending conversion off for files that
//! are not encrypted at all.

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

/// Renders the cosmetic per-pattern lines for `config`, in file order.
///
/// One line per selecting pattern: `<pattern> -text diff=git-xcrypt`, or
/// `<pattern> -text` when the pattern was declared `binary` — git's own `binary`
/// macro means `-text -diff`, and we reproduce it. Negations are left out
/// entirely: git ignores a leading `!` in `.gitattributes` and says so on
/// stderr, so rendering one would be noise at best.
///
/// The order is the order of `.git-xcrypt`, so the output is a pure function of
/// the input and two runs produce the same file.
#[must_use]
pub fn render_lines(config: &Config) -> Vec<String> {
    // A pattern may appear on several lines; git resolves attributes by last
    // match, we resolve them by merging, so the two would disagree about
    // `binary` unless a repeated pattern collapses into one line here.
    let mut patterns: Vec<(String, bool)> = Vec::new();

    for (source, decision) in config.selecting_patterns() {
        let Some(translated) = translate(source) else {
            continue;
        };
        match patterns
            .iter_mut()
            .find(|(existing, _)| *existing == translated)
        {
            Some((_, suppress_diff)) => *suppress_diff |= decision.suppress_diff,
            None => patterns.push((translated, decision.suppress_diff)),
        }
    }

    patterns
        .into_iter()
        .map(|(pattern, suppress_diff)| {
            if suppress_diff {
                format!("{pattern} -text")
            } else {
                format!("{pattern} -text diff={DRIVER}")
            }
        })
        .collect()
}

/// Spells one `.git-xcrypt` pattern the way `.gitattributes` needs it.
///
/// Three differences between the two syntaxes matter, all measured against git
/// 2.55:
///
/// * a trailing `/` matches a directory in `.gitignore` and **nothing at all**
///   in `.gitattributes`, so `secrets/` becomes `secrets/**`;
/// * a leading `/` is kept. It anchors in both files, and dropping it would let
///   `/build.env` float to every subdirectory — an attribute applied to files
///   that are not encrypted, which is the one direction of error that has a
///   cost;
/// * whitespace ends a pattern in `.gitattributes` unless the whole pattern is
///   C-quoted; the `\ ` escape `.gitignore` uses is not understood there.
///
/// Returns `None` for a pattern with nothing left to render.
///
/// Known approximation, in the harmless direction: a bare `secrets` covers the
/// directory and everything under it in `.gitignore`, while `.gitattributes`
/// applies it to the file of that name only. The subtree still gets encrypted —
/// the filter matches on `.git-xcrypt` alone — it just misses the cosmetic
/// attributes. Write `secrets/` to get them.
fn translate(pattern: &str) -> Option<String> {
    let expanded = match pattern.strip_suffix('/') {
        Some(directory) if !directory.is_empty() => format!("{directory}/**"),
        Some(_) => return None,
        None => pattern.to_string(),
    };
    if expanded.is_empty() {
        return None;
    }

    // Undo only the escape that the two syntaxes disagree about. Every other
    // backslash is wildmatch's, and wildmatch is the same engine on both sides.
    let mut plain = String::with_capacity(expanded.len());
    let mut characters = expanded.chars();
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

    // A leading quote would send git into its C-quoting parser mid-pattern.
    if !plain.contains(char::is_whitespace) && !plain.starts_with('"') {
        return Some(plain);
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
    Some(quoted)
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

/// Whether `contents` already carries a managed section.
#[must_use]
pub fn has_section(contents: &str) -> bool {
    contents.contains(BEGIN)
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
    let Some(begin) = contents.find(BEGIN) else {
        if contents.contains(END) {
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

    let Some(end) = contents[begin..].find(END) else {
        return Err(Error::Config(format!(
            "{ATTRIBUTES}: the git-xcrypt section is opened but never closed; \
             fix it by hand so nothing of yours is lost",
            ATTRIBUTES = crate::repo::ATTRIBUTES_FILE
        )));
    };

    let end = begin + end + END.len();
    // Swallow the newline that terminated the closing marker so replacing the
    // section repeatedly does not accumulate blank lines.
    let tail_start = if contents[end..].starts_with('\n') {
        end + 1
    } else {
        end
    };

    let mut out = String::with_capacity(contents.len() + section.len());
    out.push_str(&contents[..begin]);
    out.push_str(section);
    out.push_str(&contents[tail_start..]);
    Ok(out)
}

/// Writes the managed section into the attributes file at `path`.
///
/// # Errors
///
/// [`Error::Io`] on a read or write failure, [`Error::Config`] on unbalanced
/// markers.
pub fn write_section(path: &Path, extra_lines: &[String]) -> Result<bool> {
    let existing = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(Error::Io(err)),
    };

    let updated = upsert(&existing, &render_section(extra_lines))?;
    if updated == existing {
        return Ok(false);
    }
    fs::write(path, updated)?;
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
    fn a_directory_pattern_gains_the_double_star_git_needs() {
        // Measured on git 2.55: a trailing slash in `.gitattributes` matches
        // nothing, so the line would be silently dead without this.
        assert_eq!(lines("secrets/\n"), ["secrets/** -text diff=git-xcrypt"]);
    }

    #[test]
    fn binary_drops_the_diff_driver() {
        assert_eq!(lines("secrets/key.p12 binary\n"), ["secrets/key.p12 -text"]);
        assert_eq!(
            lines("secrets/key.p12 -text\n"),
            ["secrets/key.p12 -text diff=git-xcrypt"],
            "-text alone is not the `binary` macro; only `binary` drops diff"
        );
    }

    #[test]
    fn negations_are_left_out() {
        assert_eq!(
            lines("secrets/\n!secrets/README.md\n"),
            ["secrets/** -text diff=git-xcrypt"]
        );
    }

    #[test]
    fn a_leading_slash_is_kept_because_it_anchors() {
        // Dropping it would turn `/build.env` into `build.env`, which floats to
        // every subdirectory — `-text` applied to files that are not encrypted.
        assert_eq!(
            lines("/deploy/id_rsa\n/build.env\n"),
            [
                "/deploy/id_rsa -text diff=git-xcrypt",
                "/build.env -text diff=git-xcrypt"
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
            ["\"docs/READ ME.md\" -text diff=git-xcrypt"]
        );
    }

    #[test]
    fn a_wildmatch_escape_survives_translation() {
        assert_eq!(
            lines("secrets/a\\*b\n"),
            ["secrets/a\\*b -text diff=git-xcrypt"],
            "only the whitespace escape differs between the two syntaxes"
        );
        assert_eq!(
            lines("secrets/a\\*b\\ c\n"),
            ["\"secrets/a\\\\*b c\" -text diff=git-xcrypt"],
            "inside C quotes the backslash has to be doubled to survive unquoting"
        );
    }

    #[test]
    fn a_repeated_pattern_collapses_into_one_line() {
        // git resolves attributes by last match, we resolve them by merging, so
        // two lines for one pattern would disagree with the filter's own answer.
        assert_eq!(
            lines("secrets/key.p12 binary\nsecrets/key.p12 eol=lf\n"),
            ["secrets/key.p12 -text"]
        );
    }

    #[test]
    fn the_order_of_the_config_is_the_order_of_the_section() {
        assert_eq!(
            lines("*.env\nsecrets/\n*.pem\n"),
            [
                "*.env -text diff=git-xcrypt",
                "secrets/** -text diff=git-xcrypt",
                "*.pem -text diff=git-xcrypt"
            ]
        );
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
        assert!(updated.contains("secrets/** -text diff=git-xcrypt"));
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
