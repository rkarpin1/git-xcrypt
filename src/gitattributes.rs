//! The managed section of `.gitattributes`.
//!
//! The section holds one static line, `* filter=git-xcrypt`, and the whole
//! security guarantee rests on it. It does not depend on the contents of
//! `.git-xcrypt`, so it cannot drift from it — that is the entire point of the
//! catch-all construction. Per-pattern `-text` and `diff` lines are cosmetic and
//! arrive in S-02.

use std::fs;
use std::path::Path;

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

    #[test]
    fn the_catch_all_line_names_no_pattern_from_the_config() {
        // If this line ever depended on `.git-xcrypt`, the drift this design
        // removes would come straight back.
        assert_eq!(CATCH_ALL, "* filter=git-xcrypt");
        assert!(has_section(&render_section(&[])));
    }
}
