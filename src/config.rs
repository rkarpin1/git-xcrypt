//! The `.git-xcrypt` file: which paths are encrypted, and how line endings are
//! handled.
//!
//! Patterns use `.gitignore` syntax and are matched by `gix-glob`, so the
//! semantics are git's own rather than an imitation of them. Attributes use the
//! `.gitattributes` vocabulary. The two resolve on **independent axes**, exactly
//! as git splits them across two files:
//!
//! * selection — last matching line wins, `!` turns a path off;
//! * attributes — a later line overrides only the attributes it names, a line
//!   with no attributes changes nothing.
//!
//! That separation is what stops a broad pattern added below a narrow
//! declaration from silently erasing it.

use bstr::{BStr, ByteSlice};
use gix_glob::pattern::Case;
use gix_glob::{Pattern, wildmatch};

use crate::repo::{ATTRIBUTES_FILE, CONFIG_FILE, KEY_ENVELOPE_DIR};
use crate::{Error, Result};

/// How a path's content is treated before encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextMode {
    /// Decide from the content, as git's `text=auto` does. The default.
    #[default]
    Auto,
    /// Always normalise to LF before encrypting.
    Text,
    /// Never convert. Covers both `-text` and `binary`.
    Binary,
}

/// Which line ending the smudge path writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EolMode {
    /// Always LF.
    Lf,
    /// Always CRLF.
    Crlf,
    /// Whatever the platform uses.
    Native,
}

/// The attributes one line declares. `None` means "this line says nothing".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Declared {
    text: Option<TextMode>,
    eol: Option<EolMode>,
    suppress_diff: bool,
}

/// What the file says about one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Whether this path is encrypted at all.
    pub encrypt: bool,
    /// How its content is treated before encryption.
    pub text: TextMode,
    /// An explicit line ending for the smudge path, if one was declared.
    pub eol: Option<EolMode>,
    /// Whether `binary` asked for the diff driver to be left off.
    pub suppress_diff: bool,
}

impl Default for Decision {
    fn default() -> Self {
        Self {
            encrypt: false,
            text: TextMode::Auto,
            eol: None,
            suppress_diff: false,
        }
    }
}

/// One line of the file.
#[derive(Debug)]
struct Rule {
    pattern: Pattern,
    /// The pattern text as written, for rendering `.gitattributes` in S-02.
    source: String,
    declared: Declared,
}

/// A parsed `.git-xcrypt`.
#[derive(Debug, Default)]
pub struct Config {
    rules: Vec<Rule>,
    /// Lines that carry `eol=` on a path that is never converted.
    ///
    /// Pointless rather than dangerous — git itself lets `-text` win over `eol` —
    /// so it is a warning the caller prints once, not an error.
    pub pointless_eol: Vec<String>,
    /// The file was not on disk at all.
    ///
    /// Kept rather than turned into an error at load time because the two filter
    /// directions need opposite answers: check-in must refuse, since "no
    /// declaration" is indistinguishable from "the declaration has not been
    /// checked out yet" and guessing wrong writes a secret in the clear;
    /// check-out must carry on, because a file's own header already says
    /// everything smudge needs and git gives no order in which it writes the
    /// working tree.
    pub missing: bool,
}

impl Config {
    /// Parses the contents of a `.git-xcrypt` file.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for an unknown attribute, an attribute on a negation, or
    /// a pattern `gix-glob` refuses. Fail closed: a file we do not fully
    /// understand must stop the operation, not be half-applied.
    pub fn parse(text: &str) -> Result<Self> {
        let mut config = Self::default();

        for (number, line) in text.lines().enumerate() {
            // Deliberately not trimmed: `split_pattern` is the only thing that
            // understands the `\ ` escape, so trimming first would eat the
            // escaped trailing space and make a pattern like
            // `!secrets/README.md\ ` unwritable — the exact complement of the
            // pathnames the filter now matches correctly.
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }

            let (pattern_text, attribute_text) = split_pattern(line);
            let declared = parse_attributes(attribute_text, number + 1)?;

            let negated = pattern_text.starts_with('!');
            if negated && declared != Declared::default() {
                return Err(Error::Config(format!(
                    "{CONFIG_FILE}:{}: a negated pattern cannot carry attributes — \
                     the path is not encrypted, so there is nothing to convert",
                    number + 1
                )));
            }

            let pattern = Pattern::from_bytes(pattern_text.as_bytes()).ok_or_else(|| {
                Error::Config(format!(
                    "{CONFIG_FILE}:{}: `{pattern_text}` is not a usable pattern",
                    number + 1
                ))
            })?;

            if declared.eol.is_some() && declared.text == Some(TextMode::Binary) {
                config.pointless_eol.push(format!(
                    "{CONFIG_FILE}:{}: `eol=` has no effect on a path that is never \
                     converted; git lets -text win over eol too",
                    number + 1
                ));
            }

            config.rules.push(Rule {
                pattern,
                source: pattern_text.to_string(),
                declared,
            });
        }

        Ok(config)
    }

    /// Reads and parses the file at `path`, recording an absent file as such.
    ///
    /// An unreadable file is an error here and an absent one is flagged, because
    /// neither may end up meaning "encrypt nothing" on the check-in path.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the file exists but cannot be read, [`Error::Config`]
    /// when it cannot be understood.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                missing: true,
                ..Self::default()
            }),
            Err(err) => Err(Error::Io(err)),
        }
    }

    /// The patterns a negation takes back out, in file order, without the `!`.
    ///
    /// Rendered into `.gitattributes` as `!text !diff`, which restores git's
    /// defaults for those paths. Leaving them out instead would keep `-text` on
    /// a file that is stored in the clear, so git would stop managing its line
    /// endings — the very direction the attributes exist to control.
    #[must_use]
    pub fn negated_patterns(&self) -> Vec<&str> {
        self.rules
            .iter()
            .filter(|rule| rule.pattern.is_negative())
            .filter_map(|rule| rule.source.strip_prefix('!'))
            .collect()
    }

    /// The patterns that select paths, in file order.
    ///
    /// Used to render the per-pattern `.gitattributes` lines.
    #[must_use]
    pub fn selecting_patterns(&self) -> Vec<(&str, Decision)> {
        self.rules
            .iter()
            .filter(|rule| !rule.pattern.is_negative())
            .map(|rule| {
                (
                    rule.source.as_str(),
                    Decision {
                        encrypt: true,
                        text: rule.declared.text.unwrap_or_default(),
                        eol: rule.declared.eol,
                        suppress_diff: rule.declared.suppress_diff,
                    },
                )
            })
            .collect()
    }

    /// What this configuration says about `path`, given relative to the root.
    ///
    /// The path is bytes, not text: on Unix a path is an arbitrary byte string,
    /// and lossy decoding would match a file under a name it does not have —
    /// which in the pass-through direction means storing a secret in the clear.
    #[must_use]
    pub fn decide(&self, path: &[u8]) -> Decision {
        if is_never_encrypted(path) {
            return Decision::default();
        }

        let mut decision = Decision::default();
        let mut selected = false;

        for rule in &self.rules {
            if !matches(&rule.pattern, path) {
                continue;
            }

            // Selection: last match wins, including a negation turning it off.
            selected = !rule.pattern.is_negative();

            // Attributes: only what this line names, so a broad selection
            // pattern below a narrow declaration does not erase it.
            if let Some(text) = rule.declared.text {
                decision.text = text;
            }
            if let Some(eol) = rule.declared.eol {
                decision.eol = Some(eol);
            }
            if rule.declared.suppress_diff {
                decision.suppress_diff = true;
            }
        }

        decision.encrypt = selected;
        decision
    }
}

/// Paths that are never encrypted, whatever the patterns say.
///
/// They are needed to bootstrap: git reads `.gitattributes` to know to call us
/// at all, we read `.git-xcrypt` to know what to do, and the envelope directory
/// must stay readable to whoever holds a recipient key. Public because the
/// check-in path consults it before anything else, including before refusing on
/// a missing `.git-xcrypt` — otherwise a user who deleted the file could not
/// commit its replacement.
#[must_use]
pub fn is_never_encrypted(path: &[u8]) -> bool {
    // `.gitattributes` is matched by basename, not by root path: git reads one
    // per directory, so encrypting `sub/.gitattributes` would leave git unable
    // to read the attributes for that whole subtree. `.git-xcrypt` is read only
    // from the root, so there the root path is the right test.
    let basename = path.rsplit_str("/").next().unwrap_or(path);

    // No `format!` here: this runs once per file in the repository, and the
    // allocation bought nothing that `strip_prefix` does not.
    basename == ATTRIBUTES_FILE.as_bytes()
        || path == CONFIG_FILE.as_bytes()
        || path == KEY_ENVELOPE_DIR.as_bytes()
        || path
            .strip_prefix(KEY_ENVELOPE_DIR.as_bytes())
            .is_some_and(|rest| rest.starts_with(b"/"))
}

/// Splits a line into its pattern and its attributes.
///
/// Whitespace separates the two, so a pattern containing a space must escape it
/// as `\ ` — the same escape `.gitignore` already uses for a trailing space.
fn split_pattern(line: &str) -> (&str, &str) {
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes[index].is_ascii_whitespace() {
            return (&line[..index], line[index..].trim_start());
        }
        index += 1;
    }
    (line, "")
}

/// Parses the attribute tokens following a pattern.
fn parse_attributes(text: &str, line: usize) -> Result<Declared> {
    let mut declared = Declared::default();

    for token in text.split_whitespace() {
        match token {
            "text" => declared.text = Some(TextMode::Text),
            "-text" => declared.text = Some(TextMode::Binary),
            "text=auto" => declared.text = Some(TextMode::Auto),
            "binary" => {
                declared.text = Some(TextMode::Binary);
                declared.suppress_diff = true;
            }
            "eol=lf" => declared.eol = Some(EolMode::Lf),
            "eol=crlf" => declared.eol = Some(EolMode::Crlf),
            "eol=native" => declared.eol = Some(EolMode::Native),
            other => {
                return Err(Error::Config(format!(
                    "{CONFIG_FILE}:{line}: unknown attribute `{other}`; \
                     expected one of text, -text, binary, text=auto, \
                     eol=lf, eol=crlf, eol=native"
                )));
            }
        }
    }

    Ok(declared)
}

/// Whether `pattern` matches `path`, honouring directory patterns.
///
/// A pattern written as `secrets/` only matches a directory, so git also treats
/// everything beneath it as matched. `gix-glob` answers about one path at a
/// time, so the ancestors are offered to it explicitly.
fn matches(pattern: &Pattern, path: &[u8]) -> bool {
    if match_one(pattern, path, false) {
        return true;
    }

    for (index, byte) in path.iter().enumerate() {
        if *byte == b'/' && match_one(pattern, &path[..index], true) {
            return true;
        }
    }
    false
}

/// One `gix-glob` question.
fn match_one(pattern: &Pattern, path: &[u8], is_dir: bool) -> bool {
    let bytes: &BStr = path.as_bstr();
    let basename_start = path.rfind_byte(b'/').map(|index| index + 1);
    pattern.matches_repo_relative_path(
        bytes,
        basename_start,
        Some(is_dir),
        Case::Sensitive,
        wildmatch::Mode::NO_MATCH_SLASH_LITERAL,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        Config::parse(text).expect("the test configuration must parse")
    }

    #[test]
    fn a_directory_pattern_covers_everything_beneath_it() {
        let config = config("secrets/\n");
        assert!(config.decide(b"secrets/a/b.txt").encrypt);
        assert!(config.decide(b"secrets/one.env").encrypt);
        assert!(!config.decide(b"public/one.env").encrypt);
    }

    #[test]
    fn a_glob_does_not_cross_a_slash_but_a_double_star_does() {
        let config = config("*.env\nlogs/**/*.key\n");
        assert!(config.decide(b"one.env").encrypt);
        assert!(
            config.decide(b"nested/one.env").encrypt,
            "gitignore globs float"
        );
        assert!(config.decide(b"logs/a/b/x.key").encrypt);
    }

    #[test]
    fn a_leading_slash_anchors_to_the_root() {
        let config = config("/deploy/id_rsa\n");
        assert!(config.decide(b"deploy/id_rsa").encrypt);
        assert!(!config.decide(b"nested/deploy/id_rsa").encrypt);
    }

    #[test]
    fn a_negation_turns_a_path_back_off() {
        let config = config("secrets/\n!secrets/README.md\n");
        assert!(config.decide(b"secrets/password").encrypt);
        assert!(!config.decide(b"secrets/README.md").encrypt);
    }

    #[test]
    fn the_last_selecting_line_wins() {
        let config = config("!secrets/README.md\nsecrets/\n");
        assert!(
            config.decide(b"secrets/README.md").encrypt,
            "a later selection must override an earlier negation"
        );
    }

    #[test]
    fn a_broad_pattern_without_attributes_does_not_erase_a_narrow_declaration() {
        // This is the whole point of resolving on two axes.
        let config = config("*.env text\nsecrets/\n");
        let decision = config.decide(b"secrets/a.env");
        assert!(decision.encrypt);
        assert_eq!(decision.text, TextMode::Text);
    }

    #[test]
    fn a_later_declaration_overrides_only_what_it_names() {
        let config = config("secrets/ text eol=lf\nsecrets/*.sh eol=crlf\n");
        let decision = config.decide(b"secrets/deploy.sh");
        assert_eq!(decision.text, TextMode::Text, "text was not re-declared");
        assert_eq!(decision.eol, Some(EolMode::Crlf));
    }

    #[test]
    fn the_default_is_auto_detection() {
        let config = config("secrets/\n");
        assert_eq!(config.decide(b"secrets/x").text, TextMode::Auto);
        assert_eq!(config.decide(b"secrets/x").eol, None);
    }

    #[test]
    fn binary_is_minus_text_plus_no_diff() {
        let config = config("secrets/key.p12 binary\n");
        let decision = config.decide(b"secrets/key.p12");
        assert_eq!(decision.text, TextMode::Binary);
        assert!(decision.suppress_diff);
    }

    #[test]
    fn bootstrap_files_are_never_encrypted() {
        let config = config("*\n");
        for path in [
            ATTRIBUTES_FILE,
            // Git reads one .gitattributes per directory; encrypting a nested
            // one would blind it for that whole subtree.
            "sub/dir/.gitattributes",
            CONFIG_FILE,
            "\u{2e}git-xcrypt-keys/robert.age",
        ] {
            assert!(
                !config.decide(path.as_bytes()).encrypt,
                "{path} must never be encrypted; it is needed to bootstrap"
            );
        }
        assert!(config.decide(b"anything-else").encrypt);
    }

    #[test]
    fn an_unknown_attribute_is_refused() {
        assert!(Config::parse("*.env sparkly\n").is_err());
    }

    #[test]
    fn attributes_on_a_negation_are_refused() {
        assert!(Config::parse("secrets/\n!secrets/README.md text\n").is_err());
    }

    #[test]
    fn a_pattern_can_end_in_an_escaped_space() {
        // The complement of the pathname fix: the filter matches
        // `secrets/README.md ` correctly, so the declaration has to be able to
        // name it. Trimming the line before `split_pattern` ate the escape.
        let config = config("secrets/\n!secrets/README.md\\ \n");
        assert!(config.decide(b"secrets/password").encrypt);
        assert!(
            !config.decide(b"secrets/README.md ").encrypt,
            "the negation with an escaped trailing space did not take effect"
        );
        assert!(
            config.decide(b"secrets/README.md").encrypt,
            "and it must not spill onto the name without the space"
        );
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let config = config("# a comment\n\n   \n*.env\n");
        assert!(config.decide(b"one.env").encrypt);
    }

    #[test]
    fn eol_on_a_binary_path_is_reported_as_pointless_not_fatal() {
        let config = config("secrets/key.p12 -text eol=lf\n");
        assert_eq!(config.pointless_eol.len(), 1);
        assert!(config.decide(b"secrets/key.p12").encrypt);
    }

    #[test]
    fn an_empty_configuration_encrypts_nothing() {
        let config = Config::default();
        assert!(!config.decide(b"secrets/anything").encrypt);
    }

    #[test]
    fn selecting_patterns_skip_negations() {
        let config = config("secrets/\n*.env text\n!secrets/README.md\n");
        let patterns: Vec<&str> = config
            .selecting_patterns()
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        assert_eq!(patterns, vec!["secrets/", "*.env"]);
    }
}
