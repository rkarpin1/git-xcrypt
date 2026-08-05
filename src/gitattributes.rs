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
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::repo::{ATTRIBUTES_FILE, CONFIG_FILE, DRIVER, KEY_ENVELOPE_DIR, git_spelling};
use crate::{Error, Result};

/// Opens the section this tool owns.
const BEGIN: &str = "# >>> git-xcrypt >>>";

/// Closes it. Everything outside the pair belongs to the user.
const END: &str = "# <<< git-xcrypt <<<";

/// The line the filter actually hangs on.
///
/// Static by design: it names no pattern, so changing `.git-xcrypt` never makes
/// it stale. The filter is invoked for every file and decides for itself.
/// The one line the whole guarantee hangs on. Public so `lock` can check for
/// it without guessing at its spelling: git reads a missing attribute exactly
/// as it reads a missing driver, as no filter at all.
pub const CATCH_ALL: &str = "* filter=git-xcrypt";

/// Renders the per-pattern lines for `config`.
///
/// An encrypted path gets `-text diff=git-xcrypt`; a path a negation took back
/// out gets `!text !diff`, which restores git's defaults for it. Leaving the
/// negation unrendered would keep `-text` on a file that is stored in the clear,
/// so git would stop managing its line endings.
///
/// Two resolution rules have to be reconciled, and each one dictates part of the
/// layout:
///
/// * **Selection is last match, in both.** git takes the last matching line and
///   so does [`Config::decide`], so the two kinds of line are emitted strictly
///   in the order of `.git-xcrypt`. Grouping them by kind — negations last, as
///   an earlier version did — silently inverted `!secrets/README.md` written
///   *above* `secrets/`, leaving an encrypted file without `-text`.
/// * **`binary` is sticky in [`Config::decide`] and positional in git.** A
///   declaration anywhere suppresses the diff driver for the path, so those
///   patterns get a trailing `-diff` line: last, and naming only `diff`, so the
///   `-text` established above it survives.
///
/// Finally, the files needed to bootstrap — see [`crate::config::is_never_encrypted`] —
/// get their defaults back if any pattern reached them, because they are stored
/// in the clear whatever the patterns say.
///
/// Within each group the order is the input's, so the section is a pure function
/// of the configuration and two runs produce the same file.
#[must_use]
pub fn render_lines(config: &Config) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut suppressed: Vec<String> = Vec::new();

    for pattern in config.patterns() {
        for spelling in translate(pattern.source) {
            if pattern.negated {
                lines.push(format!("{spelling} !text !diff"));
            } else {
                lines.push(format!("{spelling} -text diff={DRIVER}"));
                if pattern.suppress_diff && !suppressed.contains(&spelling) {
                    suppressed.push(spelling);
                }
            }
        }
    }

    // A repeated line is noise, but only the *last* copy may be kept: an earlier
    // one could otherwise outlive a line between them that says the opposite.
    let mut seen: Vec<&String> = Vec::new();
    let mut deduplicated: Vec<String> = Vec::new();
    for line in lines.iter().rev() {
        if !seen.contains(&line) {
            seen.push(line);
            deduplicated.push(line.clone());
        }
    }
    deduplicated.reverse();

    deduplicated.extend(
        suppressed
            .into_iter()
            .map(|pattern| format!("{pattern} -diff")),
    );
    deduplicated.extend(bootstrap_exclusions(config));
    deduplicated
}

/// Lines putting git's defaults back on the files that bootstrap the tool.
///
/// `.gitattributes`, `.git-xcrypt` and the envelope directory are never
/// encrypted, whatever the patterns say — git needs the first to know to call us
/// at all. A pattern broad enough to name them would otherwise leave `-text` on
/// a file that is stored in the clear, and point a decrypting diff driver at it
/// once S-05 registers one. The lines are emitted only when a pattern actually
/// reaches them, so an ordinary configuration never carries them.
fn bootstrap_exclusions(config: &Config) -> Vec<String> {
    let mut lines = Vec::new();

    // `.gitattributes` is excluded by basename at any depth, the other two only
    // where they are read from.
    let reached = |path: &str| config.decide_ignoring_exclusions(path.as_bytes()).encrypt;

    if reached(ATTRIBUTES_FILE) || reached(&format!("sub/{ATTRIBUTES_FILE}")) {
        lines.push(format!("**/{ATTRIBUTES_FILE} !text !diff"));
    }
    if reached(CONFIG_FILE) {
        lines.push(format!("/{CONFIG_FILE} !text !diff"));
    }
    if reached(&format!("{KEY_ENVELOPE_DIR}/recipient")) {
        lines.push(format!("/{KEY_ENVELOPE_DIR}/** !text !diff"));
    }
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
/// C-quoted; the `\ ` escape `.gitignore` uses is not understood there.
///
/// A line opening with `[attr]` is a macro definition to git, never a pattern.
/// Quoting does not help — measured on git 2.55, the macro check runs before the
/// unquoting — so such a pattern is given a leading `**/` or `/` instead, both
/// of which mean exactly what the unprefixed spelling meant in a root
/// `.gitattributes`.
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
        spellings.push(spell(&guard(core.to_string(), anchored)));
    }
    spellings.push(spell(&guard(
        if anchored {
            format!("{core}/**")
        } else {
            format!("**/{core}/**")
        },
        anchored,
    )));
    spellings
}

/// What git reads as the start of a macro definition rather than a pattern.
const MACRO_PREFIX: &str = "[attr]";

/// Keeps a spelling out of git's macro branch without changing what it matches.
///
/// An anchored pattern already carries a slash, so a leading one only makes
/// explicit what a root `.gitattributes` does anyway; a floating one gets the
/// `**/` that git documents as equivalent to no prefix at all.
fn guard(spelling: String, anchored: bool) -> String {
    if !spelling.starts_with(MACRO_PREFIX) {
        return spelling;
    }
    if anchored {
        format!("/{spelling}")
    } else {
        format!("**/{spelling}")
    }
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

    // A leading quote would send git into its C-quoting parser mid-pattern. A
    // leading `[attr]` is handled by `guard`, not here: git checks for a macro
    // definition before it unquotes, so quoting would not have helped.
    if !plain.contains(char::is_whitespace) && !plain.starts_with('"') {
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

    // A *second* balanced pair is refused for the same reason an unbalanced one
    // is: this function rewrites the first region and leaves the rest alone, so
    // a duplicate survives every `sync` while `sync --check` compares the result
    // against the input, finds them equal and reports "up to date". Git takes
    // the **last** matching attribute line, so the copy nobody is maintaining is
    // the one that decides — and a stale `!text` on a path the filter still
    // encrypts is the CRLF corruption this module's opening comment describes.
    // A merge conflict on `.gitattributes` resolved by keeping both sides
    // produces exactly this shape.
    let rest = &contents[begin + after_end..];
    if marker_line(rest, BEGIN).is_some() || marker_line(rest, END).is_some() {
        return Err(Error::Config(format!(
            "{ATTRIBUTES}: it carries more than one git-xcrypt section. Only the first \
             would be kept up to date, and git takes the last matching line, so the \
             stale copy would win. Delete all but one by hand, then run \
             `git-xcrypt sync`.",
            ATTRIBUTES = crate::repo::ATTRIBUTES_FILE
        )));
    }

    let mut out = String::with_capacity(contents.len() + section.len());
    out.push_str(&contents[..begin]);
    out.push_str(section);
    out.push_str(rest);
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

/// Whether the attributes file at `path` carries the catch-all line.
///
/// The one question that decides whether git invokes the filter at all, so both
/// `lock` and `status` ask it — through the same function, because two spellings
/// of "is the guarantee in place" is one too many. An absent file answers `false`
/// rather than failing: it is missing the line as surely as an empty one is.
///
/// # Errors
///
/// [`Error::Io`] when the file exists but cannot be read, [`Error::Config`] when
/// it is not text.
pub fn catch_all_present(path: &Path) -> Result<bool> {
    Ok(read(path)?.lines().any(|line| line.trim_end() == CATCH_ALL))
}

/// Lines outside the managed section that set or unset `filter`.
///
/// The catch-all is one line among many, and git takes the **last** match — so
/// a line below the managed section saying `secrets/** -filter`, or setting
/// `filter=lfs`, turns this tool off for those paths. Measured on git 2.55:
/// `git check-attr filter` then reports `unset`, `git add` stores the plaintext,
/// and `status` — which only looked for the catch-all line — called the
/// repository healthy.
///
/// Reading only. The question "does any of this actually reach a declared path"
/// is answered by [`FilterResolver`], which runs git's own attribute stack; what
/// this function contributes is the text of the offending lines, so a report can
/// show a reader what to delete instead of only telling them a path is
/// unfiltered.
///
/// # Errors
///
/// [`Error::Io`] when the file exists but cannot be read, [`Error::Config`] when
/// it is not text.
pub fn foreign_filter_lines(path: &Path) -> Result<Vec<String>> {
    let text = read(path)?;
    let mut inside = false;
    let mut found = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim_end().trim_end_matches('\r');
        if trimmed == BEGIN {
            inside = true;
            continue;
        }
        if trimmed == END {
            inside = false;
            continue;
        }
        if inside || trimmed.is_empty() || trimmed.trim_start().starts_with('#') {
            continue;
        }
        // The pattern is the first field; everything after it is attributes.
        let attributes = trimmed
            .split_once(char::is_whitespace)
            .map(|(_, rest)| rest);
        if attributes.is_some_and(|rest| {
            rest.split_whitespace().any(|token| {
                token == "filter"
                    || token == "-filter"
                    || token == "!filter"
                    || token.starts_with("filter=")
            })
        }) {
            found.push(trimmed.trim().to_string());
        }
    }
    Ok(found)
}

/// Every `.gitattributes` under `root`, `.git` excluded.
///
/// Iterative rather than recursive, for the same reason the history walk is: a
/// working tree may be arbitrarily deep and a diagnostic command must not be the
/// thing that crashes on it. Directories that will not open are skipped, exactly
/// as git skips a file it cannot read — see [`FilterResolver`].
fn collect_attribute_files(root: &Path, out: &mut Vec<PathBuf>) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            // Never followed: a symbolic link out of the working tree would walk
            // somewhere that is not this repository, and one pointing back into
            // it would loop.
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                if entry.file_name() != std::ffi::OsStr::new(".git") {
                    pending.push(entry.path());
                }
            } else if entry.file_name() == std::ffi::OsStr::new(crate::repo::ATTRIBUTES_FILE) {
                out.push(entry.path());
            }
        }
    }
}

/// What git resolves the `filter` attribute to for one path.
///
/// The spelling of each variant is `git check-attr filter`'s own, so a report can
/// quote the answer a user would get from git and the two cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAttribute {
    /// `filter=git-xcrypt` — git runs this tool for the path.
    Ours,
    /// `filter=<something else>`, `filter=lfs` being the ordinary case.
    Foreign(String),
    /// `filter` with no value. Git has no driver to run.
    Set,
    /// `-filter`. Explicitly off.
    Unset,
    /// No line reaches this path at all.
    Unspecified,
}

impl FilterAttribute {
    /// Whether git would run *this* tool for the path.
    #[must_use]
    pub fn is_ours(&self) -> bool {
        matches!(self, Self::Ours)
    }

    /// The answer as `git check-attr filter` prints it.
    #[must_use]
    pub fn as_check_attr(&self) -> &str {
        match self {
            Self::Ours => DRIVER,
            Self::Foreign(value) => value,
            Self::Set => "set",
            Self::Unset => "unset",
            Self::Unspecified => "unspecified",
        }
    }
}

impl std::fmt::Display for FilterAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_check_attr())
    }
}

/// Where an attribute value came from, in terms a reader can act on.
///
/// A verdict of "git converts your ciphertext" is unactionable without this: the
/// stack has four levels and one of them, `$GIT_DIR/info/attributes`, is not
/// versioned and cannot be seen in a pull request at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Culprit {
    /// The attributes file the line sits in, when there is one.
    pub source: Option<PathBuf>,
    /// The line number within it, as git counts them.
    pub line: usize,
    /// The pattern that matched.
    pub pattern: String,
    /// The assignment, spelled the way a `.gitattributes` line spells it.
    pub assignment: String,
}

impl std::fmt::Display for Culprit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            // Forward slashes so the message reads the same on all three
            // platforms, and so a reader can paste the path back into git.
            Some(source) => write!(
                f,
                "{}:{}: {} {}",
                git_spelling(source),
                self.line,
                self.pattern,
                self.assignment
            ),
            None => write!(f, "{} {}", self.pattern, self.assignment),
        }
    }
}

/// Whether git would run **its own** end-of-line conversion over stored bytes.
///
/// The distinction this type exists for is measured, not reasoned: git's
/// `convert_attrs` maps the `text` attribute onto a `crlf_action`, and only the
/// `CRLF_AUTO*` actions consult binary detection. Our magic starts with a NUL
/// byte, so every action that does consult it leaves the ciphertext alone; the
/// ones that do not convert it unconditionally, and a converted ciphertext fails
/// its authentication tag forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EolConversion {
    /// Git leaves the bytes alone.
    Off,
    /// Git converts them, because of this assignment.
    On(Culprit),
}

/// What git resolves for one path, on both axes the managed section sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// Whether git would run this tool for the path.
    pub filter: FilterAttribute,
    /// Whether git would convert the path's line endings itself.
    pub conversion: EolConversion,
}

/// One resolved attribute: its state, and where the state came from.
type Resolved = (gix_attributes::State, Culprit);

/// Spells an assignment the way a `.gitattributes` line spells it.
fn spell_assignment(assignment: gix_attributes::AssignmentRef<'_>) -> String {
    use gix_attributes::StateRef;
    let name = assignment.name.as_str();
    match assignment.state {
        StateRef::Set => name.to_string(),
        StateRef::Unset => format!("-{name}"),
        StateRef::Unspecified => format!("!{name}"),
        StateRef::Value(value) => format!("{name}={}", value.as_bstr()),
    }
}

/// Whether the resolved `text` and `eol` make git convert the stored bytes.
///
/// The whole table, measured on git 2.55 with a 2 MB file whose ciphertext
/// carries `CRLF` pairs, judged by a byte-for-byte round trip through `git add`,
/// `git commit`, `rm` and `git checkout`:
///
/// | `text`        | `eol`      | result                                    |
/// | ------------- | ---------- | ----------------------------------------- |
/// | `unset`       | any        | untouched — `-text` beats `eol`           |
/// | `auto`        | any        | untouched — binary detection sees the NUL |
/// | `unspecified` | unset      | untouched, at every `core.autocrlf` value |
/// | `set`         | any        | **converted, file lost at checkout**      |
/// | `unspecified` | `lf`/`crlf`| **converted, file lost at checkout**      |
///
/// The last row is the one nobody expects, and it is not an accident of the
/// implementation — it is git's, in `convert_attrs`: an `eol` attribute promotes
/// an undefined `crlf_action` straight to `CRLF_TEXT_INPUT`/`CRLF_TEXT_CRLF`,
/// and only the `CRLF_AUTO*` actions consult binary detection. `-text` is
/// exempt because git skips the `eol` attribute entirely when the action is
/// `CRLF_BINARY`, which is exactly the guarantee the managed section buys.
///
/// The safe rows are as load-bearing as the dangerous ones: a gate that fires on
/// `text=auto` or on an ordinary `core.autocrlf=true` teaches a user to ignore
/// it, and an ignored gate protects nothing.
fn converts(text: Option<&Resolved>, eol: Option<&Resolved>) -> EolConversion {
    use gix_attributes::State;

    let text_state = text.map(|(state, _)| state);
    match text_state {
        Some(State::Set) => {
            return EolConversion::On(text.expect("matched just above").1.clone());
        }
        // `-text` and the `binary` macro. Git never converts, and never even
        // looks at `eol`.
        Some(State::Unset) => return EolConversion::Off,
        // `text=auto`, and anything else a value could spell: git keeps binary
        // detection, and the leading NUL of our magic answers it.
        Some(State::Value(_)) => return EolConversion::Off,
        Some(State::Unspecified) | None => {}
    }

    // `text` unspecified. A bare `eol=` is enough on its own.
    match eol {
        Some((State::Value(value), culprit)) => {
            let value = value.as_ref().as_bstr();
            if value == "lf" || value == "crlf" {
                EolConversion::On(culprit.clone())
            } else {
                EolConversion::Off
            }
        }
        _ => EolConversion::Off,
    }
}

/// Answers "would git run our filter for this path, and would git convert its
/// line endings", the way git answers both.
///
/// **Resolving rather than naming, since 2026-08-04.** The previous build listed
/// every attribute source carrying a `filter` line and left the reader to run
/// `git check-attr`. That was the last route to a green report on a repository
/// that stores plaintext: a line below the managed section, or a
/// `.gitattributes` in a subdirectory, silently outranks the catch-all, and a
/// note does not fail a CI gate. Naming also cannot tell an ordinary
/// `*.psd filter=lfs` from a line that reaches a secret, so it either cried wolf
/// or said nothing useful.
///
/// **`text` joined `filter` on 2026-08-04**, for the same reason and at the same
/// severity. The managed section writes `-text` on every encrypted path, and a
/// line below it saying `secrets/** text` puts the conversion back — measured on
/// git 2.55, with `sync` freshly run so nothing else in this command had a
/// complaint: 34 `CR` bytes eaten out of a 2 MB ciphertext, `git add` and
/// `git commit` both exit 0, and the checkout fails the authentication tag and
/// leaves no file at all. `status` printed `VERDICT: no findings.` over it. An
/// unresolved `filter` costs a plaintext secret; this costs the file outright,
/// and both answer the same question with "your declaration is not enforced".
///
/// The stack reproduced here is git's, in git's precedence order — lowest first,
/// because [`gix_attributes::Search`] matches its lists in reverse:
///
/// 1. the built-in `[attr]binary` macro;
/// 2. `core.attributesFile`, the global file;
/// 3. the working tree's `.gitattributes`, root first and each directory after
///    it, so the file closest to the path wins;
/// 4. `$GIT_DIR/info/attributes`, which outranks everything.
///
/// Macros (`[attr]name …`) are honoured only where git honours them: the root
/// file, the global file and `info/attributes`. A `[attr]` line in a
/// subdirectory is not a macro definition to git and is not one here.
///
/// A source that cannot be read is skipped, exactly as git skips it.
pub struct AttributeResolver {
    search: gix_attributes::Search,
    outcome: gix_attributes::search::Outcome,
    case: gix_glob::pattern::Case,
    sources: Vec<PathBuf>,
}

impl AttributeResolver {
    /// Loads every attribute source git would consult under `work_tree`.
    ///
    /// `global` is `core.attributesFile`; `ignore_case` is `core.ignorecase`,
    /// which git applies to attribute matching as well as to path lookup.
    #[must_use]
    pub fn new(work_tree: &Path, git_dir: &Path, global: Option<&Path>, ignore_case: bool) -> Self {
        let mut collection = gix_attributes::search::MetadataCollection::default();
        let mut buf: Vec<u8> = Vec::new();
        let mut search = gix_attributes::Search::new_globals(
            global
                .map(Path::to_path_buf)
                .into_iter()
                .collect::<Vec<_>>(),
            &mut buf,
            &mut collection,
        )
        .unwrap_or_default();

        let mut sources: Vec<PathBuf> = Vec::new();
        collect_attribute_files(work_tree, &mut sources);
        // Shallowest first: git gives the file closest to the path the higher
        // precedence, and `Search` matches its lists last-added-first. Depth
        // before name, because a plain string sort does not order `a/x/.g`
        // against `a/.g` by depth in every alphabet.
        sources.sort_by_key(|path| (path.components().count(), path.clone()));

        for source in &sources {
            // Macros only where git takes them: the root file. Anywhere deeper a
            // `[attr]` line is an ordinary pattern to git.
            let is_root = source.parent() == Some(work_tree);
            let _ = search.add_patterns_file(
                source.clone(),
                true,
                Some(work_tree),
                &mut buf,
                &mut collection,
                is_root,
            );
        }

        // Last, so it outranks every file in the working tree — which is exactly
        // what makes it the source an audit is least likely to look at.
        let info = git_dir.join("info").join("attributes");
        let _ = search.add_patterns_file(info.clone(), true, None, &mut buf, &mut collection, true);
        sources.push(info);
        // Reported alongside the rest even though it was loaded first: a global
        // file that silently unsets `filter` is a source a reader has to be told
        // about, whatever its precedence.
        sources.extend(global.map(Path::to_path_buf));

        let mut outcome = gix_attributes::search::Outcome::default();
        // Order matters: `iter_selected` yields one item per name, in this
        // order, with a placeholder where nothing matched.
        outcome.initialize_with_selection(&collection, ["filter", "text", "eol"]);

        Self {
            search,
            outcome,
            case: if ignore_case {
                gix_glob::pattern::Case::Fold
            } else {
                gix_glob::pattern::Case::Sensitive
            },
            sources,
        }
    }

    /// What git resolves for a repository-relative path, on both axes.
    pub fn resolve(&mut self, relative_path: &[u8]) -> Resolution {
        use gix_attributes::State;

        self.outcome.reset();
        self.search.pattern_matching_relative_path(
            bstr::BStr::new(relative_path),
            self.case,
            Some(false),
            &mut self.outcome,
        );

        // Collected first: every `Match` borrows the outcome, and the decision
        // below has to outlive that borrow.
        let mut found = self.outcome.iter_selected().map(|matched| {
            (
                matched.assignment.state.to_owned(),
                Culprit {
                    source: matched.location.source.map(Path::to_path_buf),
                    line: matched.location.sequence_number,
                    pattern: matched.pattern.to_string(),
                    assignment: spell_assignment(matched.assignment),
                },
            )
        });
        let filter = found.next();
        let text = found.next();
        let eol = found.next();

        Resolution {
            filter: filter.map_or(FilterAttribute::Unspecified, |(state, _)| match state {
                State::Value(value) => {
                    let value = value.as_ref().as_bstr().to_string();
                    if value == DRIVER {
                        FilterAttribute::Ours
                    } else {
                        FilterAttribute::Foreign(value)
                    }
                }
                State::Set => FilterAttribute::Set,
                State::Unset => FilterAttribute::Unset,
                State::Unspecified => FilterAttribute::Unspecified,
            }),
            conversion: converts(text.as_ref(), eol.as_ref()),
        }
    }

    /// Every attributes file this resolver read, in the order it read them.
    #[must_use]
    pub fn sources(&self) -> &[PathBuf] {
        &self.sources
    }
}

/// The configuration keys `init` writes, for `status` to check for completeness.
///
/// A clone that never ran `init` or `unlock` carries the catch-all attribute
/// through history but not `.git/config`, and git treats an undefined filter as
/// no filter at all — content passes through in the clear. `diff.git-xcrypt.*`
/// is absent on purpose even now that it exists: a missing diff driver costs a
/// readable `git diff` and nothing more, and `lock` removes it deliberately, so
/// listing it here would make every locked repository report itself broken.
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
    fn a_second_managed_section_is_refused_rather_than_left_to_win() {
        // Balanced, so neither of the two checks above sees it, and `upsert`
        // rewrites only the first region. Measured before this: `sync` reported
        // "updated" and `sync --check` reported "up to date" with both copies
        // still in the file — and git takes the *last* matching line, so the
        // copy nobody maintains decides. `git checkout --conflict` on a
        // `.gitattributes` merge produces this shape by hand.
        let doubled = format!(
            "{}{}",
            render_section(&["*.env -text diff=git-xcrypt".into()]),
            render_section(&["secrets/README.md !text !diff".into()])
        );
        assert_eq!(
            doubled.matches(BEGIN).count(),
            2,
            "the fixture must really carry two sections"
        );

        let error = upsert(&doubled, &render_section(&[])).expect_err("a duplicate must be caught");

        assert_eq!(error.exit_code(), crate::exit::CONFIG);
        assert!(
            error.to_string().contains("more than one"),
            "the message must say what is wrong: {error}"
        );
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
                "secrets/key.p12 -text diff=git-xcrypt",
                "secrets/key.p12/** -text diff=git-xcrypt",
                "secrets/key.p12 -diff",
                "secrets/key.p12/** -diff",
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
        // git takes the last matching line, `Config::decide` treats `binary` as
        // sticky, so a `binary` pattern written above a broader one would
        // otherwise have its `-diff` overruled by the broader line. The trailing
        // line names only `diff`, so the `-text` above it survives.
        assert_eq!(
            lines("secrets/key.p12 binary\nsecrets/\n"),
            [
                "secrets/key.p12 -text diff=git-xcrypt",
                "secrets/key.p12/** -text diff=git-xcrypt",
                "**/secrets/** -text diff=git-xcrypt",
                "secrets/key.p12 -diff",
                "secrets/key.p12/** -diff",
            ]
        );
    }

    #[test]
    fn a_negation_restores_gits_defaults_for_the_path() {
        // Dropping the negated pattern would leave `-text` on a file that is
        // stored in the clear, so git would stop managing its line endings.
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
    fn a_negation_a_later_pattern_overrules_does_not_reach_the_bottom_of_the_section() {
        // Selection is last match in both files, so the lines have to keep the
        // order they were written in. Grouping the negations at the end instead
        // left this encrypted file without `-text` — the protection the whole
        // section exists for.
        assert_eq!(
            lines("!secrets/README.md\nsecrets/\n"),
            [
                "secrets/README.md !text !diff",
                "secrets/README.md/** !text !diff",
                "**/secrets/** -text diff=git-xcrypt",
            ]
        );
    }

    #[test]
    fn a_broad_pattern_gives_the_bootstrap_files_their_defaults_back() {
        // They are stored in the clear whatever the patterns say, so `-text` on
        // them would stop git managing their line endings — and git needs to be
        // able to read `.gitattributes` at every depth.
        let rendered = lines("*\n");
        assert_eq!(
            &rendered[rendered.len() - 3..],
            [
                "**/.gitattributes !text !diff",
                "/.git-xcrypt !text !diff",
                "/.git-xcrypt-keys/** !text !diff",
            ]
        );
        assert!(
            !lines("secrets/\n")
                .iter()
                .any(|line| line.contains(".gitattributes")),
            "an ordinary configuration must not carry the exclusion lines"
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
    fn a_pattern_opening_with_attr_is_kept_out_of_gits_macro_branch() {
        // Measured on git 2.55: `[attr]foo …` defines a macro named `foo` and
        // applies to nothing at all. Quoting does not help — the macro check
        // runs *before* the unquoting, so `"[attr]x"` is still a macro. A
        // leading `**/` means the same as no prefix and moves the line off that
        // branch; an anchored pattern gets a leading `/` for the same reason.
        assert_eq!(
            lines("[attr]x\n"),
            [
                "**/[attr]x -text diff=git-xcrypt",
                "**/[attr]x/** -text diff=git-xcrypt"
            ]
        );
        assert_eq!(
            lines("[attr]x/y\n"),
            [
                "/[attr]x/y -text diff=git-xcrypt",
                "/[attr]x/y/** -text diff=git-xcrypt"
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
        // Only identical lines collapse, and only onto the last copy: an earlier
        // one could otherwise outlive a line between them saying the opposite.
        assert_eq!(
            lines("secrets/key.p12 binary\nsecrets/key.p12 eol=lf\n"),
            [
                "secrets/key.p12 -text diff=git-xcrypt",
                "secrets/key.p12/** -text diff=git-xcrypt",
                "secrets/key.p12 -diff",
                "secrets/key.p12/** -diff",
            ]
        );
        assert_eq!(
            lines("secrets/\n!secrets/\nsecrets/\n"),
            [
                "**/secrets/** !text !diff",
                "**/secrets/** -text diff=git-xcrypt",
            ],
            "the surviving copy has to be the last one, or the order flips"
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

    /// One attributes source: where it lives, relative to the repository root.
    struct Source<'a> {
        path: &'static str,
        body: &'a str,
    }

    /// Sets up a repository from `sources`, then asserts our answers for `path`
    /// are character for character what `git check-attr` says.
    ///
    /// All three attributes the managed section sets, not just `filter`. The
    /// stack is one stack, and a precedence bug found through `filter` alone
    /// would have been just as free to hide behind `text` — which is the more
    /// expensive of the two to get wrong.
    ///
    /// Comparative rather than expectation-based on purpose: git is the only
    /// authority on its own attribute stack, and every earlier review of this
    /// area found a place where our reading of the documentation and git's
    /// behaviour parted company.
    fn agrees_with_git(sources: &[Source<'_>], path: &str, global: Option<&str>) {
        use std::process::Command;

        let dir = tempfile::TempDir::new().expect("temporary directory");
        let root = dir.path();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .current_dir(root)
                .status()
                .expect("git must be on PATH")
                .success(),
            "git init failed"
        );

        for source in sources {
            let target = root.join(source.path);
            fs::create_dir_all(target.parent().expect("a parent")).expect("directories");
            fs::write(&target, source.body).expect("writing an attributes file");
        }

        let global_path = global.map(|body| {
            let path = root.join("global-attributes");
            fs::write(&path, body).expect("writing the global attributes file");
            assert!(
                Command::new("git")
                    .args(["config", "core.attributesFile"])
                    .arg(&path)
                    .current_dir(root)
                    .status()
                    .expect("git")
                    .success()
            );
            path
        });

        // The file has to exist for git to consult its directory's rules, and
        // `check-attr` without `--cached` reads the working tree.
        let target = root.join(path);
        fs::create_dir_all(target.parent().expect("a parent")).expect("directories");
        fs::write(&target, b"content\n").expect("writing the subject file");

        let ask = |attribute: &str| -> String {
            let output = Command::new("git")
                .args(["check-attr", attribute, "--", path])
                .current_dir(root)
                .output()
                .expect("git check-attr");
            String::from_utf8(output.stdout)
                .expect("check-attr prints text")
                .rsplit(": ")
                .next()
                .expect("check-attr always prints a value")
                .trim()
                .to_string()
        };

        let mut resolver =
            AttributeResolver::new(root, &root.join(".git"), global_path.as_deref(), false);
        let ours = resolver.resolve(path.as_bytes());

        assert_eq!(
            ours.filter.as_check_attr(),
            ask("filter"),
            "git and git-xcrypt disagree about `filter` for {path}"
        );

        // The conversion verdict rebuilt from git's own two answers. This
        // proves the *resolution* — precedence, macros, the global file — not
        // the table in `converts`, which is settled against git's behaviour by
        // the round trips in `tests/status_command.rs`.
        let (text, eol) = (ask("text"), ask("eol"));
        let converts = matches!(
            (text.as_str(), eol.as_str()),
            ("set", _) | ("unspecified", "lf" | "crlf")
        );
        assert_eq!(
            matches!(ours.conversion, EolConversion::On(_)),
            converts,
            "git says text={text} eol={eol} for {path}, and git-xcrypt read the \
             stack differently"
        );
    }

    #[test]
    fn the_filter_attribute_is_resolved_exactly_as_git_resolves_it() {
        // Ten shapes, every one of them a way a repository can end up not being
        // filtered while the catch-all line sits there looking correct.
        let catch_all = "# >>> git-xcrypt >>>\n* filter=git-xcrypt\n# <<< git-xcrypt <<<\n";

        // The healthy case, so a disagreement here would be caught too.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: catch_all,
            }],
            "secrets/db.env",
            None,
        );

        // A line below the managed section. Git takes the last match.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: &format!("{catch_all}secrets/** -filter\n"),
            }],
            "secrets/db.env",
            None,
        );

        // A `.gitattributes` in the directory of the path outranks the root.
        agrees_with_git(
            &[
                Source {
                    path: ".gitattributes",
                    body: catch_all,
                },
                Source {
                    path: "secrets/.gitattributes",
                    body: "* -filter\n",
                },
            ],
            "secrets/db.env",
            None,
        );

        // `$GIT_DIR/info/attributes` outranks everything in the working tree.
        agrees_with_git(
            &[
                Source {
                    path: ".gitattributes",
                    body: catch_all,
                },
                Source {
                    path: ".git/info/attributes",
                    body: "secrets/** -filter\n",
                },
            ],
            "secrets/db.env",
            None,
        );

        // …and it can also put the filter back, which is the direction a build
        // that merely looked for foreign lines would have got wrong.
        agrees_with_git(
            &[
                Source {
                    path: ".gitattributes",
                    body: catch_all,
                },
                Source {
                    path: "secrets/.gitattributes",
                    body: "* -filter\n",
                },
                Source {
                    path: ".git/info/attributes",
                    body: "secrets/** filter=git-xcrypt\n",
                },
            ],
            "secrets/db.env",
            None,
        );

        // An ordinary LFS line on paths no pattern of ours reaches.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: &format!("{catch_all}*.psd filter=lfs\n"),
            }],
            "secrets/db.env",
            None,
        );

        // …and the same line where it *does* reach.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: &format!("{catch_all}*.env filter=lfs\n"),
            }],
            "secrets/db.env",
            None,
        );

        // A macro, which is the indirection a reader is least likely to follow.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: &format!("[attr]plain -filter\n{catch_all}secrets/** plain\n"),
            }],
            "secrets/db.env",
            None,
        );

        // `!filter` — unspecified rather than unset, and git tells them apart.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: &format!("{catch_all}secrets/** !filter\n"),
            }],
            "secrets/db.env",
            None,
        );

        // The global file is the *lowest* precedence, so the repository wins.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: catch_all,
            }],
            "secrets/db.env",
            Some("* -filter\n"),
        );

        // …and it decides when nothing in the repository speaks.
        agrees_with_git(&[], "secrets/db.env", Some("* filter=git-xcrypt\n"));
    }

    #[test]
    fn the_text_attribute_is_resolved_exactly_as_git_resolves_it() {
        // The same stack, asked the question that costs the file rather than
        // the secret. Every shape here resolves `filter` to `git-xcrypt`, so a
        // build that only followed `filter` calls all of them healthy.
        let managed = "# >>> git-xcrypt >>>\n* filter=git-xcrypt\n\
                       **/secrets/** -text diff=git-xcrypt\n# <<< git-xcrypt <<<\n";
        let bare = "# >>> git-xcrypt >>>\n* filter=git-xcrypt\n# <<< git-xcrypt <<<\n";

        for body in [
            // The healthy case: the managed `-text` is the last word.
            managed.to_string(),
            // A line below it putting `text` back on — the finding.
            format!("{managed}secrets/** text\n"),
            // `text=auto`, which keeps git's binary detection and is harmless.
            format!("{managed}secrets/** text=auto\n"),
            // `eol=` beside `-text`, which git ignores outright.
            format!("{managed}secrets/** eol=crlf\n"),
            // No managed `-text` at all, and a bare `eol=`: harmful, and the
            // shape neither the brief nor `zalozenia.md` predicted.
            format!("{bare}secrets/** eol=lf\n"),
            // No managed `-text`, nothing else either: harmless.
            bare.to_string(),
            // Through a macro, where nothing on the reaching line says `text`.
            format!("[attr]mine text\n{managed}secrets/** mine\n"),
            // The `binary` macro, which is `-text -diff`.
            format!("{bare}secrets/** binary\n"),
        ] {
            agrees_with_git(
                &[Source {
                    path: ".gitattributes",
                    body: &body,
                }],
                "secrets/db.env",
                None,
            );
        }

        // A subdirectory file and `$GIT_DIR/info/attributes`, the two sources
        // that outrank the managed section without appearing beneath it.
        agrees_with_git(
            &[
                Source {
                    path: ".gitattributes",
                    body: managed,
                },
                Source {
                    path: "secrets/.gitattributes",
                    body: "* text\n",
                },
            ],
            "secrets/db.env",
            None,
        );
        agrees_with_git(
            &[
                Source {
                    path: ".gitattributes",
                    body: managed,
                },
                Source {
                    path: ".git/info/attributes",
                    body: "secrets/** text\n",
                },
            ],
            "secrets/db.env",
            None,
        );
        // The global file, lowest precedence: the managed `-text` still wins.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: managed,
            }],
            "secrets/db.env",
            Some("* text\n"),
        );
    }

    #[test]
    fn the_catch_all_line_names_no_pattern_from_the_config() {
        // If this line ever depended on `.git-xcrypt`, the drift this design
        // removes would come straight back.
        assert_eq!(CATCH_ALL, "* filter=git-xcrypt");
        assert!(has_section(&render_section(&[])));
    }
}
