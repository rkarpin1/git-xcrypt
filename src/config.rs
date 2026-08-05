//! The `.git-xcrypt` file: which paths are encrypted, and how line endings are
//! handled.
//!
//! Patterns use `.gitignore` syntax and are matched by `gix-glob`, so the
//! semantics are git's own rather than an imitation of them. A pattern that
//! contains a space is closed with quotes, exactly as `.gitattributes` closes
//! one — see [`split_line`] for why the backslash that used to do that job was
//! taken away from it. Attributes use the `.gitattributes` vocabulary. The two
//! resolve on **independent axes**, exactly as git splits them across two
//! files:
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

/// One line of `.git-xcrypt`, as the `.gitattributes` renderer sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternView<'a> {
    /// The pattern as written, without a leading `!`.
    pub source: &'a str,
    /// Whether this line takes paths back out.
    pub negated: bool,
    /// Whether it declared `binary`, which also means "no diff driver".
    pub suppress_diff: bool,
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

        // A UTF-8 byte-order mark is what PowerShell 5's `Set-Content
        // -Encoding UTF8` writes and what no editor shows. It is not
        // whitespace to `str::trim`, and it is not `#`, so it used to reach
        // `gix-glob` glued to the first pattern — measured: a `.git-xcrypt`
        // starting `\u{feff}secrets/` selected nothing, `git add
        // secrets/db.env` exited 0 and the plaintext went into the object
        // database with no word from anyone. Git strips one at the head of its
        // own pattern files, so this parser does the same rather than refuse a
        // file git itself reads happily.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);

        for (number, line) in text.lines().enumerate() {
            // Deliberately not trimmed: a pattern's own leading whitespace is
            // significant in `.gitignore`, so `split_line` is left to refuse an
            // indented line rather than to silently accept a different pattern
            // than the one written.
            let number = number + 1;
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }

            let split = split_line(line, number)?;
            let declared = parse_attributes(split.attributes, number)?;

            let pattern = if split.negation_syntax {
                Pattern::from_bytes(split.glob.as_bytes())
            } else {
                // A quoted pattern is taken entirely literally, so a `!` that
                // survived the unquoting is part of a file name and must not be
                // read as the negation marker — that marker stands *outside*
                // the quotes.
                Pattern::from_bytes_without_negation(split.glob.as_bytes())
            }
            .ok_or_else(|| {
                Error::Config(format!(
                    "{CONFIG_FILE}:{number}: `{}` is not a usable pattern",
                    split.source
                ))
            })?;

            if pattern.is_negative() && declared != Declared::default() {
                return Err(Error::Config(format!(
                    "{CONFIG_FILE}:{number}: a negated pattern cannot carry attributes — \
                     the path is not encrypted, so there is nothing to convert"
                )));
            }

            if declared.eol.is_some() && declared.text == Some(TextMode::Binary) {
                config.pointless_eol.push(format!(
                    "{CONFIG_FILE}:{number}: `eol=` has no effect on a path that is never \
                     converted; git lets -text win over eol too"
                ));
            }

            config.rules.push(Rule {
                pattern,
                source: split.source,
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
    ///
    /// The failure names the file, which is not decoration on this path. It is
    /// reached from the filter, so every git operation in the repository stops
    /// until it is fixed, and git's own accompanying `fatal:` line names whatever
    /// file it was cleaning when this one could not be read — measured on git
    /// 2.55, that was an innocent `secrets/db.env`. A bare
    /// `stream did not contain valid UTF-8` beside it left nothing pointing at
    /// the real culprit.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                missing: true,
                ..Self::default()
            }),
            // The kind is spelled out rather than passed through: `read_to_string`
            // reports "not valid UTF-8" for a file that is perfectly readable and
            // simply is not text, and patterns are text. Saying so is the
            // difference between a remedy and a puzzle.
            Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
                Err(Error::Io(std::io::Error::other(format!(
                    "{}: this file must be UTF-8 text and is not ({err}), so \
                     nothing here declares what to encrypt",
                    path.display()
                ))))
            }
            Err(err) => Err(Error::Io(std::io::Error::other(format!(
                "{}: could not be read ({err})",
                path.display()
            )))),
        }
    }

    /// Every pattern in file order, with the `!` stripped from the negations.
    ///
    /// File order is what the caller needs rather than a convenience: selection
    /// is resolved by last match, so a rendered `.gitattributes` only agrees
    /// with [`Config::decide`] if it keeps the lines in the order they were
    /// written. Splitting them into "selecting" and "negated" lists loses
    /// exactly the information that decides the answer.
    #[must_use]
    pub fn patterns(&self) -> Vec<PatternView<'_>> {
        self.rules
            .iter()
            .map(|rule| PatternView {
                // The `!` is already off: it is a marker on the line, not a
                // character of the pattern, and stripping it here as well would
                // eat a leading `!` that a quoted pattern means literally.
                source: rule.source.as_str(),
                negated: rule.pattern.is_negative(),
                suppress_diff: rule.declared.suppress_diff,
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
        self.decide_ignoring_exclusions(path)
    }

    /// Whether a negation is what keeps `path` out of the encrypted set.
    ///
    /// `status` reports such paths in a section of their own rather than leaving
    /// them out. A `!secrets/README.md` under a `secrets/` line is a deliberate
    /// hole in the declaration, and the founding document is explicit that a
    /// deliberate hole must never be an invisible one — silence here reads as
    /// "everything under `secrets/` is covered", which is the belief that lets a
    /// secret be filed under the exception by mistake.
    ///
    /// False for a path no pattern reaches at all: that is not an exception, it
    /// is simply a file nobody declared.
    #[must_use]
    pub fn negated(&self, path: &[u8]) -> bool {
        if is_never_encrypted(path) {
            // Not an exception either. These are excluded by the tool, not by
            // anything the user wrote, and listing them as "in the clear by
            // choice" would attribute a decision nobody made.
            return false;
        }
        self.rules
            .iter()
            .rfind(|rule| matches(&rule.pattern, path))
            .is_some_and(|rule| rule.pattern.is_negative())
    }

    /// What the patterns alone say, with the bootstrap exclusions set aside.
    ///
    /// Only one caller wants this: rendering `.gitattributes` has to know
    /// whether a pattern reaches a file that [`is_never_encrypted`] then rescues,
    /// because such a file needs a line putting git's defaults back. Everything
    /// else must go through [`Config::decide`].
    #[must_use]
    pub fn decide_ignoring_exclusions(&self, path: &[u8]) -> Decision {
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
///
/// **Compared with ASCII case folded, like everything else here** — see
/// [`MATCHING`], and note that this one is not a free consequence of that
/// decision. On a case-insensitive filesystem `.GITATTRIBUTES` *is* the
/// attributes file, so encrypting it would replace the catch-all line with
/// ciphertext and turn the filter off for **every** file in the repository, not
/// for one. On a case-sensitive filesystem the fold costs the opposite: a file
/// deliberately named `secrets/.GITATTRIBUTES` stays in the clear. Folding is
/// the direction taken because the rendered `.gitattributes` lines fold too, and
/// a filter that encrypted a path those lines put git's defaults back on would
/// leave ciphertext without `-text` — the shape measured destroying a 2 MB file
/// at checkout. Recorded in `README.md` §Known limitations.
#[must_use]
pub fn is_never_encrypted(path: &[u8]) -> bool {
    // `.gitattributes` is matched by basename, not by root path: git reads one
    // per directory, so encrypting `sub/.gitattributes` would leave git unable
    // to read the attributes for that whole subtree. `.git-xcrypt` is read only
    // from the root, so there the root path is the right test.
    let basename = path.rsplit_str("/").next().unwrap_or(path);

    // No `format!` here: this runs once per file in the repository, and the
    // allocation bought nothing that `strip_prefix` does not.
    let same = |left: &[u8], right: &str| left.eq_ignore_ascii_case(right.as_bytes());

    same(basename, ATTRIBUTES_FILE)
        || same(path, CONFIG_FILE)
        || same(path, KEY_ENVELOPE_DIR)
        || path
            .get(..KEY_ENVELOPE_DIR.len())
            .is_some_and(|head| same(head, KEY_ENVELOPE_DIR))
            && path.get(KEY_ENVELOPE_DIR.len()) == Some(&b'/')
}

/// One line, split into the two things it declares.
struct Split<'a> {
    /// The pattern as `gix-glob` must read it, negation marker included.
    glob: String,
    /// Whether `gix-glob` may read a leading `!` or `\!` in `glob` as syntax.
    ///
    /// False for a quoted pattern, whose every character is part of a name.
    negation_syntax: bool,
    /// The pattern as a renderer must reproduce it: unquoted, and without the
    /// `!` that never belonged to the name in the first place.
    source: String,
    /// Everything after the pattern.
    attributes: &'a str,
}

/// Splits a line into its pattern and its attributes.
///
/// Whitespace separates the two, so a pattern that contains whitespace is closed
/// with **quotes**, and inside them C-style escapes are read exactly as git reads
/// them in `.gitattributes` — `\"`, `\\`, `\t`, `\n`, `\r` and octal. A negation
/// keeps its `!` outside the quotes: `!"my secrets/README.md"`.
///
/// **Quotes replaced the `\ ` escape on 2026-08-05**, and the reason is not
/// taste. The backslash carried two meanings at once — an escape for whitespace
/// at the level of the line, and wildmatch's own escape for a glob metacharacter
/// inside the pattern — so `\*` and `\ ` had to be told apart by what followed
/// them. It also never really closed the second shape it was supposed to: a
/// trailing space had to be written `secrets\ ` at the end of a line, and an
/// editor that strips trailing whitespace deletes it without a word, leaving a
/// pattern that means something else. Quotes close both shapes with one
/// mechanism, and the backslash goes back to being only what a glob says it is.
fn split_line(line: &str, number: usize) -> Result<Split<'_>> {
    let (negated, rest) = match line.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, line),
    };

    if let Some(body) = rest.strip_prefix('"') {
        let (source, after) = unquote(body, number)?;
        if !after.is_empty() && !after.starts_with(|c: char| c.is_whitespace()) {
            return Err(Error::Config(format!(
                "{CONFIG_FILE}:{number}: `{after}` follows the closing quote; the quotes close \
                 the pattern, and any attributes come after a space"
            )));
        }
        refuse_quoted_attributes(&source, negated, number)?;
        return Ok(Split {
            glob: if negated {
                format!("!{source}")
            } else {
                source.clone()
            },
            negation_syntax: negated,
            source,
            attributes: after.trim_start(),
        });
    }

    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    let (source, attributes) = rest.split_at(end);

    if source.is_empty() {
        return Err(Error::Config(format!(
            "{CONFIG_FILE}:{number}: there is no pattern here — a line starts with the pattern it \
             declares, and a name that begins with whitespace is written in quotes"
        )));
    }
    if source.ends_with('\\') {
        return Err(legacy_escape_error(line, number));
    }

    Ok(Split {
        // The token exactly as written, `!` included: an unquoted pattern is
        // handed to `gix-glob` unaltered, so `\!` and `\#` keep meaning what
        // `.gitignore` says they mean.
        glob: if negated {
            format!("!{source}")
        } else {
            source.to_string()
        },
        negation_syntax: true,
        source: source.to_string(),
        attributes: attributes.trim_start(),
    })
}

/// Unwraps a C-quoted pattern, returning it and the rest of the line.
///
/// The escapes are git's own set from `unquote_c_style`, including the octal
/// form, so a name spells the same here as it does in `.gitattributes` and in
/// git's own output. An escape git does not know is refused rather than passed
/// through: a pattern nobody agrees on is a pattern that selects the wrong set of
/// files, and on the check-in path the wrong set means a secret in the clear.
fn unquote(body: &str, number: usize) -> Result<(String, &str)> {
    let unterminated = || {
        Error::Config(format!(
            "{CONFIG_FILE}:{number}: this pattern opens with `\"` and never closes it"
        ))
    };

    let bytes = body.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let text = String::from_utf8(out).map_err(|_| {
                    Error::Config(format!(
                        "{CONFIG_FILE}:{number}: the escapes in this pattern do not spell UTF-8 \
                         text, and this file is read as text"
                    ))
                })?;
                return Ok((text, &body[index + 1..]));
            }
            b'\\' => {
                // The character rather than the byte, so a backslash in front of
                // a multi-byte character neither slices mid-character nor
                // reports half of one.
                let Some(next) = body[index + 1..].chars().next() else {
                    return Err(unterminated());
                };
                let escaped = bytes[index + 1];
                index += 1 + next.len_utf8();
                match escaped {
                    b'a' => out.push(0x07),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'v' => out.push(0x0b),
                    b'\\' | b'"' => out.push(escaped),
                    b'0'..=b'7' => {
                        let mut value = u32::from(escaped - b'0');
                        for _ in 0..2 {
                            match bytes.get(index) {
                                Some(digit @ b'0'..=b'7') => {
                                    value = value * 8 + u32::from(digit - b'0');
                                    index += 1;
                                }
                                _ => break,
                            }
                        }
                        let byte = u8::try_from(value).map_err(|_| {
                            Error::Config(format!(
                                "{CONFIG_FILE}:{number}: `\\{value:o}` is not a byte; an octal \
                                 escape names one byte, from \\0 to \\377"
                            ))
                        })?;
                        out.push(byte);
                    }
                    _ => {
                        return Err(Error::Config(format!(
                            "{CONFIG_FILE}:{number}: `\\{next}` is not an escape git knows inside \
                             a quoted pattern; a literal backslash is written `\\\\`"
                        )));
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }

    Err(unterminated())
}

/// Whether `token` is one of the words the attribute vocabulary defines.
///
/// The same list [`parse_attributes`] matches on, spelled twice because the two
/// ask different questions: one parses a line, one recognises a line written for
/// the syntax that ended on 2026-08-05. Nothing makes the compiler keep them in
/// step, so a new attribute belongs in both — a word missing from this one only
/// narrows the net, never widens it.
fn is_attribute_word(token: &str) -> bool {
    matches!(
        token,
        "text" | "-text" | "binary" | "text=auto" | "eol=lf" | "eol=crlf" | "eol=native"
    )
}

/// Refuses a quoted pattern whose tail is the attribute list of an older file.
///
/// The net under the migration, and it catches the one shape that would
/// otherwise change meaning in silence: a line from before 2026-08-05 wrapped in
/// quotes whole, so `"secrets/*.sh" text` becomes a pattern that matches nothing
/// and a path that stops being encrypted without a word. Only a *trailing* run of
/// attribute words counts, so an ordinary directory called `my text files/` is
/// left alone.
fn refuse_quoted_attributes(pattern: &str, negated: bool, number: usize) -> Result<()> {
    let mut head = pattern.trim_end();
    let mut found = 0usize;
    while let Some((before, last)) = head.rsplit_once(|c: char| c.is_whitespace()) {
        if !is_attribute_word(last) {
            break;
        }
        head = before.trim_end();
        found += 1;
    }
    if found == 0 || head.is_empty() {
        return Ok(());
    }

    let attributes = pattern[head.len()..].trim();
    let marker = if negated { "!" } else { "" };
    Err(Error::Config(format!(
        "{CONFIG_FILE}:{number}: this quoted pattern ends with the attribute `{attributes}`, and \
         quotes close the pattern only — attributes stand outside them. The line reads like the \
         syntax that changed on 2026-08-05. Write it as:\n    \
         {marker}\"{head}\" {attributes}\n\
         If the path really does end in that word, spell it so it cannot be read as an \
         attribute — `[t]ext` matches the same names."
    )))
}

/// The refusal for a line still written with the `\ ` escape.
///
/// Recognising the shape is the whole point. Split by the rule in force today,
/// `my\ secrets/` falls apart into the pattern `my\` and the unknown attribute
/// `secrets/`, so the file is refused either way and no secret is stored in the
/// clear — but "unknown attribute `secrets/`" tells a reader nothing about what
/// changed, and the change is in a file they wrote once and have not looked at
/// since. The suggestion is reconstructed with the old rule, so it is the line
/// they meant rather than a template.
fn legacy_escape_error(line: &str, number: usize) -> Error {
    let (intended, attributes) = legacy_split(line);
    let (marker, intended) = match intended.strip_prefix('!') {
        Some(rest) => ("!", rest.to_string()),
        None => ("", intended),
    };

    let mut quoted = String::with_capacity(intended.len() + 2);
    for character in intended.chars() {
        if character == '"' || character == '\\' {
            quoted.push('\\');
        }
        quoted.push(character);
    }

    let suggestion = if attributes.is_empty() {
        format!("{marker}\"{quoted}\"")
    } else {
        format!("{marker}\"{quoted}\" {attributes}")
    };

    Error::Config(format!(
        "{CONFIG_FILE}:{number}: this pattern ends with a backslash, which is how a space in a \
         path was written until 2026-08-05. A space is now closed with quotes instead, and a \
         backslash means only what it means in a glob. Write the line as:\n    \
         {suggestion}\n\
         A negation keeps its `!` outside the quotes: !\"my secrets/README.md\"."
    ))
}

/// Splits a line the way this file did before 2026-08-05.
///
/// Kept for one purpose: reconstructing what the author of an old line meant, so
/// the refusal can quote the replacement instead of describing it.
fn legacy_split(line: &str) -> (String, &str) {
    let bytes = line.as_bytes();
    let mut pattern = String::new();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if let Some(escaped) = line[index + 1..].chars().next() {
                if !escaped.is_whitespace() {
                    pattern.push('\\');
                }
                pattern.push(escaped);
                index += 1 + escaped.len_utf8();
                continue;
            }
            index += 1;
            continue;
        }
        if bytes[index].is_ascii_whitespace() {
            return (pattern, line[index..].trim());
        }
        let character = line[index..].chars().next().unwrap_or('\\');
        pattern.push(character);
        index += character.len_utf8();
    }
    (pattern, "")
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

/// How every pattern in this file is matched. **Unconditionally**, and that is
/// the decision rather than a detail of it.
///
/// Settled on 2026-08-05 as open decision 13, on the owner's judgement that it
/// is the safest of the answers available. The failure it closes was measured:
/// `.git-xcrypt` declares `secrets/`, the user creates `Secrets/db.env`, and on
/// APFS and on NTFS those are **one** directory — `cd secrets` enters `Secrets`
/// and `ls` shows a single entry, so nothing in the working tree can show the
/// mistake. Byte-exact matching left the file unselected, `git add` exited `0`
/// and the plaintext went into the object database.
///
/// **Unconditional is what keeps determinism.** The obvious alternative — fold
/// when git folds — would read `core.ignorecase`, which git sets for itself by
/// probing the filesystem and which is not versioned, so the same repository
/// would encrypt a different set of files on macOS than on Linux. That is the
/// argument that keeps `core.autocrlf` off the check-in path, and it carries over
/// unchanged. Folding always reads nothing: the declaration alone decides, on
/// every machine.
///
/// **ASCII, deliberately.** `gix-glob` folds with `to_ascii_lowercase`, and so
/// does git: measured on git 2.55 with `core.ignorecase=true`, `łąka/**` matches
/// neither `ŁĄKA/a.env` nor `Łąka/a.env`. Reaching further would also have
/// nowhere to land — `.gitattributes` matches bytes, so the rendered `[łŁ]` is a
/// set of four bytes rather than two characters and matches no spelling at all,
/// and a filter that selected a path the rendered section cannot reach is the
/// "narrower" half of the rule this project holds hardest. Recorded as a
/// limitation in `README.md` §Known limitations.
const MATCHING: Case = Case::Fold;

/// Whether `pattern` matches `path`, honouring directory patterns.
///
/// A pattern written as `secrets/` only matches a directory, so git also treats
/// everything beneath it as matched. `gix-glob` answers about one path at a
/// time, so the ancestors are offered to it explicitly.
fn matches(pattern: &Pattern, path: &[u8]) -> bool {
    if match_one(pattern, path, false, MATCHING) {
        return true;
    }

    for (index, byte) in path.iter().enumerate() {
        if *byte == b'/' && match_one(pattern, &path[..index], true, MATCHING) {
            return true;
        }
    }
    false
}

/// One `gix-glob` question.
fn match_one(pattern: &Pattern, path: &[u8], is_dir: bool, case: Case) -> bool {
    let bytes: &BStr = path.as_bstr();
    let basename_start = path.rfind_byte(b'/').map(|index| index + 1);
    pattern.matches_repo_relative_path(
        bytes,
        basename_start,
        Some(is_dir),
        case,
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
    fn bootstrap_files_are_never_encrypted() {
        let config = config("*\n");
        for path in [
            ATTRIBUTES_FILE,
            // Git reads one .gitattributes per directory; encrypting a nested
            // one would blind it for that whole subtree.
            "sub/dir/.gitattributes",
            CONFIG_FILE,
            "\u{2e}git-xcrypt-keys/robert.age",
            // The same three with ASCII case folded, because on APFS and NTFS
            // `.GITATTRIBUTES` *is* the attributes file — encrypting it would
            // replace the catch-all line with ciphertext and switch the filter
            // off for every file in the repository. See `is_never_encrypted`.
            ".GITATTRIBUTES",
            "sub/dir/.GitAttributes",
            ".GIT-XCRYPT",
            "\u{2e}Git-Xcrypt-Keys/robert.age",
        ] {
            assert!(
                !config.decide(path.as_bytes()).encrypt,
                "{path} must never be encrypted; it is needed to bootstrap"
            );
        }
        assert!(config.decide(b"anything-else").encrypt);
    }

    #[test]
    fn a_byte_order_mark_does_not_glue_itself_to_the_first_pattern() {
        // What PowerShell 5's `Set-Content -Encoding UTF8` writes and no editor
        // shows. Measured before this: `\u{feff}secrets/` selected nothing,
        // `git add secrets/db.env` exited 0 and stored the plaintext. Git
        // strips one at the head of its own pattern files — measured on 2.55,
        // a `.gitignore` and a `.gitattributes` each opening with a BOM still
        // apply their first line — so the declaration follows git.
        let parsed = config("\u{feff}secrets/\n");
        assert!(
            parsed.decide(b"secrets/db.env").encrypt,
            "the invisible BOM turned the first pattern into one matching nothing"
        );
        // Only the head of the file: later lines are unaffected either way.
        let parsed = config("\u{feff}first/\nsecond/\n");
        assert!(parsed.decide(b"second/x").encrypt);
    }

    /// Every shape the line parser refuses, and the word that says why.
    ///
    /// A scenario walks one path per run, so it can prove that a good file is
    /// read correctly and that one bad file is caught — it cannot economically
    /// cover eleven refusals. Measured on 2026-08-05, when this table did not
    /// exist: dropping the unterminated-quote guard left all 91 tests green, so
    /// `.git-xcrypt` could open a quote and never close it and still be read as
    /// a declaration. The other ten are here because a parser is a table and is
    /// cheapest to guard as one.
    ///
    /// Each row asserts a fragment of the message, not the whole of it. The
    /// wording is free to improve; what must not change is that the refusal
    /// happens and names the reason, because the alternative to a refusal here
    /// is a pattern that matches nothing and a file that stops being encrypted
    /// without saying so.
    #[test]
    fn every_shape_the_parser_refuses_is_refused_and_says_why() {
        let refused: &[(&str, &str, &str)] = &[
            ("an unterminated quote", "\"my secrets/\n", "never closes"),
            (
                "text after the closing quote",
                "\"my secrets/\"oops\n",
                "follows the closing",
            ),
            ("nothing but a negation", "!\n", "there is no pattern here"),
            (
                "the pre-2026-08-05 backslash escape",
                "my\\ secrets/\n",
                "ends with a backslash",
            ),
            (
                "an old line quoted whole",
                "\"secrets/*.sh text eol=lf\"\n",
                "ends with the attribute",
            ),
            (
                "an escape that is not one",
                "\"secrets/\\q.env\"\n",
                "is not an escape",
            ),
            (
                "an octal escape past a byte",
                "\"secrets/\\777.env\"\n",
                "is not a byte",
            ),
            (
                "octal escapes that do not spell UTF-8",
                "\"secrets/\\377.env\"\n",
                "do not spell",
            ),
            (
                "an attribute nobody defined",
                "secrets/ text=maybe\n",
                "unknown attribute",
            ),
            (
                "attributes on a negation",
                "!secrets/README.md text\n",
                "cannot carry",
            ),
        ];

        for (label, text, fragment) in refused {
            let error = Config::parse(text)
                .err()
                .unwrap_or_else(|| panic!("{label}: this must not parse, but it did"));
            let message = error.to_string();
            assert!(
                message.contains(fragment),
                "{label}: the refusal must say `{fragment}`, and says: {message}"
            );
            assert!(
                message.contains(CONFIG_FILE),
                "{label}: the refusal must name the file it is about: {message}"
            );
        }
    }

    /// Every shape the line parser accepts, and what it makes of it.
    ///
    /// The awkward half of this table is not decoration. A leading `!` and a
    /// leading `#` inside quotes are parts of a name, not syntax — both were
    /// real defects, found on 2026-08-05, that ended in git dropping the
    /// generated `.gitattributes` line and taking the file's ciphertext with
    /// it. A trailing space is the case a backslash never really closed,
    /// because editors strip it; quotes close it.
    #[test]
    fn every_shape_the_parser_accepts_means_what_it_says() {
        // (label, declaration, path, encrypted?, text mode, eol)
        type Row<'a> = (&'a str, &'a str, &'a [u8], bool, TextMode, Option<EolMode>);
        let accepted: &[Row] = &[
            (
                "a bare pattern",
                "secrets/\n",
                b"secrets/db.env",
                true,
                TextMode::Auto,
                None,
            ),
            (
                "a bare pattern with attributes",
                "secrets/deploy.ps1 text eol=crlf\n",
                b"secrets/deploy.ps1",
                true,
                TextMode::Text,
                Some(EolMode::Crlf),
            ),
            (
                "a quoted name holding a space",
                "\"my secrets/\"\n",
                b"my secrets/db.env",
                true,
                TextMode::Auto,
                None,
            ),
            (
                "a quoted name with attributes",
                "\"my secrets/*.sh\" text eol=lf\n",
                b"my secrets/go.sh",
                true,
                TextMode::Text,
                Some(EolMode::Lf),
            ),
            (
                "a name that ends in a space",
                "\"secrets /\"\n",
                b"secrets /a.env",
                true,
                TextMode::Auto,
                None,
            ),
            (
                "a leading ! that is part of the name",
                "\"!odd.env\"\n",
                b"!odd.env",
                true,
                TextMode::Auto,
                None,
            ),
            (
                "a leading # that is part of the name",
                "\"#notes.env\"\n",
                b"#notes.env",
                true,
                TextMode::Auto,
                None,
            ),
            (
                "a quote inside the name",
                "\"od\\\"d.env\"\n",
                b"od\"d.env",
                true,
                TextMode::Auto,
                None,
            ),
            (
                "an octal escape spelling a letter",
                "\"secrets/\\101.env\"\n",
                b"secrets/A.env",
                true,
                TextMode::Auto,
                None,
            ),
            (
                "binary suppresses the diff driver",
                "secrets/key.p12 binary\n",
                b"secrets/key.p12",
                true,
                TextMode::Binary,
                None,
            ),
            (
                "a negation keeps its ! outside the quotes",
                "\"my secrets/\"\n!\"my secrets/README.md\"\n",
                b"my secrets/README.md",
                false,
                TextMode::Auto,
                None,
            ),
            (
                "a bare negation still works",
                "secrets/\n!secrets/README.md\n",
                b"secrets/README.md",
                false,
                TextMode::Auto,
                None,
            ),
            // Open decision 13, settled 2026-08-05. See `MATCHING`.
            (
                "a pattern reaches every ASCII spelling of the name",
                "secrets/\n",
                b"SEcrets/db.env",
                true,
                TextMode::Auto,
                None,
            ),
            (
                "…attributes come with it",
                "secrets/*.sh text\n",
                b"SEcrets/Go.SH",
                true,
                TextMode::Text,
                None,
            ),
            (
                "…and so does a negation, or the hole closes on a rename",
                "secrets/\n!secrets/README.md\n",
                b"SEcrets/README.MD",
                false,
                TextMode::Auto,
                None,
            ),
            (
                "folding stops at ASCII, exactly where git stops",
                "\u{142}\u{105}ka/\n",
                "\u{141}\u{104}KA/a.txt".as_bytes(),
                false,
                TextMode::Auto,
                None,
            ),
        ];

        for (label, text, path, encrypt, mode, eol) in accepted {
            let parsed = Config::parse(text)
                .unwrap_or_else(|error| panic!("{label}: this must parse, and says: {error}"));
            let decision = parsed.decide(path);
            assert_eq!(
                decision.encrypt,
                *encrypt,
                "{label}: `{}` should{} be encrypted",
                String::from_utf8_lossy(path),
                if *encrypt { "" } else { " not" }
            );
            if *encrypt {
                assert_eq!(decision.text, *mode, "{label}: wrong text mode");
                assert_eq!(decision.eol, *eol, "{label}: wrong end-of-line mode");
            }
        }
    }
}
