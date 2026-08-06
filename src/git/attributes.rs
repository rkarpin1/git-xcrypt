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

use crate::git::repo::{ATTRIBUTES_FILE, CONFIG_FILE, DRIVER, KEY_ENVELOPE_DIR, git_spelling};
use crate::rules::declaration::Config;
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
/// Finally, the files needed to bootstrap — see [`crate::rules::declaration::is_never_encrypted`] —
/// get their defaults back if any pattern reached them, because they are stored
/// in the clear whatever the patterns say.
///
/// Within each group the order is the input's, so the section is a pure function
/// of the configuration and two runs produce the same file.
#[must_use]
pub fn render_lines(config: &Config, rendering: Rendering) -> Vec<String> {
    let fold = match rendering {
        // One line, and nothing about it depends on the declaration — which is
        // exactly what makes a stale section impossible in this mode.
        Rendering::Global => return vec![GLOBAL_LINE.to_string()],
        Rendering::PerPattern { fold_case } => fold_case,
    };
    let mut lines: Vec<String> = Vec::new();
    let mut suppressed: Vec<String> = Vec::new();

    for pattern in config.patterns() {
        for spelling in translate(pattern.source, fold) {
            if pattern.negated {
                lines.push(format!("{spelling} !text !diff"));
            } else {
                lines.push(format!("{spelling} filter={DRIVER} -text diff={DRIVER}"));
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
    deduplicated.extend(bootstrap_exclusions(config, fold));
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
///
/// Folded like every other line here, because [`crate::rules::declaration::is_never_encrypted`]
/// compares these three names with ASCII case folded too. A line narrower than
/// the exclusion would put `-text` and a decrypting diff driver on a file that is
/// stored in the clear; a line broader than it would take them off one that is
/// not. Both halves have to move together.
///
/// **The probes are representatives, not an enumeration, and the gap is known
/// and measured (2026-08-05).** `sub/.gitattributes` stands in for "a nested
/// attributes file", so a pattern that reaches one only under its own directory
/// — `secrets/` reaching `secrets/.gitattributes` — emits no exclusion, and
/// that file carries `-text diff=git-xcrypt` while stored in the clear.
/// Measured on git 2.55 with `core.autocrlf=true`: the file round-trips byte
/// for byte, `git status` stays clean, `git diff` renders normally (the
/// textconv driver passes plain text through), and git itself strips the `CR`
/// of a CRLF-spelled attributes line when parsing, so even the un-managed line
/// endings change nothing the file *does*. The only observable effect is that
/// git stops normalising that one clear file's line endings. Enumerating
/// faithfully would need the working tree at render time — the section is a
/// pure function of the configuration on purpose — and emitting the exclusion
/// unconditionally would rewrite every generated file to cover a state with no
/// measured cost.
fn bootstrap_exclusions(config: &Config, fold: bool) -> Vec<String> {
    let mut lines = Vec::new();

    // `.gitattributes` is excluded by basename at any depth, the other two only
    // where they are read from.
    let reached = |path: &str| config.decide_ignoring_exclusions(path.as_bytes()).encrypt;

    if reached(ATTRIBUTES_FILE) || reached(&format!("sub/{ATTRIBUTES_FILE}")) {
        lines.push(format!("**/{} !text !diff", folded(ATTRIBUTES_FILE, fold)));
    }
    if reached(CONFIG_FILE) {
        lines.push(format!("/{} !text !diff", folded(CONFIG_FILE, fold)));
    }
    if reached(&format!("{KEY_ENVELOPE_DIR}/recipient")) {
        lines.push(format!(
            "/{}/** !text !diff",
            folded(KEY_ENVELOPE_DIR, fold)
        ));
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
/// C-quoted — which is also how `.git-xcrypt` has spelled such a pattern since
/// 2026-08-05, so the two files now close a space the same way and [`spell`]
/// only has to put the quotes back around what the parser took them off.
///
/// Two openings send git somewhere other than its pattern matcher, and quoting
/// rescues neither: a line opening with `[attr]` is a macro definition, and one
/// opening with `!` is discarded outright (`warning: Negative patterns are
/// ignored in git attributes`). Both are given a leading `**/` or `/` by
/// [`guard`] instead, which means exactly what the unprefixed spelling meant in
/// a root `.gitattributes`.
fn translate(pattern: &str, fold: bool) -> Vec<String> {
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
        spellings.push(spell(&folded(&guard(core.to_string(), anchored), fold)));
    }
    spellings.push(spell(&folded(
        &guard(
            if anchored {
                format!("{core}/**")
            } else {
                format!("**/{core}/**")
            },
            anchored,
        ),
        fold,
    )));
    spellings
}

/// Spells a pattern so it matches either case of every ASCII letter.
///
/// The other half of open decision 13, settled on 2026-08-05, and it is not
/// optional: [`crate::rules::declaration::MATCHING`] folds ASCII case unconditionally, so a
/// rendered line that did not would be **narrower** than the filter — and the
/// narrow direction is the one measured eating 34 `CR` bytes out of a 2 MB
/// ciphertext and losing the file at checkout. Emitting the fold rather than
/// leaning on `core.ignorecase` is what makes the two agree on every machine:
/// measured on git 2.55, `**/secrets/**` answers `unspecified` for
/// `SEcrets/db.txt` where the setting is false, while
/// `**/[sS][eE][cC][rR][eE][tT][sS]/**` answers `unset` whatever it is set to.
///
/// Four things in a pattern are not plain letters, and each is left meaning what
/// it meant:
///
/// * **a glob escape.** `\s` is the literal `s`, so it becomes `[sS]` — the
///   backslash was doing nothing a character class does not. `\*` and every
///   other escaped metacharacter is passed through with its backslash.
/// * **a character class.** `[a-z]` cannot become `[[aA]-[zZ]]`; the counterpart
///   is added *inside* the brackets instead, giving `[a-zA-Z]`. A negated class
///   gets it too, which is right: folding `[!a]` must stop it matching `A`.
/// * **a POSIX class**, `[[:alpha:]]`, whose members are named rather than
///   spelled, so there is nothing to rewrite and it is copied whole — except
///   the two classes that *are* a case: `[:upper:]` and `[:lower:]` each gain
///   their counterpart, because the selection side folds them too. Measured:
///   `gix-glob` under `Case::Fold` lowercases the candidate first, so
///   `[[:upper:]]dir/` selects `xdir/a.env` — and a verbatim copy answers
///   `unspecified` for it at `core.ignorecase=false`, the narrower-than-the-
///   filter direction that costs the file.
/// * **anything outside ASCII**, which is copied byte for byte. That is the
///   documented boundary — see [`crate::rules::declaration::MATCHING`].
///
/// Quoting is not this function's business. It runs before [`spell`], which puts
/// the quotes back around a pattern that needs them, and `[`, `]` and `-` are
/// ordinary characters to git's C-unquoting. It runs *after* [`guard`] for the
/// opposite reason: `guard` recognises a literal `[attr]` opening, and folding
/// first would turn it into `[attrATTR]` and hide it.
/// How the managed section spells what it protects.
///
/// Two shapes, and the choice is a trade this project measured rather than
/// guessed.
///
/// `PerPattern` writes a line per declared pattern, each naming the filter, the
/// `-text` that protects the ciphertext and the diff driver — the shape
/// `git-crypt` users will recognise. It is what `sync` writes when nothing asks
/// otherwise, and it confines the diff driver to declared paths.
///
/// `Global` is one line covering the whole repository. `init` writes it, so a
/// repository works correctly before `sync` has ever run and nothing can go
/// stale; `sync --global` puts it back. Its cost is the diff driver on every
/// file.
///
/// The cost that decides between them is the `diff` driver, and it is a process
/// per blob — git has no long-running protocol for `textconv` the way it has one
/// for filters. Measured on git 2.55, 2026-08-06, against the same repository
/// with the driver unregistered:
///
/// | files in the diff | global | per pattern |
/// | --- | --- | --- |
/// | 5 | 72 ms | 21 ms |
/// | 20 | 201 ms | 22 ms |
/// | 100 | 899 ms | 25 ms |
/// | 1000 | 8461 ms | 23 ms |
///
/// So an everyday diff pays nothing anyone notices, and a thousand-file review
/// pays eight seconds. `init` writes `Global` so a fresh repository is correct
/// with no second command; `sync` writes `PerPattern`, which is what a
/// repository settles into once anyone runs it.
///
/// The other half of `Global` is `-text` on every path, which stops git
/// normalising line endings anywhere in the repository. That is the price of
/// needing no `sync`: the same attribute is what keeps git's CRLF conversion
/// off the ciphertext, and one line cannot say it for some paths only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rendering {
    /// One line, covering everything. Correct with no `sync` in the flow.
    Global,
    /// One line per declared pattern, with ASCII case folded when asked.
    PerPattern { fold_case: bool },
}

/// The one line `Rendering::Global` emits after the catch-all.
const GLOBAL_LINE: &str = "* -text diff=git-xcrypt";

/// [`render_lines`] in whichever spelling the file already uses.
///
/// For the three commands that repair this section without being asked to
/// change it — `init`, `unlock`, `lock`. Only `sync` decides the spelling, and
/// a repair that silently picked the other one would undo that decision:
/// measured before this existed, an ordinary `unlock` rewrote a section written
/// by `sync --ignorecase` back to the literal form and left `git status` dirty.
///
/// A file that matches neither spelling is out of date either way, and gets the
/// literal one — the same default `sync` uses when nothing asks otherwise.
#[must_use]
pub fn render_lines_as_written(path: &std::path::Path, config: &Config) -> Vec<String> {
    for rendering in ACCEPTED {
        let lines = render_lines(config, rendering);
        if desired(path, &lines).is_ok_and(|(existing, wanted)| existing == wanted) {
            return lines;
        }
    }
    render_lines(config, Rendering::Global)
}

/// Every spelling of the section this build considers current.
///
/// Order matters only for the tie nobody can hit — a repository declaring
/// nothing renders the same either way. `Global` comes first because it is what
/// `init` wrote, so it is what a repository nobody has run `sync` in will
/// match.
pub const ACCEPTED: [Rendering; 3] = [
    Rendering::Global,
    Rendering::PerPattern { fold_case: false },
    Rendering::PerPattern { fold_case: true },
];

/// [`fold_case`] when asked, the pattern untouched when not.
///
/// The choice belongs to `sync --ignorecase` and is threaded through every
/// renderer rather than read from anywhere, because four other commands write
/// this same section and a setting only one of them knew would be undone by the
/// next one — measured: a hand-written literal section was rewritten folded by
/// an ordinary `unlock`, leaving `git status` dirty.
fn folded(pattern: &str, fold: bool) -> String {
    if fold {
        fold_case(pattern)
    } else {
        pattern.to_string()
    }
}

fn fold_case(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() * 4);
    let mut index = 0;

    while index < pattern.len() {
        let character = pattern[index..]
            .chars()
            .next()
            .expect("index sits on a character boundary");

        if character == '\\' {
            match pattern[index + 1..].chars().next() {
                Some(escaped) if escaped.is_ascii_alphabetic() => {
                    push_either_case(&mut out, escaped);
                    index += 1 + escaped.len_utf8();
                }
                Some(escaped) => {
                    out.push('\\');
                    out.push(escaped);
                    index += 1 + escaped.len_utf8();
                }
                // A trailing backslash escapes nothing. The parser refuses one
                // in `.git-xcrypt`, so this is only ever reached through a
                // quoted pattern, and passing it through is what keeps the two
                // files spelling the same name.
                None => {
                    out.push('\\');
                    index += 1;
                }
            }
            continue;
        }

        if character == '[' {
            if let Some((folded, after)) = fold_class(pattern, index) {
                out.push_str(&folded);
                index = after;
                continue;
            }
            // Unterminated: wildmatch reads the `[` as an ordinary character,
            // and so must this.
            out.push('[');
            index += 1;
            continue;
        }

        if character.is_ascii_alphabetic() {
            push_either_case(&mut out, character);
        } else {
            out.push(character);
        }
        index += character.len_utf8();
    }

    out
}

/// Writes `letter` as the two-character class matching either of its cases.
fn push_either_case(out: &mut String, letter: char) {
    out.push('[');
    out.push(letter.to_ascii_lowercase());
    out.push(letter.to_ascii_uppercase());
    out.push(']');
}

/// The same letter in the other case.
fn flip_case(letter: char) -> char {
    if letter.is_ascii_lowercase() {
        letter.to_ascii_uppercase()
    } else {
        letter.to_ascii_lowercase()
    }
}

/// Folds one bracket expression starting at `start`, returning it and its end.
///
/// `None` when the bracket is never closed, which wildmatch reads as a literal
/// `[`. Members are kept exactly as written and their counterparts appended, so
/// the class grows rather than changing shape: `[a-z_]` becomes `[a-z_A-Z]`.
fn fold_class(pattern: &str, start: usize) -> Option<(String, usize)> {
    let bytes = pattern.as_bytes();
    let mut index = start + 1;
    let mut body = String::new();
    let mut extra = String::new();

    // A leading `!` or `^` negates; a `]` straight after either is a member.
    if matches!(bytes.get(index), Some(b'!' | b'^')) {
        body.push(char::from(bytes[index]));
        index += 1;
    }
    if bytes.get(index) == Some(&b']') {
        body.push(']');
        index += 1;
    }

    while index < bytes.len() {
        if bytes[index] == b']' {
            // A literal `-` is a member only when nothing follows it, so the
            // case counterparts have to slide in *before* it. Appending them
            // after made `[a-]` render as `[a-A]` — measured on git 2.55 with
            // `core.ignorecase=false`, that line matches `a.env` and neither
            // `A.env` nor `-.env`, both of which the filter selects: encrypted
            // paths with no `-text`, the half of the covering rule that costs
            // the file. An *escaped* trailing dash stays where it is — it
            // cannot open a range.
            let (kept, trailing_dash) = if body.ends_with('-') && !body.ends_with("\\-") {
                (&body[..body.len() - 1], true)
            } else {
                (body.as_str(), false)
            };
            let mut out = String::with_capacity(body.len() + extra.len() + 2);
            out.push('[');
            out.push_str(kept);
            out.push_str(&extra);
            if trailing_dash {
                out.push('-');
            }
            out.push(']');
            return Some((out, index + 1));
        }

        // `[:alpha:]` and friends name their members, so there is nothing to
        // add — and a `[` that opens one is not a member either. Two of the
        // names *are* a case, and selection folds them: under `Case::Fold`
        // `gix-glob` lowercases the candidate before the class test and lets
        // `[:upper:]` accept a lowercase letter, so each of the pair matches
        // every ASCII letter — exactly what the named counterpart adds here.
        if bytes[index] == b'[' && bytes.get(index + 1) == Some(&b':') {
            let end = index + pattern[index..].find(":]")? + 2;
            body.push_str(&pattern[index..end]);
            match &pattern[index + 2..end - 2] {
                "upper" => extra.push_str("[:lower:]"),
                "lower" => extra.push_str("[:upper:]"),
                _ => {}
            }
            index = end;
            continue;
        }

        if bytes[index] == b'\\' {
            let escaped = pattern[index + 1..].chars().next()?;
            body.push('\\');
            body.push(escaped);
            if escaped.is_ascii_alphabetic() {
                extra.push('\\');
                extra.push(flip_case(escaped));
            }
            index += 1 + escaped.len_utf8();
            continue;
        }

        let low = pattern[index..]
            .chars()
            .next()
            .expect("index sits on a character boundary");
        let after_low = index + low.len_utf8();

        // A range, but only where the `-` really separates two members: a `-`
        // immediately before the closing bracket is itself a member.
        if bytes.get(after_low) == Some(&b'-')
            && bytes.get(after_low + 1).is_some_and(|byte| *byte != b']')
        {
            let high = pattern[after_low + 1..].chars().next()?;
            body.push(low);
            body.push('-');
            body.push(high);
            // Only a range whose ends share a case has a counterpart range; the
            // ends of anything else are not letters in the same alphabet and
            // flipping them could invert the range.
            if low.is_ascii_alphabetic()
                && high.is_ascii_alphabetic()
                && low.is_ascii_lowercase() == high.is_ascii_lowercase()
            {
                extra.push(flip_case(low));
                extra.push('-');
                extra.push(flip_case(high));
            }
            index = after_low + 1 + high.len_utf8();
            continue;
        }

        body.push(low);
        if low.is_ascii_alphabetic() {
            extra.push(flip_case(low));
        }
        index = after_low;
    }

    None
}

/// What git reads as the start of a macro definition rather than a pattern.
const MACRO_PREFIX: &str = "[attr]";

/// Keeps a spelling out of the branches git takes before it ever matches it.
///
/// An anchored pattern already carries a slash, so a leading one only makes
/// explicit what a root `.gitattributes` does anyway; a floating one gets the
/// `**/` that git documents as equivalent to no prefix at all.
///
/// Two openings need it, and in both cases the line is lost in silence without
/// it — the pattern simply never reaches git's matcher, so the `-text` this
/// renderer exists to place is not there:
///
/// * `[attr]`, which git reads as a macro definition rather than a pattern;
/// * `!`, which git discards with `warning: Negative patterns are ignored in
///   git attributes`. A name whose leading `!` is part of it became spellable on
///   2026-08-05, when quoting arrived in `.git-xcrypt` and the parser stopped
///   reading a quoted `!` as the negation marker — so `"!weird.env"` selects a
///   real file, and `.gitattributes` has to cover it.
///
/// **Quoting rescues neither**, which is why this is a prefix rather than a
/// stanza in [`spell`]. Measured on git 2.55: the macro check runs before the
/// unquoting, and `"!weird.env"` draws the negative-pattern warning too, so git
/// tests for `!` *after* unquoting. `**/!weird.env` and `/!secrets/x.env` were
/// measured resolving `text: unset` and `diff: xc` for the paths they name.
fn guard(spelling: String, anchored: bool) -> String {
    if !spelling.starts_with(MACRO_PREFIX) && !spelling.starts_with('!') {
        return spelling;
    }
    if anchored {
        format!("/{spelling}")
    } else {
        format!("**/{spelling}")
    }
}

/// One pattern, escaped and quoted the way git's attribute parser reads it.
///
/// The pattern arrives literal: `.git-xcrypt` has already unwrapped its own
/// quoting, so every backslash still standing here is wildmatch's — and
/// wildmatch is the same engine on both sides, so it is passed through
/// untouched, doubled only where the C-quoting layer would otherwise eat it.
fn spell(pattern: &str) -> String {
    // Three shapes have to be quoted, and each one is a silent failure
    // otherwise: whitespace ends the pattern and turns the rest into
    // attributes; a leading quote sends git into its C-quoting parser
    // mid-pattern; a leading `#` makes git read the whole line as a comment, so
    // the `-text` for that path would simply not be there. A leading `[attr]`
    // and a leading `!` are handled by `guard` rather than here, because quoting
    // does not rescue either — measured on git 2.55, the macro check runs before
    // the unquoting, and the negative-pattern check runs after it.
    if !pattern.contains(char::is_whitespace)
        && !pattern.starts_with('"')
        && !pattern.starts_with('#')
    {
        return pattern.to_string();
    }

    let mut quoted = String::with_capacity(pattern.len() + 2);
    quoted.push('"');
    for character in pattern.chars() {
        match character {
            '"' | '\\' => {
                quoted.push('\\');
                quoted.push(character);
            }
            '\t' => quoted.push_str("\\t"),
            '\r' => quoted.push_str("\\r"),
            '\n' => quoted.push_str("\\n"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// Renders the body of the managed section, LF-terminated.
#[must_use]
pub fn render_section(extra_lines: &[String]) -> String {
    render_section_with(extra_lines, "\n")
}

/// Renders the body of the managed section with a chosen line terminator.
///
/// `ending` is `"\n"` everywhere a file is being created from nothing, and
/// `"\r\n"` when the file being edited already spells its lines that way — see
/// [`line_ending_of`] for why that is not cosmetic.
#[must_use]
pub fn render_section_with(extra_lines: &[String], ending: &str) -> String {
    let mut out = String::new();
    out.push_str(BEGIN);
    out.push_str(ending);
    out.push_str(CATCH_ALL);
    out.push_str(ending);
    for line in extra_lines {
        out.push_str(line);
        out.push_str(ending);
    }
    out.push_str(END);
    out.push_str(ending);
    out
}

/// The line terminator a rewrite of this file should reproduce.
///
/// **Not always LF, and that is a correctness matter rather than tidiness.**
/// Nothing in the managed section declares `.gitattributes` itself, so under
/// `core.autocrlf=true` — what Git for Windows installs by default — git checks
/// that file out with CRLF. Rendering the replacement with LF then made the
/// comparison in [`desired`] fail on a section that was current in every way git
/// can see, and the consequences were all in the wrong direction:
///
/// * `sync --check`, which exists to be a CI gate, exited `1` on a healthy
///   repository — and a gate that fires on the platform's default configuration
///   is a gate that gets switched off, the same argument that won `status` its
///   own exit code `6`;
/// * `status` printed a note saying the per-pattern lines were out of date and
///   the ciphertext was at risk of silent corruption, which was false;
/// * running `sync` to settle it wrote an LF section into a CRLF file, leaving
///   `git status` dirty with no way out: the next checkout put the CRLF back.
///
/// Measured on git 2.55: for a CRLF-spelled section `git check-attr filter text
/// diff` answers `git-xcrypt`, `unset`, `git-xcrypt` — identical to the LF
/// spelling. Git strips the `CR` itself, so both spellings enforce the same
/// thing and the file's own convention is the one worth keeping.
///
/// The section's opening marker decides, because the section is the only part of
/// the file a rewrite touches. With no section yet the file's first line decides,
/// and an empty file gets LF.
fn line_ending_of(contents: &str) -> &'static str {
    let sample = marker_line(contents, BEGIN)
        .map(|(begin, after)| &contents[begin..after])
        .or_else(|| contents.split_inclusive('\n').next())
        .unwrap_or_default();

    if sample.ends_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
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
                ATTRIBUTES = crate::git::repo::ATTRIBUTES_FILE
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
            ATTRIBUTES = crate::git::repo::ATTRIBUTES_FILE
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
            ATTRIBUTES = crate::git::repo::ATTRIBUTES_FILE
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
    // The file's own spelling, not ours: see [`line_ending_of`]. A file that
    // already uses LF — every repository on Unix, and every one this tool
    // created — renders exactly as it always did.
    let section = render_section_with(extra_lines, line_ending_of(&existing));
    let updated = upsert(&existing, &section)?;
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
    crate::util::atomic::write(path, updated.as_bytes())?;
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

/// Lines outside the managed section that touch one of `axes`.
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
/// `axes` names the attributes worth looking for — `status` asks about `filter`
/// alone, `sync` about the axes that can cost something. `diff` is deliberately
/// on nobody's list: measured 2026-08-05, a foreign line setting `diff=lfs`,
/// `-diff` or `diff` on a declared path costs a readable `git diff` and not one
/// byte in the repository.
///
/// # Errors
///
/// [`Error::Io`] when the file exists but cannot be read, [`Error::Config`] when
/// it is not text.
pub fn foreign_lines_touching(path: &Path, axes: &[&str]) -> Result<Vec<String>> {
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
                axes.iter().any(|axis| {
                    let bare = token
                        .strip_prefix('-')
                        .or_else(|| token.strip_prefix('!'))
                        .unwrap_or(token);
                    bare == *axis || bare.starts_with(&format!("{axis}="))
                })
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
///
/// **Each directory's file is probed by name, never matched against the
/// listing.** Git does the same — it `open`s `<dir>/.gitattributes` and lets
/// the filesystem resolve the name — and the two ways differ exactly where it
/// costs a file: on APFS and NTFS a file *stored* as `.GITATTRIBUTES` **is**
/// the attributes file to git, measured on git 2.55 (`* -text` in
/// `secrets/.GITATTRIBUTES` answered `text: unset` for `secrets/db.env`),
/// while a listing comparison never saw it — so a `text` line in one converted
/// the ciphertext with no gate firing anywhere. On a case-sensitive filesystem
/// the same probe finds nothing, which is also exactly git. The probe works in
/// a directory whose mode allows lookup but not listing, too — git never lists
/// either.
fn collect_attribute_files(root: &Path, out: &mut Vec<PathBuf>) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let file = directory.join(crate::git::repo::ATTRIBUTES_FILE);
        // Never followed: a symbolic link out of the working tree would walk
        // somewhere that is not this repository, and one pointing back into
        // it would loop.
        if fs::symlink_metadata(&file).is_ok_and(|metadata| metadata.is_file()) {
            out.push(file);
        }

        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() && entry.file_name() != std::ffi::OsStr::new(".git") {
                pending.push(entry.path());
            }
        }
    }
}

/// A `.gitattributes` whose working-tree file is gone but whose staged copy
/// git still reads on the check-in path.
///
/// Git's `read_attr` tries the working-tree file first and, when it is not
/// there, reads the **index** copy — measured on git 2.55: with a
/// `secrets/** text` line staged in `.gitattributes` and the file deleted from
/// the working tree, `git add` still converted the filter's output (7003 `CR`
/// bytes eaten out of a 512 KiB ciphertext, exit 0, file unrecoverable at
/// checkout). A resolver that read only the working tree was blind to exactly
/// that — and deleting the file is the very move the check-in refusal's own
/// message can prompt, when it says to delete the offending *line*.
#[derive(Debug, Clone)]
pub struct StagedAttributes {
    /// The absolute path the file would occupy in the working tree.
    pub path: PathBuf,
    /// The staged contents.
    pub contents: Vec<u8>,
}

/// The `.gitattributes` files git would read from the index for check-in.
///
/// One entry per `.gitattributes` recorded in the index whose working-tree file
/// is absent; a file that is present wins outright on the check-in side, so it
/// is not listed here at all. The name is compared the way git looks it up:
/// byte-exact, or ASCII-case-folded when `core.ignorecase` is set — the same
/// split the resolver itself applies to pattern matching.
///
/// Everything that cannot be read answers with an **empty list** rather than an
/// error, and that direction is deliberate: the resolver's one consumer that
/// must never grow a false refusal is the filter, and a missing fallback only
/// ever reproduces the pre-2026-08-05 behaviour. `status` reports an unreadable
/// index through its own `undetermined` section, not through this.
#[must_use]
pub fn staged_fallbacks(
    work_tree: &Path,
    index_path: &Path,
    common_dir: &Path,
    hash: gix_hash::Kind,
    ignore_case: bool,
) -> Vec<StagedAttributes> {
    let Ok(crate::git::index::Listed::Read(entries)) = crate::git::index::list(index_path, hash)
    else {
        return Vec::new();
    };

    let wanted = crate::git::repo::ATTRIBUTES_FILE.as_bytes();
    let named = |name: &[u8]| {
        if ignore_case {
            name.eq_ignore_ascii_case(wanted)
        } else {
            name == wanted
        }
    };

    use gix_object::Find as _;

    let basename_of = |entry: &crate::git::index::Tracked| -> Vec<u8> {
        entry
            .path
            .rsplit(|&byte| byte == b'/')
            .next()
            .unwrap_or(&entry.path)
            .to_vec()
    };

    let mut candidates: Vec<&crate::git::index::Tracked> = entries
        .iter()
        .filter(|entry| entry.holds_content() && named(&basename_of(entry)))
        .collect();
    // One copy per folded path. With `core.ignorecase` the index can hold two
    // spellings at once — a tree made on a case-sensitive filesystem, checked
    // out here — while git's own lookup finds a single entry. The byte-exact
    // name is the one git probes for, so it goes first and wins; reading both
    // could hand the resolver a line in the copy git ignores, and on the
    // filter that is a false refusal.
    candidates.sort_by_key(|entry| basename_of(entry) != wanted);
    let mut seen: Vec<Vec<u8>> = Vec::new();

    let mut objects = None;
    let mut buffer = Vec::new();
    let mut found = Vec::new();
    for entry in candidates {
        if ignore_case {
            let folded = entry.path.to_ascii_lowercase();
            if seen.contains(&folded) {
                continue;
            }
            seen.push(folded);
        }

        // The working-tree probe, by name, exactly as `collect_attribute_files`
        // probes: a file that is there — under any spelling the filesystem
        // resolves — is the one git reads, and the staged copy stays out of it.
        let absolute = work_tree.join(crate::git::repo::working_tree_path(&entry.path));
        if fs::symlink_metadata(&absolute).is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }

        // The object store is opened only when a fallback actually exists, so a
        // repository whose attribute files are all on disk never pays for it.
        if objects.is_none() {
            objects = Some(crate::git::history::objects(common_dir, hash).ok());
        }
        let Some(Some(store)) = objects.as_ref() else {
            return Vec::new();
        };
        let Ok(id) = gix_hash::oid::try_from_bytes(&entry.id) else {
            continue;
        };
        if let Ok(Some(data)) = store.try_find(id, &mut buffer) {
            found.push(StagedAttributes {
                path: absolute,
                contents: data.data.to_vec(),
            });
        }
    }
    found
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

/// The `eol=` value git resolved, in the only two spellings that decide anything.
///
/// Kept beside [`EolConversion`] instead of folded into it because the two answer
/// different questions. [`EolConversion`] is the check-**in** verdict and does not
/// depend on configuration at all: `text` strips `CR` on the way into the object
/// database whatever `core.autocrlf` says. The check-**out** direction does depend
/// on it, and on this attribute — `text eol=lf` converts on the way in and writes
/// the stored bytes out untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredEol {
    /// No `eol=`, or a value git does not recognise: the configuration decides.
    Unspecified,
    /// `eol=lf`.
    Lf,
    /// `eol=crlf`.
    Crlf,
}

/// What git resolves for one path, on both axes the managed section sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// Whether git would run this tool for the path.
    pub filter: FilterAttribute,
    /// Whether git would convert the path's line endings itself.
    pub conversion: EolConversion,
    /// The `eol=` the path resolved to, which only the check-out side reads.
    pub eol: DeclaredEol,
}

impl Resolution {
    /// The line that makes git expand `LF` to `CRLF` on the way **out** of the
    /// object database, if any.
    ///
    /// Not the same question as [`Self::conversion`], and the difference is
    /// measured rather than reasoned. On git 2.55, with `core.autocrlf=true` and
    /// a blob full of lone `LF`:
    ///
    /// | line                | check-in            | check-out          |
    /// | ------------------- | ------------------- | ------------------ |
    /// | `p text`            | strips `CR`         | **expands**        |
    /// | `p text eol=lf`     | strips `CR`         | untouched          |
    /// | `p text eol=crlf`   | strips `CR`         | **expands**        |
    /// | `p eol=crlf`        | strips `CR`         | **expands**        |
    /// | `p -text`, `binary` | untouched           | untouched          |
    /// | `p text=auto`       | untouched (the NUL) | untouched          |
    ///
    /// Reusing the check-in verdict here would claim the second row damages a
    /// checkout, which it does not — and on that row the bytes handed to the
    /// authentication tag really are the stored ones, so a failing tag means the
    /// file, not the configuration.
    #[must_use]
    pub fn expands_on_checkout(
        &self,
        autocrlf: Option<&str>,
        core_eol: Option<&str>,
    ) -> Option<&Culprit> {
        let EolConversion::On(culprit) = &self.conversion else {
            return None;
        };
        let writes_crlf = match self.eol {
            DeclaredEol::Crlf => true,
            DeclaredEol::Lf => false,
            DeclaredEol::Unspecified => crate::rules::eol::git_writes_crlf(autocrlf, core_eol),
        };
        writes_crlf.then_some(culprit)
    }
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

/// One axis' contribution to git's `crlf_action`, before `eol` is consulted.
///
/// The mapping is `git_path_check_crlf`, and one function serves two
/// attributes on purpose: git consults `text` first and, when it says nothing,
/// falls back to the pre-1.7.2 `crlf` attribute — which it still honours.
/// Measured on git 2.55 rather than read from the sources, on a file whose
/// leading NUL would satisfy any binary detection: `set` and the value `input`
/// convert unconditionally, `unset` is binary and skips `eol` entirely (the
/// `-crlf eol=lf` row was measured untouched, like `-text`), the value `auto`
/// keeps binary detection, and any other value is as if the attribute were not
/// on the line at all — inert alone, promoted by a bare `eol=` exactly as
/// `unspecified` is.
enum CrlfAction<'a> {
    /// `text` / `crlf`: converts on the way in, direction from `eol` and the
    /// configuration on the way out.
    Convert(&'a Culprit),
    /// `text=input` / `crlf=input`: converts on the way in, writes `LF` on the
    /// way out whatever the configuration says — measured, a blob of lone `LF`
    /// under `text=input` checked out untouched at `core.autocrlf=true`.
    ConvertAsInput(&'a Culprit),
    /// `-text` / `-crlf`: no conversion, and `eol` is skipped entirely.
    Binary,
    /// `text=auto` / `crlf=auto`: binary detection, which our leading NUL answers.
    Auto,
}

/// What one of the two text axes says, or `None` when it says nothing.
fn crlf_action(resolved: Option<&Resolved>) -> Option<CrlfAction<'_>> {
    use gix_attributes::State;
    match resolved {
        Some((State::Set, culprit)) => Some(CrlfAction::Convert(culprit)),
        Some((State::Unset, _)) => Some(CrlfAction::Binary),
        Some((State::Value(value), culprit)) => match value.as_ref().as_bstr() {
            value if value == "auto" => Some(CrlfAction::Auto),
            value if value == "input" => Some(CrlfAction::ConvertAsInput(culprit)),
            _ => None,
        },
        Some((State::Unspecified, _)) | None => None,
    }
}

/// Whether the resolved `text`, `crlf` and `eol` make git convert stored bytes.
///
/// The whole table, measured on git 2.55 — the 2 MB rows by a byte-for-byte
/// round trip through `git add`, `git commit`, `rm` and `git checkout`, the
/// remaining rows on a NUL-led file with `CRLF` pairs and `core.autocrlf=false`,
/// judged by the stored blob's size:
///
/// | `text`        | `crlf`       | `eol`      | result                               |
/// | ------------- | ------------ | ---------- | ------------------------------------ |
/// | `unset`       | any          | any        | untouched — `-text` beats both       |
/// | `auto`        | any          | any        | untouched — detection sees the NUL   |
/// | `set`         | —            | any        | **converted, file lost at checkout** |
/// | `input`       | —            | any        | **converted** — no binary detection  |
/// | says nothing  | `set`/`input`| any        | **converted** — the legacy fallback  |
/// | says nothing  | `unset`      | any        | untouched — `-crlf` beats `eol` too  |
/// | says nothing  | `auto`       | any        | untouched — detection sees the NUL   |
/// | says nothing  | says nothing | unset      | untouched, at every `core.autocrlf`  |
/// | says nothing  | says nothing | `lf`/`crlf`| **converted, file lost at checkout** |
///
/// "Says nothing" covers `unspecified` *and* any value other than `auto` and
/// `input` — `text=junk` was measured inert alone and fatal with a bare
/// `eol=crlf` beside it, exactly like `unspecified`. The promotion row is
/// git's own rule, in `convert_attrs`: an `eol` attribute promotes an undefined
/// `crlf_action` straight to `CRLF_TEXT_INPUT`/`CRLF_TEXT_CRLF`, and only the
/// `CRLF_AUTO*` actions consult binary detection.
///
/// The safe rows are as load-bearing as the dangerous ones: a gate that fires on
/// `text=auto` or on an ordinary `core.autocrlf=true` teaches a user to ignore
/// it, and an ignored gate protects nothing.
fn converts(
    text: Option<&Resolved>,
    crlf: Option<&Resolved>,
    eol: Option<&Resolved>,
) -> EolConversion {
    use gix_attributes::State;

    match crlf_action(text).or_else(|| crlf_action(crlf)) {
        Some(CrlfAction::Convert(culprit) | CrlfAction::ConvertAsInput(culprit)) => {
            return EolConversion::On(culprit.clone());
        }
        Some(CrlfAction::Binary | CrlfAction::Auto) => return EolConversion::Off,
        None => {}
    }

    // Neither axis says anything. A bare `eol=` is enough on its own.
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
    ///
    /// `common_dir`, **not this checkout's git directory**: `info/` is on git's
    /// common list, so every linked worktree reads the *same*
    /// `info/attributes`. Measured on git 2.55 with one linked worktree and
    /// `secrets/** -filter` in the main `.git/info/attributes`: `git check-attr
    /// filter` answers `unset` in both checkouts, and a file dropped in
    /// `.git/worktrees/side/info/attributes` is ignored in both. Reading the
    /// worktree's own directory therefore got it wrong twice over — it missed
    /// the source that decides and would have read one git never consults.
    ///
    /// `staged` is what [`staged_fallbacks`] found: the `.gitattributes` files
    /// git reads from the **index** because their working-tree file is gone.
    /// They take part in the ordinary precedence, by the directory they would
    /// occupy — git treats the fallback copy exactly as it would treat the
    /// file.
    #[must_use]
    pub fn new(
        work_tree: &Path,
        common_dir: &Path,
        global: Option<&Path>,
        ignore_case: bool,
        staged: Vec<StagedAttributes>,
    ) -> Self {
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

        let mut on_disk: Vec<PathBuf> = Vec::new();
        collect_attribute_files(work_tree, &mut on_disk);
        // The staged copies join the on-disk files in one list, so the sort
        // below is the only thing deciding precedence for both.
        let mut tree_sources: Vec<(PathBuf, Option<Vec<u8>>)> = on_disk
            .into_iter()
            .map(|path| (path, None))
            .chain(
                staged
                    .into_iter()
                    .map(|fallback| (fallback.path, Some(fallback.contents))),
            )
            .collect();
        // Shallowest first: git gives the file closest to the path the higher
        // precedence, and `Search` matches its lists last-added-first. Depth
        // before name, because a plain string sort does not order `a/x/.g`
        // against `a/.g` by depth in every alphabet.
        tree_sources.sort_by_key(|(path, _)| (path.components().count(), path.clone()));

        let mut sources: Vec<PathBuf> = Vec::new();
        for (source, contents) in tree_sources {
            // Macros only where git takes them: the root file. Anywhere deeper a
            // `[attr]` line is an ordinary pattern to git.
            let is_root = source.parent() == Some(work_tree);
            match contents {
                None => {
                    let _ = search.add_patterns_file(
                        source.clone(),
                        true,
                        Some(work_tree),
                        &mut buf,
                        &mut collection,
                        is_root,
                    );
                }
                Some(contents) => search.add_patterns_buffer(
                    &contents,
                    source.clone(),
                    Some(work_tree),
                    &mut collection,
                    is_root,
                ),
            }
            sources.push(source);
        }

        // Last, so it outranks every file in the working tree — which is exactly
        // what makes it the source an audit is least likely to look at.
        let info = common_dir.join("info").join("attributes");
        let _ = search.add_patterns_file(info.clone(), true, None, &mut buf, &mut collection, true);
        sources.push(info);
        // Reported alongside the rest even though it was loaded first: a global
        // file that silently unsets `filter` is a source a reader has to be told
        // about, whatever its precedence.
        sources.extend(global.map(Path::to_path_buf));

        let mut outcome = gix_attributes::search::Outcome::default();
        // Order matters: `iter_selected` yields one item per name, in this
        // order, with a placeholder where nothing matched.
        // `crlf` is the pre-1.7.2 spelling of `text`, and git still consults it
        // whenever `text` says nothing — leaving it out is how a `secrets/**
        // crlf` line converted a ciphertext with no gate firing anywhere.
        outcome.initialize_with_selection(&collection, ["filter", "text", "eol", "crlf"]);

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
        let crlf = found.next();

        // `text=input` and `crlf=input` fix the check-out direction to `LF`
        // whatever the configuration says — measured on git 2.55, a blob of
        // lone `LF` under `text=input` checked out untouched at
        // `core.autocrlf=true`. An explicit `eol=` still wins, so the override
        // applies only where the attribute said nothing.
        let checked_in_as_input = matches!(
            crlf_action(text.as_ref()).or_else(|| crlf_action(crlf.as_ref())),
            Some(CrlfAction::ConvertAsInput(_))
        );

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
            conversion: converts(text.as_ref(), crlf.as_ref(), eol.as_ref()),
            eol: {
                let declared = match eol.as_ref().map(|(state, _)| state) {
                    Some(State::Value(value)) => match value.as_ref().as_bstr() {
                        value if value == "lf" => DeclaredEol::Lf,
                        value if value == "crlf" => DeclaredEol::Crlf,
                        // `eol=native` and anything else git does not recognise:
                        // `git_path_check_eol` answers `EOL_UNSET` for them, so
                        // the configuration decides, exactly as with no `eol=`
                        // at all.
                        _ => DeclaredEol::Unspecified,
                    },
                    _ => DeclaredEol::Unspecified,
                };
                match declared {
                    DeclaredEol::Unspecified if checked_in_as_input => DeclaredEol::Lf,
                    declared => declared,
                }
            },
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

    /// Parses a `.git-xcrypt` body and renders the cosmetic lines from it.
    fn lines(config: &str) -> Vec<String> {
        render_lines(
            &Config::parse(config).expect("the test configuration must parse"),
            Rendering::PerPattern { fold_case: true },
        )
    }

    #[test]
    fn a_directory_pattern_covers_the_subtree_at_any_depth() {
        // Two mistakes are possible here and both were made once. A trailing
        // slash matches nothing in `.gitattributes`, so the subtree needs
        // `/**`; and `secrets/**` carries a slash, which anchors it to the root,
        // while `.gitignore`'s `secrets/` floats. The filter encrypts
        // `app/secrets/x`, so the line has to reach it. Since 2026-08-05 every
        // ASCII letter is spelled as the class matching either of its cases,
        // because selection folds unconditionally — see `fold_case`.
        assert_eq!(
            lines("secrets/\n"),
            ["**/[sS][eE][cC][rR][eE][tT][sS]/** filter=git-xcrypt -text diff=git-xcrypt"]
        );
    }

    /// What [`fold_case`] makes of every construct a pattern can hold.
    ///
    /// A table rather than a scenario, because the awkward rows are the ones no
    /// realistic `.git-xcrypt` contains and every one of them is a silent
    /// failure: a class turned inside out, an escape eaten, a POSIX name folded
    /// into nonsense. Whether the *result* is what git matches is settled by
    /// `tests/attributes.rs`, against a real `git check-attr`.
    #[test]
    fn folding_leaves_every_other_construct_meaning_what_it_meant() {
        let rows: &[(&str, &str, &str)] = &[
            ("a plain name", "secrets", "[sS][eE][cC][rR][eE][tT][sS]"),
            ("digits and punctuation", "a1-_.b", "[aA]1-_.[bB]"),
            ("wildcards are untouched", "*.e?v", "*.[eE]?[vV]"),
            ("a glob escape on a letter", "\\a", "[aA]"),
            ("a glob escape on a metacharacter", "\\*x", "\\*[xX]"),
            ("a character class gains its counterpart", "[ab]", "[abAB]"),
            ("a range gains its counterpart range", "[a-z]", "[a-zA-Z]"),
            (
                "a mixed class keeps its non-letters",
                "[a-z_0-9]",
                "[a-z_0-9A-Z]",
            ),
            ("a negated class folds too", "[!ab]", "[!abAB]"),
            ("…including the other spelling of it", "[^a]", "[^aA]"),
            ("a `]` first is a member", "[]a]", "[]aA]"),
            // The counterparts land *before* the trailing dash: `[a-A]` is a
            // reversed range to git's wildmatch and matches none of `a`, `A`,
            // `-` — measured with `git check-attr` at `core.ignorecase=false`,
            // while the filter's folded match selects all three.
            ("a `-` last is a member", "[a-]", "[aA-]"),
            ("a `-` after a range is a member", "[a-z-]", "[a-zA-Z-]"),
            ("an escaped `-` last stays put", "[a\\-]", "[a\\-A]"),
            (
                "a POSIX class is named, not spelled",
                "[[:alpha:]]",
                "[[:alpha:]]",
            ),
            (
                "…and its neighbours still fold",
                "[[:digit:]x]",
                "[[:digit:]xX]",
            ),
            // Selection folds these two like any letter: `gix-glob` lowercases
            // the candidate first and lets `[:upper:]` accept a lowercase
            // letter under `Case::Fold`, so each class selects every ASCII
            // letter. A verbatim copy was measured answering `unspecified` for
            // `xdir/a.env` under `**/[[:upper:]]dir/**` at
            // `core.ignorecase=false`, while the filter encrypted it — the
            // narrower-than-the-filter direction that costs the file.
            (
                "the upper class gains the lower",
                "[[:upper:]]",
                "[[:upper:][:lower:]]",
            ),
            (
                "the lower class gains the upper",
                "[[:lower:]]",
                "[[:lower:][:upper:]]",
            ),
            (
                "…negated too, so it keeps refusing every letter",
                "[![:upper:]]",
                "[![:upper:][:lower:]]",
            ),
            ("an escape inside a class", "[\\a\\]]", "[\\a\\]\\A]"),
            ("an unterminated class is a literal", "[ab", "[[aA][bB]"),
            (
                "nothing outside ASCII is touched",
                "\u{142}\u{105}ka",
                "\u{142}\u{105}[kK][aA]",
            ),
        ];

        for (label, pattern, expected) in rows {
            assert_eq!(
                fold_case(pattern),
                *expected,
                "{label}: `{pattern}` folded wrongly"
            );
        }
    }

    #[test]
    fn a_macro_opening_is_still_recognised_before_anything_is_folded() {
        // `guard` tests the *unfolded* opening, so the order of the two is what
        // keeps a pattern starting with `[attr]` out of git's macro branch —
        // where the line is not a pattern at all and the `-text` it carries is
        // simply absent. Folding first would spell it `[attrATTR]`, which no
        // longer opens with the six characters git looks for, and the prefix
        // would never be added.
        assert_eq!(
            lines("[attr]odd.env\n"),
            [
                "**/[attrATTR][oO][dD][dD].[eE][nN][vV] filter=git-xcrypt -text diff=git-xcrypt",
                "**/[attrATTR][oO][dD][dD].[eE][nN][vV]/** filter=git-xcrypt -text diff=git-xcrypt",
            ]
        );
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

        let mut resolver = AttributeResolver::new(
            root,
            &root.join(".git"),
            global_path.as_deref(),
            false,
            Vec::new(),
        );
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
        let (text, eol, crlf) = (ask("text"), ask("eol"), ask("crlf"));
        // `git_path_check_crlf`, as the measured table in `converts` records it:
        // `set` and `input` convert, `unset` and `auto` do not and stop the
        // question, anything else defers — to the legacy `crlf` attribute
        // first, then to the bare-`eol=` promotion.
        let action = |value: &str| match value {
            "set" | "input" => Some(true),
            "unset" | "auto" => Some(false),
            _ => None,
        };
        let converts = action(&text)
            .or_else(|| action(&crlf))
            .unwrap_or(matches!(eol.as_str(), "lf" | "crlf"));
        assert_eq!(
            matches!(ours.conversion, EolConversion::On(_)),
            converts,
            "git says text={text} eol={eol} crlf={crlf} for {path}, and \
             git-xcrypt read the stack differently"
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

        // `text=input` converts without consulting binary detection — the one
        // value besides `auto` that `git_path_check_crlf` recognises. It used
        // to be read as `text=auto` here, and the gate stayed silent while git
        // ate the `CR` bytes out of the ciphertext.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: &format!("{catch_all}secrets/** -text\nsecrets/** text=input\n"),
            }],
            "secrets/db.env",
            None,
        );

        // The pre-1.7.2 `crlf` attribute, which git still honours whenever
        // `text` says nothing. `text=junk` says nothing, so the fallback is
        // what decides here.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: &format!("{catch_all}secrets/** text=junk\nsecrets/** crlf\n"),
            }],
            "secrets/db.env",
            None,
        );

        // And the safe side of both: `-crlf` beats a bare `eol=` exactly as
        // `-text` does, so a gate firing here would be one shape too wide.
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: &format!("{catch_all}secrets/** -crlf\nsecrets/** eol=lf\n"),
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

        // The spelling the renderer emits for a POSIX class — the pair
        // `[[:upper:][:lower:]]` — resolved through gix the way git resolves
        // it. Discriminating on purpose: the class line must *beat* the `text`
        // above it, so a resolver that failed to match the bracket would
        // answer "converts" where git answers "untouched".
        agrees_with_git(
            &[Source {
                path: ".gitattributes",
                body: &format!("{catch_all}* text\n**/[[:upper:][:lower:]][dD][iI][rR]/** -text\n"),
            }],
            "xdir/db.env",
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
}
