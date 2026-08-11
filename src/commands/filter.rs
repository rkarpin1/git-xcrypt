//! The long-running filter: one process for a whole git operation.
//!
//! Registering `filter.git-xcrypt.process` rather than `clean`/`smudge` is not
//! an optimisation. With the catch-all attribute git hands us every file in the
//! repository, and a process per file measured 12 105 ms against 596 ms for one
//! long-running process on the same 2000 files.
//!
//! Everything the protocol says goes over `stdout`, which makes the rule from
//! AGENTS.md absolute here: no `println!` anywhere beneath this module.

use std::io::{Read, Write};

use bstr::ByteSlice as _;

use crate::crypto::key::MasterKey;
use crate::git::attributes;
use crate::git::pktline::{self, Packet};
use crate::git::repo::Repo;
use crate::rules::decide;
use crate::rules::declaration::Config;
use crate::{Error, Result};

/// What the repository can tell the filter, resolved once per process.
///
/// Loading this once is the point of the long-running protocol: the
/// configuration and the key are read on startup, not per file.
pub struct Context {
    config: Config,
    /// Where `config` came from, so an absent one can be looked for again.
    config_path: std::path::PathBuf,
    key: Option<MasterKey>,
    autocrlf: Option<String>,
    core_eol: Option<String>,
    /// Where to look for a path's earlier, plain-text self.
    ///
    /// `None` means "not tried yet"; `Some(None)` means "tried, nothing to look
    /// in". Lazy on purpose: a repository that declares nothing must not pay for
    /// opening the object database on every git operation, and the question is
    /// only ever asked about a file that is actually being encrypted.
    head: Option<Option<crate::git::history::HeadLookup>>,
    /// What [`crate::git::history::HeadLookup::open`] needs, kept so it can be built
    /// later.
    location: Option<Location>,
    /// Git's own attribute stack, built on first use.
    ///
    /// Lazy for the same reason as `head`, and it costs more: building it walks
    /// the working tree for every `.gitattributes` in it. A repository that
    /// encrypts nothing must never pay for that, so it is built only when a path
    /// is actually about to be encrypted — and then once, for the whole
    /// operation, which is what the long-running protocol is for.
    attributes: Option<attributes::AttributeResolver>,
    /// Whether the managed section has been checked for staleness yet.
    ///
    /// Once per process, and only once something is actually encrypted — a
    /// repository that stores nothing as ciphertext is not hurt by a stale
    /// section and must not pay for the answer. Measured at 2.6 ms for the whole
    /// render-and-compare, which the long-running protocol spends once per git
    /// operation rather than once per file.
    section_checked: bool,
    /// What the `HEAD` lookup answered for each path this process has seen.
    ///
    /// Both answers are kept, and the negative one matters more. One process
    /// serves one git operation and git cleans the same file several times
    /// within one — measured on git 2.55, a single `git status` filtered one
    /// path four times. Remembering only the positive answer would fix the
    /// duplicated warning and leave the *healthy* repository, where the answer
    /// is always `false`, decompressing that path's `HEAD` blob in full on every
    /// one of those four calls, for ever. So `true` suppresses the repeat
    /// message and `false` suppresses the repeat work.
    answered: std::collections::HashMap<Vec<u8>, bool>,
}

/// Where this repository's objects, references and attribute sources live.
struct Location {
    git_dir: std::path::PathBuf,
    common_dir: std::path::PathBuf,
    work_tree: std::path::PathBuf,
    hash: gix_hash::Kind,
    /// `core.attributesFile`, the global attribute source.
    attributes_file: Option<std::path::PathBuf>,
    /// `core.ignorecase`, which git applies to attribute matching too.
    ignore_case: bool,
}

impl Context {
    /// Gathers everything the filter needs from `repo`.
    ///
    /// A missing key is not fatal here: a locked repository still has to check
    /// out its ciphertext and pass unselected files through.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when `.git-xcrypt` cannot be understood — that must
    /// stop the operation rather than silently encrypt nothing.
    pub fn load(repo: &Repo) -> Result<Self> {
        let config_path = repo.xcrypt_config_path();
        let config = Config::load(&config_path)?;
        for warning in &config.pointless_eol {
            eprintln!("git-xcrypt: {warning}");
        }

        let key = match repo.load_key() {
            Ok(key) => Some(key),
            Err(Error::NoKey) => None,
            Err(err) => return Err(err),
        };

        // Full precedence, not just `.git/config`: `core.autocrlf` lives in the
        // user's global file on nearly every machine that sets it at all.
        //
        // Both directories, because git splits them: `config` is shared and
        // comes from the common one — a linked worktree has a git dir of its own
        // with no `config` in it — while `config.worktree` belongs to *this*
        // checkout. Reading that one from the common directory handed a linked
        // worktree the main checkout's settings, and a `core.attributesFile` set
        // there cost a file at checkout.
        let git_config = crate::git::config::open_full(repo.git_dir(), repo.common_dir())?;
        Ok(Self {
            config,
            config_path,
            key,
            autocrlf: crate::git::config::get(&git_config, "core.autocrlf"),
            core_eol: crate::git::config::get(&git_config, "core.eol"),
            head: None,
            attributes: None,
            location: Some(Location {
                git_dir: repo.git_dir().to_path_buf(),
                // The common directory, not this worktree's: `info/attributes`
                // is shared by every checkout — see [`attributes::AttributeResolver::new`].
                common_dir: repo.common_dir().to_path_buf(),
                work_tree: repo.work_tree().to_path_buf(),
                hash: crate::git::index::object_hash(
                    crate::git::config::get(&git_config, "extensions.objectformat").as_deref(),
                ),
                // Resolved, not read verbatim — see
                // [`crate::git::config::global_attributes_file`]. A `text` line in
                // the global file reached the ciphertext with `git add` exiting
                // 0 and the file gone at checkout.
                attributes_file: crate::git::config::global_attributes_file(&git_config),
                ignore_case: crate::git::config::get(&git_config, "core.ignorecase")
                    .is_some_and(|value| crate::git::config::is_true(&value)),
            }),
            section_checked: false,
            answered: std::collections::HashMap::new(),
        })
    }

    /// Says so, once, when the managed `.gitattributes` section is out of date.
    ///
    /// **A warning and never a refusal.** With `required = true` a non-zero exit
    /// aborts every git operation in the repository, and a stale section is not
    /// a reason to stop anyone working: nothing is stored in the clear over it.
    /// What it costs is the `-text` that keeps git's own CRLF conversion off the
    /// ciphertext of any path some other attribute calls `text` — measured at 34
    /// `CR` bytes gone from a 2 MB blob, the commit succeeding, and the file
    /// unrecoverable at checkout. So it is worth a line on `stderr` and nothing
    /// stronger.
    ///
    /// **Nothing is rewritten here, deliberately.** Measured on git 2.55,
    /// 2026-08-06 with a stand-in filter: git reads `.gitattributes` **once per
    /// operation**, so a rewrite from this path would take effect only from the
    /// next command — the very drift the catch-all construction exists to remove,
    /// moved one invocation along. It would also dirty a tracked file in the
    /// middle of `git add`, which is not something a command that only adds a
    /// file may do.
    ///
    /// Any shape this build writes counts as current, so a repository that ran
    /// `sync --global` is not nagged for it.
    fn warn_if_the_section_is_stale(&mut self) {
        if self.section_checked {
            return;
        }
        self.section_checked = true;
        let Some(location) = self.location.as_ref() else {
            return;
        };
        let path = location.work_tree.join(crate::git::repo::ATTRIBUTES_FILE);
        let current = attributes::ACCEPTED.into_iter().any(|rendering| {
            let lines = attributes::render_lines(&self.config, rendering);
            attributes::desired(&path, &lines).is_ok_and(|(existing, wanted)| existing == wanted)
        });
        if !current {
            // An unreadable section answers "not current" above, and that is the
            // safe direction for a warning: `status` is the gate, and it reports
            // the same file as a state conflict rather than a note.
            eprintln!(
                "git-xcrypt: {} no longer matches {} — run `git-xcrypt sync`. \
                 Nothing is stored in the clear over this, but the missing \
                 `-text` lets git convert the ciphertext of any path another \
                 attribute calls `text`, which costs the file at checkout.",
                crate::git::repo::ATTRIBUTES_FILE,
                crate::git::repo::CONFIG_FILE
            );
        }
    }

    /// Says so when normalising this file throws away the working tree's own
    /// line endings, so the next checkout cannot restore it byte for byte.
    ///
    /// This is git's `core.safecrlf`, which we did not have — Open Decision 8,
    /// closed 2026-08-06. Two shapes reach it, and neither is exotic:
    ///
    /// * **mixed `CRLF` and lone `LF`**, under the default `text=auto` as much as
    ///   under an explicit `text`. The file comes back with every ending the same
    ///   and `git status` stays **clean**, because the new bytes normalise to the
    ///   plaintext already stored. Nothing at all signals it today.
    /// * **`CR` immediately before `CRLF`** under an explicit `text`, which
    ///   collapses a byte per pass and does show up as modified. Measured on git
    ///   2.55: git is silent here even with `safecrlf=warn`, because its two
    ///   counters cannot see a lone `CR`.
    ///
    /// **Narrower than git's**, deliberately. `core.safecrlf` asks whether the
    /// bytes will change, so on a machine with `core.autocrlf=true` it warns
    /// about every LF-only file; git can afford that because the setting is
    /// opt-in and defaults to false. This one is always on and has no knob, so it
    /// asks whether the original is *recoverable* — which leaves a uniform file
    /// alone whichever ending it uses. A warning that fires on healthy content
    /// would be worse than none here.
    ///
    /// **A warning and never a refusal**, unlike the conversion check above.
    /// Git's own `safecrlf=true` refuses with `rc=128`, and we cannot: with
    /// `required = true` that would stop every git operation in the repository
    /// over content that is converted, not lost. The remedy is inside this tool —
    /// declaring the path `binary` in `.git-xcrypt` stores it verbatim — so the
    /// message names it.
    ///
    /// Asked on `clean` rather than reported by `status` for the reason the
    /// conversion refusal is: `status` resolves only paths the index already
    /// knows, so on a new file it says nothing until the checkout that changes it.
    fn warn_if_the_round_trip_loses_bytes(
        &self,
        path: &[u8],
        decision: &crate::rules::declaration::Decision,
        content: &[u8],
    ) {
        if crate::rules::eol::normalisation_is_reversible(decision.text, content) {
            return;
        }
        eprintln!(
            "git-xcrypt: {}: its line endings are mixed, so they do not survive a \
             round trip — after the next checkout this file will not be \
             byte-for-byte what it is now. Give it one kind of line ending, or \
             declare it `binary` in {} to store it verbatim.",
            path.as_bstr(),
            crate::git::repo::CONFIG_FILE
        );
    }

    /// Says so when a declared `eol=` will not reach this file after all.
    ///
    /// `eol=` only ever applies to content the check-in path normalised: the
    /// header records that in bit 0, and `smudge` leaves on the spot when it is
    /// clear, without so much as looking at the declaration. Under the default
    /// `text=auto` that verdict comes from the **content**, so one pattern can
    /// honour `eol=crlf` for one file and silently ignore it for the next one in
    /// the same directory. Measured before this existed: `blobs/ eol=crlf` over
    /// binary content checked out with `LF`, and nothing said a word.
    ///
    /// The parser already refuses the shape it *can* see — `-text` or `binary`
    /// beside an `eol=`, which is a contradiction on the line itself — and that
    /// warning fires once, at load. This one cannot live there: at parse time
    /// there is no content to classify. So it is asked here, on the same gate as
    /// the two warnings above, and only for `TextMode::Auto`; repeating the
    /// parser's answer per file would be noise on a repository that already got
    /// the message.
    ///
    /// A warning, never a refusal, for the reason every warning on this path is
    /// one: with `required = true` a non-zero exit stops every git operation in
    /// the repository, and nothing here is lost — the file is stored verbatim,
    /// which is the safe direction.
    fn warn_if_the_declared_eol_will_not_apply(
        &self,
        path: &[u8],
        decision: &crate::rules::declaration::Decision,
        content: &[u8],
    ) {
        use crate::rules::declaration::{EolMode, TextMode};

        let Some(eol) = decision.eol else { return };
        if decision.text != TextMode::Auto
            || crate::rules::eol::should_normalise(TextMode::Auto, content)
        {
            return;
        }

        let spelling = match eol {
            EolMode::Lf => "lf",
            EolMode::Crlf => "crlf",
            EolMode::Native => "native",
        };
        eprintln!(
            "git-xcrypt: {}: `eol={spelling}` does not reach this file — its \
             content reads as binary by git's own rule, so it is stored verbatim \
             and every checkout writes back exactly those bytes. Declare the path \
             `text` in {} if it should be converted anyway.",
            path.as_bstr(),
            crate::git::repo::CONFIG_FILE
        );
    }

    /// Whether `path` needs the "already in `HEAD` in the clear" warning.
    ///
    /// Built on first use and kept for the rest of the process, which is what the
    /// long-running protocol makes worth doing: one `git add -A` asks this once
    /// per newly encrypted file, over the same trees.
    ///
    /// **A path already answered gets `false`, whatever the answer was.** Both
    /// halves of that are deliberate: a repeat `true` would print the same
    /// message a second time in the same git operation, and a repeat `false`
    /// would re-walk the trees and decompress the `HEAD` blob again to reach the
    /// same conclusion.
    fn head_holds_in_the_clear(&mut self, path: &[u8]) -> bool {
        if self.answered.contains_key(path) {
            return false;
        }
        if self.head.is_none() {
            let opened = self.location.as_ref().and_then(|location| {
                crate::git::history::HeadLookup::open(
                    &location.git_dir,
                    &location.common_dir,
                    location.hash,
                )
            });
            self.head = Some(opened);
        }
        let found = self
            .head
            .as_mut()
            .and_then(Option::as_mut)
            .is_some_and(|head| head.holds_in_the_clear(path));
        self.answered.insert(path.to_vec(), found);
        found
    }

    /// Whether git would run **its own** line-ending conversion over the
    /// ciphertext this filter is about to hand back, and which line decides it.
    ///
    /// Git's order on the check-in side is `clean` → blob → git's conversion, so
    /// the conversion lands on the filter's *output*. On a path where some other
    /// attribute source resolves `text` to `set`, or leaves it unspecified while
    /// a bare `eol=` is in force, that eats the `CR` bytes out of a ciphertext:
    /// measured on git 2.55, 32 bytes gone from a 2 MB blob, `git add` and
    /// `git commit` both exit 0, and the checkout fails the authentication tag
    /// and leaves no file at all.
    ///
    /// Asked of git's own attribute stack, never of the managed section alone:
    /// the managed `-text` is one line among many and git takes the last match,
    /// so the only thing that answers this is a full resolution.
    fn ciphertext_would_be_converted(&mut self, path: &[u8]) -> Option<attributes::Culprit> {
        match self.attribute_stack()?.resolve(path).conversion {
            attributes::EolConversion::On(culprit) => Some(culprit),
            attributes::EolConversion::Off => None,
        }
    }

    /// Git's attribute stack, built on first use and kept for the process.
    ///
    /// `None` only when there is no repository behind this process, which is the
    /// unit-test shape; every caller then skips its check rather than guessing.
    fn attribute_stack(&mut self) -> Option<&mut attributes::AttributeResolver> {
        if self.attributes.is_none() {
            let location = self.location.as_ref()?;
            // The index copies git falls back to for a deleted `.gitattributes`
            // — without them the refusal went blind the moment the user deleted
            // the file the refusal itself told them to edit, and git converted
            // the ciphertext with exit 0. Measured; see `staged_fallbacks`.
            let staged = attributes::staged_fallbacks(
                &location.work_tree,
                &location.git_dir.join("index"),
                &location.common_dir,
                location.hash,
                location.ignore_case,
            );
            let resolver = attributes::AttributeResolver::new(
                &location.work_tree,
                &location.common_dir,
                location.attributes_file.as_deref(),
                location.ignore_case,
                staged,
            );
            self.attributes = Some(resolver);
        }
        self.attributes.as_mut()
    }

    /// Turns "the file has been altered" into the truth when **git** altered it.
    ///
    /// The check-in side refuses before anything is stored; this is the other end
    /// of the same mistake, on a repository where the line arrived after the
    /// commit. Git's check-out order is blob, then git's own conversion, then
    /// smudge, so a `text` line outranking the managed `-text` hands the
    /// authentication tag bytes that were never stored. Measured on git 2.55 with
    /// a filter that copied its stdin aside: a 4118-byte blob holding 18 lone
    /// `LF` and no `CRLF` arrived as 4136 bytes holding 18 `CRLF` and no lone
    /// `LF`. The tag is right to refuse that — but the blob is intact to the
    /// byte, and `the file has been altered` reads as "your repository is corrupt
    /// and the data is gone".
    ///
    /// **Asked only after the tag has already failed**, which is what makes it
    /// free. The smudge path runs for every file of every checkout and every
    /// clone, so a question asked before the failure would be paid for by every
    /// healthy repository; a failed tag is rare enough that building the whole
    /// attribute stack here costs nothing measurable.
    ///
    /// Three things have to agree before this claims anything, and the cheapest
    /// is asked first so the stack is built only for content that already looks
    /// converted:
    ///
    /// 1. the bytes carry the shape git's expansion leaves behind;
    /// 2. git's attribute stack really does convert this path;
    /// 3. git's check-out direction on **this machine** is `CRLF`.
    ///
    /// What it deliberately does not do is prove the stored blob would decrypt.
    /// It cannot: the expansion is not invertible, since an output `CRLF` may
    /// have come from a stored `CRLF` or from a stored lone `LF`. The residual
    /// case is a ciphertext damaged by this same conversion running on the way
    /// *in*, under a build older than 2026-08-05, in a repository that still
    /// carries the line. Two things keep it honest: nothing this message claims
    /// is false there either — a checkout only reads — and the state is
    /// self-correcting, because once the line is gone the predicate stops firing
    /// and the very next checkout says `the file has been altered` after all.
    fn conversion_explains_a_failed_tag(
        &mut self,
        path: &[u8],
        content: &[u8],
    ) -> Option<attributes::Culprit> {
        if !bears_the_mark_of_an_expansion(content) {
            return None;
        }

        let resolved = self.attribute_stack()?.resolve(path);
        resolved
            .expands_on_checkout(self.autocrlf.as_deref(), self.core_eol.as_deref())
            .cloned()
    }

    /// Replaces a smudge failure's message when git's conversion explains it.
    ///
    /// Only [`Error::Crypto`], which on this path is the authentication tag and
    /// nothing else: [`Error::Format`] is a header this build cannot read and
    /// [`Error::KeyMismatch`] is another key's file, and no `.gitattributes` line
    /// can cause either. Re-explaining those would be the same lie in the other
    /// direction.
    fn explain_a_failed_smudge(&mut self, path: &[u8], content: &[u8], err: Error) -> Error {
        if !matches!(err, Error::Crypto(_)) {
            return err;
        }
        match self.conversion_explains_a_failed_tag(path, content) {
            Some(culprit) => self.report_conversion_at_checkout(&culprit),
            None => err,
        }
    }

    /// The message a checkout git converted gets instead of "altered".
    ///
    /// Three things it has to carry, in this order, because they are the three a
    /// reader is missing: that nothing was lost, which line did it, and what to
    /// do. The first is the load-bearing one — everything the user can see says
    /// the opposite.
    fn report_conversion_at_checkout(&self, culprit: &attributes::Culprit) -> Error {
        Error::Config(format!(
            "git rewrote this file's line endings on the way out of the object \
             database, before this filter saw a byte of it, because this line \
             outranks the managed `-text`:\n  {}\nGit's check-out order is blob, \
             then git's own conversion, then smudge, so what reached the \
             authentication tag is not what was stored: every lone `LF` in the \
             ciphertext arrived here as `CRLF`. Refusing that is correct.\n\
             Nothing is lost. A checkout only reads: the object database still \
             holds exactly the blob that was committed, this command changed \
             nothing on disk, and no key and no history were touched — what \
             failed is a copy made in flight.\nDelete or narrow that line so the \
             managed `-text` wins, run `git-xcrypt sync`, and check this file out \
             again. If it still fails once that line is gone, the stored \
             ciphertext itself was altered and `git-xcrypt status` will name it",
            self.spell(culprit)
        ))
    }

    /// Turns that answer into the refusal git aborts the operation with.
    ///
    /// A refusal nobody can act on is only half of one: the stack has four
    /// levels, and the one that outranks the rest — `$GIT_DIR/info/attributes` —
    /// is not versioned and cannot be seen in a pull request at all. So the
    /// message names the file, the line, the pattern and the assignment, spelled
    /// relative to the working tree where there is one.
    fn refuse_conversion(&self, culprit: &attributes::Culprit) -> Error {
        let shown = self.spell(culprit);

        Error::Config(format!(
            "git would convert this path's line endings itself, because this line \
             outranks the managed `-text`:\n  {shown}\nThat conversion runs over \
             the **ciphertext** this filter produces, not over the plain text: it \
             eats the `CR` bytes out of it, `git add` and `git commit` both exit 0, \
             and the next checkout fails the authentication tag and leaves no file \
             at all — measured on git 2.55, 32 bytes gone from a 2 MB blob, \
             unrecoverable with any key. Nothing has been stored, so nothing is \
             lost. Delete or narrow that line so the managed `-text` wins, run \
             `git-xcrypt sync`, and try again"
        ))
    }

    /// Names an attribute line relative to the working tree, where there is one.
    ///
    /// A refusal nobody can act on is only half of one, and the level that
    /// outranks the rest — `$GIT_DIR/info/attributes` — is not versioned and
    /// cannot be seen in a pull request at all. Both directions print it the same
    /// way on purpose: the reader is looking for one line, not for two dialects.
    fn spell(&self, culprit: &attributes::Culprit) -> String {
        match (&culprit.source, self.location.as_ref()) {
            (Some(source), Some(location)) => attributes::Culprit {
                source: Some(
                    source
                        .strip_prefix(&location.work_tree)
                        .unwrap_or(source)
                        .to_path_buf(),
                ),
                ..culprit.clone()
            }
            .to_string(),
            _ => culprit.to_string(),
        }
    }

    /// Looks for `.git-xcrypt` again if it was absent when the process started.
    ///
    /// One process serves a whole git operation, and a `git checkout` that
    /// restores `.git-xcrypt` filters other files in the same run. Latching the
    /// absence would make the check-in refusal outlive its own cause and leave
    /// the repository unrepairable from inside git.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when the file has reappeared but cannot be understood.
    fn refresh_config_if_absent(&mut self) -> Result<()> {
        if !self.config.missing {
            return Ok(());
        }

        let reloaded = Config::load(&self.config_path)?;
        if !reloaded.missing {
            for warning in &reloaded.pointless_eol {
                eprintln!("git-xcrypt: {warning}");
            }
            self.config = reloaded;
        }
        Ok(())
    }
}

/// Whether `content` carries the shape git's check-out conversion leaves behind.
///
/// Git's `crlf_to_worktree` rewrites every **lone** `LF` as `CRLF` and leaves an
/// existing `CRLF` alone, so its output has no lone `LF` left anywhere. That
/// makes the fingerprint exact in both halves:
///
/// * **no lone `LF`** — bytes git expanded cannot contain one. The damage the
///   *other* direction does is excluded by the same clause: conversion on the way
///   in strips `CR`, so a blob it broke is full of lone `LF`, and after a
///   round trip through this clause it is correctly called altered.
/// * **at least one `CRLF`** — with nothing to expand, git hands the blob over
///   untouched and a failing tag is the file's own doing, not git's.
///
/// Measured on git 2.55, 2026-08-05, with a filter that copied its stdin aside: a
/// 4118-byte blob holding 18 lone `LF` and no `CRLF` arrived as 4136 bytes
/// holding 18 `CRLF` and no lone `LF`.
///
/// One pass, no allocation, and only ever on a path whose tag has already failed.
fn bears_the_mark_of_an_expansion(content: &[u8]) -> bool {
    let mut expanded = false;
    for (index, &byte) in content.iter().enumerate() {
        if byte == b'\n' {
            if index == 0 || content[index - 1] != b'\r' {
                return false;
            }
            expanded = true;
        }
    }
    expanded
}

/// Runs the protocol to completion on the given streams.
///
/// # Errors
///
/// [`Error::Io`] or [`Error::Format`] when the handshake itself fails. A failure
/// on a single file is reported to git as `status=error` instead, which with
/// `required = true` aborts the operation.
pub fn run(context: &mut Context, input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    handshake(input, output)?;
    negotiate_capabilities(input, output)?;

    loop {
        let Some(request) = read_request(input)? else {
            return Ok(());
        };
        serve(context, &request, output)?;
    }
}

/// One `command=` / `pathname=` pair and the content that followed it.
struct Request {
    command: String,
    /// Kept as bytes: on Unix a path is an arbitrary byte string, and decoding
    /// it lossily would hand the decision a name the file does not have.
    pathname: Vec<u8>,
    content: Vec<u8>,
}

/// Agrees on the protocol version.
fn handshake(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let greeting = pktline::read_until_flush(input)?;
    let announces_version_2 = greeting
        .iter()
        .any(|item| item.as_slice() == b"version=2\n");
    if !announces_version_2 {
        return Err(Error::Format(
            "git asked for a filter protocol version this build does not speak".into(),
        ));
    }

    pktline::write_data(output, b"git-filter-server\n")?;
    pktline::write_data(output, b"version=2\n")?;
    pktline::write_flush(output)?;
    Ok(())
}

/// Tells git which operations we handle.
fn negotiate_capabilities(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let _offered = pktline::read_until_flush(input)?;
    pktline::write_data(output, b"capability=clean\n")?;
    pktline::write_data(output, b"capability=smudge\n")?;
    pktline::write_flush(output)?;
    Ok(())
}

/// Reads one request, or `None` when git closed the stream.
fn read_request(input: &mut impl Read) -> Result<Option<Request>> {
    let mut command = None;
    let mut pathname = None;

    loop {
        match pktline::read_packet(input) {
            Ok(Packet::Flush) => break,
            Ok(Packet::Data(payload)) => {
                // Exactly the one terminating newline comes off, never
                // `trim_end`: a filename may legally end in a space, and
                // trimming it matches the file under a different name — which
                // on the check-in side means storing a secret in the clear.
                let value = payload.strip_suffix(b"\n").unwrap_or(&payload);
                if let Some(rest) = value.strip_prefix(b"command=") {
                    command = Some(String::from_utf8_lossy(rest).into_owned());
                } else if let Some(rest) = value.strip_prefix(b"pathname=") {
                    pathname = Some(rest.to_vec());
                }
            }
            // git closes the stream when the operation is over, which arrives
            // as an unexpected end of file rather than as a message. Only a
            // clean boundary counts: an end of file *after* a field has arrived
            // is a truncated request, and treating it as a shutdown would exit
            // zero having answered nothing — which tells git the file was
            // handled. `read_content` already treats the same condition as an
            // error, so this keeps the two halves in step.
            Err(Error::Io(err))
                if err.kind() == std::io::ErrorKind::UnexpectedEof
                    && command.is_none()
                    && pathname.is_none() =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
    }

    let (command, pathname) = match (command, pathname) {
        (Some(command), Some(pathname)) => (command, pathname),
        // Neither field is how a clean shutdown looks; one of the two is a
        // request we did not understand, and answering nothing while exiting
        // zero would tell git the file was handled.
        (None, None) => return Ok(None),
        (command, _) => {
            return Err(Error::Format(format!(
                "git sent an incomplete filter request (command={}, pathname missing or absent)",
                command.as_deref().unwrap_or("<none>")
            )));
        }
    };

    Ok(Some(Request {
        command,
        pathname,
        content: pktline::read_content(input)?,
    }))
}

/// Answers one request.
fn serve(context: &mut Context, request: &Request, output: &mut impl Write) -> Result<()> {
    let mut first_encryption = None;
    let outcome = match request.command.as_str() {
        "clean" => context.refresh_config_if_absent().and_then(|()| {
            // Gated before anything is looked up. The catch-all attribute sends
            // every file in the repository through here, so an ungated check
            // would open the object database for a repository that encrypts
            // nothing, and would ask about files no pattern selects — the same
            // shape of mistake that once turned a 301-file checkout into 301
            // warnings. Content that already carries our magic is not a first
            // encryption either: that is a re-add of something already stored.
            let decision = context.config.decide(&request.pathname);
            let stored_as_ciphertext =
                !crate::rules::declaration::is_never_encrypted(&request.pathname)
                    && decision.encrypt;

            // Before the encryption, not after it, and unlike the warning below
            // this one *does* refuse. Git converts the filter's output, so what
            // this repository is one `git add` away from is not a leaked secret
            // but a blob nobody can ever decrypt again. At this instant nothing
            // is damaged yet: with `required = true` a `status=error` costs a
            // refused `git add`, which is the cheapest outcome on offer. The
            // question is asked only of a path that is genuinely about to become
            // ciphertext — a path stored in the clear is git's to convert, and
            // refusing over that would be an outage in a healthy repository.
            if stored_as_ciphertext
                && let Some(culprit) = context.ciphertext_would_be_converted(&request.pathname)
            {
                return Err(context.refuse_conversion(&culprit));
            }

            if stored_as_ciphertext {
                // Here rather than at start-up: a repository that encrypts
                // nothing must not pay for an answer it cannot act on.
                context.warn_if_the_section_is_stale();
            }
            if stored_as_ciphertext && !crate::crypto::format::looks_encrypted(&request.content) {
                // Both of these are about content on its way from plaintext to
                // ciphertext. Content that already carries our magic is a re-add
                // of something stored, and asking either question about
                // ciphertext would be nonsense — worse than nonsense for the
                // line endings, since an explicit `text` normalises whatever it
                // is handed and would report a locked repository's own blobs.
                first_encryption = Some(request.pathname.clone());
                context.warn_if_the_round_trip_loses_bytes(
                    &request.pathname,
                    &decision,
                    &request.content,
                );
                context.warn_if_the_declared_eol_will_not_apply(
                    &request.pathname,
                    &decision,
                    &request.content,
                );
            }
            decide::clean(
                context.key.as_ref(),
                &context.config,
                &request.pathname,
                &request.content,
            )
        }),
        "smudge" => {
            let decision = context.config.decide(&request.pathname);
            // The failure is where the diagnosis happens, and nowhere earlier:
            // this path runs for every file of every checkout and every clone,
            // so a healthy repository must not pay a byte for it.
            decide::smudge(
                context.key.as_ref(),
                &request.pathname,
                &request.content,
                decision.encrypt,
                decision.eol,
                context.autocrlf.as_deref(),
                context.core_eol.as_deref(),
            )
            .map_err(|err| {
                context.explain_a_failed_smudge(&request.pathname, &request.content, err)
            })
        }
        other => Err(Error::Format(format!(
            "git asked for the unknown filter command `{other}`"
        ))),
    };

    match outcome {
        Ok(outcome) => {
            if let Some(warning) = outcome.warning {
                eprintln!("git-xcrypt: {warning}");
            }
            // After the encryption succeeded, and never as a reason to fail it.
            // With `required = true` a non-zero exit would abort the whole
            // operation, and this is news about the past, not a refusal of the
            // present — so it is a line on `stderr` and nothing more.
            if let Some(path) = first_encryption
                && context.head_holds_in_the_clear(&path)
            {
                eprintln!(
                    "git-xcrypt: {}: this is the first time it is being encrypted, \
                     and HEAD already holds it in the clear. The plain text stays in \
                     history; run `git-xcrypt status` to see what is exposed, and \
                     rotate the secret if it was ever pushed.",
                    path.as_bstr()
                );
            }
            pktline::write_data(output, b"status=success\n")?;
            pktline::write_flush(output)?;
            pktline::write_data(output, &outcome.content)?;
            pktline::write_flush(output)?;
            pktline::write_flush(output)?;
        }
        Err(err) => {
            // With `required = true` this aborts the whole git operation, which
            // is the point: better a refused commit than a leaked secret.
            eprintln!("git-xcrypt: {}: {err}", request.pathname.as_bstr());
            pktline::write_data(output, b"status=error\n")?;
            pktline::write_flush(output)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key::MASTER_KEY_LEN;
    use crate::git::pktline::{write_data, write_flush};

    fn context() -> Context {
        Context {
            config: Config::parse("*.env\n").expect("test config"),
            config_path: std::path::PathBuf::from(".git-xcrypt"),
            key: Some(MasterKey::from_bytes([11u8; MASTER_KEY_LEN])),
            autocrlf: None,
            core_eol: None,
            // No repository behind these unit tests, so there is nothing for the
            // first-encryption warning to look in; `head_holds_in_the_clear`
            // answers `false` and the protocol is exercised on its own. The
            // conversion check needs `location` for the same reason and skips
            // itself without it — what it does when there *is* a repository is
            // a question only a real git can answer, and
            // `tests/attributes.rs` asks it there.
            head: Some(None),
            attributes: None,
            location: None,
            section_checked: true,
            answered: std::collections::HashMap::new(),
        }
    }

    /// Builds the byte stream git would send for one request.
    fn conversation(command: &str, pathname: &str, content: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();
        write_data(&mut buffer, b"git-filter-client\n").expect("writing");
        write_data(&mut buffer, b"version=2\n").expect("writing");
        write_flush(&mut buffer).expect("writing");
        write_data(&mut buffer, b"capability=clean\n").expect("writing");
        write_data(&mut buffer, b"capability=smudge\n").expect("writing");
        write_flush(&mut buffer).expect("writing");
        write_data(&mut buffer, format!("command={command}\n").as_bytes()).expect("writing");
        write_data(&mut buffer, format!("pathname={pathname}\n").as_bytes()).expect("writing");
        write_flush(&mut buffer).expect("writing");
        write_data(&mut buffer, content).expect("writing");
        write_flush(&mut buffer).expect("writing");
        buffer
    }

    /// Pulls the payload of the reply that follows `status=success`.
    fn reply_content(reply: &[u8]) -> Vec<u8> {
        let mut cursor = reply;
        // server greeting, capabilities, then the status list.
        pktline::read_until_flush(&mut cursor).expect("greeting");
        pktline::read_until_flush(&mut cursor).expect("capabilities");
        let status = pktline::read_until_flush(&mut cursor).expect("status");
        assert_eq!(
            status[0], b"status=success\n",
            "the filter reported a failure"
        );
        pktline::read_content(&mut cursor).expect("content")
    }

    #[test]
    fn a_pathname_keeps_the_space_it_legally_ends_in() {
        // `trim_end()` here once matched a file against a pattern it does not
        // match, and in the pass-through direction that stores a secret in the
        // clear. The integration test that guards the same rule builds the file
        // on disk, which Windows cannot do — NTFS strips a trailing space from
        // a name — so this drives the request parser directly instead, and runs
        // everywhere. `a.env ` is not `a.env`: the declaration is `*.env`, so a
        // parser that trims hands back ciphertext and one that does not hands
        // back the bytes it was given.
        let mut reply = Vec::new();
        let input = conversation("clean", "a.env ", b"secret\n");
        run(&mut context(), &mut input.as_slice(), &mut reply).expect("the protocol must complete");
        assert_eq!(
            reply_content(&reply),
            b"secret\n",
            "the trailing space was trimmed, so the file matched `*.env` under a \
             name it does not have"
        );
    }
}
