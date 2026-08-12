//! `git-xcrypt unlock` — make a cloned repository readable again.
//!
//! This is the command PRD US-01 is about: the code is on the new machine, the
//! secrets are not, and one key file has to turn ciphertext in the working tree
//! back into the bytes that were committed.
//!
//! Three properties shape the implementation.
//!
//! **The registration comes before the decryption.** `.git/config` is not
//! versioned, so a clone has no driver; and the `* filter=git-xcrypt` line in
//! `.gitattributes` is only there if whoever set the repository up committed
//! that file. Both are repaired here, because git treats a missing attribute and
//! an undefined driver identically — as no filter. Decrypting first would leave
//! a window in which the working tree holds plaintext and git has no filter,
//! where `git status` reports every secret as modified and the next `git add`
//! stores it in the clear.
//!
//! **A wrong key changes nothing at all.** Every encrypted file is inspected —
//! 38 bytes each, no decryption — before a single byte is written, and before
//! the key is even installed. Discovering the mismatch on the fourth file out of
//! ten would leave a working tree that is half readable and a repository holding
//! a key that does not belong to it. The limit of that promise is worth naming:
//! the check can only object to a key it has evidence against, so a working tree
//! with no encrypted file in it accepts any key. That case gets a warning rather
//! than a refusal, because proving it would mean scanning history, which is
//! `status`'s job in S-06.
//!
//! **Interrupting it is survivable.** The files are converted in place, one at a
//! time, so a run cut short leaves some plain and some not. That is recoverable
//! only because each file says what it is in its own header: a second `unlock`
//! skips what is already plain and finishes the rest. Working from the object
//! database instead would have been no safer and would have missed every file
//! that is not committed yet.
//!
//! Which files get decrypted is decided by the **header**, not by `.git-xcrypt`
//! — the same rule the smudge path follows, and for the same reason. It is also
//! what makes the result byte-identical to a checkout, which is what `git
//! status` being clean afterwards actually proves.

use std::fs;
use std::io::{BufRead, Read as _, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::format::{self, Header, KEY_ID_LEN, OVERHEAD};
use crate::crypto::keyfile;
use crate::git::config as gitconfig;
use crate::git::repo::{Repo, git_spelling};
use crate::rules::decide;
use crate::rules::declaration::Config;
use crate::{Error, Result};

/// What `unlock` did.
#[derive(Debug)]
pub struct Report {
    /// Fingerprint of the key the repository now holds.
    pub key_id: [u8; KEY_ID_LEN],
    /// A key file was written. False when the key was already in place.
    pub key_imported: bool,
    /// The filter registration was written or repaired.
    pub config_written: bool,
    /// The managed `.gitattributes` section was written or repaired.
    pub attributes_written: bool,
    /// Paths, relative to the working tree, that were converted.
    pub decrypted: Vec<PathBuf>,
    /// Paths that could not be read, so may still be encrypted.
    ///
    /// Separate from [`Report::warnings`] because the count belongs in the
    /// closing line: "decrypted 3 files" and "decrypted 3 files, 1 could not be
    /// read" are different outcomes and must not look the same.
    pub unreadable: Vec<PathBuf>,
    /// Anything worth saying once, carried out so the binary owns the messages.
    pub warnings: Vec<String>,
}

/// Where the key comes from, when one is offered at all.
///
/// A type rather than two `Option`s so the two cannot both be set, and so the
/// call site reads as the choice it is. Both go through the same parser and the
/// same refusals; only the reading differs.
#[derive(Debug, Clone, Copy)]
pub enum KeySource<'a> {
    /// A file written by `export-key`.
    File(&'a Path),
    /// The text of such a file, handed over directly.
    ///
    /// **Visible in the process list for as long as the command runs, and kept
    /// for ever in the shell's history** — measured on macOS: `ps -ww -o command
    /// -p <pid>` prints the material verbatim. That is the price of the one
    /// thing a file cannot do, which is arrive from a CI secret without ever
    /// being written to disk, and it is the caller's to pay knowingly. The
    /// binary says so on `stderr` every time.
    Material(&'a str),
}

/// Room for the export a key file actually is, so the buffer never grows.
///
/// The text below holds the master key in the clear, and [`Zeroizing`] only
/// protects a buffer that is never reallocated — a reallocation leaves the
/// half-read key behind on the heap, where nothing wipes it. Today's export is
/// 80 bytes (a 16-byte prefix, the version, a space, sixteen hex digits, then 44
/// base64 characters, each line ending in `\n`); this is comfortably above it,
/// and the same reasoning as `keyfile::encode_portable`'s sizing.
const KEY_ENTRY_ROOM: usize = 128;

/// Reads the text of a key file from `input`, prompting on `output`.
///
/// This is what `unlock --key` uses. It exists for the two shapes a path cannot
/// serve: a key pasted by hand, and a key arriving over a pipe from whatever
/// holds secrets — `cat key | git-xcrypt unlock --key`. The text goes through
/// [`keyfile::decode_portable`] exactly like a file's, so the header still
/// verifies the material behind it.
///
/// **Entry ends at a blank line, or at end of input.** The blank line is what
/// makes the interactive form usable: an export is two lines, and pressing Enter
/// once more is easier to reach for than the end-of-file key, which is `Ctrl+Z`
/// on Windows and `Ctrl+D` everywhere else. Leading blank lines are skipped
/// rather than treated as the end, because a key travelling through a password
/// manager or an email body picks them up — the same tolerance
/// `keyfile::significant_lines` already grants a file. The recorded limit of
/// that: a `#` comment counts as content here, so a comment followed by a blank
/// line ends the entry before the key arrives. It fails closed — the parser
/// says this is not a key file — and the one shape this command is pointed at,
/// what `export-key` writes, has no comment in it.
///
/// **The terminal answer is an argument, not a question asked here**, for the
/// reason `export_key::to_writer` splits the same way: a test cannot portably
/// arrange a terminal, and both arms have to be reachable on all three
/// platforms. It decides two things and neither is the parsing — whether to
/// print a prompt at all, which would be noise in a CI log, and whether the key
/// was echoed and is therefore sitting in the scrollback.
///
/// # Errors
///
/// [`Error::Io`] when the prompt cannot be shown or the input cannot be read,
/// including input that is not UTF-8 — a key file is text, and the file route
/// refuses the same shape.
pub fn read_key_material<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    input_is_a_terminal: bool,
) -> Result<Zeroizing<String>> {
    if input_is_a_terminal {
        writeln!(
            output,
            "Paste the contents of a file written by `export-key`, \
             then press Enter on an empty line:"
        )?;
        output.flush()?;
    }

    let mut text = Zeroizing::new(String::with_capacity(KEY_ENTRY_ROOM));
    let mut seen_content = false;
    loop {
        let start = text.len();
        if input.read_line(&mut text)? == 0 {
            // End of input. The pipe form ends here, and so does a terminal
            // whose user pressed the end-of-file key instead of Enter.
            break;
        }
        if text[start..].trim().is_empty() {
            // Never part of the key, whichever side of the entry it falls on.
            text.truncate(start);
            if seen_content {
                break;
            }
        } else {
            seen_content = true;
        }
    }
    // No assertion on the capacity here, unlike `keyfile::encode_portable`: what
    // it sizes is a key of known length, and this is whatever the caller pasted.
    // A longer paste reallocates and leaves a copy on the heap — the honest
    // limit of this route, and not a reason to panic on someone's input.

    if input_is_a_terminal {
        // Only here. Over a pipe nothing was echoed, and a warning that is false
        // half the time is one people learn to skip — the same reason the
        // conversion gate in `filter.rs` is narrower than git's.
        writeln!(
            output,
            "git-xcrypt: {}",
            super::export_key::SCROLLBACK_WARNING
        )?;
        output.flush()?;
    }
    Ok(text)
}

/// Unlocks `repo`, optionally installing the key at `key_source` first.
///
/// With `key_only` the working tree is left exactly as it is: the key goes in,
/// the filter and the managed section are repaired, and nothing is decrypted.
/// That was a command of its own until 2026-08-06 — `import-key` — and it is a
/// flag now because the two differed by this one step and by nothing else,
/// while `unlock <key-file>` was already the path every message pointed at.
/// The evidence check still runs, so a key the working tree's own headers
/// contradict is refused here exactly as it is on the full path.
///
/// # Errors
///
/// [`Error::NoKey`] when no key is given and none is present. [`Error::Config`]
/// when `.git-xcrypt` cannot be understood, or when the repository already holds
/// a key other than the one offered — note that this second case is code `2`
/// rather than the `4` a file-level mismatch reports, because the refusal comes
/// from the repository's own key file and not from anything a header said.
/// [`Error::Format`] when a file in the working tree belongs to another key.
/// [`Error::Io`] on a read or write failure.
pub fn run(repo: &Repo, key_source: Option<KeySource<'_>>, key_only: bool) -> Result<Report> {
    let key = match key_source {
        Some(source) => {
            let key = match source {
                KeySource::File(path) => keyfile::read_portable(path)?,
                // The same parser, so the header still verifies the material
                // behind it: a key truncated on its way through a clipboard or
                // a CI variable is refused rather than installed.
                KeySource::Material(text) => keyfile::decode_portable(text)?,
            };
            // Asked before anything is written: a refusal that has already
            // installed a key has not refused.
            refuse_on_conflict(repo, &key)?;
            key
        }
        None => repo.load_key()?,
    };
    let key_id = key.key_id();

    // Everything that must be readable before anything is written. `.git-xcrypt`
    // is loaded here rather than after the key is installed, so a typo in it
    // cannot leave a key behind on its way out.
    let config = Config::load(&repo.xcrypt_config_path())?;
    let git_config = gitconfig::open_full(repo.git_dir(), repo.common_dir())?;
    let autocrlf = gitconfig::get(&git_config, "core.autocrlf");
    let core_eol = gitconfig::get(&git_config, "core.eol");

    // Everything carrying our magic, and the key each one asks for. Gathered
    // before the first write, so a mismatch costs nothing.
    let mut walk = Walk::default();
    let encrypted = collect_encrypted(repo, &mut walk)?;
    refuse_foreign_keys(repo, &encrypted, &key_id)?;

    let key_imported = install(repo, &key)?;
    // Both before the decryption, never after — see the module comment. The
    // attributes section matters as much as the registration: a driver with no
    // `* filter=git-xcrypt` above it is never invoked, so git would store the
    // plaintext this command is about to put in the working tree, with exit
    // code 0 and no signal. Measured on git 2.55 in a clone whose origin never
    // committed `.gitattributes`.
    let config_written = super::init::register_driver(repo)?;
    let attributes_written = crate::git::attributes::write_section(
        &repo.attributes_path(),
        // Whichever spelling is already there: repairing this section must not
        // silently undo a `sync --ignorecase`.
        &crate::git::attributes::render_lines_as_written(&repo.attributes_path(), &config),
    )?;

    let mut report = Report {
        key_id,
        key_imported,
        config_written,
        attributes_written,
        decrypted: Vec::new(),
        unreadable: walk.unreadable,
        warnings: config.pointless_eol.clone(),
    };
    report.warnings.append(&mut walk.warnings);

    if config.missing {
        // Not an error here — the headers say everything decryption needs — but
        // the check-in path treats the same state as fatal, so without this the
        // command would report success and leave a tree in which every `git add`
        // aborts.
        report.warnings.push(format!(
            "{} is missing, so every `git add` in this repository will refuse \
             until it is restored; run `git-xcrypt init` to create one",
            crate::git::repo::CONFIG_FILE
        ));
    }

    if key_imported && encrypted.is_empty() {
        // The check above can only object to a key it has evidence against, and
        // an empty working tree offers none. Saying so is the honest version of
        // "a wrong key changes nothing": nothing was changed, but nothing
        // confirmed the key either, and committing under the wrong one would
        // split the repository's history across two keys.
        report.warnings.push(format!(
            "no encrypted file was found here, so nothing confirmed that key {} \
             is this repository's. Run `git-xcrypt status` once the secrets are \
             checked out.",
            crate::format_key_id(&key_id)
        ));
    }
    if key_only {
        // Everything above is "put this repository in a state where git filters
        // it"; everything below is "and now write the plain text out". Stopping
        // here is the whole difference, and it is deliberately *after* the
        // evidence check and both repairs: a key handed to a repository whose
        // filter is not registered is not a safe place to leave anyone, whether
        // or not the tree was decrypted on the way.
        return Ok(report);
    }

    // The same paths, spelled the way the index stores them.
    let mut rewritten: Vec<Vec<u8>> = Vec::new();

    // **The loop stops at the first failure, but does not return from here.**
    // Every step below used to be a bare `?`, which dropped the whole report
    // together with the list of files already decrypted — and with it the stat
    // refresh underneath. Measured, on a clone whose second declared file sat in
    // a directory the user could not write: the first file was decrypted, the
    // message was `i/o failure: Permission denied (os error 13)` naming nothing,
    // and `git status` reported the decrypted file as modified for good, because
    // a later run finds it already in the clear and so never refreshes it.
    let mut stopped = None;
    for file in &encrypted {
        let relative = relative_to(repo, &file.path);
        let name = repo_relative_bytes(&relative);
        let content = match fs::read(&file.path) {
            Ok(content) => content,
            Err(err) => {
                stopped = Some(named_io(&relative, "read", &err));
                break;
            }
        };
        let decision = config.decide(&name);

        // The very function the smudge path calls, on purpose: anything else
        // here would be a second implementation of line-ending handling, and the
        // two would drift into a working tree git reports as modified.
        let outcome = match decide::smudge(
            Some(&key),
            &name,
            &content,
            decision.encrypt,
            decision.eol,
            autocrlf.as_deref(),
            core_eol.as_deref(),
        ) {
            Ok(outcome) => outcome,
            Err(err) => {
                stopped = Some(Error::Format(format!("{}: {err}", git_spelling(&relative))));
                break;
            }
        };

        if let Some(warning) = outcome.warning {
            report.warnings.push(warning);
        }

        // Zeroizing: this is the secret, now in the clear on the heap.
        let plaintext = Zeroizing::new(outcome.content);
        if *plaintext == content {
            // Unreachable for anything `collect_encrypted` yields — ciphertext
            // is 38 bytes longer than its plaintext, so the two can never be
            // equal. Skipping what is already plain happens one level up, in the
            // walk; this is only here so a write can never be a no-op.
            continue;
        }
        // Atomic, and inheriting the file's own mode, so an interruption cannot
        // leave a half-written secret and an executable stays executable.
        match crate::util::atomic::write(&file.path, &plaintext) {
            Ok(()) => {}
            Err(Error::Io(err)) => {
                stopped = Some(named_io(&relative, "replace", &err));
                break;
            }
            Err(err) => {
                stopped = Some(err);
                break;
            }
        }
        rewritten.push(name);
        report.decrypted.push(relative);
    }

    // Last, and not optional: without it git compares the new size against the
    // one it cached for the ciphertext, concludes the file changed and never
    // runs the filter to find out otherwise. `git status` would then report
    // every unlocked secret as modified, for good. See `crate::git::index`.
    //
    // Run even when the loop stopped, and that is the point: the files already
    // rewritten are the ones whose cached size is now wrong, and no later run
    // will come back for them — they are plain text by then, so the walk does
    // not select them at all.
    let refreshed = crate::git::index::forget_stat(
        &repo.git_dir().join("index"),
        crate::git::index::object_hash(
            gitconfig::get(&git_config, "extensions.objectformat").as_deref(),
        ),
        &rewritten,
    );
    match refreshed {
        Ok(crate::git::index::Outcome::Cleared(_)) => {}
        Ok(crate::git::index::Outcome::Skipped(why)) => report.warnings.push(why),
        // A warning, not a return: the decryption already happened, and a bare
        // `Err` here threw the whole report away — the user was never told that
        // N files now sit in the clear, and a second run cannot say it either,
        // because the files are plain by then and the walk no longer selects
        // them. `Skipped` (a held lock, a split index) already answers the
        // identical situation with a warning carrying the remedy; a failed read
        // or write differs only in the errno. The report's own decrypted list
        // is the load-bearing half — what changed on disk must reach the user
        // whatever the stat cache did.
        Err(err) if stopped.is_none() => report.warnings.push(format!(
            "the index's stat cache could not be refreshed ({err}). The files \
             are decrypted correctly; if `git status` shows them as modified, \
             `git add --renormalize .` settles it."
        )),
        // A second failure on top of the one that stopped the loop. The first is
        // what the user has to act on; this one goes with it rather than
        // replacing it.
        Err(err) => report.warnings.push(err.to_string()),
    }

    if let Some(err) = stopped {
        return Err(interrupted(&report, &encrypted, err));
    }

    Ok(report)
}

/// Refuses when the repository already holds a key that is not this one.
///
/// Separate from [`install`] because this question has to be asked before
/// anything at all is written: a refusal that has already installed a key has
/// not refused.
///
/// # Errors
///
/// [`Error::Config`] for a different key, [`Error::Format`] when the key file
/// already in the repository cannot be read.
fn refuse_on_conflict(repo: &Repo, key: &crate::crypto::key::MasterKey) -> Result<()> {
    match repo.load_key() {
        Ok(existing) if existing.key_id() == key.key_id() => Ok(()),
        Ok(existing) => Err(Error::Config(format!(
            "this repository already holds key {}, and that file offers key {}.\n\
             Replacing it would make every file encrypted so far impossible to read, for good.\n\
             If you really mean to change keys, remove {} deliberately first.",
            crate::format_key_id(&existing.key_id()),
            crate::format_key_id(&key.key_id()),
            repo.key_path().display()
        ))),
        Err(Error::NoKey) => Ok(()),
        // A key file we cannot parse is not evidence of absence. Naming it is
        // the whole repair the user needs.
        Err(Error::Format(message)) => Err(Error::Format(format!(
            "{}: {message}",
            repo.key_path().display()
        ))),
        Err(other) => Err(other),
    }
}

/// Writes `key` into the repository, reporting whether it had to.
///
/// Only correct after [`refuse_on_conflict`] has passed: on its own it would
/// treat a *different* key already in place as "nothing to do".
///
/// # Errors
///
/// [`Error::Io`] when the key file cannot be written.
fn install(repo: &Repo, key: &crate::crypto::key::MasterKey) -> Result<bool> {
    if repo.has_key() {
        return Ok(false);
    }
    keyfile::write(&repo.key_path(), key)?;
    Ok(true)
}

/// Puts a path and the operation in front of a bare I/O failure.
///
/// `Permission denied (os error 13)` names neither the file nor what was being
/// done to it, which for a command part way through rewriting a working tree is
/// the least useful message it could produce. Measured before this: a `unlock`
/// stopped by one unwritable directory said exactly that and nothing else.
fn named_io(relative: &Path, action: &str, err: &std::io::Error) -> Error {
    Error::Io(std::io::Error::other(format!(
        "{}: could not {action} it ({err})",
        git_spelling(relative)
    )))
}

/// Adds what was already done to an error that stopped the decryption pass.
///
/// The bare error drops the report, and with it the only record that part of the
/// working tree is now in the clear and part of it is not. The same shape `lock`
/// uses for the same reason — and, unlike `lock`, this one has to say that a
/// second run will *not* revisit what already succeeded, because a file in the
/// clear no longer carries the magic the walk selects on.
fn interrupted(report: &Report, encrypted: &[Encrypted], err: Error) -> Error {
    let done = report.decrypted.len();
    let left = encrypted.len().saturating_sub(done);
    let context = format!(
        "\nunlock stopped part way: {done} file(s) are now in the clear and {left} \
         are still encrypted. The key is in place, so running unlock again picks up \
         the rest once the cause above is fixed."
    );
    match err {
        Error::Format(message) => Error::Format(message + &context),
        Error::Crypto(message) => Error::Crypto(message + &context),
        Error::Config(message) => Error::Config(message + &context),
        Error::Io(err) => Error::Io(std::io::Error::other(format!("{err}{context}"))),
        other => other,
    }
}

/// A working-tree file that carries our magic, and the header it carries.
#[derive(Debug)]
pub(super) struct Encrypted {
    path: PathBuf,
    header: Header,
}

/// Every encrypted file in the working tree, in a stable order.
///
/// Only the first 38 bytes of each file are read, so the cost is one open per
/// file rather than one full read — the same reasoning that lets `status` scan a
/// whole history cheaply. The walk is otherwise exhaustive: it has no notion of
/// `.gitignore`, so it does descend `target/` and `node_modules/`. That is the
/// price of deciding by header, and it buys the case that matters — an encrypted
/// file that no current pattern selects still gets decrypted, exactly as a
/// checkout would decrypt it.
///
/// Untracked files are included for the same reason, and the bootstrap
/// exclusions (`.gitattributes`, `.git-xcrypt`) are not consulted: a file
/// carrying our magic is one of ours whatever its name, and leaving it as
/// ciphertext would be the surprise.
///
/// A path that cannot be read becomes a warning rather than a failure. One
/// root-owned build artefact must not be able to stop a user recovering their
/// secrets, and skipping a file only ever means leaving it encrypted — but the
/// skipped paths are counted and reported, because "decrypted everything" and
/// "decrypted what it could" must not read the same.
///
/// Symbolic links are left alone: following one would write outside the
/// repository, and replacing it would destroy the link.
///
/// **A directory holding a `.git` entry is another repository and is not
/// entered.** Skipping the entry named `.git` is not enough — that leaves the
/// submodule's *working tree* in the walk, and a submodule encrypted with its
/// own key then makes the parent's `unlock` fail with a key mismatch it cannot
/// be talked out of, having decrypted nothing. Measured. A submodule has its own
/// configuration, its own key and its own index; it needs its own `unlock`.
pub(super) fn collect_encrypted(repo: &Repo, walk: &mut Walk) -> Result<Vec<Encrypted>> {
    let mut found = Vec::new();
    let mut pending = vec![repo.work_tree().to_path_buf()];

    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(err) => {
                walk.warnings
                    .push(format!("{}: not searched ({err})", directory.display()));
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    walk.warnings
                        .push(format!("{}: not searched ({err})", directory.display()));
                    continue;
                }
            };
            if entry.file_name() == ".git" {
                continue;
            }

            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                walk.warnings
                    .push(format!("{}: skipped, it could not be read", path.display()));
                walk.unreadable.push(relative_to(repo, &path));
                continue;
            };
            if metadata.is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                if path.join(".git").exists() {
                    walk.warnings.push(format!(
                        "{}: a repository of its own, left to its own `git-xcrypt unlock`",
                        git_spelling(&relative_to(repo, &path))
                    ));
                } else {
                    pending.push(path);
                }
                continue;
            }
            if !metadata.is_file() {
                continue;
            }

            match peek_header(&path) {
                // A file whose header will not parse is one of ours and broken;
                // that has to stop the run, unlike a file we simply cannot open.
                Ok(Some(header)) => found.push(Encrypted { path, header }),
                Ok(None) => {}
                Err(Error::Io(err)) => {
                    walk.warnings
                        .push(format!("{}: skipped ({err})", path.display()));
                    walk.unreadable.push(relative_to(repo, &path));
                }
                Err(err) => return Err(err),
            }
        }
    }

    found.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(found)
}

/// What the walk noticed on its way through, besides the files it found.
#[derive(Debug, Default)]
pub(super) struct Walk {
    /// Paths that could not be read, so may still hold ciphertext.
    unreadable: Vec<PathBuf>,
    /// Messages for the user, one per thing skipped.
    pub(super) warnings: Vec<String>,
}

/// A path relative to the working tree, or the path itself if it is outside.
fn relative_to(repo: &Repo, path: &Path) -> PathBuf {
    repo.relative(path)
        .map_or_else(|| path.to_path_buf(), Path::to_path_buf)
}

/// Reads the header of `path`, or `None` when the file is not one of ours.
///
/// A file that starts with our magic but is too short to hold a header is an
/// error rather than a shrug: it is a truncated encrypted file, and carrying on
/// would mean deciding it is plaintext.
fn peek_header(path: &Path) -> Result<Option<Header>> {
    let mut file = fs::File::open(path)?;
    let mut prefix = [0u8; OVERHEAD];
    let read = fill(&mut file, &mut prefix)?;
    let prefix = &prefix[..read];

    if !format::looks_encrypted(prefix) {
        return Ok(None);
    }

    Header::parse(prefix)
        .map(Some)
        .map_err(|err| Error::Format(format!("{}: {err}", path.display())))
}

/// Reads until `buffer` is full or the file ends, returning how much arrived.
///
/// `Interrupted` is retried rather than reported, the way `std`'s own readers
/// do: a signal arriving during a 38-byte read is not a reason to abandon a
/// user's repository half unlocked.
fn fill(file: &mut fs::File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

/// Refuses when any file belongs to a key other than the one offered.
///
/// Deliberately an [`Error::Format`] rather than [`Error::KeyMismatch`]: both
/// report exit code 4, and this one can name the file, which is what turns
/// "authentication failed" into an instruction.
pub(super) fn refuse_foreign_keys(
    repo: &Repo,
    encrypted: &[Encrypted],
    key_id: &[u8; KEY_ID_LEN],
) -> Result<()> {
    for file in encrypted {
        if file.header.key_id == *key_id {
            continue;
        }

        let relative = relative_to(repo, &file.path);
        return Err(Error::Format(format!(
            "{} was encrypted with key {}, but the key offered here is {}.\n\
             Nothing has been changed. Unlock this repository with the key whose id is {}.",
            git_spelling(&relative),
            crate::format_key_id(&file.header.key_id),
            crate::format_key_id(key_id),
            crate::format_key_id(&file.header.key_id)
        )));
    }
    Ok(())
}

/// A repository-relative path as the pattern matcher expects it.
///
/// Bytes rather than text, and forward slashes: on Unix a path is an arbitrary
/// byte string, and decoding it lossily would match a file under a name it does
/// not have.
fn repo_relative_bytes(relative: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        relative.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        relative.to_string_lossy().replace('\\', "/").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The export shape every case below is a variation on.
    const EXPORT: &str = "git-xcrypt-key-v1 fd2f0a5c2d19a55b\n\
                          KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=\n";

    fn read(input: &str, terminal: bool) -> (String, String) {
        let mut said = Vec::new();
        let text = read_key_material(&mut input.as_bytes(), &mut said, terminal)
            .expect("reading from a slice cannot fail");
        (
            text.to_string(),
            String::from_utf8(said).expect("the prompt is text"),
        )
    }

    /// Both terminators, because a pipe reaches one and a person reaches the
    /// other, and the same text has to come out of each.
    #[test]
    fn entry_ends_at_a_blank_line_or_at_the_end_of_the_input() {
        let (piped, _) = read(EXPORT, false);
        assert_eq!(piped, EXPORT, "end of input did not end the entry");

        // What a person types: the two lines, then Enter on an empty one. The
        // blank line is not part of the key and must not reach the parser.
        let (typed, _) = read(&format!("{EXPORT}\n"), true);
        assert_eq!(typed, EXPORT, "the blank line was kept, or ate the key");

        // Anything after the blank line belongs to whoever comes next — a
        // second command reading the same pipe — and never to this key.
        let (stopped, _) = read(&format!("{EXPORT}\nnot the key\n"), true);
        assert_eq!(stopped, EXPORT, "reading ran past the blank line");

        // The same two shapes spelled `\r\n`, which is what a Windows console
        // hands a `read_line` and what a clipboard carries out of a password
        // manager or an email — the very routes this entry form exists for.
        // `str::trim` is what makes such a line read as blank; a terminator
        // that only knew `\n` would run straight past it, and at a terminal
        // that is a command which never returns. Asserted through the second
        // shape rather than the first, because that one *fails*: the text that
        // followed becomes a third significant line and the parser refuses the
        // file for carrying more than one key.
        let crlf = EXPORT.replace('\n', "\r\n");
        let (typed_crlf, _) = read(&format!("{crlf}\r\n"), true);
        assert_eq!(
            typed_crlf, crlf,
            "a CRLF blank line was kept, or ate the key"
        );
        let (stopped_crlf, _) = read(&format!("{crlf}\r\nnot the key\r\n"), true);
        assert_eq!(stopped_crlf, crlf, "reading ran past a CRLF blank line");

        for (shape, text) in [
            ("piped", piped.as_str()),
            ("typed", typed.as_str()),
            ("stopped", stopped.as_str()),
            ("typed with CRLF", typed_crlf.as_str()),
            ("stopped at a CRLF blank line", stopped_crlf.as_str()),
        ] {
            keyfile::decode_portable(text)
                .unwrap_or_else(|err| panic!("the {shape} entry does not parse: {err}"));
        }
    }

    /// A key out of a password manager or an email body arrives padded.
    ///
    /// The file route already tolerates this — `keyfile::significant_lines`
    /// skips blank lines wherever they fall — so the typed route refusing it
    /// would make the same key readable one way and not the other.
    #[test]
    fn a_leading_blank_line_is_skipped_rather_than_read_as_the_end() {
        let (text, _) = read(&format!("\n\n{EXPORT}\n"), true);
        assert!(
            keyfile::decode_portable(&text).is_ok(),
            "a leading blank line ended the entry before the key: {text:?}"
        );
    }

    /// The terminal arm, which `tests/second_machine.rs` cannot reach.
    ///
    /// A pty is a Unix mechanism and this rule holds on all three platforms, so
    /// the answer comes in as an argument exactly as it does for
    /// `export_key::to_writer`. Asserted in **both** directions: the warning is
    /// only true when something was echoed, and one that fires over a pipe is a
    /// warning people stop reading.
    #[test]
    fn only_an_echoing_terminal_is_told_the_key_is_in_the_scrollback() {
        let (_, over_a_pipe) = read(EXPORT, false);
        assert_eq!(
            over_a_pipe, "",
            "a pipe was prompted at, or warned about a scrollback it has not got"
        );

        let (_, at_a_terminal) = read(&format!("{EXPORT}\n"), true);
        assert!(
            at_a_terminal.contains("export-key"),
            "nothing said what to paste: {at_a_terminal:?}"
        );
        assert!(
            at_a_terminal.contains("scrollback"),
            "the key was echoed and nothing said so: {at_a_terminal:?}"
        );
        assert!(
            !at_a_terminal.contains("KioqKioq"),
            "the prompt printed the key back: {at_a_terminal:?}"
        );
    }
}
