//! `git-xcrypt lock` — close an unlocked repository, and delete its key.
//!
//! This is the most expensive command in the product to get wrong. `.git/` is
//! neither versioned nor pushed, so the key file it removes is the **only** copy
//! anywhere; `unlock` will not undo that, whatever its name suggests. Worse, the
//! loss is deferred: nothing breaks at the moment it runs, and the truth surfaces
//! months later at the first attempt to read anything. Most of this module is
//! therefore refusals, not work.
//!
//! **The order of operations is the whole design.** Prove the working tree holds
//! nothing that would be lost → warn and ask → encrypt every selected file →
//! *then* remove the key. Reversed, an interruption would leave a working tree in
//! the clear with no key left to encrypt it with, which is the one state this
//! command must never produce.
//!
//! **Selection is by pattern, not by header** — the mirror image of `unlock`, and
//! necessarily so: a plaintext file carries no header saying it is a secret, so
//! `.git-xcrypt` is the only thing that can say. The encryption itself goes
//! through [`decide::clean`], the very function git calls on the check-in path,
//! so the bytes this command writes are the bytes that are already committed.
//! That is what makes `git status` clean afterwards, and it is why line-ending
//! handling cannot drift between the two.
//!
//! **Two refusals, for two different losses.** The key is one; uncommitted work
//! is the other, and `--yes` waives only the first. Content that is not stored
//! in the repository exists nowhere but in the file `lock` is about to encrypt,
//! and after the key is gone that is the same as gone. The founding document is
//! explicit that this deserves a decision of its own.
//!
//! Everything this command cannot verify, it refuses over. A directory it cannot
//! list might hold a secret; an index it cannot parse cannot vouch for anything.
//! `unlock` skips such things and says so, because there the cost of skipping is
//! a file left encrypted. Here it would be a plaintext secret left behind by the
//! command that promised to remove it, so the two commands lean opposite ways on
//! purpose.

use std::fmt;
use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config::Config;
use crate::format::KEY_ID_LEN;
use crate::key::MasterKey;
use crate::repo::{Repo, git_spelling};
use crate::{Error, Result, atomic, decide, gitconfig, gitindex};

/// What `lock` did.
#[derive(Debug)]
pub struct Report {
    /// Fingerprint of the key that was removed. Safe to print; the key is not.
    pub key_id: [u8; KEY_ID_LEN],
    /// How many working-tree files the declaration selected.
    ///
    /// Separate from [`Report::encrypted`] so the closing line can tell "nothing
    /// to do, everything was already closed" from "nothing matched at all". The
    /// two look identical through a count of files written, and only one of them
    /// is a repository that is now safe.
    pub declared: usize,
    /// Paths, relative to the working tree, that were encrypted in place.
    pub encrypted: Vec<PathBuf>,
    /// Leftover temporary files that were deleted on the way through.
    ///
    /// Reported rather than swallowed: each one may have held a decrypted
    /// secret, and a user is entitled to know one was lying around.
    pub swept: Vec<PathBuf>,
    /// The filter registration was written or repaired.
    pub config_written: bool,
    /// The diff driver was deregistered — which happens on every healthy lock.
    ///
    /// Separate from [`Report::config_written`], which means "something was
    /// broken and I fixed it". Merging them made every lock claim a repair.
    pub diff_driver_removed: bool,
    /// The managed `.gitattributes` section was written or repaired.
    pub attributes_written: bool,
    /// The key file is gone.
    pub key_removed: bool,
    /// Anything worth saying once, carried out so the binary owns the messages.
    pub warnings: Vec<String>,
}

/// How a run ended.
#[derive(Debug)]
pub enum Outcome {
    /// The working tree is encrypted and the key is gone.
    Locked(Box<Report>),
    /// The user declined. Nothing was changed at all.
    Aborted,
}

/// Everything `lock` says before it does anything irreversible.
///
/// A value rather than a printed string so the same text reaches the user in
/// both modes, and so a test can assert on it without capturing a stream. It
/// names the key by fingerprint and **never** by material: printing the key here
/// was considered and rejected — it would survive in scrollback, in a terminal
/// multiplexer's buffer, in a CI log, and in the working tree the moment someone
/// redirects this command's output.
#[derive(Debug)]
pub struct Warning {
    /// Fingerprint of the key about to be deleted.
    pub key_id: [u8; KEY_ID_LEN],
    /// Where that key lives.
    pub key_path: PathBuf,
    /// How many working-tree files the declaration selects.
    pub declared: usize,
    /// How many of those are still plaintext, so will actually change.
    pub still_open: usize,
    /// Temporary files this run will delete.
    ///
    /// Named here rather than only in the closing report, because deleting an
    /// untracked file is irreversible and disclosing it afterwards is too late
    /// to be a disclosure.
    pub sweeping: Vec<PathBuf>,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_id = crate::format_key_id(&self.key_id);
        writeln!(
            f,
            "WARNING: lock deletes the only copy of this repository's key.\n\
             \n  \
             key_id: {key_id}\n  \
             path:   {}\n  \
             files:  {} declared, {} of them still in the clear\n\
             \n\
             After this, decrypting anything — including the entire history — will be\n\
             possible only from a copy of the key held outside this directory.\n\
             unlock WILL NOT UNDO THIS.\n\
             \n\
             If you do not have a copy, abort and run:\n  \
             git-xcrypt export-key <a path outside this repository>/git-xcrypt-{}.key",
            self.key_path.display(),
            self.declared,
            self.still_open,
            &key_id[..8],
        )?;

        if self.declared == 0 {
            writeln!(
                f,
                "\nNothing in this working tree matches {}, so nothing will be encrypted.\n\
                 If you expected secrets to be closed here, abort and check the declaration.",
                crate::repo::CONFIG_FILE
            )?;
        }

        if !self.sweeping.is_empty() {
            writeln!(
                f,
                "\nThese temporary files, left by an interrupted run, will be deleted.\n\
                 They are untracked, so deleting them cannot be undone:"
            )?;
            for path in &self.sweeping {
                writeln!(f, "  {}", git_spelling(path))?;
            }
        }
        Ok(())
    }
}

/// Decides whether the irreversible half of `lock` may go ahead.
///
/// An injected decision rather than a flag, so the interactive path is exercised
/// by tests instead of being the one branch nothing covers.
pub trait Confirm {
    /// Presents `warning` and answers whether to proceed.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the warning cannot be shown or the answer cannot be
    /// read. Refusing is the safe default, so a failure here must not be turned
    /// into a yes.
    fn confirm(&mut self, warning: &Warning) -> Result<bool>;
}

/// `--yes`: shows the warning, asks nothing.
///
/// The warning is printed in this mode too, deliberately. A non-interactive run
/// still has a reader — the CI log, the terminal it scrolled past — and silence
/// would make the destructive step invisible in exactly the setting where nobody
/// is watching it happen.
#[derive(Debug)]
pub struct Assumed<W> {
    output: W,
}

impl<W: Write> Assumed<W> {
    /// Writes the warning to `output` and proceeds.
    pub const fn new(output: W) -> Self {
        Self { output }
    }
}

impl<W: Write> Confirm for Assumed<W> {
    fn confirm(&mut self, warning: &Warning) -> Result<bool> {
        writeln!(self.output, "{warning}")?;
        writeln!(
            self.output,
            "Proceeding without asking, because --yes was given."
        )?;
        self.output.flush()?;
        Ok(true)
    }
}

/// The default: shows the warning and waits for the word `yes`.
///
/// The streams are whatever the caller hands over, which in the binary means
/// `stdin` and `stderr` rather than the controlling terminal. Two consequences
/// worth knowing rather than discovering: `git-xcrypt lock < answers.txt`
/// proceeds if the first line is `yes`, and `git-xcrypt lock 2>/dev/null` waits
/// on a prompt nobody can see. Opening `/dev/tty` instead would fix both on Unix
/// and has no portable equivalent, and this binary ships on Windows too.
#[derive(Debug)]
pub struct Ask<R, W> {
    input: R,
    output: W,
}

impl<R: BufRead, W: Write> Ask<R, W> {
    /// Asks on `output` and reads the answer from `input`.
    pub const fn new(input: R, output: W) -> Self {
        Self { input, output }
    }
}

impl<R: BufRead, W: Write> Confirm for Ask<R, W> {
    /// Accepts the exact word `yes` and nothing else.
    ///
    /// Not `y`, not `YES`: the founding document asks for a word typed in full
    /// because the point of the prompt is to interrupt a reflex. End of input —
    /// a run with no terminal behind it, `lock < /dev/null` in a script — reads
    /// as a refusal, which is the direction that changes nothing.
    fn confirm(&mut self, warning: &Warning) -> Result<bool> {
        writeln!(self.output, "{warning}")?;
        write!(self.output, "\nType `yes` to delete the key: ")?;
        self.output.flush()?;

        // ASCII whitespace only: `str::trim` also strips U+00A0 and friends, and
        // a non-breaking space is exactly the kind of thing a paste from a web
        // page carries. `\u{a0}yes` reading as consent is not a risk this
        // particular prompt should take.
        let mut answer = String::new();
        if self.input.read_line(&mut answer)? == 0 {
            // No newline was echoed, so the next line the user sees would run
            // into the prompt.
            writeln!(self.output)?;
            return Ok(false);
        }
        Ok(answer.trim_matches(|c: char| c.is_ascii_whitespace()) == "yes")
    }
}

/// Locks `repo`: encrypts every selected file, then removes the key.
///
/// # Errors
///
/// [`Error::NoKey`] when there is no key to remove — which is also what a second
/// run reports, harmlessly. [`Error::Config`] when `.git-xcrypt` is missing or
/// unreadable, when a selected file holds content the repository does not store,
/// or when something in the way stops this command proving either. [`Error::Format`]
/// or [`Error::KeyMismatch`] for a file already encrypted under another key.
/// [`Error::Io`] on a read or write failure.
pub fn run(repo: &Repo, confirm: &mut dyn Confirm) -> Result<Outcome> {
    // First, so a repository with nothing to lock says so before anything is
    // read, walked or asked.
    let key = repo.load_key()?;
    let key_id = key.key_id();

    let config = Config::load(&repo.xcrypt_config_path())?;
    if config.missing {
        // The check-in path treats this as fatal for the same reason: without
        // the declaration a secret and a readme are indistinguishable, and the
        // wrong guess here leaves a secret in the clear in a repository whose
        // key has just been deleted.
        return Err(Error::Config(format!(
            "{}: the file that says what to encrypt is missing, so lock cannot tell \
             which files to close. Restore it from the repository or run \
             `git-xcrypt init`. Nothing has been changed.",
            crate::repo::CONFIG_FILE
        )));
    }

    // Before anything else that costs work: this repository's key is shared by
    // every checkout, and the walk below only ever sees one of them.
    refuse_other_worktrees(repo)?;

    let git_config = gitconfig::open_full(repo.common_dir())?;
    let hash =
        gitindex::object_hash(gitconfig::get(&git_config, "extensions.objectformat").as_deref());

    let mut walk = Walk::default();
    let found = collect(repo, &config, &mut walk)?;
    let stored = stored_ids(repo, hash, &found.selected, &found.residue)?;

    // Every name the first walk saw, captured before any sweep decision thins
    // the lists. The late "did the tree move" check compares a fresh walk
    // against this, and the fresh walk cannot know which residue was sweepable
    // — so the two sides have to count the same things, or a *tracked* residue
    // file (excluded from the sweep, and possibly from the selection) reads as
    // "appeared while lock was running" and refuses for ever over a tree that
    // never moved.
    let mut surveyed_names: Vec<Vec<u8>> = found
        .selected
        .iter()
        .chain(&found.residue)
        .map(|file| file.name.clone())
        .collect();
    surveyed_names.sort_unstable();
    surveyed_names.dedup();

    // The sweep is settled first, because what it takes must not then be
    // surveyed: residue is untracked by construction, so surveying it would
    // refuse every lock that has any.
    let residue = sweepable(&found.residue, &stored.residue, &mut walk);
    let (selected, stored_selected) = drop_swept(found.selected, stored.selected, &residue);

    let survey = survey(&key, &config, &selected, &stored_selected, hash)?;

    let warning = Warning {
        key_id,
        key_path: repo.key_path(),
        declared: selected.len(),
        still_open: survey.still_open,
        sweeping: residue.iter().map(|file| file.relative.clone()).collect(),
    };
    if !confirm.confirm(&warning)? {
        return Ok(Outcome::Aborted);
    }

    let mut report = Report {
        key_id,
        declared: selected.len(),
        encrypted: Vec::new(),
        swept: Vec::new(),
        config_written: false,
        diff_driver_removed: false,
        attributes_written: false,
        key_removed: false,
        warnings: config.pointless_eol.clone(),
    };
    report.warnings.append(&mut walk.warnings);
    if selected.is_empty() {
        // Not an error — an empty declaration is legal — but it is also what a
        // typo in `.git-xcrypt`, or a branch predating it, looks like from here.
        // Saying "locked" over it would assert a state that does not hold, and
        // the key is about to be gone, so this is the last chance to notice.
        report.warnings.push(format!(
            "no file in the working tree matches {}, so nothing was encrypted. \
             If you expected secrets to be closed here, check the declaration \
             before relying on this repository being safe.",
            crate::repo::CONFIG_FILE
        ));
    }

    // Nothing above this line has touched anything, so an abort really did
    // change nothing. From here on it has, which is why the last look at the
    // working tree happens now: a declared file created while the prompt waited
    // is not in the selection, and locking around it would delete the key over a
    // plaintext secret nobody mentioned. Measured before this check: a file
    // created 1.5 s into the prompt survived a successful lock, in the clear.
    refuse_if_the_tree_moved(repo, &config, &surveyed_names)?;

    // The last command run before the key goes is the last chance to notice that
    // git has no filter behind the catch-all attribute — and a locked repository
    // needs it more than an unlocked one, because there the clean path is what
    // turns "no key" into a refused `git add` instead of a stored plaintext.
    // Measured on git 2.55: with either half missing, `git add` on a secret in a
    // locked repository exits 0 and stores the plaintext.
    //
    // Only what is *missing*, in both halves. The cosmetic lines are allowed to
    // be out of date — `.git-xcrypt` is the source of truth and `sync` is what
    // regenerates them — so rewriting the section here would leave `git status`
    // dirty after a successful lock, disclosed to nobody and after the key was
    // already gone.
    //
    // The same call takes the diff driver back *out*: with no key, textconv
    // drags the smudge filter into every `git log -p` and aborts it. See
    // `init::register_driver_for_lock`.
    let registration = super::init::register_driver_for_lock(repo)?;
    report.config_written = registration.repaired;
    report.diff_driver_removed = registration.diff_driver_removed;

    // A textconv cache holds decrypted copies inside `.git/`, and this is the
    // command after which nobody can decrypt anything — so it is the last moment
    // the plaintext left behind is worth naming.
    report
        .warnings
        .extend(super::init::textconv_cache_warning(repo));
    report.attributes_written = write_catch_all_if_missing(repo, &config)?;

    // Before the encryption pass, so nothing we are about to write is mistaken
    // for residue, and so a leftover of a file we then encrypt cannot outlive
    // the command holding that file's plaintext.
    sweep(&residue, &mut report);

    encrypt_in_place(&key, &config, &selected, &survey, hash, &mut report)
        .map_err(|err| interrupted(&report, err))?;

    // Every selected file, not only the ones this run rewrote. Git compares the
    // new size against the one it cached for the plaintext, concludes the file
    // changed and never runs the filter to find out otherwise — so `git status`
    // reports every locked secret as modified, for good. Passing only the
    // rewritten ones left a file encrypted by an *interrupted* earlier run
    // permanently modified, because the second run skipped it as already closed.
    // Measured. See `crate::gitindex`.
    let names: Vec<Vec<u8>> = selected.iter().map(|file| file.name.clone()).collect();
    match gitindex::forget_stat(&repo.git_dir().join("index"), hash, &names)? {
        gitindex::Outcome::Cleared(cleared) if cleared < names.len() => {
            // Every selected file was proved tracked by the survey, so a name
            // the index did not match is a name spelled differently there than
            // on disk — case folding on macOS and Windows, or NFD against NFC.
            report.warnings.push(format!(
                "{} of {} file(s) were not found in the index under the name they \
                 have on disk, so their cached size was left alone. They are \
                 encrypted correctly; if `git status` shows them as modified, \
                 `git add --renormalize .` settles it.",
                names.len() - cleared,
                names.len()
            ));
        }
        gitindex::Outcome::Cleared(_) => {}
        gitindex::Outcome::Skipped(why) => report.warnings.push(why),
    }

    // The last thing asked before the irreversible step, and the only one asked
    // of the *index* rather than of the walk. Everything above trusts that a
    // walk of the working tree sees every declared file; that is true only while
    // the two agree on how a name is spelled. Measured on git 2.55 and APFS,
    // where they need not: `mv secrets Secrets` leaves the index saying
    // `secrets/db.env`, the disk saying `Secrets/`, `git status` saying nothing
    // at all — and this command saying "no file here is declared for
    // encryption", exiting 0 with the key deleted over a plaintext secret.
    // `src/gitindex.rs` described that case and called the outcome safe for
    // `lock` because it "refuses rather than proceeds". It did not.
    //
    // Asked about content, not about spelling, so it settles nothing about what
    // a pattern ought to mean on such a filesystem — only whether this run has
    // done what it is about to promise.
    refuse_if_a_declared_file_is_still_open(repo, &config, hash)?;

    // Last, and only once every file above is ciphertext. A failure before this
    // point leaves the key in place, so re-running finishes the job.
    remove_key(repo, &mut report)?;

    Ok(Outcome::Locked(Box::new(report)))
}

/// Refuses while another checkout of this repository shares the key.
///
/// The key lives in the common directory, so every worktree reads the same one,
/// but the walk below only ever sees the checkout it was run from. Locking one
/// and deleting the key leaves the others holding **plaintext with no key left
/// to close them** — the exact state this module exists to make impossible, and
/// reached on the success path rather than by interruption. Measured on git
/// 2.55: `lock` in the main worktree left a linked one readable, and `lock`
/// there then failed with "no repository key".
///
/// Refusing rather than locking them all: each checkout has its own index, its
/// own `HEAD` and possibly its own `.git-xcrypt`, so proving them clean means
/// running this whole command per worktree, which the user can do.
///
/// **The registration directory is the evidence, not the checkout.** An earlier
/// version asked whether the path in `worktrees/<name>/gitdir` still existed and
/// treated a miss as a stale registration. Two measured ways that was wrong: the
/// pointer is sometimes relative, so `exists()` answered against the process's
/// current directory and the same command gave opposite answers from the
/// repository root and from a subdirectory of it; and a checkout moved with `mv`
/// rather than `git worktree move` is fully alive while its back-pointer names
/// nothing. Both ended with the key deleted and a live checkout left in the
/// clear. A registration git would really prune costs the user one
/// `git worktree prune`, which the message names.
///
/// **An unreadable registration directory refuses, it does not read as "none".**
/// This listing *is* the evidence the whole refusal rests on, so a failure to
/// take it has to be fatal here the way it is in [`collect`] — only the
/// directory being absent means there are no linked worktrees. Measured before
/// this distinction existed: `chmod 000 .git/worktrees` over a repository with
/// one linked checkout took `lock --yes` all the way to "locked; key … has been
/// deleted", left `../side/secrets/db.env` reading `TOP SECRET`, and `unlock`
/// there answered "no repository key". The permission is only the cheapest
/// trigger — an I/O error, an exhausted descriptor table or a stale network
/// handle reach the same line, and every one of them is a question rather than
/// an answer. Note the contrast with [`crate::repo::Repo::work_trees`], which
/// swallows the identical failure on purpose: that list is only ever used to
/// *widen* a refusal, so a short one costs nothing, while a short list here is
/// what deletes the key.
fn refuse_other_worktrees(repo: &Repo) -> Result<()> {
    let mut others = Vec::new();

    let registrations = repo.common_dir().join("worktrees");
    match fs::read_dir(&registrations) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|err| unverifiable(&registrations, &err))?;
                let registration = entry.path();
                if same_path(&registration, repo.git_dir()) {
                    continue;
                }
                others.push(describe_worktree(repo, &registration));
            }
        }
        // The ordinary case: a repository that has never had a linked worktree
        // has no such directory at all.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(unverifiable(&registrations, &err)),
    }

    // And, when this *is* a linked worktree, the main checkout — which is not
    // listed anywhere under `worktrees/`.
    if !same_path(repo.git_dir(), repo.common_dir())
        && let Some(main) = main_checkout(repo)
    {
        others.push(main);
    }

    if others.is_empty() {
        return Ok(());
    }

    others.sort();
    let list = others
        .iter()
        .map(|what| format!("  {what}"))
        .collect::<Vec<_>>()
        .join("\n");
    Err(Error::Config(format!(
        "this repository has {} other checkout(s), and they all read the key lock \
         would delete:\n\
         {list}\n\
         Locking only this one would leave their files in the clear with no key left \
         to close them. Lock each checkout first, or remove it with \
         `git worktree remove`; if one of them is already gone, `git worktree prune` \
         clears the registration. Nothing has been changed.",
        others.len()
    )))
}

/// Refuses if the working tree stopped matching what was surveyed and agreed to.
///
/// The prompt is an unbounded human-scale wait. An edit to a file already in the
/// selection is caught later, by the object id [`survey`] recorded; this catches
/// the other half — a declared file that **appeared** or **vanished** meanwhile,
/// which no per-file check can see because it was never in the list.
///
/// `before` is the full name set of the first walk — selection and residue
/// candidates alike, sorted and deduplicated — and the fresh walk here is
/// reduced to exactly the same shape. Comparing anything narrower is how a
/// tracked residue file, which the sweep declines and the selection may not
/// contain, used to read as a file that "appeared" between the two walks.
fn refuse_if_the_tree_moved(repo: &Repo, config: &Config, before: &[Vec<u8>]) -> Result<()> {
    let mut walk = Walk::default();
    let now = collect(repo, config, &mut walk)?;

    let mut after: Vec<&[u8]> = now
        .selected
        .iter()
        .chain(&now.residue)
        .map(|file| file.name.as_slice())
        .collect();
    after.sort_unstable();
    after.dedup();

    let before: Vec<&[u8]> = before.iter().map(Vec::as_slice).collect();
    if before == after {
        return Ok(());
    }
    Err(Error::Config(
        "the set of declared files changed while lock was running, so what it \
         checked is no longer what is here. Nothing has been changed and the key \
         has been kept; run lock again."
            .into(),
    ))
}

/// Refuses while a declared file the index tracks still holds plain text.
///
/// The walk this command is built on reads directory entries; the index keeps
/// whatever spelling a path was added under. On a case-insensitive filesystem —
/// APFS, and NTFS with `core.ignorecase`, which git sets by default on both —
/// those two can drift apart with **no signal anywhere**: after `mv secrets
/// Secrets` the index still says `secrets/db.env`, `git status` is clean, and
/// the walk selects nothing, because selection matches bytes. Measured on git
/// 2.55 before this existed: `lock --yes` printed "no file here is declared for
/// encryption", exited 0, deleted the key, and left `hunter2-secret` readable in
/// the working tree. The interactive path did the same after a typed `yes`.
///
/// Asked last, after the encryption pass, because before it every declared path
/// legitimately holds plain text — that is what the pass is for. Asked of the
/// content rather than of the two spellings, which is what keeps it free of the
/// open question about what a pattern means on such a filesystem: whatever the
/// answer to that turns out to be, a command that is one statement away from
/// "the key is gone" must not make it over a file it can still read.
///
/// A declared entry with nothing at its path is not a finding: a staged deletion
/// leaves the index naming a file that is gone, and there is no plain text in a
/// file that does not exist. That is the **only** read failure treated as an
/// answer — measured when it was not: with a declared file at mode `000` and the
/// spellings already drifted apart, an earlier version of this gate skipped it,
/// the key went, and the plain text was readable again the moment the mode was
/// put back. Symlinks and gitlinks are skipped for the reason
/// `gitindex::Tracked::holds_content` gives — their blob is not file content and
/// no filter ever ran on them.
///
/// An index that cannot be read is a refusal too, not a pass. This is the last
/// gate in front of an irreversible step, and "I could not check" is the one
/// answer it must never round down.
fn refuse_if_a_declared_file_is_still_open(
    repo: &Repo,
    config: &Config,
    hash: gix_hash::Kind,
) -> Result<()> {
    let index_path = repo.git_dir().join("index");
    let entries = match gitindex::list(&index_path, hash)? {
        gitindex::Listed::Read(entries) => entries,
        gitindex::Listed::Unavailable(why) => {
            return Err(Error::Config(format!(
                "{} could not be read ({why}), so lock cannot prove that every \
                 declared file here is closed. The key has been kept and every \
                 file it did encrypt is encrypted; nothing else has changed.",
                index_path.display()
            )));
        }
    };

    let mut open: Vec<String> = Vec::new();
    for entry in entries {
        if !entry.holds_content() || !config.decide(&entry.path).encrypt {
            continue;
        }
        let path = repo
            .work_tree()
            .join(crate::repo::working_tree_path(&entry.path));
        // Only the header is needed, and reading the whole file would be a
        // pointless copy of a secret into this process for the large ones.
        let mut head = [0u8; crate::format::MAGIC.len()];
        let read = std::fs::File::open(&path).and_then(|mut file| {
            use std::io::Read as _;
            file.read(&mut head)
        });
        match read {
            Ok(read) if head[..read] == crate::format::MAGIC => {}
            // Nothing at that path: a staged deletion leaves the index naming a
            // file that is gone, and a file that does not exist holds no plain
            // text. The **only** failure that is an answer rather than a
            // question — measured before it was the only one: with a declared
            // file at mode `000` this arm swallowed the refusal, the key went,
            // and the plain text was readable again the moment the mode was put
            // back.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => open.push(bstr::BStr::new(&entry.path).to_string()),
            Err(err) => {
                return Err(Error::Config(format!(
                    "refusing to delete the key: {} is declared and tracked, and \
                     could not be read ({err}), so lock cannot show it is closed. \
                     The key has been kept and every file lock did encrypt is \
                     encrypted; nothing else has changed.",
                    path.display()
                )));
            }
        }
    }

    if open.is_empty() {
        return Ok(());
    }
    open.sort();
    Err(Error::Config(format!(
        "refusing to delete the key: {} declared file(s) the index tracks still \
         hold plain text in the working tree, so locking now would leave them \
         readable with no key left to close them — {}. The usual cause is a name \
         spelled one way in the index and another on disk, which a \
         case-insensitive filesystem hides completely: `git ls-files` shows the \
         index's spelling, `ls` shows the disk's. Rename the file to the \
         spelling `git ls-files` gives, or declare it as it is on disk, then run \
         lock again. The key has been kept and every file lock did encrypt is \
         encrypted.",
        open.len(),
        open.join(", ")
    )))
}

/// Writes the managed section only when the catch-all line is missing entirely.
///
/// The line `* filter=git-xcrypt` is the one thing the whole guarantee hangs on,
/// and git reads a missing attribute exactly as it reads a missing driver — as
/// no filter. Everything else in the section is cosmetic and is `sync`'s job, so
/// a section that is merely out of date is left alone: rewriting it would leave
/// a modified `.gitattributes` behind a command that reported success and has
/// already deleted the key.
fn write_catch_all_if_missing(repo: &Repo, config: &Config) -> Result<bool> {
    let path = repo.attributes_path();
    if crate::gitattributes::catch_all_present(&path)? {
        return Ok(false);
    }
    crate::gitattributes::write_section(&path, &crate::gitattributes::render_lines(config))
}

/// Names a linked checkout for the refusal, however little can be read.
fn describe_worktree(repo: &Repo, registration: &Path) -> String {
    let name = registration.file_name().map_or_else(
        || registration.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );

    // For the message only — never as evidence of whether the checkout is
    // there. A relative pointer is resolved against the registration, which is
    // where git measures it from, not against the process's current directory.
    let Ok(text) = fs::read_to_string(registration.join("gitdir")) else {
        return name;
    };
    let pointer = Path::new(text.trim_end_matches(['\n', '\r']));
    if pointer.as_os_str().is_empty() {
        return name;
    }
    let absolute = if pointer.is_absolute() {
        pointer.to_path_buf()
    } else {
        crate::repo::lexically_normal(&registration.join(pointer))
    };
    let checkout = absolute.parent().unwrap_or(&absolute);
    let _ = repo;
    format!("{name} at {}", checkout.display())
}

/// Where the main checkout is, when this command runs in a linked one.
///
/// Not "the parent of the common directory": with `git init --separate-git-dir`
/// the common directory is somewhere else entirely and is not called `.git`.
/// Git finds the checkout through `core.worktree` in that case, so this does
/// too. Measured before this: from a linked worktree of a separate-git-dir
/// repository, `lock` deleted the key and left the main checkout not merely in
/// the clear but unable to run `git status` at all, since `required = true` and
/// no key makes every filter call fail.
///
/// When neither route answers, the checkout is reported as unknown rather than
/// assumed absent — this function decides whether to refuse, and guessing "no
/// checkout" is the guess that deletes the key.
fn main_checkout(repo: &Repo) -> Option<String> {
    let config = gitconfig::open_local(&repo.config_path()).ok()?;
    if gitconfig::get(&config, "core.bare").as_deref() == Some("true") {
        // A bare repository has no checkout of its own to strand.
        return None;
    }

    if let Some(declared) = gitconfig::get(&config, "core.worktree")
        && !declared.is_empty()
    {
        let path = Path::new(&declared);
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            crate::repo::lexically_normal(&repo.common_dir().join(path))
        };
        return Some(format!("the main checkout at {}", absolute.display()));
    }

    if repo.common_dir().file_name() == Some(std::ffi::OsStr::new(".git"))
        && let Some(main) = repo.common_dir().parent()
    {
        return Some(format!("the main checkout at {}", main.display()));
    }

    Some("the main checkout, whose location this build could not determine".into())
}

/// Whether two paths name the same place, without insisting they exist.
fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// A working-tree file this command has something to say about.
#[derive(Debug)]
struct Candidate {
    /// Absolute path in the working tree.
    path: PathBuf,
    /// Repository-relative path, as the matcher and the index spell it.
    name: Vec<u8>,
    /// The same path, for messages.
    relative: PathBuf,
}

/// What one walk of the working tree turned up.
#[derive(Debug, Default)]
struct Found {
    /// Files the declaration selects for encryption.
    selected: Vec<Candidate>,
    /// Files shaped like the residue of an interrupted run of our own.
    residue: Vec<Candidate>,
}

/// What the walk noticed on its way through, besides the files it selected.
#[derive(Debug, Default)]
struct Walk {
    /// Messages for the user.
    warnings: Vec<String>,
}

/// Every selected file in the working tree, in a stable order.
///
/// Unlike `unlock`'s walk, a path that cannot be read is fatal here. `lock`
/// promises that no plaintext of a selected path survives it, and a directory it
/// could not list may hold one — reporting success over that would be a lie in
/// the one direction that matters. The user can fix the permission and run again;
/// there is no equivalent repair for a secret left behind.
///
/// Symbolic links are left alone: git does not filter them, following one would
/// write outside the repository, and replacing it would destroy the link.
///
/// **A directory holding a `.git` entry is another repository and is not
/// entered.** A submodule has its own key, its own index and its own
/// declaration; it needs its own `lock`.
fn collect(repo: &Repo, config: &Config, walk: &mut Walk) -> Result<Found> {
    let mut found = Found::default();
    let mut pending = vec![repo.work_tree().to_path_buf()];

    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|err| unverifiable(&directory, &err))?;

        for entry in entries {
            let entry = entry.map_err(|err| unverifiable(&directory, &err))?;
            if entry.file_name() == ".git" {
                continue;
            }

            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|err| unverifiable(&path, &err))?;
            if metadata.is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                if path.join(".git").exists() {
                    walk.warnings.push(format!(
                        "{}: a repository of its own, left to its own `git-xcrypt lock`",
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

            let relative = relative_to(repo, &path);
            let name = repo_relative_bytes(&relative);

            // Residue of `secrets/db.env` is called
            // `secrets/db.env.git-xcrypt-<hex>.tmp` and may hold that file's
            // plaintext, so it is a candidate for deletion — but only a
            // candidate: `sweepable` adds the condition that makes deleting it
            // safe. Being a candidate does **not** take it out of the selection
            // below, because the filter's answer for this path does not change
            // and lock must not encrypt a different set of files from git.
            if let Some(target) = atomic::strip_temporary_suffix(&name) {
                if config.decide(target).encrypt {
                    found.residue.push(Candidate {
                        path: path.clone(),
                        name: name.clone(),
                        relative: relative.clone(),
                    });
                } else {
                    walk.warnings.push(format!(
                        "{}: shaped like a temporary file of ours, but nothing \
                         declares its target, so it was left alone",
                        git_spelling(&relative)
                    ));
                }
            }

            if !config.decide(&name).encrypt {
                continue;
            }
            found.selected.push(Candidate {
                path,
                name,
                relative,
            });
        }
    }

    found
        .selected
        .sort_by(|left, right| left.path.cmp(&right.path));
    found
        .residue
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(found)
}

/// The refusal for anything that stops `lock` proving its own promise.
fn unverifiable(path: &Path, err: &std::io::Error) -> Error {
    Error::Config(format!(
        "{}: lock cannot promise this working tree holds no plaintext, because this \
         path could not be read ({err}). Nothing has been changed.",
        path.display()
    ))
}

/// The object ids the index records, for everything this command looked at.
#[derive(Debug, Default)]
struct Stored {
    /// One entry per selected file, in the same order.
    selected: Vec<Option<Vec<u8>>>,
    /// One entry per residue candidate, in the same order.
    residue: Vec<Option<Vec<u8>>>,
}

/// Asks the index about every path at once, or refuses if it cannot be read.
///
/// One read rather than two: the index is a snapshot, and asking twice could see
/// two different ones. An index this build cannot parse is a hard refusal —
/// "cannot tell" must never be mistaken for "nothing is at risk" by a command
/// that deletes the key.
fn stored_ids(
    repo: &Repo,
    hash: gix_hash::Kind,
    selected: &[Candidate],
    residue: &[Candidate],
) -> Result<Stored> {
    if selected.is_empty() && residue.is_empty() {
        return Ok(Stored::default());
    }

    let index_path = repo.git_dir().join("index");
    let names: Vec<Vec<u8>> = selected
        .iter()
        .chain(residue)
        .map(|file| file.name.clone())
        .collect();

    match gitindex::staged_ids(&index_path, hash, &names)? {
        gitindex::Staged::Read(mut ids) => {
            let tail = ids.split_off(selected.len());
            Ok(Stored {
                selected: ids,
                residue: tail,
            })
        }
        gitindex::Staged::Unavailable(why) => Err(Error::Config(format!(
            "lock cannot tell whether your work is safe: {} could not be used because \
             {why}. Nothing has been changed.\n\
             For a split index, `git update-index --no-split-index` converts it back.",
            index_path.display()
        ))),
    }
}

/// Why a file's content is not stored in this repository.
///
/// Three states, because the remedies are three different commands and telling
/// the user the wrong one wastes the only chance they have to notice.
#[derive(Debug, Clone, Copy)]
enum Unstored {
    /// The index has no stage-0 entry: never added, or mid-merge.
    Untracked,
    /// The index holds this content **in the clear** — an exposure, not an edit.
    InTheClear,
    /// The index holds something else: an ordinary unsaved change.
    Modified,
}

/// What the pre-flight pass learned about the selected files.
#[derive(Debug, Default)]
struct Survey {
    /// The object id each file's ciphertext hashes to, in selection order.
    ///
    /// Carried into the encryption pass and compared again there. Without it the
    /// window between "proved stored" and "written" is the whole length of an
    /// interactive prompt — an unbounded human-scale wait, during which an
    /// editor autosave turns proved-safe content into content that exists
    /// nowhere, and the key is deleted over it anyway.
    expected: Vec<Vec<u8>>,
    /// How many selected files are still plaintext and will actually change.
    still_open: usize,
}

/// Proves every selected file's content is already a blob, or refuses.
///
/// The test is exact and needs no object database: the index records the object
/// id of every tracked path's **cleaned** content, encryption is deterministic,
/// so hashing the ciphertext the clean path would produce and comparing to that
/// id answers "is this exact content already a blob here".
///
/// `--yes` never reaches this function, and that is the point. Losing the key
/// and losing unsaved work are different risks; the founding document gives each
/// its own decision, and only the first has a flag.
fn survey(
    key: &MasterKey,
    config: &Config,
    selected: &[Candidate],
    stored: &[Option<Vec<u8>>],
    hash: gix_hash::Kind,
) -> Result<Survey> {
    let mut survey = Survey::default();
    let mut unstored: Vec<(&Path, Unstored)> = Vec::new();

    for (file, stored) in selected.iter().zip(stored) {
        // Zeroizing: this is the secret, in the clear on the heap.
        let content =
            Zeroizing::new(fs::read(&file.path).map_err(|err| unverifiable(&file.path, &err))?);
        let outcome = decide::clean(Some(key), config, &file.name, &content)
            .map_err(|err| named(&file.relative, err))?;

        let closed = outcome.content == *content;
        if !closed {
            survey.still_open += 1;
        }

        let id = blob_id(hash, &outcome.content, &file.relative)?;
        if stored.as_deref() != Some(id.as_slice()) {
            let reason = match stored {
                None => Unstored::Untracked,
                Some(stored)
                    if !closed
                        && stored.as_slice()
                            == blob_id(hash, &content, &file.relative)?.as_slice() =>
                {
                    Unstored::InTheClear
                }
                Some(_) => Unstored::Modified,
            };
            unstored.push((&file.relative, reason));
        }
        survey.expected.push(id);
    }

    if unstored.is_empty() {
        return Ok(survey);
    }
    Err(refusal(&unstored))
}

/// The blob id of `content`, or a refusal naming the file it belonged to.
fn blob_id(hash: gix_hash::Kind, content: &[u8], relative: &Path) -> Result<Vec<u8>> {
    gitindex::blob_id(hash, content).ok_or_else(|| {
        Error::Config(format!(
            "{}: its object id could not be computed, so lock cannot tell whether it \
             is stored. Nothing has been changed.",
            git_spelling(relative)
        ))
    })
}

/// The refusal, grouped so each group carries the remedy that actually works.
fn refusal(unstored: &[(&Path, Unstored)]) -> Error {
    let mut message = format!(
        "{} file(s) hold content lock cannot prove this repository stores:\n",
        unstored.len()
    );

    let groups = [
        (
            "not tracked here at all, or in the middle of a merge — `git add` them \
             (with `-f` if they are ignored), or take them out of the declaration",
            Unstored::Untracked,
        ),
        (
            "stored in the clear: the repository holds this exact plaintext, from \
             before the pattern covered it. `git add` re-stages it through the filter; \
             the plaintext already in history stays there, so rotate the secret",
            Unstored::InTheClear,
        ),
        (
            // `git add` leads, because it is the one remedy that works for all
            // of them. `git add -N` records the empty blob, so a path that was
            // only ever intent-to-add lands in this group and `git commit`
            // refuses it outright — measured on git 2.55.
            "changed since they were last added — `git add` them, then commit or \
             stash",
            Unstored::Modified,
        ),
    ];

    for (explanation, wanted) in groups {
        let paths: Vec<&Path> = unstored
            .iter()
            .filter(|(_, reason)| std::mem::discriminant(reason) == std::mem::discriminant(&wanted))
            .map(|(path, _)| *path)
            .collect();
        if paths.is_empty() {
            continue;
        }
        message.push_str(&format!("\n  {explanation}:\n"));
        for path in paths {
            message.push_str(&format!("    {}\n", git_spelling(path)));
        }
    }

    message.push_str(
        "\nlock would leave that content readable only with the key it is about to \
         delete.\n\
         --yes does not waive this check: losing unsaved work is a different risk from \
         losing the key. Nothing has been changed.",
    );
    Error::Config(message)
}

/// Encrypts each selected file in place, returning the paths git must re-examine.
///
/// [`decide::clean`] and nothing else: a second implementation of line-ending
/// handling here would drift from the check-in path, and the drift would show up
/// as a working tree git reports as modified for reasons nobody can find.
///
/// A file that is already our ciphertext comes back unchanged — `clean` verifies
/// its tag and its `key_id` before saying so — and is skipped, which is what
/// makes a second `lock` after an interrupted one finish the job rather than
/// double-encrypt.
///
/// Every file is checked against the id [`survey`] recorded before writing it,
/// and a mismatch stops the run before that write. The file is read twice
/// because holding every selected file's ciphertext in memory at once is what
/// turns a repository of large secrets into a failed allocation; re-checking is
/// what keeps the second read from silently replacing the first.
fn encrypt_in_place(
    key: &MasterKey,
    config: &Config,
    selected: &[Candidate],
    survey: &Survey,
    hash: gix_hash::Kind,
    report: &mut Report,
) -> Result<Vec<Vec<u8>>> {
    let mut rewritten = Vec::new();

    for (file, expected) in selected.iter().zip(&survey.expected) {
        let content = Zeroizing::new(
            fs::read(&file.path).map_err(|err| named_io(&file.relative, "read", &err))?,
        );
        let outcome = decide::clean(Some(key), config, &file.name, &content)
            .map_err(|err| named(&file.relative, err))?;

        if blob_id(hash, &outcome.content, &file.relative)? != *expected {
            return Err(Error::Config(format!(
                "{}: it changed while lock was running, so what is in it now is not \
                 what lock proved this repository stores. The key has been kept.",
                git_spelling(&file.relative)
            )));
        }

        if let Some(warning) = outcome.warning {
            report.warnings.push(warning);
        }
        if outcome.content == *content {
            continue;
        }

        // Atomic, and inheriting the file's own mode, so an interruption cannot
        // leave a half-written file and an executable stays executable.
        atomic::write(&file.path, &outcome.content).map_err(|err| named(&file.relative, err))?;
        rewritten.push(file.name.clone());
        report.encrypted.push(file.relative.clone());
    }

    Ok(rewritten)
}

/// Narrows the residue candidates to the ones it is safe to delete.
///
/// Two conditions beyond the name, and both exist because this list is a
/// **deletion** list. The target has to be a path the declaration selects, which
/// [`collect`] has already checked; and the file has to be untracked, which it
/// always is for residue of ours — git never saw it. Anything tracked with that
/// shape belongs to the user, however unlikely the name, and deleting it would
/// both destroy their file and leave `git status` reporting a deletion nobody
/// asked for. Measured: without this, a committed
/// `build.git-xcrypt-deadbeefcafef00d.tmp` was removed and the tree left dirty.
fn sweepable<'a>(
    residue: &'a [Candidate],
    stored: &[Option<Vec<u8>>],
    walk: &mut Walk,
) -> Vec<&'a Candidate> {
    let mut sweepable = Vec::new();
    for (file, stored) in residue.iter().zip(stored) {
        if stored.is_some() {
            walk.warnings.push(format!(
                "{}: shaped like a temporary file of ours, but it is tracked, so it \
                 was left alone",
                git_spelling(&file.relative)
            ));
            continue;
        }
        sweepable.push(file);
    }
    sweepable
}

/// Takes the files the sweep will remove out of the encryption list.
///
/// A path cannot be both deleted and encrypted, and residue is untracked by
/// construction, so leaving it in would make the unstored check refuse every
/// lock that has any. Anything the sweep declined — a *tracked* file of that
/// shape — stays, because git's filter still encrypts it and the two must not
/// disagree about which files are secrets.
///
/// The index answers are filtered in the same pass rather than truncated
/// afterwards: they are positional, so dropping a file anywhere but the end
/// would leave every later file compared against its neighbour's object id.
fn drop_swept(
    selected: Vec<Candidate>,
    stored: Vec<Option<Vec<u8>>>,
    residue: &[&Candidate],
) -> (Vec<Candidate>, Vec<Option<Vec<u8>>>) {
    let doomed: Vec<&[u8]> = residue.iter().map(|file| file.name.as_slice()).collect();
    let mut kept = Vec::with_capacity(selected.len());
    let mut ids = Vec::with_capacity(selected.len());

    for (file, id) in selected.into_iter().zip(stored) {
        if doomed.contains(&file.name.as_slice()) {
            continue;
        }
        kept.push(file);
        ids.push(id);
    }
    (kept, ids)
}

/// Deletes the residue of an earlier, killed run.
///
/// Best effort by design: one file that will not delete must not stop a lock
/// that is otherwise complete, but it does have to be said out loud, because the
/// thing left behind may be a decrypted secret.
fn sweep(residue: &[&Candidate], report: &mut Report) {
    for file in residue {
        match fs::remove_file(&file.path) {
            Ok(()) => report.swept.push(file.relative.clone()),
            Err(err) => report.warnings.push(format!(
                "{}: a temporary file left by an interrupted run could not be removed \
                 ({err}); it may hold a decrypted secret",
                git_spelling(&file.relative)
            )),
        }
    }
}

/// Adds what was already done to an error that stopped the encryption pass.
///
/// Returning the bare error would drop the report, and with it the only record
/// that some files are now ciphertext and some temporary files are gone. The
/// key is still here — nothing after this point ran — so the instruction is to
/// run the command again.
fn interrupted(report: &Report, err: Error) -> Error {
    let done = report.encrypted.len();
    let swept = report.swept.len();
    let context = format!(
        "\nlock stopped part way: {done} file(s) were already encrypted and {swept} \
         temporary file(s) removed. The key has NOT been deleted, so running lock \
         again finishes the job."
    );
    match err {
        Error::Format(message) => Error::Format(message + &context),
        Error::Crypto(message) => Error::Crypto(message + &context),
        Error::Config(message) => Error::Config(message + &context),
        Error::Io(err) => Error::Io(std::io::Error::other(format!("{err}{context}"))),
        other => other,
    }
}

/// Puts a path and the operation in front of a bare I/O failure.
///
/// `Permission denied (os error 13)` on its own names neither the file nor what
/// was being done to it, which for a command mid-way through rewriting a working
/// tree is the least useful message it could produce.
fn named_io(relative: &Path, action: &str, err: &std::io::Error) -> Error {
    Error::Io(std::io::Error::other(format!(
        "{}: could not {action} it ({err})",
        git_spelling(relative)
    )))
}

/// Removes the key file, which is the irreversible half of the command.
fn remove_key(repo: &Repo, report: &mut Report) -> Result<()> {
    let path = repo.key_path();
    match fs::remove_file(&path) {
        Ok(()) => {
            report.key_removed = true;
            Ok(())
        }
        // Someone else got there first. The working tree is already closed, so
        // this is the outcome that was asked for, not a failure.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            report.key_removed = true;
            Ok(())
        }
        Err(err) => Err(Error::Io(std::io::Error::other(format!(
            "{}: the working tree is encrypted but the key could not be removed \
             ({err}); run lock again once that is fixed",
            path.display()
        )))),
    }
}

/// Puts a path in front of an error that only knew about content.
///
/// The exit code is preserved throughout: a foreign `key_id` becomes a format
/// error, which is the code [`Error::KeyMismatch`] reports anyway, and gains the
/// file name its own message cannot carry — "this file was encrypted with key …"
/// names no file. `NoKey` is passed through untouched, because it is about the
/// repository rather than about any one path.
fn named(relative: &Path, err: Error) -> Error {
    let at = git_spelling(relative);
    match err {
        Error::Format(message) => Error::Format(format!("{at}: {message}")),
        Error::Crypto(message) => Error::Crypto(format!("{at}: {message}")),
        Error::Config(message) => Error::Config(format!("{at}: {message}")),
        Error::Io(err) => Error::Io(std::io::Error::other(format!("{at}: {err}"))),
        mismatch @ Error::KeyMismatch { .. } => Error::Format(format!("{at}: {mismatch}")),
        other => other,
    }
}

/// A path relative to the working tree, or the path itself if it is outside.
fn relative_to(repo: &Repo, path: &Path) -> PathBuf {
    repo.relative(path)
        .map_or_else(|| path.to_path_buf(), Path::to_path_buf)
}

/// A repository-relative path as the pattern matcher expects it.
///
/// Bytes rather than text, and forward slashes: on Unix a path is an arbitrary
/// byte string, and decoding it lossily would match a file under a name it does
/// not have.
fn repo_relative_bytes(relative: &Path) -> Vec<u8> {
    os_str_bytes(relative)
}

fn os_str_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().replace('\\', "/").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// A confirmer that answers as told and keeps what it was shown.
    struct Scripted {
        answer: bool,
        shown: String,
    }

    impl Scripted {
        fn new(answer: bool) -> Self {
            Self {
                answer,
                shown: String::new(),
            }
        }
    }

    impl Confirm for Scripted {
        fn confirm(&mut self, warning: &Warning) -> Result<bool> {
            self.shown = warning.to_string();
            Ok(self.answer)
        }
    }

    fn git(dir: &Path, args: &[&str]) -> std::process::Output {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git must be on PATH");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn init_repo() -> TempDir {
        let dir = TempDir::new().expect("temporary directory");
        git(dir.path(), &["init", "-q"]);
        git(dir.path(), &["config", "user.name", "t"]);
        git(dir.path(), &["config", "user.email", "t@t.invalid"]);
        dir
    }

    /// A repository set up by `init`, with `secrets/` declared.
    fn prepared() -> (TempDir, Repo) {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        super::super::init::run(&repo).expect("init must succeed");
        fs::write(repo.xcrypt_config_path(), "secrets/\n").expect("declarations");
        (dir, repo)
    }

    /// Writes `content` at `relative` and stages the bytes it would clean to.
    ///
    /// Staging goes through `hash-object` and `update-index` rather than
    /// `git add`, because `init` registered the *test* binary as the filter and
    /// git cannot run it. What lands in the index is exactly what a real
    /// `git add` would have put there.
    fn write_and_stage(repo: &Repo, dir: &TempDir, relative: &str, content: &[u8]) {
        let path = repo.work_tree().join(relative);
        fs::create_dir_all(path.parent().expect("a parent")).expect("directories");
        fs::write(&path, content).expect("writing");

        let config = Config::load(&repo.xcrypt_config_path()).expect("declarations");
        let key = repo.load_key().ok();
        let cleaned = decide::clean(key.as_ref(), &config, relative.as_bytes(), content)
            .expect("the clean path must succeed")
            .content;

        let blob = dir.path().join("staged.bin");
        fs::write(&blob, &cleaned).expect("writing");
        let hashed = git(
            dir.path(),
            &["hash-object", "-w", "--no-filters", "--", "staged.bin"],
        );
        fs::remove_file(&blob).expect("removing");
        let oid = String::from_utf8(hashed.stdout).expect("git printed a hash");
        git(
            dir.path(),
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("100644,{},{relative}", oid.trim()),
            ],
        );
    }

    #[test]
    fn a_declared_file_that_appears_while_the_prompt_waits_stops_the_run() {
        // The other half of the same window. An edit to a file already surveyed
        // is caught by its recorded object id; a file that was never in the list
        // cannot be, and locking around it would delete the key over a plaintext
        // secret nobody mentioned. Measured before this check: a file created
        // 1.5 s into the prompt survived a successful lock, in the clear.
        struct Meddling(PathBuf);
        impl Confirm for Meddling {
            fn confirm(&mut self, _warning: &Warning) -> Result<bool> {
                fs::write(&self.0, b"brand new secret\n").expect("writing");
                Ok(true)
            }
        }

        let (dir, repo) = prepared();
        write_and_stage(&repo, &dir, "secrets/db.env", b"hunter2\n");
        let late = repo.work_tree().join("secrets").join("late.env");

        let error = run(&repo, &mut Meddling(late.clone()))
            .expect_err("a secret that appeared must not be locked around");

        assert_eq!(error.exit_code(), crate::exit::CONFIG);
        assert!(repo.has_key(), "the key went over a file nobody checked");
        assert_eq!(
            fs::read(&late).expect("reading"),
            b"brand new secret\n",
            "the new file was encrypted without ever being checked"
        );
        assert_eq!(
            fs::read(repo.work_tree().join("secrets/db.env")).expect("reading"),
            b"hunter2\n",
            "the run wrote something despite refusing"
        );
    }

    #[test]
    fn a_missing_declaration_stops_lock_rather_than_encrypting_nothing() {
        let (_dir, repo) = prepared();
        fs::remove_file(repo.xcrypt_config_path()).expect("removing the declarations");

        let error = run(&repo, &mut Scripted::new(true)).expect_err("lock must refuse");

        assert_eq!(error.exit_code(), crate::exit::CONFIG);
        assert!(repo.has_key());
    }
}
