//! `git-xcrypt status` — whether the declarations are actually enforced.
//!
//! The boundary is worth stating before anything else, because it is easy to
//! read this command as more than it is: it answers **"are my declarations
//! enforced"**, not **"are there secrets in this repository"**. A file that never
//! matched a pattern is invisible here, by construction.
//!
//! Within that boundary it has two jobs, and the first is the one nothing else
//! covers. A clone inherits `.gitattributes` through history but not
//! `.git/config`, so it carries the catch-all line with no driver behind it —
//! and git reads an undefined filter exactly as it reads no filter, which means
//! the next `git add` on a secret exits 0 and stores the plaintext. Nothing in
//! that sequence produces a signal. Asking for one is what this command is for.
//!
//! The exit code is part of the contract: `5` on any finding, so the command
//! works as a CI gate and so "the repository has a problem" is distinguishable
//! from "the tool broke".

use std::fmt;

use crate::config::Config;
use crate::repo::{DRIVER, Repo};
use crate::{Result, gitattributes, gitconfig, gitindex, history};

/// One reason git would not be filtering this repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupGap {
    /// A `filter.git-xcrypt.*` key is not set anywhere git reads.
    MissingKey(String),
    /// The key is set, but not to anything git reads as true.
    NotTrue {
        /// The dotted key.
        key: String,
        /// What it is set to.
        value: String,
    },
    /// `.gitattributes` carries no `* filter=git-xcrypt` line.
    CatchAllMissing,
}

impl fmt::Display for SetupGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey(key) => write!(
                f,
                "{key} is not set, so git has no filter to run for this repository"
            ),
            Self::NotTrue { key, value } => write!(
                f,
                "{key} is `{value}`, not true — without it a failing filter is \
                 ignored and git stores the unfiltered content with exit code 0"
            ),
            Self::CatchAllMissing => write!(
                f,
                "{} carries no `{}` line, so git never calls the filter",
                crate::repo::ATTRIBUTES_FILE,
                gitattributes::CATCH_ALL
            ),
        }
    }
}

/// What `status` found.
///
/// Four sections, deliberately separate, because the remedies are four different
/// things and a single list would hide which one applies.
#[derive(Debug, Default)]
pub struct Report {
    /// Reasons git is not filtering here. Any of these means the guarantee is off.
    pub setup: Vec<SetupGap>,
    /// Whether a repository key is present at all.
    pub has_key: bool,
    /// Declared paths the index already stores as ciphertext. The good case.
    pub encrypted: Vec<Vec<u8>>,
    /// Declared paths the index stores **in the clear** — what a commit made now
    /// would push. This is the set `--fix` repairs.
    pub in_the_clear: Vec<Vec<u8>>,
    /// Declared paths that reachable history holds in the clear.
    ///
    /// Nothing local repairs this. The report says so in as many words.
    pub leaked: Vec<crate::history::Exposure>,
    /// Paths a negation deliberately keeps in the clear.
    ///
    /// Listed rather than left out: a hole a user wrote on purpose must not be
    /// invisible, or the declaration reads as covering more than it does.
    pub by_choice: Vec<Vec<u8>>,
    /// Things this build could not determine, and why.
    ///
    /// These fail the gate. "I could not tell" reported as a pass is the one
    /// answer a command like this must never give.
    pub undetermined: Vec<String>,
    /// How much history was walked, for the closing line.
    pub scanned: Scanned,
    /// Notes that describe a lesser problem and never change the exit code.
    pub notes: Vec<String>,
    /// Anything worth saying once, carried out so the binary owns the messages.
    pub warnings: Vec<String>,
}

/// How much of the repository the scan covered.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Scanned {
    /// Commits visited.
    pub commits: usize,
    /// Distinct blobs under a declared path that were read.
    pub blobs: usize,
}

impl Report {
    /// Whether anything was found that should fail a CI gate.
    #[must_use]
    pub fn exposed(&self) -> bool {
        !self.setup.is_empty()
            || !self.in_the_clear.is_empty()
            || !self.leaked.is_empty()
            || !self.undetermined.is_empty()
    }
}

/// A repository-relative path as a message shows it.
///
/// Lossy on purpose and only here: a path is arbitrary bytes on Unix, so the
/// decision paths — matching, hashing, index lookup — keep the bytes, and only
/// the moment of printing gives up on them.
fn show(path: &[u8]) -> String {
    bstr::BStr::new(path).to_string()
}

/// Renders the whole report, sections and remedies included.
///
/// A `Display` rather than a pile of `eprintln!` in the binary: the wording here
/// *is* part of the safeguard — a user must never read "fixed" as "the secret is
/// safe" — so it has to be assertable from a test.
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.setup.is_empty() {
            writeln!(
                f,
                "setup: git is configured to run the filter in this repository."
            )?;
        } else {
            writeln!(
                f,
                "setup: git is NOT filtering this repository. Until this is fixed, \
                 committing a declared file stores it in the clear, with exit code 0 \
                 and no warning."
            )?;
            for gap in &self.setup {
                writeln!(f, "  - {gap}")?;
            }
            writeln!(f, "\n  Fix it with one of:")?;
            if self.has_key {
                writeln!(f, "    git-xcrypt init      # the key here is kept")?;
            } else {
                writeln!(f, "    git-xcrypt unlock <key-file>")?;
                writeln!(f, "    git-xcrypt import-key <key-file>")?;
            }
        }

        self.write_undetermined(f)?;
        self.write_encrypted(f)?;
        self.write_in_the_clear(f)?;
        self.write_leaked(f)?;
        self.write_by_choice(f)?;

        for note in &self.notes {
            writeln!(f, "\nnote: {note}")?;
        }

        writeln!(
            f,
            "\nscanned {} commit(s) and {} distinct blob(s) under a declared path. \
             `status` answers whether your declarations are enforced, not whether \
             this repository holds secrets: a path no pattern ever matched is \
             invisible to it.",
            self.scanned.commits, self.scanned.blobs
        )
    }
}

impl Report {
    /// What could not be determined, and therefore what nothing here proves.
    fn write_undetermined(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.undetermined.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nundetermined: this run could not answer the following, so nothing \
             below is a clean bill of health."
        )?;
        for reason in &self.undetermined {
            writeln!(f, "  - {reason}")?;
        }
        Ok(())
    }

    /// The good case: declared and already stored as ciphertext.
    fn write_encrypted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.encrypted.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nencrypted: {} declared path(s) are stored as ciphertext.",
            self.encrypted.len()
        )?;
        for path in &self.encrypted {
            writeln!(f, "  {}", show(path))?;
        }
        Ok(())
    }

    /// Declared, and stored in the clear right now.
    fn write_in_the_clear(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.in_the_clear.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nin the clear: {} declared path(s) are stored unencrypted right now, \
             so a commit made from here would push the plain text.",
            self.in_the_clear.len()
        )?;
        for path in &self.in_the_clear {
            writeln!(f, "  {}", show(path))?;
        }
        writeln!(
            f,
            "\n  `git add` on each of them re-stages the content through the filter, \
             and `git-xcrypt status --fix` does exactly that for all of them at once. \
             It changes what the NEXT commit stores. It does not touch history, and \
             any plain text already committed stays where it is."
        )
    }

    /// Declared, and somewhere in reachable history in the clear.
    ///
    /// The wording is load-bearing. Rewriting history does not undo a leak — the
    /// plaintext is in every clone, fork, cache and CI log that ever saw it — so
    /// the procedure has to open with rotation and say why. A user who reads
    /// "cleaned up" here has been told the wrong thing.
    fn write_leaked(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.leaked.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nleaked in history: {} declared path(s) sat in this repository in the \
             clear at some point, and the blobs are still here.",
            self.leaked.len()
        )?;
        for exposure in &self.leaked {
            writeln!(
                f,
                "  {} — {} plaintext blob(s)",
                show(&exposure.path),
                exposure.sightings.len()
            )?;
            for sighting in &exposure.sightings {
                writeln!(
                    f,
                    "      blob {} in commit {}",
                    sighting.blob, sighting.commit
                )?;
            }
        }

        writeln!(
            f,
            "\n  Rewriting history does NOT undo this. If the repository was ever \
             pushed, the plain text is in every clone, fork, cache and CI log that \
             saw it. In order:"
        )?;
        writeln!(
            f,
            "\n  1. ROTATE THE SECRET. This is the only step that actually revokes \
             the exposure, and it is worth doing even if you do nothing else."
        )?;
        writeln!(
            f,
            "  2. Re-stage the current content so future commits are encrypted:\n\
             \x20      git-xcrypt status --fix"
        )?;
        writeln!(
            f,
            "  3. Only then, and only if you also want the old blobs gone, rewrite \
             history with the external git-filter-repo. git-xcrypt does not rewrite \
             history and will not pretend to:"
        )?;
        write!(f, "\x20      git filter-repo --invert-paths")?;
        for exposure in &self.leaked {
            write!(f, " --path '{}'", show(&exposure.path))?;
        }
        writeln!(f)?;
        writeln!(
            f,
            "     That deletes the file from every commit. To keep the file and drop \
             only its history, remove it, rewrite, then add it back through the \
             filter. Either way everyone with a clone has to re-clone."
        )
    }

    /// Paths a negation keeps in the clear on purpose.
    fn write_by_choice(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.by_choice.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nin the clear by choice: {} path(s) a `!` line in {} takes back out, \
             so they are stored unencrypted on purpose.",
            self.by_choice.len(),
            crate::repo::CONFIG_FILE
        )?;
        for path in &self.by_choice {
            writeln!(f, "  {}", show(path))?;
        }
        Ok(())
    }
}

/// Inspects `repo` and reports what it found.
///
/// # Errors
///
/// [`Error::Config`] when git's configuration or `.gitattributes` cannot be
/// read — "cannot tell" must never be reported as "nothing is wrong" by the one
/// command whose whole job is to tell.
///
/// [`Error::Config`]: crate::Error::Config
pub fn run(repo: &Repo) -> Result<Report> {
    let mut report = Report {
        has_key: repo.has_key(),
        ..Report::default()
    };

    // The full cascade, not `.git/config` alone: git resolves a driver through
    // system, global and local files alike, so a registration in `~/.gitconfig`
    // is a working registration and reporting it as missing would be wrong.
    // The common directory, because a linked worktree has a `config` file git
    // ignores — the same resolution `init` had to be taught.
    let config = gitconfig::open_full(repo.common_dir())?;

    for key in gitattributes::driver_keys() {
        match gitconfig::get(&config, &key) {
            None => report.setup.push(SetupGap::MissingKey(key)),
            Some(value) if key.ends_with(".required") && !gitconfig::is_true(&value) => {
                report.setup.push(SetupGap::NotTrue { key, value });
            }
            Some(value) if value.trim().is_empty() && key.ends_with(".process") => {
                // An empty command is not a command. Git would try to run it and
                // fail, which with `required` set aborts everything — but the
                // honest report is that nothing is registered.
                report.setup.push(SetupGap::MissingKey(key));
            }
            Some(_) => {}
        }
    }

    if !gitattributes::catch_all_present(&repo.attributes_path())? {
        report.setup.push(SetupGap::CatchAllMissing);
    }

    report.notes.extend(diff_driver_note(repo, &config));

    let declarations = Config::load(&repo.xcrypt_config_path())?;
    if declarations.missing {
        // Without the declaration nothing below can be answered at all, and the
        // check-in path refuses on the same state — so this repository is not
        // leaking, it is simply unusable until the file comes back.
        report.undetermined.push(format!(
            "{} is missing, so nothing here declares what to encrypt. Every \
             `git add` in this repository refuses until it is restored; \
             `git-xcrypt init` creates one.",
            crate::repo::CONFIG_FILE
        ));
        return Ok(report);
    }
    report.warnings.extend(declarations.pointless_eol.clone());

    let hash = gitindex::object_hash(gitconfig::get(&config, "extensions.objectformat").as_deref());
    let objects = history::objects(repo.common_dir())?;

    inspect_index(repo, &declarations, &objects, hash, &mut report)?;

    let scan = history::scan(
        &objects,
        repo.git_dir(),
        repo.common_dir(),
        hash,
        &declarations,
    )?;
    report.scanned = Scanned {
        commits: scan.commits,
        blobs: scan.blobs,
    };
    report.warnings.extend(scan.warnings);
    if scan.unreadable > 0 {
        report.undetermined.push(format!(
            "{} object(s) in this repository could not be read, so they were not \
             judged. A history scan that skipped something has proved nothing \
             about it; `git fsck` says what is missing.",
            scan.unreadable
        ));
    }
    report.leaked = scan.exposed;

    Ok(report)
}

/// Reads what the index would have the next commit store.
///
/// The index rather than `HEAD`, because that is the question with a remedy: a
/// declared path whose staged blob is plain text is what a commit made now would
/// push, and `git add` fixes exactly that. `HEAD` is covered by the history scan,
/// which reaches it along with everything else.
fn inspect_index(
    repo: &Repo,
    declarations: &Config,
    objects: &gix_odb::Handle,
    hash: gix_hash::Kind,
    report: &mut Report,
) -> Result<()> {
    let index_path = repo.git_dir().join("index");
    let entries = match gitindex::list(&index_path, hash)? {
        gitindex::Listed::Read(entries) => entries,
        gitindex::Listed::Unavailable(why) => {
            // Refusing outright would withhold the history scan, which needs no
            // index at all and carries the finding that matters most. Failing
            // the gate over it keeps "could not tell" from reading as "fine".
            report.undetermined.push(format!(
                "{} could not be used because {why}, so nothing is known about what \
                 the next commit would store. For a split index, \
                 `git update-index --no-split-index` converts it back.",
                index_path.display()
            ));
            return Ok(());
        }
    };

    for (name, id) in entries {
        if declarations.negated(&name) {
            report.by_choice.push(name);
            continue;
        }
        if !declarations.decide(&name).encrypt {
            continue;
        }

        let Ok(id) = gix_hash::oid::try_from_bytes(&id) else {
            report.undetermined.push(format!(
                "{}: the index records an object id this build cannot read",
                show(&name)
            ));
            continue;
        };
        match history::stored_in_the_clear(objects, id) {
            Some(true) => report.in_the_clear.push(name),
            Some(false) => report.encrypted.push(name),
            None => report.undetermined.push(format!(
                "{}: the index names object {id}, which is not in this repository's \
                 object database, so what it holds is unknown",
                show(&name)
            )),
        }
    }

    report.encrypted.sort();
    report.in_the_clear.sort();
    report.by_choice.sort();
    Ok(())
}

/// Mentions an absent diff driver, without letting it fail the gate.
///
/// Deliberately outside [`gitattributes::driver_keys`] and outside the exit
/// code. A missing `diff.git-xcrypt.textconv` costs a readable `git diff` and
/// nothing else — no secret reaches the object database over it — and `lock`
/// removes it **on purpose**, because with no key the driver drags a failing
/// smudge filter into every `git log -p`. Counting it as a finding would make
/// every correctly locked repository report itself broken, which is the fastest
/// way to teach a user to ignore this command.
///
/// So it is said only where it is actionable: a repository that holds a key, and
/// therefore could be showing plaintext diffs, and is not.
fn diff_driver_note(repo: &Repo, config: &gix_config::File) -> Option<String> {
    if !repo.has_key() {
        return None;
    }
    if gitconfig::get(config, &format!("diff.{DRIVER}.textconv")).is_some() {
        return None;
    }
    Some(format!(
        "diff.{DRIVER}.textconv is not registered, so `git diff` on an encrypted \
         file reports `Binary files differ` instead of comparing the plain text. \
         `git-xcrypt init` registers it. Nothing is stored in the clear over this."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_repo() -> TempDir {
        let dir = TempDir::new().expect("temporary directory");
        let ok = Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .expect("git must be on PATH")
            .success();
        assert!(ok, "git init failed");
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

    #[test]
    fn a_repository_after_init_reports_a_complete_setup() {
        let (_dir, repo) = prepared();

        let report = run(&repo).expect("status must succeed");

        assert!(report.setup.is_empty(), "{:?}", report.setup);
        assert!(!report.exposed());
        assert!(report.has_key);
    }

    #[test]
    fn a_clone_without_a_registration_is_reported_as_unfiltered() {
        // The whole point of the check: `.gitattributes` travels through
        // history, `.git/config` does not, and git reads an undefined filter as
        // no filter at all.
        let (_dir, repo) = prepared();
        fs::write(repo.config_path(), "[core]\n\tbare = false\n").expect("clobbering the config");

        let report = run(&repo).expect("status must succeed");

        assert!(report.exposed());
        assert!(
            report
                .setup
                .iter()
                .any(|gap| matches!(gap, SetupGap::MissingKey(key) if key.ends_with(".process"))),
            "{:?}",
            report.setup
        );
        assert!(
            report.to_string().contains("stores it in the clear"),
            "the report has to say what the gap costs: {report}"
        );
    }

    #[test]
    fn a_required_flag_that_is_not_true_is_caught() {
        // Without the flag git ignores a failing filter: `git add` exits 0 and
        // the plaintext reaches the object database.
        let (_dir, repo) = prepared();
        let path = repo.config_path();
        let mut config = gitconfig::open_local(&path).expect("config");
        gitconfig::set(&mut config, &format!("filter.{DRIVER}.required"), "false")
            .expect("setting");
        gitconfig::save_local(&path, &config).expect("saving");

        let report = run(&repo).expect("status must succeed");

        assert!(
            report
                .setup
                .iter()
                .any(|gap| matches!(gap, SetupGap::NotTrue { .. })),
            "{:?}",
            report.setup
        );
    }

    #[test]
    fn every_git_spelling_of_true_is_accepted_for_required() {
        // `required = 1` is an ordinary thing to find in a config file, and
        // reading it as "off" would send a user chasing a gap that is not there.
        let (_dir, repo) = prepared();
        let path = repo.config_path();

        for spelling in ["true", "1", "yes", "on", "TRUE"] {
            let mut config = gitconfig::open_local(&path).expect("config");
            gitconfig::set(&mut config, &format!("filter.{DRIVER}.required"), spelling)
                .expect("setting");
            gitconfig::save_local(&path, &config).expect("saving");

            let report = run(&repo).expect("status must succeed");
            assert!(
                report.setup.is_empty(),
                "`required = {spelling}` was read as false: {:?}",
                report.setup
            );
        }
    }

    #[test]
    fn a_missing_catch_all_line_is_caught() {
        let (_dir, repo) = prepared();
        fs::write(repo.attributes_path(), "# nothing of ours\n").expect("writing");

        let report = run(&repo).expect("status must succeed");

        assert!(report.setup.contains(&SetupGap::CatchAllMissing));
    }

    #[test]
    fn an_absent_attributes_file_counts_as_a_missing_catch_all() {
        let (_dir, repo) = prepared();
        fs::remove_file(repo.attributes_path()).expect("removing");

        let report = run(&repo).expect("status must succeed");

        assert!(report.setup.contains(&SetupGap::CatchAllMissing));
    }

    #[test]
    fn a_keyless_repository_is_pointed_at_unlock_rather_than_init() {
        // `init` refuses in a repository that carries traces and no key, so
        // naming it there would send the user into a dead end.
        let (_dir, repo) = prepared();
        fs::remove_file(repo.key_path()).expect("removing the key");
        fs::write(repo.attributes_path(), "# nothing of ours\n").expect("writing");

        let report = run(&repo).expect("status must succeed");
        let text = report.to_string();

        assert!(text.contains("unlock"), "{text}");
        assert!(!text.contains("git-xcrypt init"), "{text}");
    }

    #[test]
    fn a_locked_repository_is_not_reported_broken_over_its_missing_diff_driver() {
        // `lock` removes the diff driver deliberately. Counting that as a
        // finding would make every correctly locked repository fail the gate.
        let (_dir, repo) = prepared();
        let path = repo.config_path();
        let mut config = gitconfig::open_local(&path).expect("config");
        gitconfig::unset(&mut config, &format!("diff.{DRIVER}.textconv")).expect("unsetting");
        gitconfig::save_local(&path, &config).expect("saving");
        fs::remove_file(repo.key_path()).expect("removing the key");

        let report = run(&repo).expect("status must succeed");

        assert!(report.setup.is_empty(), "{:?}", report.setup);
        assert!(report.notes.is_empty(), "{:?}", report.notes);
    }

    #[test]
    fn an_unlocked_repository_missing_the_diff_driver_is_told_so_without_failing() {
        let (_dir, repo) = prepared();
        let path = repo.config_path();
        let mut config = gitconfig::open_local(&path).expect("config");
        gitconfig::unset(&mut config, &format!("diff.{DRIVER}.textconv")).expect("unsetting");
        gitconfig::save_local(&path, &config).expect("saving");

        let report = run(&repo).expect("status must succeed");

        assert!(!report.exposed(), "a cosmetic gap must not fail the gate");
        assert_eq!(report.notes.len(), 1, "{:?}", report.notes);
    }
}
