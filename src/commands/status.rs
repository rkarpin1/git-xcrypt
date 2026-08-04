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

use crate::repo::{DRIVER, Repo};
use crate::{Result, gitattributes, gitconfig};

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
#[derive(Debug, Default)]
pub struct Report {
    /// Reasons git is not filtering here. Any of these means the guarantee is off.
    pub setup: Vec<SetupGap>,
    /// Whether a repository key is present at all.
    pub has_key: bool,
    /// Notes that describe a lesser problem and never change the exit code.
    pub notes: Vec<String>,
    /// Anything worth saying once, carried out so the binary owns the messages.
    pub warnings: Vec<String>,
}

impl Report {
    /// Whether anything was found that should fail a CI gate.
    #[must_use]
    pub fn exposed(&self) -> bool {
        !self.setup.is_empty()
    }
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

        for note in &self.notes {
            writeln!(f, "\nnote: {note}")?;
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
    Ok(report)
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
