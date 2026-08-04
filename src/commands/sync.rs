//! `git-xcrypt sync` — regenerate the cosmetic lines in `.gitattributes`.
//!
//! Only the cosmetic lines. The catch-all line above them is static, written
//! once by `init`, and carries the whole security guarantee; nothing here can
//! make it stale, which is the point of the construction. Forgetting to run
//! `sync` therefore costs a worse `git diff`, never a secret.
//!
//! `--check` exists so a CI job can say "the section is out of date" without
//! writing to the working tree.

use crate::config::Config;
use crate::repo::{CONFIG_FILE, Repo};
use crate::{Error, Result, gitattributes};

/// What `sync` found, and what it did about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The section already said what it should. Nothing was written.
    UpToDate,
    /// The section was regenerated.
    Updated,
    /// The section is out of date and `--check` forbade writing.
    Stale,
}

/// What `sync` did, plus anything the configuration file is worth warning about.
#[derive(Debug)]
pub struct Report {
    /// The verdict.
    pub outcome: Outcome,
    /// Lines of `.git-xcrypt` that declare something pointless.
    ///
    /// Carried out rather than printed here so the binary owns every message,
    /// as it does for `init`.
    pub warnings: Vec<String>,
}

/// Runs `sync` in `repo`, writing unless `check` is set.
///
/// # Errors
///
/// [`Error::Config`] when `.git-xcrypt` is absent or cannot be understood, or
/// when the managed section in `.gitattributes` has unbalanced markers;
/// [`Error::Io`] on a read or write failure.
pub fn run(repo: &Repo, check: bool) -> Result<Report> {
    let config = Config::load(&repo.xcrypt_config_path())?;
    if config.missing {
        return Err(Error::Config(format!(
            "{CONFIG_FILE} is missing, so there is nothing to synchronise; \
             run `git-xcrypt init` to create it"
        )));
    }

    let lines = gitattributes::render_lines(&config);
    let path = repo.attributes_path();

    let outcome = if check {
        let (existing, wanted) = gitattributes::desired(&path, &lines)?;
        if existing == wanted {
            Outcome::UpToDate
        } else {
            Outcome::Stale
        }
    } else if gitattributes::write_section(&path, &lines)? {
        Outcome::Updated
    } else {
        Outcome::UpToDate
    };

    Ok(Report {
        outcome,
        warnings: config.pointless_eol,
    })
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

    /// A repository set up the way a user's would be, with `declarations` in
    /// `.git-xcrypt`.
    fn prepared(declarations: &str) -> (TempDir, Repo) {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        crate::commands::init::run(&repo).expect("init must succeed");
        fs::write(repo.xcrypt_config_path(), declarations).expect("writing the declarations");
        (dir, repo)
    }

    #[test]
    fn a_new_pattern_reaches_the_section() {
        let (_dir, repo) = prepared("secrets/\n");

        let report = run(&repo, false).expect("sync must succeed");

        assert_eq!(report.outcome, Outcome::Updated);
        let attributes = fs::read_to_string(repo.attributes_path()).expect("attributes");
        assert!(attributes.contains("secrets/** -text diff=git-xcrypt"));
        assert!(
            attributes.contains("* filter=git-xcrypt"),
            "the line the security rests on must survive every regeneration"
        );
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let (_dir, repo) = prepared("secrets/\n*.env\n");
        run(&repo, false).expect("first sync");
        let after_first = fs::read_to_string(repo.attributes_path()).expect("attributes");

        let report = run(&repo, false).expect("second sync");

        assert_eq!(report.outcome, Outcome::UpToDate);
        assert_eq!(
            after_first,
            fs::read_to_string(repo.attributes_path()).expect("attributes"),
            "a settled section must not be rewritten"
        );
    }

    #[test]
    fn check_reports_staleness_without_writing() {
        let (_dir, repo) = prepared("secrets/\n");
        let before = fs::read_to_string(repo.attributes_path()).expect("attributes");

        let report = run(&repo, true).expect("check must succeed");

        assert_eq!(report.outcome, Outcome::Stale);
        assert_eq!(
            before,
            fs::read_to_string(repo.attributes_path()).expect("attributes"),
            "--check must never touch the working tree"
        );

        run(&repo, false).expect("sync");
        assert_eq!(
            run(&repo, true).expect("check").outcome,
            Outcome::UpToDate,
            "the check and the write must not disagree"
        );
    }

    #[test]
    fn a_removed_pattern_leaves_the_section() {
        let (_dir, repo) = prepared("secrets/\n*.env\n");
        run(&repo, false).expect("first sync");

        fs::write(repo.xcrypt_config_path(), "secrets/\n").expect("shrinking the declarations");
        run(&repo, false).expect("second sync");

        let attributes = fs::read_to_string(repo.attributes_path()).expect("attributes");
        assert!(attributes.contains("secrets/** -text"));
        assert!(
            !attributes.contains("*.env -text"),
            "a pattern the user deleted must not linger in the section"
        );
    }

    #[test]
    fn user_content_outside_the_markers_is_untouched() {
        let (_dir, repo) = prepared("secrets/\n");
        let path = repo.attributes_path();
        let with_user_lines = format!(
            "# mine\n*.png binary\n{}",
            fs::read_to_string(&path).expect("attributes")
        );
        fs::write(&path, &with_user_lines).expect("writing");

        run(&repo, false).expect("sync");

        let attributes = fs::read_to_string(&path).expect("attributes");
        assert!(attributes.starts_with("# mine\n*.png binary\n"));
    }

    #[test]
    fn a_missing_declaration_file_is_refused() {
        let (_dir, repo) = prepared("secrets/\n");
        fs::remove_file(repo.xcrypt_config_path()).expect("removing the declarations");

        match run(&repo, false) {
            Err(Error::Config(message)) => assert!(message.contains("init")),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_declaration_file_is_refused_rather_than_emptying_the_section() {
        let (_dir, repo) = prepared("secrets/ sparkly\n");

        let error = run(&repo, false).expect_err("an unknown attribute must stop sync");
        assert_eq!(error.exit_code(), crate::exit::CONFIG);
    }

    #[test]
    fn broken_markers_stop_the_command_with_the_configuration_code() {
        let (_dir, repo) = prepared("secrets/\n");
        fs::write(
            repo.attributes_path(),
            "# >>> git-xcrypt >>>\n* filter=git-xcrypt\n",
        )
        .expect("breaking the markers");

        let error = run(&repo, false).expect_err("guessing the boundary would lose user content");
        assert_eq!(error.exit_code(), crate::exit::CONFIG);
    }

    #[test]
    fn a_pointless_eol_declaration_is_carried_out_as_a_warning() {
        let (_dir, repo) = prepared("secrets/key.p12 binary eol=lf\n");

        let report = run(&repo, false).expect("a pointless declaration is not fatal");

        assert_eq!(report.outcome, Outcome::Updated);
        assert_eq!(report.warnings.len(), 1);
    }
}
