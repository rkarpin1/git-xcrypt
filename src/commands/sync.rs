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
    /// How many lines outside the managed section touch `filter`, `text`,
    /// `eol` or `crlf`.
    ///
    /// A count and nothing more, on purpose. Whether any of them actually
    /// reaches a declared path is a question about git's whole attribute stack,
    /// and `status` already answers it by running that stack — a second
    /// spelling here would be one too many, and a `sync` that quoted an
    /// ordinary `*.psd filter=lfs` at its user every run would teach them to
    /// stop reading it. So this only says "something outside this section could
    /// have an opinion" and points at the command that knows.
    pub foreign: usize,
}

/// Runs `sync` in `repo`, writing unless `check` is set.
///
/// # Errors
///
/// [`Error::Config`] when `.git-xcrypt` is absent or cannot be understood, or
/// when the managed section in `.gitattributes` has unbalanced markers;
/// [`Error::Io`] on a read or write failure.
pub fn run(repo: &Repo, check: bool, rendering: gitattributes::Rendering) -> Result<Report> {
    let config = Config::load(&repo.xcrypt_config_path())?;
    if config.missing {
        return Err(Error::Config(format!(
            "{CONFIG_FILE} is missing, so there is nothing to synchronise; \
             run `git-xcrypt init` to create it"
        )));
    }

    let lines = gitattributes::render_lines(&config, rendering);
    let path = repo.attributes_path();

    let outcome = if check {
        // Any shape this build writes counts as current, not just the one asked
        // for on this command line. `--check` is a CI gate, and its question is
        // "does the section still describe the declaration" — a repository that
        // still on the section `init` wrote has not gone stale by never having
        // run `sync`, and failing it there would teach the gate's owner to
        // ignore it.
        // A section that matches *none* of them is what staleness looks like.
        let current = gitattributes::ACCEPTED.into_iter().any(|rendering| {
            let lines = gitattributes::render_lines(&config, rendering);
            gitattributes::desired(&path, &lines).is_ok_and(|(existing, wanted)| existing == wanted)
        });
        if current {
            Outcome::UpToDate
        } else {
            Outcome::Stale
        }
    } else if gitattributes::write_section(&path, &lines)? {
        Outcome::Updated
    } else {
        Outcome::UpToDate
    };

    // Cheap: one read of a file already on disk, no attribute resolution. An
    // unreadable `.gitattributes` answers zero rather than failing — `sync` has
    // just written it, and the gate for that state is `status`.
    let foreign = gitattributes::foreign_lines_touching(&path, &["filter", "text", "eol", "crlf"])
        .map(|lines| lines.len())
        .unwrap_or(0);

    Ok(Report {
        outcome,
        foreign,
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
    fn only_the_per_pattern_section_can_go_stale() {
        // The global section is one line that says nothing about the
        // declaration, so no change to `.git-xcrypt` can make it wrong — which
        // is exactly why it is the default: `sync` stops being part of the flow.
        let (_dir, repo) = prepared("secrets/\n");
        let before = fs::read_to_string(repo.attributes_path()).expect("attributes");
        assert_eq!(
            run(&repo, true, gitattributes::Rendering::Global)
                .expect("check must succeed")
                .outcome,
            Outcome::UpToDate,
            "a global section was called stale, which it cannot be"
        );
        fs::write(repo.xcrypt_config_path(), "secrets/\n*.env\nmore/\n")
            .expect("changing the declarations");
        assert_eq!(
            run(&repo, true, gitattributes::Rendering::Global)
                .expect("check must succeed")
                .outcome,
            Outcome::UpToDate,
            "a global section went stale over a changed declaration"
        );
        assert_eq!(
            before,
            fs::read_to_string(repo.attributes_path()).expect("attributes"),
            "--check must never touch the working tree"
        );

        // Split, and it can. That is the trade a plain `sync` buys into: the
        // diff driver stops running for undeclared paths, and `sync` becomes
        // something to run after every change to the declaration.
        let per_pattern = gitattributes::Rendering::PerPattern { fold_case: false };
        run(&repo, false, per_pattern).expect("sync");
        assert_eq!(
            run(&repo, true, per_pattern).expect("check").outcome,
            Outcome::UpToDate,
            "the check and the write must not disagree"
        );

        let before = fs::read_to_string(repo.attributes_path()).expect("attributes");
        fs::write(
            repo.xcrypt_config_path(),
            "secrets/\n*.env\nmore/\nlater/\n",
        )
        .expect("changing the declarations again");
        assert_eq!(
            run(&repo, true, per_pattern).expect("check").outcome,
            Outcome::Stale,
            "a split section did not notice the declaration changing under it"
        );
        assert_eq!(
            before,
            fs::read_to_string(repo.attributes_path()).expect("attributes"),
            "--check must never touch the working tree"
        );
    }
}
