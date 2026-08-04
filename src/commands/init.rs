//! `git-xcrypt init` — make a repository ready to encrypt.
//!
//! The hard part is not setting things up, it is deciding whether to. Four
//! independent pieces of state exist (the key, the filter registration, the
//! config file, the managed attributes section) and getting the decision wrong
//! in one direction destroys the key. Three rules replace the sixteen cases:
//!
//! * a key exists → never touch it, repair the rest;
//! * no key but traces of an earlier setup → refuse, this is a clone or a locked
//!   repository and a fresh key would strand every existing blob forever;
//! * no key and no traces → initialise.

use std::fs;

use crate::key::MasterKey;
use crate::repo::{DRIVER, Repo};
use crate::{Error, Result, gitattributes, gitconfig, keyfile};

/// What `init` changed, so it can tell the user rather than work in silence.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// A key was generated. False when an existing one was left alone.
    pub key_created: bool,
    /// The filter registration was written or repaired.
    pub config_written: bool,
    /// The managed section in `.gitattributes` was written or repaired.
    pub attributes_written: bool,
    /// The `.git-xcrypt` file was created.
    pub config_file_created: bool,
}

impl Report {
    /// Whether anything at all changed.
    #[must_use]
    pub fn changed_anything(&self) -> bool {
        self.key_created
            || self.config_written
            || self.attributes_written
            || self.config_file_created
    }
}

/// The starting contents of `.git-xcrypt`.
///
/// Comments only: an empty file encrypts nothing, which is the safe default, and
/// the comments show the syntax without the user having to find the manual.
const CONFIG_TEMPLATE: &str = "\
# git-xcrypt — which paths leave this machine encrypted, and how line endings
# are handled. Patterns use .gitignore syntax; attributes use .gitattributes
# vocabulary. Without an attribute a path is treated as `text=auto`.
#
# secrets/
# *.env
# secrets/deploy.ps1   text eol=crlf
# secrets/key.p12      binary
# !secrets/README.md
";

/// Runs `init` in `repo`.
///
/// # Errors
///
/// [`Error::Config`] when the repository carries traces of an earlier setup but
/// no key — generating one would make existing blobs undecryptable forever.
pub fn run(repo: &Repo) -> Result<Report> {
    let mut report = Report::default();

    if !repo.has_key() {
        refuse_if_previously_configured(repo)?;
        keyfile::write(&repo.key_path(), &MasterKey::generate()?)?;
        report.key_created = true;
    }

    report.config_written = register_driver(repo)?;
    report.config_file_created = create_config_file(repo)?;
    report.attributes_written = gitattributes::write_section(&repo.attributes_path(), &[])?;

    Ok(report)
}

/// Refuses to generate a key in a repository that already used one.
///
/// The traces we look for are the ones a clone inherits through history: the
/// managed attributes section and the versioned config file. Both survive
/// cloning; the key does not.
fn refuse_if_previously_configured(repo: &Repo) -> Result<()> {
    let attributes = fs::read_to_string(repo.attributes_path()).unwrap_or_default();
    let has_section = gitattributes::has_section(&attributes);
    let has_config = repo.xcrypt_config_path().is_file();

    if !has_section && !has_config {
        return Ok(());
    }

    Err(Error::Config(format!(
        "this repository was already set up for git-xcrypt but its key is missing.\n\
         Generating a new one would make every file encrypted so far impossible to \
         read, for good.\n\
         If this is a clone, run `git-xcrypt unlock <key-file>`.\n\
         If you have the key elsewhere, run `git-xcrypt import-key <key-file>`.\n\
         (found: {})",
        match (has_section, has_config) {
            (true, true) => "a managed .gitattributes section and .git-xcrypt",
            (true, false) => "a managed .gitattributes section",
            _ => ".git-xcrypt",
        }
    )))
}

/// Registers the filter and diff drivers, reporting whether anything changed.
///
/// `required = true` is what makes a failing filter abort the operation. Without
/// it git treats the failure as harmless and commits the unfiltered content with
/// exit code 0 — for this product, a secret in the clear.
///
/// The filter is registered as `process`, the long-running protocol: a process
/// per file was measured 22× slower, which the catch-all construction cannot
/// afford.
fn register_driver(repo: &Repo) -> Result<bool> {
    let path = repo.config_path();
    let mut config = gitconfig::open_local(&path)?;
    let binary = current_executable()?;

    let wanted = [
        (
            format!("filter.{DRIVER}.process"),
            format!("{binary} process"),
        ),
        (format!("filter.{DRIVER}.required"), "true".to_string()),
        (format!("diff.{DRIVER}.textconv"), format!("{binary} diff")),
    ];

    let mut changed = false;
    for (key, value) in wanted {
        if gitconfig::get(&config, &key).as_deref() != Some(value.as_str()) {
            gitconfig::set(&mut config, &key, &value)?;
            changed = true;
        }
    }

    if changed {
        gitconfig::save_local(&path, &config)?;
    }
    Ok(changed)
}

/// Creates `.git-xcrypt` if it is absent, reporting whether it did.
fn create_config_file(repo: &Repo) -> Result<bool> {
    let path = repo.xcrypt_config_path();
    if path.exists() {
        return Ok(false);
    }
    fs::write(&path, CONFIG_TEMPLATE)?;
    Ok(true)
}

/// The command git should run, quoted so a space in the path survives.
///
/// Git hands the value to a shell, so a path containing a space or a quote would
/// otherwise be split. Single quotes stop the shell expanding anything; a
/// literal quote is closed, escaped and reopened.
fn current_executable() -> Result<String> {
    let path = std::env::current_exe()?;
    let text = path.to_string_lossy().replace('\\', "/");
    Ok(format!("'{}'", text.replace('\'', r"'\''")))
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn a_fresh_repository_gains_everything() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");

        let report = run(&repo).expect("init must succeed");

        assert!(report.key_created);
        assert!(report.config_written);
        assert!(report.attributes_written);
        assert!(report.config_file_created);
        assert!(repo.has_key());
        assert!(repo.xcrypt_config_path().is_file());

        let config = gitconfig::open_local(&repo.config_path()).expect("config");
        assert_eq!(
            gitconfig::get(&config, &format!("filter.{DRIVER}.required")).as_deref(),
            Some("true"),
            "without required = true a failing filter commits the plaintext"
        );
        assert!(gitconfig::get(&config, &format!("filter.{DRIVER}.process")).is_some());
    }

    #[test]
    fn a_second_run_leaves_the_key_untouched() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");

        run(&repo).expect("first init");
        let before = fs::read(repo.key_path()).expect("the key must exist");

        let report = run(&repo).expect("second init must succeed");
        let after = fs::read(repo.key_path()).expect("the key must still exist");

        assert!(!report.key_created, "the key must never be regenerated");
        assert_eq!(before, after, "the key file changed on a repeated init");
        assert!(
            !report.changed_anything(),
            "a settled repository needs no repair"
        );
    }

    #[test]
    fn a_missing_registration_is_repaired_without_touching_the_key() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        run(&repo).expect("first init");
        let before = fs::read(repo.key_path()).expect("the key must exist");

        fs::write(repo.config_path(), "[core]\n\tbare = false\n").expect("clobbering the config");
        let report = run(&repo).expect("init must repair");

        assert!(report.config_written);
        assert!(!report.key_created);
        assert_eq!(before, fs::read(repo.key_path()).expect("key"));
    }

    #[test]
    fn a_clone_without_a_key_is_refused() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        run(&repo).expect("first init");

        // Exactly the state after a clone: the versioned traces survive, the key
        // does not.
        fs::remove_file(repo.key_path()).expect("removing the key");

        match run(&repo) {
            Err(Error::Config(message)) => {
                assert!(
                    message.contains("unlock"),
                    "the message must point somewhere useful"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(!repo.has_key(), "the refusal must not have created a key");
    }

    #[test]
    fn an_existing_config_file_is_not_overwritten() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        fs::write(repo.xcrypt_config_path(), "*.env\n").expect("writing the config");

        // A pre-existing .git-xcrypt is a trace of an earlier setup, so a keyless
        // repository is refused before anything else happens.
        assert!(run(&repo).is_err());

        assert_eq!(
            fs::read_to_string(repo.xcrypt_config_path()).expect("config"),
            "*.env\n"
        );
    }
}
