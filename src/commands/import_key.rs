//! `git-xcrypt import-key` — put a carried key back into a repository.
//!
//! The dangerous direction here is not refusing too often, it is accepting too
//! easily: writing a second key over the one a repository already uses makes
//! every blob committed so far unreadable, for good, and nothing about the
//! command's output would say so. So a key that differs from the one already in
//! place is refused outright, and an identical one is an empty success — which
//! is what makes re-running the command harmless.
//!
//! Accepting too easily has a second face, closed on 2026-08-05: a key the
//! working tree's own headers contradict. Importing the wrong repository's key
//! into a fresh clone used to succeed — no key was in place, so nothing
//! conflicted — and from then on every command answered around the mistake:
//! `unlock` refused (correctly) over the first file, and importing the *right*
//! key hit the different-key refusal, whose "replacing it would make every file
//! unreadable" warning is simply false when the key in place has encrypted
//! nothing. The way out existed — the refusal names the key file to remove —
//! but the state should never form. So a key that would actually be installed
//! is asked past the same evidence `unlock` gathers: every encrypted file in
//! the working tree names the key it wants, 38 bytes each, and a key they
//! contradict is refused before it is on disk. A tree with no encrypted file
//! offers no evidence and accepts any key, exactly as `unlock` does.
//!
//! Both halves of the filter are repaired at the same time, and neither is
//! optional. `.git/config` is not versioned, so a clone has no driver; and the
//! `* filter=git-xcrypt` line in `.gitattributes` is only there if whoever set
//! the repository up committed the file — `init` writes it but does not commit
//! it, so a clone can easily arrive with neither. Git reads a missing attribute
//! and an undefined filter the same way: as no filter, so the next `git add` on
//! a secret stores plaintext with exit code 0 and says nothing. A key handed to
//! a repository in that state is not a safe place to leave anyone, even though
//! the plan gave this job to `unlock` alone.

use std::path::Path;

use crate::config::Config;
use crate::format::KEY_ID_LEN;
use crate::key::MasterKey;
use crate::repo::Repo;
use crate::{Error, Result, gitattributes, keyfile};

/// What `import-key` found and what it did about it.
#[derive(Debug)]
pub struct Report {
    /// Fingerprint of the key now in place.
    pub key_id: [u8; KEY_ID_LEN],
    /// A key file was written. False when the same key was already there.
    pub imported: bool,
    /// The filter registration was written or repaired.
    pub config_written: bool,
    /// The managed `.gitattributes` section was written or repaired.
    pub attributes_written: bool,
    /// What the evidence walk could not read, one message per skip.
    pub warnings: Vec<String>,
}

/// Imports the key stored in `source`.
///
/// # Errors
///
/// [`Error::Usage`] when the file is not there, [`Error::Format`] when it is not
/// a key file, [`Error::Config`] when the repository already holds a different
/// key, [`Error::Format`] when a working-tree file was encrypted with a
/// different key — the headers are the only evidence there is, and installing a
/// key they contradict is the one state this command cannot cleanly leave —
/// [`Error::Io`] when the key cannot be written.
pub fn run(repo: &Repo, source: &Path) -> Result<Report> {
    let key = keyfile::read_portable(source)?;
    refuse_on_conflict(repo, &key)?;

    // Only when the key would actually be installed: with the same key already
    // in place there is nothing to install and the walk would cost a re-run of
    // the command its harmlessness. The pass itself is `unlock`'s, on purpose —
    // two spellings of "which key does this tree ask for" would drift.
    let mut warnings = Vec::new();
    if !repo.has_key() {
        let mut walk = super::unlock::Walk::default();
        let encrypted = super::unlock::collect_encrypted(repo, &mut walk)?;
        super::unlock::refuse_foreign_keys(repo, &encrypted, &key.key_id())?;
        warnings = walk.warnings;
    }

    let imported = install(repo, &key)?;
    let config_written = super::init::register_driver(repo)?;

    // Same order as `init`: the registration is saved first, so an unreadable
    // `.git-xcrypt` stops the command with the repair already half landed and a
    // message naming the offending line. An absent one is not an error — the
    // section it renders is then just the catch-all, which is the line the whole
    // guarantee rests on.
    let config = Config::load(&repo.xcrypt_config_path())?;
    let attributes_written = gitattributes::write_section(
        &repo.attributes_path(),
        &gitattributes::render_lines(&config),
    )?;

    Ok(Report {
        key_id: key.key_id(),
        imported,
        config_written,
        attributes_written,
        warnings,
    })
}

/// Refuses when the repository already holds a key that is not this one.
///
/// Separate from [`install`] because `unlock` has to ask this question before it
/// touches anything at all: a refusal that has already written a key file has
/// not refused.
///
/// # Errors
///
/// [`Error::Config`] for a different key, [`Error::Format`] when the key file
/// already in the repository cannot be read.
pub(crate) fn refuse_on_conflict(repo: &Repo, key: &MasterKey) -> Result<()> {
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
pub(crate) fn install(repo: &Repo, key: &MasterKey) -> Result<bool> {
    if repo.has_key() {
        return Ok(false);
    }
    keyfile::write(&repo.key_path(), key)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MASTER_KEY_LEN;
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

    /// A key file outside any repository, holding `seed`'s key.
    fn exported(seed: u8) -> (TempDir, std::path::PathBuf, MasterKey) {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("repo.key");
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        keyfile::write_portable(&path, &key).expect("writing the export");
        (dir, path, key)
    }

    #[test]
    fn a_different_key_is_refused_and_the_original_survives() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        let (_mine, mine, my_key) = exported(33);
        let (_theirs, theirs, _their_key) = exported(34);
        run(&repo, &mine).expect("first import");

        let error = run(&repo, &theirs).expect_err("a second key must be refused");

        assert_eq!(error.exit_code(), crate::exit::CONFIG);
        assert_eq!(
            repo.load_key().expect("key").expose_bytes(),
            my_key.expose_bytes(),
            "the refusal replaced the key anyway"
        );
    }
}
