//! Locating the repository and reading its state — without spawning `git`.
//!
//! Spawning is not an option: git starts a fresh filter process per operation
//! and the binary is required to be self-contained, so every answer here comes
//! from a library.

use std::path::{Path, PathBuf};

use crate::key::MasterKey;
use crate::{Error, Result, keyfile};

/// Name of the versioned configuration file listing what to encrypt.
pub const CONFIG_FILE: &str = ".git-xcrypt";

/// Directory holding key envelopes, once recipients exist. Never encrypted.
pub const KEY_ENVELOPE_DIR: &str = ".git-xcrypt-keys";

/// The attributes file git actually reads.
pub const ATTRIBUTES_FILE: &str = ".gitattributes";

/// Name of the filter driver as registered in `.git/config`.
pub const DRIVER: &str = "git-xcrypt";

/// A discovered repository.
#[derive(Debug)]
pub struct Repo {
    git_dir: PathBuf,
    work_tree: PathBuf,
}

impl Repo {
    /// Finds the repository containing `start`, walking upwards.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when there is no repository, or when it is bare —
    /// a bare repository has no working tree, so there is nothing to filter.
    pub fn discover(start: &Path) -> Result<Self> {
        let (path, _trust) = gix_discover::upwards(start)
            .map_err(|err| Error::Config(format!("not inside a git repository: {err}")))?;
        let (git_dir, work_tree) = path.into_repository_and_work_tree_directories();
        let work_tree = work_tree.ok_or_else(|| {
            Error::Config("this is a bare repository, so there is nothing to encrypt".into())
        })?;

        Ok(Self {
            git_dir: absolute(&git_dir),
            work_tree: absolute(&work_tree),
        })
    }

    /// Finds the repository containing the current directory.
    ///
    /// # Errors
    ///
    /// As [`Repo::discover`], plus [`Error::Io`] if the current directory is gone.
    pub fn discover_from_cwd() -> Result<Self> {
        let cwd = std::env::current_dir()?;
        Self::discover(&cwd)
    }

    /// The `.git` directory.
    #[must_use]
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    /// The working tree root.
    #[must_use]
    pub fn work_tree(&self) -> &Path {
        &self.work_tree
    }

    /// Where the repository key lives. Never versioned, never committed.
    #[must_use]
    pub fn key_path(&self) -> PathBuf {
        self.git_dir.join(DRIVER).join("keys").join("default")
    }

    /// The repository-local config file.
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.git_dir.join("config")
    }

    /// The versioned list of what to encrypt.
    #[must_use]
    pub fn xcrypt_config_path(&self) -> PathBuf {
        self.work_tree.join(CONFIG_FILE)
    }

    /// The attributes file git reads.
    #[must_use]
    pub fn attributes_path(&self) -> PathBuf {
        self.work_tree.join(ATTRIBUTES_FILE)
    }

    /// Whether a repository key is present.
    #[must_use]
    pub fn has_key(&self) -> bool {
        self.key_path().is_file()
    }

    /// Loads the repository key.
    ///
    /// # Errors
    ///
    /// [`Error::NoKey`] when the repository is locked or was never initialised.
    pub fn load_key(&self) -> Result<MasterKey> {
        keyfile::read(&self.key_path())
    }

    /// Turns a path inside the working tree into a repository-relative one.
    ///
    /// Returns `None` for a path outside the working tree, which is how callers
    /// refuse to act on something that is not part of this repository.
    #[must_use]
    pub fn relative<'a>(&self, path: &'a Path) -> Option<&'a Path> {
        path.strip_prefix(&self.work_tree).ok()
    }
}

/// Makes a path absolute without touching the filesystem when it already is.
///
/// `canonicalize` would resolve symlinks, which changes what the user sees in
/// messages and would make a repository reached through a symlink report a
/// different root than the one they typed.
fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// Creates a real repository; these paths are not worth faking.
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
    fn discovery_finds_the_repository_from_a_subdirectory() {
        let dir = init_repo();
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).expect("creating directories must succeed");

        let repo = Repo::discover(&nested).expect("discovery must succeed");
        assert!(repo.git_dir().ends_with(".git"));
        assert!(repo.key_path().starts_with(repo.git_dir()));
    }

    #[test]
    fn discovery_fails_outside_a_repository() {
        let dir = TempDir::new().expect("temporary directory");
        match Repo::discover(dir.path()) {
            Err(Error::Config(_)) => {}
            other => panic!("expected a config error outside a repository, got {other:?}"),
        }
    }

    #[test]
    fn a_fresh_repository_has_no_key() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery must succeed");
        assert!(!repo.has_key());
        match repo.load_key() {
            Err(Error::NoKey) => {}
            Err(other) => panic!("expected NoKey, got {other:?}"),
            Ok(_) => panic!("a fresh repository must not hand out a key"),
        }
    }

    #[test]
    fn paths_outside_the_working_tree_are_rejected() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery must succeed");
        assert!(repo.relative(Path::new("/definitely/elsewhere")).is_none());
    }
}
