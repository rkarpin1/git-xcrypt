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
    common_dir: PathBuf,
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

        let git_dir = absolute(&git_dir);
        Ok(Self {
            common_dir: common_dir(&git_dir),
            git_dir,
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

    /// The directory shared by every worktree — the real `.git`.
    ///
    /// The same as [`Repo::git_dir`] outside a linked worktree.
    #[must_use]
    pub fn common_dir(&self) -> &Path {
        &self.common_dir
    }

    /// Where the repository key lives. Never versioned, never committed.
    ///
    /// In the common directory, so every linked worktree of a repository reads
    /// the same key — the alternative is a per-worktree key, which cannot
    /// decrypt what the other worktrees committed.
    #[must_use]
    pub fn key_path(&self) -> PathBuf {
        self.common_dir.join(DRIVER).join("keys").join("default")
    }

    /// The config file git actually reads for this repository.
    ///
    /// In the common directory, again: a linked worktree's own git dir has a
    /// `config` file, but git ignores it unless `extensions.worktreeConfig` is
    /// set. Registering the driver there left git with no filter at all —
    /// measured on git 2.55, `git add` on a secret from a linked worktree exited
    /// 0 and stored the plaintext.
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.common_dir.join("config")
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

    /// Every checkout of this repository: this one, the main one, and every
    /// linked worktree.
    ///
    /// [`Repo::work_tree`] answers for the checkout a command was run from, and
    /// that is not the same question. A key written into a *sibling* checkout is
    /// as committable as one written into this one — measured on git 2.55,
    /// `export-key ../linked/k.key` from the main checkout put the key in the
    /// linked worktree's `git status` as `?? k.key`, one `git add -A` from a
    /// commit. `lock` already had to know this geometry to avoid stranding a
    /// sibling; the refusal in `export-key` needs the same list.
    ///
    /// Best effort on the pointers, and that is the honest limit: a worktree
    /// whose registration this cannot read is not in the list, so a caller uses
    /// it to *widen* a refusal, never to prove a path is safe.
    #[must_use]
    pub fn work_trees(&self) -> Vec<PathBuf> {
        let mut trees = vec![self.work_tree.clone()];

        // `worktrees/<name>/gitdir` names the `.git` *file* in the checkout, so
        // the checkout itself is its parent. A relative pointer is measured from
        // the registration, which is where git measures it from.
        for entry in std::fs::read_dir(self.common_dir.join("worktrees"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let registration = entry.path();
            let Ok(text) = std::fs::read_to_string(registration.join("gitdir")) else {
                continue;
            };
            let pointer = Path::new(text.trim_end_matches(['\n', '\r']));
            if pointer.as_os_str().is_empty() {
                continue;
            }
            let absolute = if pointer.is_absolute() {
                pointer.to_path_buf()
            } else {
                lexically_normal(&registration.join(pointer))
            };
            if let Some(checkout) = absolute.parent() {
                trees.push(checkout.to_path_buf());
            }
        }

        if let Some(main) = self.main_work_tree() {
            trees.push(main);
        }
        trees
    }

    /// Where the main checkout is, when this is a linked worktree.
    ///
    /// Not "the parent of the common directory": with `git init
    /// --separate-git-dir` the common directory is somewhere else entirely and
    /// is not called `.git`. Git finds the checkout through `core.worktree`
    /// there, so this does too.
    fn main_work_tree(&self) -> Option<PathBuf> {
        let config = crate::gitconfig::open_local(&self.config_path()).ok()?;
        if crate::gitconfig::get(&config, "core.bare")
            .as_deref()
            .is_some_and(crate::gitconfig::is_true)
        {
            return None;
        }

        if let Some(declared) = crate::gitconfig::get(&config, "core.worktree")
            && !declared.is_empty()
        {
            let path = Path::new(&declared);
            return Some(if path.is_absolute() {
                path.to_path_buf()
            } else {
                lexically_normal(&self.common_dir.join(path))
            });
        }

        (self.common_dir.file_name() == Some(std::ffi::OsStr::new(".git")))
            .then(|| self.common_dir.parent().map(Path::to_path_buf))
            .flatten()
    }
}

/// The directory every worktree of this repository shares.
///
/// A linked worktree's git dir is `.git/worktrees/<name>`, and it names the real
/// one in a `commondir` file. Everything that belongs to the repository rather
/// than to one checkout — the key, the filter registration — lives there.
fn common_dir(git_dir: &Path) -> PathBuf {
    let Ok(text) = std::fs::read_to_string(git_dir.join("commondir")) else {
        return git_dir.to_path_buf();
    };
    let target = Path::new(text.trim_end_matches(['\n', '\r']));
    if target.as_os_str().is_empty() {
        return git_dir.to_path_buf();
    }
    if target.is_absolute() {
        return target.to_path_buf();
    }
    lexically_normal(&git_dir.join(target))
}

/// Resolves `.` and `..` without touching the filesystem.
///
/// `commondir` holds a relative path such as `../..`, and leaving it in place
/// would make every message name a path no user recognises. `export-key` needs
/// the same thing for a destination that does not exist yet, which is why this
/// is public: a path it cannot resolve is a path it cannot prove lies outside
/// the repository.
///
/// Only safe on a path whose components are known not to be symlinks — popping
/// on `..` is what a symlink would make wrong.
#[must_use]
pub fn lexically_normal(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// The working-tree path an index entry names, without decoding it.
///
/// The index spells paths as raw bytes with forward slashes, and on Unix that is
/// what a filename is — going through a lossy `String` would turn any byte that
/// is not UTF-8 into U+FFFD and open a file that does not exist, or worse, a
/// different one. The same mistake was found and fixed on the filter path in the
/// S-01 review.
///
/// Shared rather than spelled once per caller: `status` reads working-tree files
/// by index name and `lock` proves them closed by index name, and two answers to
/// "which file does this entry mean" is one answer too many. Messages take a
/// different route — they may be lossy, and they say so.
#[must_use]
pub fn working_tree_path(name: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        PathBuf::from(std::ffi::OsStr::from_bytes(name))
    }
    #[cfg(not(unix))]
    {
        // Windows filenames are UTF-16 and git spells them as UTF-8 here, so
        // there is no lossless byte route and nothing is lost by this one.
        PathBuf::from(String::from_utf8_lossy(name).into_owned())
    }
}

/// The separator this platform's [`Path`] renders, and the only character it is
/// safe to rewrite into git's spelling.
///
/// On Unix a backslash is an ordinary character in a file name, so rewriting one
/// there would name a *different* file — which is the same class of bug as
/// decoding a path lossily.
/// Shared with `init`, which has to spell the filter command git runs the same
/// way for the same reason: two answers to "which character is a separator here"
/// is one answer too many.
#[cfg(windows)]
pub(crate) const NATIVE_SEPARATOR: char = '\\';
#[cfg(not(windows))]
pub(crate) const NATIVE_SEPARATOR: char = '/';

/// Renders a path the way git spells one: forward slashes on every platform.
///
/// Git prints forward slashes on Windows too — `git status`, `git ls-files`,
/// `git diff --name-only`, all of them — and so do the index, the pattern
/// matcher and `.gitattributes` in this crate. A message that tells the user to
/// `git add` a file has to spell it the way the `git status` next to it will, or
/// the two do not look like the same file.
///
/// For a path *inside* the repository, and for an attribute source a reader is
/// meant to paste back into git. An absolute filesystem path the user is to hand
/// to their shell — a key file, a git directory, a destination for `export-key` —
/// keeps its native separators and must not come through here.
#[must_use]
pub fn git_spelling(path: &Path) -> String {
    with_separator(&path.display().to_string(), NATIVE_SEPARATOR)
}

/// The platform-independent core, so both spellings are testable from either
/// platform. A no-op when the native separator already is git's.
pub(crate) fn with_separator(rendered: &str, separator: char) -> String {
    if separator == '/' {
        return rendered.to_string();
    }
    rendered.replace(separator, "/")
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

    /// The Windows half of [`git_spelling`], exercised from any platform.
    ///
    /// The developing machine is not Windows, so the branch that matters most
    /// would otherwise be covered by CI alone — and it was CI that found the
    /// message this helper exists to fix.
    #[test]
    fn a_path_built_from_components_is_spelled_the_way_git_spells_it() {
        let joined = Path::new("secrets").join("db.env");

        // What Windows renders, put through the same core the Windows build uses.
        assert_eq!(
            with_separator("secrets\\db.env", '\\'),
            "secrets/db.env",
            "a message must not show a spelling `git status` never prints"
        );
        assert_eq!(with_separator("a\\b\\c.env", '\\'), "a/b/c.env");

        // And on a platform whose separator already is git's, nothing moves.
        assert_eq!(with_separator("secrets/db.env", '/'), "secrets/db.env");

        // Whichever platform this runs on, the public entry point agrees.
        assert_eq!(git_spelling(&joined), "secrets/db.env");
    }
}
