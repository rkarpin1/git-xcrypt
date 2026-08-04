//! `git-xcrypt export-key` — hand the repository key to the user, once.
//!
//! This is the command that gives a key away, so it is the shortest route to a
//! leak in the whole product. PRD FR-007 says as much: "one run inside CI, or
//! one redirect into the repository directory, is all it takes". Three refusals
//! close the routes that do not need a compromised machine:
//!
//! * the key never reaches `stdout` — not here and not anywhere else, so no
//!   redirect and no CI log can capture it;
//! * a destination inside the working tree is refused outright, because that is
//!   one `git add -A` away from a commit;
//! * an existing file is refused unless `--force`, so a mistyped path cannot
//!   silently destroy someone's backup of a *different* key.
//!
//! The file itself is written owner-only and atomically, by the same code that
//! writes the repository's own key.

use std::path::{Path, PathBuf};

use crate::format::KEY_ID_LEN;
use crate::repo::Repo;
use crate::{Error, Result, keyfile};

/// What `export-key` wrote, so the binary can say so without naming the key.
#[derive(Debug)]
pub struct Report {
    /// Fingerprint of the exported key. Safe to print; the key is not.
    pub key_id: [u8; KEY_ID_LEN],
    /// Where it landed, resolved the way the refusal check saw it.
    pub path: PathBuf,
}

/// Writes the repository key to `destination`.
///
/// # Errors
///
/// [`Error::Config`] when the destination is inside the working tree or already
/// exists without `--force`, [`Error::NoKey`] when the repository has no key,
/// [`Error::Io`] when the file cannot be written.
pub fn run(repo: &Repo, destination: &Path, force: bool) -> Result<Report> {
    // Before the key is even loaded: a refusal must never be reached with key
    // material already in this process's memory if it does not have to be.
    let resolved = refuse_bad_destination(repo, destination, force)?;

    let key = repo.load_key()?;
    let key_id = key.key_id();

    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
    {
        create_key_directory(parent)?;
    }
    keyfile::write_portable(destination, &key)?;

    Ok(Report {
        key_id,
        path: resolved,
    })
}

/// Refuses every destination that would defeat the point of the command.
///
/// Returns the resolved path, so the message the user sees names the place the
/// check actually looked at rather than what they typed.
fn refuse_bad_destination(repo: &Repo, destination: &Path, force: bool) -> Result<PathBuf> {
    let here = std::env::current_dir()?;
    let resolved = resolve(&here, destination);
    let work_tree = resolve(&here, repo.work_tree());

    if resolved.starts_with(&work_tree) {
        return Err(Error::Config(format!(
            "refusing to write the repository key to {}: it is inside the working tree of {}, \
             which is one `git add` away from a commit. Choose a path outside the repository, \
             such as a directory only you can read.",
            resolved.display(),
            work_tree.display()
        )));
    }

    // `symlink_metadata`, not `exists`: a broken symlink is still an entry the
    // rename would replace, and `exists` follows the link and says no.
    if !force && destination.symlink_metadata().is_ok() {
        return Err(Error::Config(format!(
            "{} already exists; pass --force to replace it. \
             Overwriting a key file destroys the only copy of whatever key it held.",
            destination.display()
        )));
    }

    Ok(resolved)
}

/// Creates the directory the key is about to land in, owner-only.
///
/// A directory this command creates exists to hold keys, so `0700` rather than
/// the usual `0755` — the file itself is `0600` either way, but a directory
/// anyone can list is one more thing a user did not ask for. Directories that
/// already exist keep whatever permissions their owner chose.
fn create_key_directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }

    // The bare error is `File exists`, which for a parent that is a regular file
    // reads as "you told me not to overwrite" rather than "there is a file where
    // a directory has to go", and names nothing.
    builder.create(path).map_err(|err| {
        Error::Io(std::io::Error::other(format!(
            "{}: could not create the directory to hold the key ({err})",
            path.display()
        )))
    })
}

/// An absolute, symlink-resolved form of `path`, which need not exist yet.
///
/// Canonicalising the whole path is not an option — the destination is normally
/// a file that is about to be created — so the deepest ancestor that does exist
/// is canonicalised and the rest is appended and normalised lexically. Without
/// the canonicalisation the check would miss the case that matters most on
/// macOS, where a repository under `/var/folders/...` is reached through a
/// symlink from `/private/var/folders/...` and the two spellings do not compare
/// equal.
///
/// `base` is the directory a relative path is measured from — the process's
/// current directory in production, and an argument here so the refusal can be
/// tested without mutating process-wide state.
fn resolve(base: &Path, path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };

    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut probe: &Path = &absolute;

    loop {
        if let Ok(real) = probe.canonicalize() {
            let mut out = real;
            for name in tail.iter().rev() {
                out.push(name);
            }
            return crate::repo::lexically_normal(&out);
        }

        let (Some(parent), Some(name)) = (probe.parent(), probe.file_name()) else {
            // Nothing along the path exists, which on a sane system means the
            // root does not either. Lexical normalisation is all that is left.
            return crate::repo::lexically_normal(&absolute);
        };
        tail.push(name);
        probe = parent;
    }
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

    /// A repository with a key, plus a directory outside it to export into.
    fn prepared() -> (TempDir, TempDir, Repo) {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        crate::commands::init::run(&repo).expect("init must succeed");
        let elsewhere = TempDir::new().expect("temporary directory");
        (dir, elsewhere, repo)
    }

    #[test]
    fn an_exported_key_reads_back_as_the_same_key() {
        let (_dir, elsewhere, repo) = prepared();
        let path = elsewhere.path().join("repo.key");

        let report = run(&repo, &path, false).expect("export must succeed");

        let back = keyfile::read_portable(&path).expect("the export must parse");
        assert_eq!(back.key_id(), report.key_id);
        assert_eq!(
            back.expose_bytes(),
            repo.load_key().expect("key").expose_bytes()
        );
    }

    #[test]
    fn a_destination_inside_the_working_tree_is_refused_without_creating_it() {
        let (_dir, _elsewhere, repo) = prepared();
        let path = repo.work_tree().join("keys").join("leaked.key");

        let error = run(&repo, &path, false).expect_err("the key must never land in the tree");

        assert_eq!(error.exit_code(), crate::exit::CONFIG);
        assert!(!path.exists(), "the refusal still created the file");
        assert!(
            !repo.work_tree().join("keys").exists(),
            "the refusal created a directory in the working tree"
        );
    }

    #[test]
    fn a_destination_inside_the_git_directory_is_refused_too() {
        // `.git/` is not versioned, but it is inside the tree and a user who
        // typed it meant something else.
        let (_dir, _elsewhere, repo) = prepared();
        let path = repo.git_dir().join("exported.key");
        assert!(run(&repo, &path, false).is_err());
    }

    #[test]
    fn a_relative_destination_is_measured_from_where_the_user_stands() {
        // The realistic spelling of the mistake: `export-key repo.key` typed
        // while standing in the repository.
        let (dir, elsewhere, _repo) = prepared();
        let inside = resolve(dir.path(), Path::new("repo.key"));
        let outside = resolve(elsewhere.path(), Path::new("repo.key"));

        assert!(inside.starts_with(resolve(dir.path(), dir.path())));
        assert!(!outside.starts_with(resolve(dir.path(), dir.path())));
    }

    #[test]
    fn resolution_sees_through_the_symlink_a_temporary_directory_hides_behind() {
        // On macOS a repository under /var/folders is the same place as one
        // under /private/var/folders. Comparing the two spellings without
        // canonicalising lets the refusal be walked straight past.
        let (dir, _elsewhere, repo) = prepared();
        let typed = dir.path().join("secrets").join("leak.key");

        let resolved = resolve(dir.path(), &typed);

        assert!(
            resolved.starts_with(resolve(dir.path(), repo.work_tree())),
            "{} was not recognised as inside {}",
            resolved.display(),
            repo.work_tree().display()
        );
    }

    #[test]
    fn a_path_climbing_back_out_of_the_repository_is_allowed() {
        let (dir, elsewhere, repo) = prepared();
        let climbing = dir.path().join("..").join("..");
        let resolved = resolve(elsewhere.path(), &climbing);
        assert!(!resolved.starts_with(resolve(dir.path(), repo.work_tree())));
    }

    #[test]
    fn a_repository_without_a_key_reports_that_and_writes_nothing() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        let elsewhere = TempDir::new().expect("temporary directory");
        let path = elsewhere.path().join("repo.key");

        match run(&repo, &path, false) {
            Err(Error::NoKey) => {}
            other => panic!("expected NoKey, got {other:?}"),
        }
        assert!(!path.exists());
    }

    #[test]
    fn an_existing_file_is_refused_unless_force_says_otherwise() {
        let (_dir, elsewhere, repo) = prepared();
        let path = elsewhere.path().join("repo.key");
        fs::write(&path, b"someone else's key").expect("writing");

        let error = run(&repo, &path, false).expect_err("a mistyped path must not destroy a key");
        assert_eq!(error.exit_code(), crate::exit::CONFIG);
        assert_eq!(fs::read(&path).expect("reading"), b"someone else's key");

        run(&repo, &path, true).expect("--force must replace it");
        assert!(keyfile::read_portable(&path).is_ok());
    }

    #[test]
    fn missing_parent_directories_are_created() {
        let (_dir, elsewhere, repo) = prepared();
        let path = elsewhere
            .path()
            .join("keys")
            .join("nested")
            .join("repo.key");

        run(&repo, &path, false).expect("export must succeed");

        assert!(keyfile::read_portable(&path).is_ok());
    }
}
