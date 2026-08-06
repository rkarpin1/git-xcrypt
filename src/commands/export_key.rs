//! `git-xcrypt export-key` — hand the repository key to the user, once.
//!
//! This is the command that gives a key away, so it is the shortest route to a
//! leak in the whole product. PRD FR-007 says as much: "one run inside CI, or
//! one redirect into the repository directory, is all it takes". Three refusals
//! close the routes that do not need a compromised machine:
//!
//! * the key reaches `stdout` only when `--stdout` asks for it, and never when
//!   `stdout` is a terminal — a key in the scrollback outlives the window, the
//!   multiplexer's buffer and often the session log. Added 2026-08-06 for the
//!   one workflow the file form cannot serve: piping the key straight into a
//!   secret store (`| pbcopy`, `| gh secret set …`) without it ever touching
//!   the disk. What that flag cannot police is a shell redirect: `--stdout >
//!   secrets/key.txt` writes where the refusals below would have said no,
//!   because a process cannot portably learn the path behind its own file
//!   descriptor. Said out loud in the command's own warning and in the README,
//!   because it is the FR-007 leak with the guard rail removed by hand;
//! * a destination inside the working tree is refused outright, because that is
//!   one `git add -A` away from a commit;
//! * an existing file is refused unless `--force`, so a mistyped path cannot
//!   silently destroy someone's backup of a *different* key.
//!
//! The file itself is written owner-only and atomically, by the same code that
//! writes the repository's own key.

use std::path::{Path, PathBuf};

use crate::crypto::format::KEY_ID_LEN;
use crate::crypto::keyfile;
use crate::git::repo::Repo;
use crate::{Error, Result};

/// What `export-key` wrote, so the binary can say so without naming the key.
#[derive(Debug)]
pub struct Report {
    /// Fingerprint of the exported key. Safe to print; the key is not.
    pub key_id: [u8; KEY_ID_LEN],
    /// Where it landed, resolved the way the refusal check saw it.
    pub path: PathBuf,
}

/// Writes the repository key to `stdout`, for piping into a secret store.
///
/// Refuses a terminal, and only a terminal: everything else is a pipe or a
/// redirect the caller chose deliberately. The refusal is the cheap half of the
/// bargain — see the module comment for the half no process can enforce.
///
/// # Errors
///
/// [`Error::Config`] when `stdout` is a terminal, [`Error::NoKey`] when the
/// repository has no key, [`Error::Io`] when the write fails.
pub fn to_stdout(repo: &Repo) -> Result<[u8; KEY_ID_LEN]> {
    use std::io::IsTerminal as _;
    to_writer(
        repo,
        &mut std::io::stdout().lock(),
        std::io::stdout().is_terminal(),
    )
}

/// [`to_stdout`], with the destination and the terminal answer as arguments.
///
/// Split for the same reason as `gitconfig::global_attributes_file_for`: the
/// refusal this function exists for fires only when the destination is a
/// terminal, and a test cannot portably arrange one — a pty is a Unix mechanism
/// and this rule has to hold on all three platforms. Passing the answer in
/// makes both arms reachable from anywhere, which is worth more than a guard
/// that runs on one platform out of three.
///
/// # Errors
///
/// As [`to_stdout`].
fn to_writer(
    repo: &Repo,
    out: &mut impl std::io::Write,
    destination_is_a_terminal: bool,
) -> Result<[u8; KEY_ID_LEN]> {
    // Before the key is loaded, for the same reason as the destination checks:
    // a refusal must not be reached with key material already in memory.
    if destination_is_a_terminal {
        return Err(Error::Config(
            "refusing to print the key to a terminal: it would stay in the \
             scrollback, in your multiplexer's buffer and in any session log.\n\
             Pipe it somewhere (`git-xcrypt export-key --stdout | pbcopy`), or \
             write a file with `git-xcrypt export-key <path>`."
                .into(),
        ));
    }

    let key = repo.load_key()?;
    let key_id = key.key_id();
    // The same text the file form writes, so one format round-trips through
    // both routes and the header keeps verifying the material behind it.
    let exported = keyfile::encode_portable(&key);
    out.write_all(exported.as_bytes())?;
    out.flush()?;
    Ok(key_id)
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

    // **Every** checkout, not just the one this command was run from. A linked
    // worktree is a different directory that is not a prefix of this one, so a
    // single comparison let `export-key ../linked/k.key` through — measured on
    // git 2.55, the key landed in the sibling checkout's `git status` as an
    // untracked file, which is the exact state this refusal exists to prevent.
    for work_tree in repo.work_trees() {
        let work_tree = resolve(&here, &work_tree);
        if resolved.starts_with(&work_tree) {
            return Err(Error::Config(format!(
                "refusing to write the repository key to {}: it is inside the working tree of {}, \
                 which is one `git add` away from a commit. Choose a path outside the repository, \
                 such as a directory only you can read.",
                resolved.display(),
                work_tree.display()
            )));
        }
    }

    // The git directory is not always inside a working tree: with `git init
    // --separate-git-dir` it sits somewhere else entirely, and the loop above
    // then has nothing to say about it. Nothing legitimate writes an exported
    // key in there, and the repository's own key already lives one directory
    // down, where `--force` would overwrite it.
    for private in [repo.git_dir(), repo.common_dir()] {
        let private = resolve(&here, private);
        if resolved.starts_with(&private) {
            return Err(Error::Config(format!(
                "refusing to write the repository key to {}: it is inside the git directory {}, \
                 which is where this repository's own key lives. Choose a path outside the \
                 repository, such as a directory only you can read.",
                resolved.display(),
                private.display()
            )));
        }
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
///
/// On Windows neither number applies: there is no mode to set, so the directory
/// and the key file both inherit the ACL of wherever the user pointed this
/// command. That is the limitation recorded in `README.md` §Known limitations,
/// and it is why the message there tells a Windows user to pick the directory
/// deliberately.
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
            return crate::git::repo::lexically_normal(&out);
        }

        let (Some(parent), Some(name)) = (probe.parent(), probe.file_name()) else {
            // Nothing along the path exists, which on a sane system means the
            // root does not either. Lexical normalisation is all that is left.
            return crate::git::repo::lexically_normal(&absolute);
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
    fn a_destination_inside_the_git_directory_is_refused_too() {
        // `.git/` is not versioned, but it is inside the tree and a user who
        // typed it meant something else.
        let (_dir, _elsewhere, repo) = prepared();
        let path = repo.git_dir().join("exported.key");
        assert!(run(&repo, &path, false).is_err());
    }

    #[test]
    fn an_existing_file_is_refused_unless_force_says_otherwise() {
        let (_dir, elsewhere, repo) = prepared();
        let path = elsewhere.path().join("repo.key");
        fs::write(&path, b"someone else's key").expect("writing");

        let error = run(&repo, &path, false).expect_err("a mistyped path must not destroy a key");
        assert_eq!(error.exit_code(), crate::util::exit::CONFIG);
        assert_eq!(fs::read(&path).expect("reading"), b"someone else's key");

        run(&repo, &path, true).expect("--force must replace it");
        assert!(keyfile::read_portable(&path).is_ok());
    }

    /// Both arms of the one refusal a test cannot arrange from outside.
    ///
    /// A terminal needs a pty, which is a Unix mechanism, and this rule has to
    /// hold on all three platforms — so the answer arrives as an argument. The
    /// negative arm carries as much weight as the positive one: refusing a pipe
    /// would break the only workflow the flag exists for.
    #[test]
    fn the_key_goes_to_a_pipe_and_never_to_a_terminal() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        crate::commands::init::run(&repo).expect("init must succeed");

        let mut piped: Vec<u8> = Vec::new();
        let key_id = to_writer(&repo, &mut piped, false).expect("a pipe must be written to");
        let text = String::from_utf8(piped).expect("an export is text");
        assert!(
            text.contains(&crate::format_key_id(&key_id)),
            "the export must name the key it holds: {text}"
        );
        // The one format, so a key piped out reads back through the same parser
        // a file goes through — the header still verifies the material.
        let parsed = keyfile::decode_portable(&text).expect("the export must parse");
        assert_eq!(parsed.key_id(), key_id);

        let mut to_a_terminal: Vec<u8> = Vec::new();
        let refused = to_writer(&repo, &mut to_a_terminal, true)
            .expect_err("a terminal destination must be refused");
        assert_eq!(refused.exit_code(), crate::util::exit::CONFIG);
        assert!(to_a_terminal.is_empty(), "the refusal still wrote the key");
        assert!(
            refused.to_string().contains("scrollback"),
            "the refusal must say why, or it reads as a bug: {refused}"
        );
    }
}
