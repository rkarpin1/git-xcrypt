//! `git-xcrypt unlock` — make a cloned repository readable again.
//!
//! This is the command PRD US-01 is about: the code is on the new machine, the
//! secrets are not, and one key file has to turn ciphertext in the working tree
//! back into the bytes that were committed.
//!
//! Three properties shape the implementation.
//!
//! **The registration comes before the decryption.** `.git/config` is not
//! versioned, so a clone has `* filter=git-xcrypt` in `.gitattributes` and
//! nothing behind it. Decrypting first would leave a window in which the working
//! tree holds plaintext and git has no filter — where `git status` reports every
//! secret as modified and the next `git add` stores it in the clear.
//!
//! **A wrong key changes nothing at all.** Every encrypted file is inspected —
//! 38 bytes each, no decryption — before a single byte is written, and before
//! the key is even installed. Discovering the mismatch on the fourth file out of
//! ten would leave a working tree that is half readable and a repository holding
//! a key that does not belong to it.
//!
//! **Interrupting it is survivable.** The files are converted in place, one at a
//! time, so a run cut short leaves some plain and some not. That is recoverable
//! only because each file says what it is in its own header: a second `unlock`
//! skips what is already plain and finishes the rest. Working from the object
//! database instead would have been no safer and would have missed every file
//! that is not committed yet.
//!
//! Which files get decrypted is decided by the **header**, not by `.git-xcrypt`
//! — the same rule the smudge path follows, and for the same reason. It is also
//! what makes the result byte-identical to a checkout, which is what `git
//! status` being clean afterwards actually proves.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config::Config;
use crate::format::{self, Header, KEY_ID_LEN, OVERHEAD};
use crate::repo::Repo;
use crate::{Error, Result, decide, gitconfig, keyfile};

/// What `unlock` did.
#[derive(Debug)]
pub struct Report {
    /// Fingerprint of the key the repository now holds.
    pub key_id: [u8; KEY_ID_LEN],
    /// A key file was written. False when the key was already in place.
    pub key_imported: bool,
    /// The filter registration was written or repaired.
    pub config_written: bool,
    /// Paths, relative to the working tree, that were converted.
    pub decrypted: Vec<PathBuf>,
    /// Anything worth saying once, carried out so the binary owns the messages.
    pub warnings: Vec<String>,
}

/// Unlocks `repo`, optionally importing the key at `key_source` first.
///
/// # Errors
///
/// [`Error::NoKey`] when no key is given and none is present,
/// [`Error::Config`] when the repository holds a different key or `.git-xcrypt`
/// cannot be understood, [`Error::Format`] when a file in the working tree
/// belongs to another key, [`Error::Io`] on a read or write failure.
pub fn run(repo: &Repo, key_source: Option<&Path>) -> Result<Report> {
    let key = match key_source {
        Some(path) => {
            let key = keyfile::read_portable(path)?;
            // Asked before anything is written: a refusal that has already
            // installed a key has not refused.
            super::import_key::refuse_on_conflict(repo, &key)?;
            key
        }
        None => repo.load_key()?,
    };
    let key_id = key.key_id();

    // Everything carrying our magic, and the key each one asks for. Gathered
    // before the first write, so a mismatch costs nothing.
    let encrypted = collect_encrypted(repo.work_tree())?;
    refuse_foreign_keys(repo, &encrypted, &key_id)?;

    let key_imported = super::import_key::install(repo, &key)?;
    // Before the decryption, never after — see the module comment.
    let config_written = super::init::register_driver(repo)?;

    let config = Config::load(&repo.xcrypt_config_path())?;
    let git_config = gitconfig::open_full(repo.common_dir())?;
    let autocrlf = gitconfig::get(&git_config, "core.autocrlf");
    let core_eol = gitconfig::get(&git_config, "core.eol");

    let mut report = Report {
        key_id,
        key_imported,
        config_written,
        decrypted: Vec::new(),
        warnings: config.pointless_eol.clone(),
    };
    // The same paths, spelled the way the index stores them.
    let mut rewritten: Vec<Vec<u8>> = Vec::new();

    for file in &encrypted {
        let relative = repo
            .relative(&file.path)
            .map_or_else(|| file.path.clone(), Path::to_path_buf);
        let name = repo_relative_bytes(&relative);
        let content = fs::read(&file.path)?;
        let decision = config.decide(&name);

        // The very function the smudge path calls, on purpose: anything else
        // here would be a second implementation of line-ending handling, and the
        // two would drift into a working tree git reports as modified.
        let outcome = decide::smudge(
            Some(&key),
            &name,
            &content,
            decision.encrypt,
            decision.eol,
            autocrlf.as_deref(),
            core_eol.as_deref(),
        )
        .map_err(|err| Error::Format(format!("{}: {err}", relative.display())))?;

        if let Some(warning) = outcome.warning {
            report.warnings.push(warning);
        }

        // Zeroizing: this is the secret, now in the clear on the heap.
        let plaintext = Zeroizing::new(outcome.content);
        if *plaintext == content {
            continue;
        }
        // Atomic, and inheriting the file's own mode, so an interruption cannot
        // leave a half-written secret and an executable stays executable.
        crate::atomic::write(&file.path, &plaintext)?;
        rewritten.push(name);
        report.decrypted.push(relative);
    }

    // Last, and not optional: without it git compares the new size against the
    // one it cached for the ciphertext, concludes the file changed and never
    // runs the filter to find out otherwise. `git status` would then report
    // every unlocked secret as modified, for good. See `crate::gitindex`.
    match crate::gitindex::forget_stat(
        &repo.git_dir().join("index"),
        crate::gitindex::object_hash(
            gitconfig::get(&git_config, "extensions.objectformat").as_deref(),
        ),
        &rewritten,
    )? {
        crate::gitindex::Outcome::Cleared(_) => {}
        crate::gitindex::Outcome::Skipped(why) => report.warnings.push(why),
    }

    Ok(report)
}

/// A working-tree file that carries our magic, and the header it carries.
#[derive(Debug)]
struct Encrypted {
    path: PathBuf,
    header: Header,
}

/// Every encrypted file in the working tree, in a stable order.
///
/// Only the first 38 bytes of each file are read, so the cost is one open per
/// file rather than one full read — the same reasoning that lets `status` scan a
/// whole history cheaply.
///
/// Symbolic links are left alone: following one would write outside the
/// repository, and replacing it would destroy the link. `.git` is skipped at
/// every level, which also skips submodules — they have their own configuration
/// and their own key, and are documented as needing their own `unlock`.
fn collect_encrypted(root: &Path) -> Result<Vec<Encrypted>> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_name() == ".git" {
                continue;
            }

            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            if let Some(header) = peek_header(&path)? {
                found.push(Encrypted { path, header });
            }
        }
    }

    found.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(found)
}

/// Reads the header of `path`, or `None` when the file is not one of ours.
///
/// A file that starts with our magic but is too short to hold a header is an
/// error rather than a shrug: it is a truncated encrypted file, and carrying on
/// would mean deciding it is plaintext.
fn peek_header(path: &Path) -> Result<Option<Header>> {
    let mut file = fs::File::open(path)?;
    let mut prefix = [0u8; OVERHEAD];
    let read = fill(&mut file, &mut prefix)?;
    let prefix = &prefix[..read];

    if !format::looks_encrypted(prefix) {
        return Ok(None);
    }

    Header::parse(prefix)
        .map(Some)
        .map_err(|err| Error::Format(format!("{}: {err}", path.display())))
}

/// Reads until `buffer` is full or the file ends, returning how much arrived.
fn fill(file: &mut fs::File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    Ok(filled)
}

/// Refuses when any file belongs to a key other than the one offered.
///
/// Deliberately an [`Error::Format`] rather than [`Error::KeyMismatch`]: both
/// report exit code 4, and this one can name the file, which is what turns
/// "authentication failed" into an instruction.
fn refuse_foreign_keys(
    repo: &Repo,
    encrypted: &[Encrypted],
    key_id: &[u8; KEY_ID_LEN],
) -> Result<()> {
    for file in encrypted {
        if file.header.key_id == *key_id {
            continue;
        }

        let relative = repo
            .relative(&file.path)
            .map_or_else(|| file.path.clone(), Path::to_path_buf);
        return Err(Error::Format(format!(
            "{} was encrypted with key {}, but the key offered here is {}.\n\
             Nothing has been changed. Unlock this repository with the key whose id is {}.",
            relative.display(),
            crate::format_key_id(&file.header.key_id),
            crate::format_key_id(key_id),
            crate::format_key_id(&file.header.key_id)
        )));
    }
    Ok(())
}

/// A repository-relative path as the pattern matcher expects it.
///
/// Bytes rather than text, and forward slashes: on Unix a path is an arbitrary
/// byte string, and decoding it lossily would match a file under a name it does
/// not have.
fn repo_relative_bytes(relative: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        relative.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        relative.to_string_lossy().replace('\\', "/").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::key::{MASTER_KEY_LEN, MasterKey};
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

    /// Writes `content` encrypted under `key` at `relative`.
    fn write_encrypted(repo: &Repo, relative: &str, key: &MasterKey, content: &[u8]) {
        let path = repo.work_tree().join(relative);
        fs::create_dir_all(path.parent().expect("a parent")).expect("directories");
        fs::write(&path, crypto::encrypt(key, 0, content).expect("encryption")).expect("writing");
    }

    #[test]
    fn an_encrypted_working_tree_comes_back_in_the_clear() {
        let (_dir, repo) = prepared();
        let key = repo.load_key().expect("key");
        write_encrypted(&repo, "secrets/db.env", &key, b"hunter2\n");
        fs::write(repo.work_tree().join("README.md"), b"public\n").expect("writing");

        let report = run(&repo, None).expect("unlock must succeed");

        assert_eq!(report.decrypted.len(), 1);
        assert_eq!(
            fs::read(repo.work_tree().join("secrets/db.env")).expect("reading"),
            b"hunter2\n"
        );
        assert_eq!(
            fs::read(repo.work_tree().join("README.md")).expect("reading"),
            b"public\n",
            "an ordinary file must not be touched"
        );
    }

    #[test]
    fn a_second_run_finishes_what_an_interrupted_one_left() {
        let (_dir, repo) = prepared();
        let key = repo.load_key().expect("key");
        write_encrypted(&repo, "secrets/a.env", &key, b"one\n");
        write_encrypted(&repo, "secrets/b.env", &key, b"two\n");

        run(&repo, None).expect("first unlock");
        let report = run(&repo, None).expect("a repeated unlock must be harmless");

        assert!(
            report.decrypted.is_empty(),
            "an already plain file was rewritten: {:?}",
            report.decrypted
        );
        assert_eq!(
            fs::read(repo.work_tree().join("secrets/a.env")).expect("reading"),
            b"one\n"
        );
    }

    #[test]
    fn a_file_belonging_to_another_key_stops_everything_before_the_first_write() {
        let (_dir, repo) = prepared();
        let key = repo.load_key().expect("key");
        let stranger = MasterKey::from_bytes([99u8; MASTER_KEY_LEN]);
        write_encrypted(&repo, "secrets/mine.env", &key, b"mine\n");
        write_encrypted(&repo, "secrets/theirs.env", &stranger, b"theirs\n");
        let mine_before = fs::read(repo.work_tree().join("secrets/mine.env")).expect("reading");

        let error = run(&repo, None).expect_err("a foreign key must stop the run");

        assert_eq!(error.exit_code(), crate::exit::FORMAT);
        assert!(
            error.to_string().contains("theirs.env"),
            "the message must name the file: {error}"
        );
        assert_eq!(
            fs::read(repo.work_tree().join("secrets/mine.env")).expect("reading"),
            mine_before,
            "a file was decrypted before the mismatch was found"
        );
    }

    #[test]
    fn a_repository_with_no_key_at_all_says_so() {
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        match run(&repo, None) {
            Err(Error::NoKey) => {}
            other => panic!("expected NoKey, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_encrypted_file_is_refused_rather_than_read_as_plaintext() {
        let (_dir, repo) = prepared();
        let path = repo.work_tree().join("secrets").join("cut.env");
        fs::create_dir_all(path.parent().expect("a parent")).expect("directories");
        fs::write(&path, format::MAGIC).expect("writing");

        let error = run(&repo, None).expect_err("a truncated file must be refused");
        assert_eq!(error.exit_code(), crate::exit::FORMAT);
    }

    #[test]
    fn the_git_directory_is_never_walked() {
        // The repository's own key file starts with its own magic, not ours, but
        // walking `.git` at all would be a bug waiting for a file that does.
        let (_dir, repo) = prepared();
        let key = repo.load_key().expect("key");
        let planted = repo.git_dir().join("planted");
        fs::write(
            &planted,
            crypto::encrypt(&key, 0, b"not yours\n").expect("encryption"),
        )
        .expect("writing");

        let report = run(&repo, None).expect("unlock must succeed");

        assert!(report.decrypted.is_empty());
        assert!(
            format::looks_encrypted(&fs::read(&planted).expect("reading")),
            "unlock reached into the git directory"
        );
    }
}
