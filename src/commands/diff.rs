//! `git-xcrypt diff` — the textconv driver behind `git diff` on a secret.
//!
//! Registered by `init` as `diff.git-xcrypt.textconv`. Git runs it with the path
//! of a file and reads its `stdout` as the text to compare, which makes this the
//! one place in the product where writing to `stdout` is the contract rather
//! than a corruption. The rule it looks like an exception to is narrower than it
//! sounds: on the *filter* path git treats `stdout` as the file itself, so a
//! stray byte damages a user's file. Here `stdout` is a diff, never a file.
//!
//! Four properties shape it.
//!
//! **It decides from the header, never from `.git-xcrypt`.** The same rule the
//! smudge path follows, and it is not a stylistic choice here either: git hands
//! this command two different kinds of content under the same argument. For a
//! blob it writes a temporary file holding the stored bytes — ciphertext. For a
//! working-tree side, and for a blob whose working-tree copy is already
//! identical, git *borrows the working-tree file itself* rather than converting
//! it, so the argument is plaintext. Only the header can tell the two apart.
//!
//! **Content without our magic passes through untouched.** That is the same
//! case, plus the one the plan names: a file committed before it was ever
//! declared. Failing on it would break `git log -p` across the whole history,
//! and the content is not a secret this command could protect anyway — it is
//! already in the object database in the clear.
//!
//! **The output is git-form, never working-tree form.** The decrypting branch is
//! only reached when the smudge filter did *not* run first — a repository where
//! the diff driver is registered and the filter is not. Both sides of such a
//! diff arrive as ciphertext, so emitting the bytes that were fed to the cipher
//! keeps them comparable, and it makes the output a function of the blob alone
//! rather than of the machine's `core.autocrlf`.
//!
//! **The key is fetched only when the content needs it.** A clone with no key
//! can still run `git log -p` over history from before the repository was
//! configured, and `git diff` on an ordinary file never touches the key at all.

use std::fs;
use std::path::{Path, PathBuf};

use bstr::ByteSlice as _;

use crate::config::EolMode;
use crate::decide::{self, Outcome};
use crate::format::looks_encrypted;
use crate::key::MasterKey;
use crate::repo::Repo;
use crate::{Error, Result, keyfile};

/// Reads `path` and returns the text git should diff.
///
/// # Errors
///
/// [`Error::Config`] for a path inside the git directory, [`Error::Io`] when the
/// file cannot be read, [`Error::NoKey`] when it is ours and no key is loaded,
/// and the errors [`crate::crypto::decrypt`] reports for content that is ours
/// but belongs to another key, is truncated or fails authentication.
pub fn run(path: &Path) -> Result<Outcome> {
    // Discovered once, up front, because both branches want it: one to refuse a
    // path this command must never print, the other to find the key.
    let repo = Repo::discover_from_cwd();
    if let Ok(repo) = &repo {
        refuse_private_path(repo, path)?;
    }

    let content = fs::read(path).map_err(|err| named_io(path, &err))?;

    let key = if looks_encrypted(&content) {
        Some(repo?.load_key()?)
    } else {
        None
    };

    convert(key.as_ref(), &name_of(path), &content)
}

/// Refuses to print anything from inside the git directory.
///
/// The key file lives there and carries its own magic, one byte different from
/// the data magic, so [`looks_encrypted`] says no and the pass-through branch
/// would hand the repository's master key to `stdout` — where
/// `git-xcrypt diff .git/git-xcrypt/keys/default > k` puts it in the working
/// tree, one `git add -A` from a commit. That is the leak `export-key` guards
/// against by hand, and the rule behind it has no exception: a key reaches
/// `stdout` from `export-key` and from nowhere else.
///
/// Git never asks for a path in there, so nothing legitimate is lost.
fn refuse_private_path(repo: &Repo, path: &Path) -> Result<()> {
    let Some(target) = resolved(path) else {
        return Ok(());
    };

    for private in [repo.git_dir(), repo.common_dir()] {
        if resolved(private).is_some_and(|private| target.starts_with(private)) {
            return Err(Error::Config(format!(
                "{}: this is inside the git directory, which this command never prints. \
                 To carry the repository key to another machine, use `git-xcrypt export-key`.",
                path.display()
            )));
        }
    }
    Ok(())
}

/// An absolute path with symlinks resolved, so the check above cannot be walked
/// around by pointing a link in the working tree at the key.
///
/// Falls back to a lexical answer for a path that does not exist — the caller
/// then fails on the read instead, which is the same outcome.
fn resolved(path: &Path) -> Option<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    Some(fs::canonicalize(&absolute).unwrap_or_else(|_| crate::repo::lexically_normal(&absolute)))
}

/// Puts the path in front of a bare I/O failure.
///
/// `No such file or directory (os error 2)` names nothing, and here the path is
/// usually one git invented rather than one the user typed.
fn named_io(path: &Path, err: &std::io::Error) -> Error {
    Error::Io(std::io::Error::other(format!(
        "{}: could not read it ({err})",
        path.display()
    )))
}

/// Turns one file's bytes into the text git should diff.
///
/// Split from [`run`] so the decision is testable without a repository on disk,
/// and so the decryption itself goes through [`decide::smudge`] — the very
/// function the checkout path calls. A second implementation here is exactly
/// what the roadmap names as this slice's risk: it would drift from the format
/// the first time the format changes.
///
/// # Errors
///
/// As [`run`], minus the I/O.
pub fn convert(key: Option<&MasterKey>, name: &[u8], content: &[u8]) -> Result<Outcome> {
    // Decided on the content, so it holds wherever the file is and whatever the
    // current directory is — the location check in `run` cannot say that, and it
    // has nothing to say at all about a copy `export-key` wrote into the working
    // tree. The rule has no exception: a key leaves through `export-key`.
    if keyfile::holds_a_key(content) {
        return Err(refuse_key(name));
    }

    if !looks_encrypted(content) {
        return Ok(Outcome {
            content: content.to_vec(),
            warning: None,
        });
    }

    // `EolMode::Lf` rather than git's configuration: see the module comment. It
    // makes the output a function of the blob alone, which is what keeps the two
    // sides of a diff comparable on the one path that reaches here. Content
    // recorded as binary is unaffected either way — `smudge` writes it out
    // verbatim, because its header says it never went through a conversion.
    // `selected` is false because it only governs a warning on the branch above,
    // which the header has already ruled out.
    let outcome = decide::smudge(key, name, content, false, Some(EolMode::Lf), None, None)?;

    // Asked again of what is about to be printed, not only of what was read.
    // The check above sees ciphertext for a key file that was committed under a
    // declared pattern, and ciphertext is not a key file — the decrypted bytes
    // are. Measured on git 2.55: with a `secrets/** -filter` line below the
    // managed section (so smudge never ran and the working tree held
    // ciphertext) and the diff driver still registered, `git log -p` printed
    // the decrypted master key to stdout. The rule has no exception, so the
    // question is asked on both sides of the cipher.
    if keyfile::holds_a_key(&outcome.content) {
        // The decrypted key does not outlive the refusal on the heap.
        drop(zeroize::Zeroizing::new(outcome.content));
        return Err(refuse_key(name));
    }
    Ok(outcome)
}

/// The one refusal both sides of the cipher share.
fn refuse_key(name: &[u8]) -> Error {
    Error::Config(format!(
        "{}: this is a git-xcrypt key file, and a key is never printed. \
         To carry it to another machine, use `git-xcrypt export-key`.",
        name.as_bstr()
    ))
}

/// The path as the decision function wants it: bytes, not text.
///
/// Only ever used in a message. On Unix a path is an arbitrary byte string, and
/// this is the spelling the rest of the crate passes around.
fn name_of(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().replace('\\', "/").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MASTER_KEY_LEN;

    fn key() -> MasterKey {
        MasterKey::from_bytes([5u8; MASTER_KEY_LEN])
    }

    #[test]
    fn an_encrypted_key_file_is_refused_after_decryption_too() {
        // The check on the way in sees ciphertext for a key file that was
        // committed under a declared pattern, and ciphertext is not a key file.
        // The decrypting branch is reached exactly when the smudge filter did
        // not run first — measured on git 2.55: a `secrets/** -filter` line
        // below the managed section left the working tree holding ciphertext,
        // and `git log -p` printed the decrypted master key to stdout. The
        // refusal has to be asked of what is about to be printed, not only of
        // what was read.
        let exported = crate::keyfile::encode_portable(&key());
        let blob =
            crate::crypto::encrypt(&key(), 0, exported.as_bytes()).expect("encryption succeeds");

        let error = convert(Some(&key()), b"secrets/backup.key", &blob).expect_err("must refuse");
        assert_eq!(error.exit_code(), crate::exit::CONFIG);
        assert!(
            error.to_string().contains("export-key"),
            "the refusal must say where a key is allowed to go: {error}"
        );
    }

    #[test]
    fn a_key_file_is_refused_although_it_carries_no_data_magic() {
        // Both shapes. Neither starts with the data magic, so without this the
        // pass-through branch would print the repository's master key.
        let exported = crate::keyfile::encode_portable(&key());
        for content in [exported.as_bytes(), b"\0GITXCRYPTKEY\0\x01somekeymaterial"] {
            let error = convert(Some(&key()), b"notes.txt", content).expect_err("must refuse");
            assert_eq!(error.exit_code(), crate::exit::CONFIG);
            assert!(
                error.to_string().contains("export-key"),
                "the refusal must say where a key is allowed to go: {error}"
            );
        }
    }
}
