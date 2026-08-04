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
//! **The output is git-form, never working-tree form.** Whatever the working
//! tree holds, the bytes that were fed to the cipher were normalised to LF or
//! not, and that is what the other side of the diff will be. Asking git's
//! `core.autocrlf` here — the one thing the smudge path *does* do — would emit
//! CRLF against an LF counterpart and report every line of the file as changed.
//!
//! **The key is fetched only when the content needs it.** A clone with no key
//! can still run `git log -p` over history from before the repository was
//! configured, and `git diff` on an ordinary file never touches the key at all.

use std::fs;
use std::path::Path;

use crate::Result;
use crate::config::EolMode;
use crate::decide::{self, Outcome};
use crate::format::looks_encrypted;
use crate::key::MasterKey;
use crate::repo::Repo;

/// Reads `path` and returns the text git should diff.
///
/// # Errors
///
/// [`Error::Io`](crate::Error::Io) when the file cannot be read,
/// [`Error::NoKey`](crate::Error::NoKey) when it is ours and no key is loaded,
/// and the errors [`crate::crypto::decrypt`] reports for content that is ours
/// but belongs to another key, is truncated or fails authentication.
pub fn run(path: &Path) -> Result<Outcome> {
    let content = fs::read(path)?;

    // Looked at before the repository is even discovered, so the branch that
    // needs nothing carries no cost and cannot fail for a reason of its own.
    let key = if looks_encrypted(&content) {
        Some(Repo::discover_from_cwd()?.load_key()?)
    } else {
        None
    };

    convert(key.as_ref(), &name_of(path), &content)
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
    if !looks_encrypted(content) {
        return Ok(Outcome {
            content: content.to_vec(),
            warning: None,
        });
    }

    // `EolMode::Lf` rather than git's configuration: see the module comment.
    // Content recorded as binary is unaffected either way — `smudge` writes it
    // out verbatim, because its header says it never went through a conversion.
    // `selected` is false because it only governs a warning on the branch above,
    // which the header has already ruled out.
    decide::smudge(key, name, content, false, Some(EolMode::Lf), None, None)
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
    use crate::crypto;
    use crate::eol;
    use crate::key::MASTER_KEY_LEN;
    use crate::{Error, format};

    fn key() -> MasterKey {
        MasterKey::from_bytes([5u8; MASTER_KEY_LEN])
    }

    #[test]
    fn our_ciphertext_comes_back_as_the_plaintext_it_was_made_from() {
        let blob = crypto::encrypt(&key(), 0, b"api_key = hunter2\n").expect("encryption");
        let outcome = convert(Some(&key()), b"a.env", &blob).expect("decryption");
        assert_eq!(outcome.content, b"api_key = hunter2\n");
    }

    #[test]
    fn content_without_our_magic_passes_through_byte_for_byte() {
        // `git log -p` reaches commits from before the pattern existed, and git
        // hands this command the working-tree file itself whenever it is already
        // identical to the blob it wants. Both arrive here without magic.
        for content in [
            &b""[..],
            b"was here first\r\n",
            b"\0not ours\0",
            &(0u8..=255).collect::<Vec<u8>>(),
        ] {
            let outcome = convert(Some(&key()), b"a.env", content).expect("pass-through");
            assert_eq!(outcome.content, content);
            assert!(outcome.warning.is_none());
        }
    }

    #[test]
    fn a_normalised_file_is_shown_with_lf_whatever_the_machine_prefers() {
        // The other side of the diff is a blob, and a blob holds LF. Emitting
        // CRLF here would report every line of an unchanged file as changed.
        let stored = crate::decide::clean(
            Some(&key()),
            &crate::config::Config::parse("*.env\n").expect("configuration"),
            b"a.env",
            b"one\r\ntwo\r\n",
        )
        .expect("clean")
        .content;

        let outcome = convert(Some(&key()), b"a.env", &stored).expect("decryption");
        assert_eq!(outcome.content, b"one\ntwo\n");
    }

    #[test]
    fn a_file_recorded_as_binary_keeps_its_bytes() {
        let content: Vec<u8> = vec![0x00, 0x0d, 0x0a, 0xff];
        assert!(!eol::should_normalise(
            crate::config::TextMode::Auto,
            &content
        ));
        let blob = crypto::encrypt(&key(), 0, &content).expect("encryption");
        let outcome = convert(Some(&key()), b"a.p12", &blob).expect("decryption");
        assert_eq!(outcome.content, content);
    }

    #[test]
    fn our_ciphertext_without_a_key_refuses_rather_than_printing_noise() {
        let blob = crypto::encrypt(&key(), 0, b"secret").expect("encryption");
        match convert(None, b"a.env", &blob) {
            Err(Error::NoKey) => {}
            other => panic!("expected NoKey, got {other:?}"),
        }
    }

    #[test]
    fn ciphertext_from_another_key_is_refused() {
        let theirs = MasterKey::from_bytes([6u8; MASTER_KEY_LEN]);
        let blob = crypto::encrypt(&theirs, 0, b"secret").expect("encryption");
        let error = convert(Some(&key()), b"a.env", &blob).expect_err("must refuse");
        assert_eq!(error.exit_code(), crate::exit::FORMAT);
    }

    #[test]
    fn tampered_ciphertext_is_refused_rather_than_shown() {
        let mut blob = crypto::encrypt(&key(), 0, b"secret").expect("encryption");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let error = convert(Some(&key()), b"a.env", &blob).expect_err("must refuse");
        assert_eq!(error.exit_code(), crate::exit::FORMAT);
    }

    #[test]
    fn a_truncated_file_of_ours_is_refused_rather_than_passed_through() {
        // It carries the magic, so calling it plaintext would print a header as
        // though it were content.
        let error =
            convert(Some(&key()), b"a.env", &format::MAGIC).expect_err("must refuse a stub");
        assert_eq!(error.exit_code(), crate::exit::FORMAT);
    }
}
