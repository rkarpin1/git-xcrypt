//! The one place where "encrypt this or pass it through" is decided.
//!
//! With the catch-all attribute the filter is handed **every** file in the
//! repository, so pass-through has to be byte-identical for arbitrary input. A
//! bug here corrupts the whole project, not just the secrets — which is why
//! `passthrough(x) == x` is a property test rather than a nicety.

use crate::config::{self, Config, EolMode};
use crate::crypto;
use crate::eol;
use crate::format::{FLAG_LF_NORMALIZED, Header, looks_encrypted};
use crate::key::MasterKey;
use crate::{Error, Result};

use bstr::ByteSlice as _;

/// The result of filtering one file.
pub struct Outcome {
    /// The bytes to hand back to git.
    pub content: Vec<u8>,
    /// A message for `stderr`, if the caller should say something.
    ///
    /// Returned rather than printed so the decision stays testable and so
    /// nothing on this path can reach `stdout` by accident.
    pub warning: Option<String>,
}

/// Reports the size of the content, never the content itself.
///
/// A derived `Debug` would put file bytes into any `assert!` message that
/// mentions an `Outcome` — and a failing test prints to a CI log. "Secrets never
/// reach the repository, tests and examples included" covers that too.
impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outcome")
            .field("content", &format_args!("<{} bytes>", self.content.len()))
            .field("warning", &self.warning)
            .finish()
    }
}

impl Outcome {
    /// Content with nothing to report.
    fn plain(content: Vec<u8>) -> Self {
        Self {
            content,
            warning: None,
        }
    }
}

/// The check-in direction: working tree → object database.
///
/// Never passes plaintext through for a selected path. Content that already
/// carries our magic and our key is handed back unchanged, which determinism
/// makes exactly equal to re-encrypting it.
///
/// # Errors
///
/// [`Error::NoKey`] when a path needs encrypting and no key is present,
/// [`Error::KeyMismatch`] or [`Error::Format`] for content belonging to another
/// key or another version.
pub fn clean(
    key: Option<&MasterKey>,
    config: &Config,
    path: &[u8],
    content: &[u8],
) -> Result<Outcome> {
    if config::is_never_encrypted(path) {
        // Checked ahead of everything, including the refusal below: these are
        // the files a user needs in order to repair the very state that refusal
        // reports, so they must always be committable.
        return Ok(Outcome::plain(content.to_vec()));
    }

    if config.missing {
        // Without the declaration we cannot tell a secret from a readme, and
        // "encrypt nothing" is the one answer that loses a secret for good. One
        // `rm .git-xcrypt` must not be all it takes.
        return Err(Error::Config(format!(
            "{}: the file that says what to encrypt is missing, so nothing can be \
             added safely; restore it from the repository or run `git-xcrypt init`",
            crate::repo::CONFIG_FILE
        )));
    }

    let decision = config.decide(path);
    if !decision.encrypt {
        return Ok(Outcome::plain(content.to_vec()));
    }

    if looks_encrypted(content) {
        return already_encrypted(key, path, content);
    }

    let key = key.ok_or(Error::NoKey)?;
    let normalise = eol::should_normalise(decision.text, content);

    let (flags, plaintext) = if normalise {
        (FLAG_LF_NORMALIZED, eol::normalise_to_lf(content))
    } else {
        (0, content.to_vec())
    };

    Ok(Outcome::plain(crypto::encrypt(key, flags, &plaintext)?))
}

/// Content that is already encrypted, arriving on the check-in path.
///
/// This is the locked-repository and re-add case. Handing it back unchanged is
/// safe *only* when it is ours **and intact**: determinism means re-encrypting
/// its plaintext would produce these very bytes, but that argument only holds
/// for bytes the tag vouches for. Matching the `key_id` alone is not enough —
/// `key_id` sits in the header, where anyone can write it — so the tag is
/// verified here too. Anything else has to stop, or a corrupted blob, or one
/// belonging to a key we do not hold, would be silently adopted.
fn already_encrypted(key: Option<&MasterKey>, path: &[u8], content: &[u8]) -> Result<Outcome> {
    let header = Header::parse(content)?;
    let Some(key) = key else {
        // Without a key we cannot prove it is ours, but we also cannot damage
        // it: the bytes are already ciphertext. Passing them through keeps a
        // locked repository usable.
        return Ok(Outcome {
            content: content.to_vec(),
            warning: Some(format!(
                "{}: already encrypted and no key is loaded; storing it unchanged",
                path.as_bstr()
            )),
        });
    };

    if header.key_id != key.key_id() {
        return Err(Error::KeyMismatch {
            wanted: header.key_id,
            have: key.key_id(),
        });
    }

    // The plaintext is dropped immediately; only the verdict matters. Wrapped
    // so the copy it makes does not outlive this line on the heap.
    drop(zeroize::Zeroizing::new(crypto::decrypt(key, content)?.1));

    Ok(Outcome::plain(content.to_vec()))
}

/// The check-out direction: object database → working tree.
///
/// Decides from the file's own header, never from `.git-xcrypt`. Git does not
/// promise to write `.git-xcrypt` before the files it filters, so reading the
/// declaration here would be a race; and a file that was never normalised must
/// never receive a conversion its content did not go through.
///
/// # Errors
///
/// [`Error::NoKey`] for our content with no key loaded, plus the errors
/// [`crypto::decrypt`] reports.
pub fn smudge(
    key: Option<&MasterKey>,
    path: &[u8],
    content: &[u8],
    selected: bool,
    declared_eol: Option<EolMode>,
    autocrlf: Option<&str>,
    core_eol: Option<&str>,
) -> Result<Outcome> {
    if !looks_encrypted(content) {
        // Committed before the pattern existed. Refusing would make checking out
        // old history impossible, and plaintext in the working tree is where
        // plaintext belongs — so this passes through, loudly.
        //
        // Loudly only for a path the declaration actually selects, though. The
        // catch-all attribute sends every file in the repository through here,
        // so warning unconditionally buries the one message that means something
        // under one per ordinary file — and a fresh clone becomes a wall of
        // "whether it leaked". The case this warning exists for is narrow: a
        // *selected* path found in the clear.
        let warning = selected.then(|| {
            format!(
                "{}: stored in the clear, so it is checked out unchanged; \
                 run `git-xcrypt status` to see whether it leaked",
                path.as_bstr()
            )
        });
        return Ok(Outcome {
            content: content.to_vec(),
            warning,
        });
    }

    let key = key.ok_or(Error::NoKey)?;
    let (flags, plaintext) = crypto::decrypt(key, content)?;

    if flags & FLAG_LF_NORMALIZED == 0 {
        return Ok(Outcome::plain(plaintext));
    }

    let mode = eol::resolve_output(declared_eol, autocrlf, core_eol);
    Ok(Outcome::plain(eol::apply(&plaintext, mode)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MASTER_KEY_LEN;

    fn key() -> MasterKey {
        MasterKey::from_bytes([5u8; MASTER_KEY_LEN])
    }

    fn config() -> Config {
        Config::parse("secrets/\n*.env\n!secrets/README.md\n").expect("test config")
    }

    /// The property the whole catch-all construction rests on.
    #[test]
    fn pass_through_is_byte_identical_for_arbitrary_content() {
        let config = config();
        let samples: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"x".to_vec(),
            b"plain text\r\nwith crlf\r\n".to_vec(),
            (0u8..=255).collect(),
            (0u8..=255).cycle().take(100_000).collect(),
            vec![0u8; 4096],
            b"\0GITXCRYPT".to_vec(),
        ];

        for content in samples {
            for path in [&b"README.md"[..], b"src/main.rs", b"secrets/README.md"] {
                let outcome = clean(Some(&key()), &config, path, &content)
                    .expect("an unselected path must never fail");
                assert_eq!(
                    outcome.content,
                    content,
                    "{} was altered on its way into the object database",
                    path.as_bstr()
                );
            }
        }
    }

    #[test]
    fn a_selected_path_is_encrypted() {
        let outcome = clean(Some(&key()), &config(), b"secrets/pw", b"hunter2\n")
            .expect("encryption must succeed");
        assert!(looks_encrypted(&outcome.content));
        assert_ne!(outcome.content, b"hunter2\n");
    }

    #[test]
    fn a_missing_declaration_stops_the_check_in_rather_than_encrypting_nothing() {
        // One `rm .git-xcrypt` used to turn every selected path back into
        // plaintext, silently and with exit code 0.
        let dir = tempfile::TempDir::new().expect("temporary directory");
        let absent = Config::load(&dir.path().join(".git-xcrypt")).expect("an absent file loads");
        assert!(absent.missing);
        match clean(Some(&key()), &absent, b"secrets/pw", b"hunter2\n") {
            Err(Error::Config(_)) => {}
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_selected_path_without_a_key_refuses_rather_than_passing_plaintext() {
        match clean(None, &config(), b"secrets/pw", b"hunter2\n") {
            Err(Error::NoKey) => {}
            Err(other) => panic!("expected NoKey, got {other:?}"),
            Ok(_) => panic!("plaintext must never pass through the clean path"),
        }
    }

    #[test]
    fn re_encrypting_our_own_ciphertext_returns_it_unchanged() {
        let first = clean(Some(&key()), &config(), b"a.env", b"x=1\n").expect("first pass");
        let second = clean(Some(&key()), &config(), b"a.env", &first.content).expect("second pass");
        assert_eq!(first.content, second.content);
    }

    #[test]
    fn ciphertext_from_another_key_is_refused_on_the_way_in() {
        let other = MasterKey::from_bytes([6u8; MASTER_KEY_LEN]);
        let theirs = crypto::encrypt(&other, 0, b"secret").expect("encryption");

        match clean(Some(&key()), &config(), b"a.env", &theirs) {
            Err(Error::KeyMismatch { .. }) => {}
            other => panic!("expected a key mismatch, got {other:?}"),
        }
    }

    #[test]
    fn tampered_ciphertext_is_refused_on_the_way_in() {
        // The `key_id` still says the blob is ours — only the tag can tell that
        // its body was altered. Passing it through would store bytes nobody can
        // ever decrypt again.
        let mut stored = clean(Some(&key()), &config(), b"a.env", b"secret")
            .expect("clean")
            .content;
        let last = stored.len() - 1;
        stored[last] ^= 0x01;

        match clean(Some(&key()), &config(), b"a.env", &stored) {
            Err(Error::Crypto(_)) => {}
            other => panic!("expected an authentication failure, got {other:?}"),
        }
    }

    #[test]
    fn the_round_trip_reproduces_the_working_tree_byte_for_byte() {
        for content in [
            b"api_key = secret\n".to_vec(),
            b"crlf\r\nfile\r\n".to_vec(),
            (0u8..=255).collect(),
            Vec::new(),
        ] {
            let stored = clean(Some(&key()), &config(), b"a.env", &content).expect("clean");
            let back = smudge(
                Some(&key()),
                b"a.env",
                &stored.content,
                true,
                None,
                Some("input"),
                None,
            )
            .expect("smudge");
            assert_eq!(back.content, eol::normalise_to_lf(&content));
        }
    }

    #[test]
    fn a_binary_file_is_never_line_ending_converted() {
        let content: Vec<u8> = vec![0x00, 0x0d, 0x0a, 0xff, 0x0d, 0x0a];
        let stored = clean(Some(&key()), &config(), b"a.env", &content).expect("clean");
        let back = smudge(
            Some(&key()),
            b"a.env",
            &stored.content,
            true,
            None,
            Some("true"),
            None,
        )
        .expect("smudge");
        assert_eq!(
            back.content, content,
            "autocrlf=true must not touch a file recorded as binary"
        );
    }

    #[test]
    fn text_is_written_out_with_the_requested_line_ending() {
        let stored = clean(Some(&key()), &config(), b"a.env", b"one\ntwo\n").expect("clean");
        let back = smudge(
            Some(&key()),
            b"a.env",
            &stored.content,
            true,
            Some(EolMode::Crlf),
            None,
            None,
        )
        .expect("smudge");
        assert_eq!(back.content, b"one\r\ntwo\r\n");
    }

    #[test]
    fn an_unselected_path_in_the_clear_is_checked_out_silently() {
        // The catch-all attribute sends every file in the repository through
        // smudge. Warning for each one buries the single message that means
        // something: a *selected* path found unencrypted.
        let outcome = smudge(
            Some(&key()),
            b"README.md",
            b"public\n",
            false,
            None,
            None,
            None,
        )
        .expect("passing through must succeed");
        assert_eq!(outcome.content, b"public\n");
        assert!(
            outcome.warning.is_none(),
            "an ordinary file must not be reported as a possible leak"
        );
    }

    #[test]
    fn content_stored_in_the_clear_is_checked_out_with_a_warning() {
        let outcome = smudge(
            Some(&key()),
            b"a.env",
            b"was here first\n",
            true,
            None,
            None,
            None,
        )
        .expect("passing through must succeed");
        assert_eq!(outcome.content, b"was here first\n");
        assert!(outcome.warning.is_some(), "silence would hide a leak");
    }

    #[test]
    fn our_ciphertext_without_a_key_cannot_be_checked_out() {
        let stored = clean(Some(&key()), &config(), b"a.env", b"secret").expect("clean");
        match smudge(None, b"a.env", &stored.content, true, None, None, None) {
            Err(Error::NoKey) => {}
            other => panic!("expected NoKey, got {other:?}"),
        }
    }
}
