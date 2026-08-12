//! The one place where "encrypt this or pass it through" is decided.
//!
//! With the catch-all attribute the filter is handed **every** file in the
//! repository, so pass-through has to be byte-identical for arbitrary input. A
//! bug here corrupts the whole project, not just the secrets — which is why
//! `passthrough(x) == x` is a property test rather than a nicety.

use crate::crypto::cipher;
use crate::crypto::format::{FLAG_LF_NORMALIZED, Header, looks_encrypted};
use crate::crypto::key::MasterKey;
use crate::rules::declaration::{self, Config, EolMode};
use crate::rules::eol;
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
/// A pure function of `(key, config, path, content)`, and kept that way. S-06
/// wanted a warning here — "this path is already in `HEAD` in the clear" — and
/// it lives in [`crate::commands::filter`] instead, because answering it needs the object
/// database and a repository handle, which neither this signature nor `lock`,
/// the other caller, has any business carrying. `lock` depends on this function
/// producing exactly the bytes git stores; the fewer things it can reach, the
/// longer that stays true.
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
    if declaration::is_never_encrypted(path) {
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
            crate::git::repo::CONFIG_FILE
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

    Ok(Outcome::plain(cipher::encrypt(key, flags, &plaintext)?))
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
    drop(zeroize::Zeroizing::new(cipher::decrypt(key, content)?.1));

    Ok(Outcome::plain(content.to_vec()))
}

/// The check-out direction: object database → working tree.
///
/// Decides from the file's own header, never from `.git-xcrypt`. Git does not
/// promise to write `.git-xcrypt` before the files it filters, so reading the
/// declaration here would be a race; and a file that was never normalised must
/// never receive a conversion its content did not go through.
///
/// Content that is ours and a repository that holds no key are **not** an
/// error: the stored bytes are handed back with a warning, which is what keeps
/// a repository closed by `lock` able to check its own files out. See the arm
/// itself for what that costs and why it risks nothing.
///
/// # Errors
///
/// The errors [`cipher::decrypt`] reports — a header this build cannot read,
/// another key's file, or a failed authentication tag.
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

    let Some(key) = key else {
        // A locked repository, and the mirror of [`already_encrypted`] on the
        // check-in side — same state, same answer, and for the same reason:
        // handing the stored bytes back is what keeps a locked repository
        // usable. `lock` deliberately leaves the filter registered and
        // `required = true` set, because that is what turns a `git add` of a
        // new secret into a refusal instead of a stored plaintext; the cost of
        // erroring *here* was that the same flag aborted every checkout.
        //
        // Measured on git 2.55 before this returned: in a repository closed by
        // `lock`, `git checkout <branch>` and `git checkout -- <path>` alike
        // exited **128**, and since git removes the old file before it calls
        // the filter, the declared file was gone from the working tree — with
        // `git reset --hard` failing the same way, so nothing could put it
        // back without the key that had just been deleted.
        //
        // Nothing is risked by passing them through. These bytes are
        // ciphertext, so this writes no plaintext anywhere; they are the bytes
        // `lock` itself left in the working tree, so `git status` stays clean;
        // and the next `clean` hands the same bytes back unchanged. This is
        // also exactly what a clone with no filter registered receives.
        //
        // **Only a key file that is not there gets here.** `Context::load`
        // turns [`Error::NoKey`] — which `keyfile::read` reports for a missing
        // file and nothing else — into `None`, while an unreadable or corrupt
        // one fails the whole filter process. So this cannot become a silent
        // pass-through for a repository that does have a key.
        return Ok(Outcome {
            content: content.to_vec(),
            warning: Some(format!(
                "{}: encrypted, and this repository holds no key, so it is \
                 written out as it is stored; `git-xcrypt unlock <key-file>` \
                 opens it",
                path.as_bstr()
            )),
        });
    };
    let (flags, plaintext) = cipher::decrypt(key, content)?;

    if flags & FLAG_LF_NORMALIZED == 0 {
        return Ok(Outcome::plain(plaintext));
    }

    let mode = eol::resolve_output(declared_eol, autocrlf, core_eol);
    Ok(Outcome::plain(eol::apply(&plaintext, mode)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key::MASTER_KEY_LEN;

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
            // The full 11-byte magic, so the sample really wears it: an earlier
            // spelling was ten bytes — one short — and covered nothing, since
            // `looks_encrypted` said no. What this pins is that an *unselected*
            // path passes through before the magic is even consulted.
            b"\0GITXCRYPT\0not actually one of ours".to_vec(),
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

    proptest::proptest! {
        // `AGENTS.md` calls `passthrough(x) == x` a property test rather than a
        // nicety, and `zalozenia.md` §Konstrukcja catch-all asks for it over
        // *arbitrary* bytes: with the catch-all attribute every file in the
        // repository comes through here, so the blast radius of a bug is the
        // whole project. The listed shapes above stay; this covers what a list
        // cannot.
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn an_unselected_path_is_handed_back_byte_for_byte(
            content in proptest::collection::vec(proptest::num::u8::ANY, 0..16384),
            path in proptest::prelude::prop_oneof![
                proptest::prelude::Just(&b"README.md"[..]),
                proptest::prelude::Just(&b"src/main.rs"[..]),
                proptest::prelude::Just(&b"secrets/README.md"[..]),
                proptest::prelude::Just(&b".gitattributes"[..]),
                proptest::prelude::Just(&b".git-xcrypt"[..]),
            ],
        ) {
            let outcome = clean(Some(&key()), &config(), path, &content)
                .expect("an unselected path must never fail");
            proptest::prop_assert_eq!(&outcome.content, &content);
            proptest::prop_assert!(outcome.warning.is_none());
        }

        /// The other half: content git already stores in the clear must reach
        /// the working tree untouched, whatever it is.
        #[test]
        fn content_without_our_magic_reaches_the_working_tree_unchanged(
            content in proptest::collection::vec(proptest::num::u8::ANY, 0..16384),
        ) {
            proptest::prop_assume!(!looks_encrypted(&content));
            let outcome = smudge(Some(&key()), b"README.md", &content, false, None, None, None)
                .expect("content that is not ours must pass through");
            proptest::prop_assert_eq!(&outcome.content, &content);
        }

        /// The full working-tree round trip, on arbitrary content, for a path
        /// the declaration does select. Anything the clean path normalises has
        /// to come back as the bytes git would hand out again — otherwise
        /// `git status` reports a file nobody edited.
        #[test]
        fn a_selected_path_survives_check_in_and_check_out(
            content in proptest::collection::vec(proptest::num::u8::ANY, 0..16384),
        ) {
            proptest::prop_assume!(!looks_encrypted(&content));
            let stored = clean(Some(&key()), &config(), b"secrets/pw", &content)
                .expect("encryption must succeed");
            proptest::prop_assert!(looks_encrypted(&stored.content));

            let back = smudge(
                Some(&key()),
                b"secrets/pw",
                &stored.content,
                true,
                Some(EolMode::Lf),
                None,
                None,
            )
            .expect("decryption must succeed");

            // Equal to the input except where the clean path normalised CRLF,
            // which is exactly what `normalise_to_lf` did on the way in.
            let expected = if eol::should_normalise(config().decide(b"secrets/pw").text, &content) {
                eol::normalise_to_lf(&content)
            } else {
                content.clone()
            };
            proptest::prop_assert_eq!(&back.content, &expected);

            // And the loop closes: feeding the working tree back in reproduces
            // the same blob, which is what keeps `git status` quiet.
            let again = clean(Some(&key()), &config(), b"secrets/pw", &back.content)
                .expect("re-encryption must succeed");
            proptest::prop_assert_eq!(&again.content, &stored.content);
        }
    }
}
