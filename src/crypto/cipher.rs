//! Encryption and decryption — the one pair of functions every path shares.
//!
//! AES-256-SIV (RFC 5297) is a deterministic AEAD: the synthetic IV is computed
//! from the content, so identical plaintext under identical key yields byte
//! identical ciphertext. That is not a workaround, it is the construction, and
//! it is what keeps `git status` quiet on an unchanged file.

use aes_siv::KeyInit;
use aes_siv::siv::Aes256Siv;

use crate::crypto::format::{Header, KEY_ID_LEN, SUITE_AES_256_SIV};
use crate::crypto::key::{MasterKey, SuiteKey};
use crate::{Error, Result};

/// Borrows a suite key as the cipher's own key type.
///
/// Both lengths are compile-time constants and both are 64 — `SIV_KEY_LEN` here
/// and `Aes256Siv`'s key size in `aes-siv` — so this cannot fail today. It is
/// written as an error rather than an `expect` because the two constants live
/// in different crates: if a future suite ever moves one without the other, the
/// right answer is a refused file, not a panic in the middle of a git
/// operation, where `required = true` turns an abort into a broken repository.
fn cipher_key(key: &SuiteKey) -> Result<&aes_siv::Key<Aes256Siv>> {
    key.expose_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("the suite key does not fit the cipher".into()))
}

/// Encrypts `plaintext`, recording `flags` in the authenticated header.
///
/// The returned blob is `header || synthetic IV || ciphertext`. The header goes
/// in as associated data, so flipping the suite or flag byte invalidates the
/// tag instead of quietly changing how the file is read.
///
/// # Errors
///
/// [`Error::Crypto`] if the cipher refuses the input, which for a single
/// associated-data item cannot happen in practice.
pub fn encrypt(key: &MasterKey, flags: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
    let header = Header::new(flags, key.key_id()).to_bytes();
    let suite_key = key.suite_key(SUITE_AES_256_SIV)?;

    let mut cipher = Aes256Siv::new(cipher_key(&suite_key)?);
    let sealed = cipher
        .encrypt([header.as_slice()], plaintext)
        .map_err(|_| Error::Crypto("encryption failed".into()))?;

    let mut blob = Vec::with_capacity(header.len() + sealed.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Decrypts a blob produced by [`encrypt`], returning its flags and plaintext.
///
/// # Errors
///
/// [`Error::Format`] for anything the header rejects, [`Error::KeyMismatch`]
/// when the file belongs to a different key, and [`Error::Crypto`] when the
/// authentication tag does not verify. A failed tag is an error, never a
/// warning: passing the bytes through would hand the caller content nobody
/// vouched for.
pub fn decrypt(key: &MasterKey, blob: &[u8]) -> Result<(u8, Vec<u8>)> {
    let header = Header::parse(blob)?;
    let our_key_id = key.key_id();
    if header.key_id != our_key_id {
        return Err(Error::KeyMismatch {
            wanted: header.key_id,
            have: our_key_id,
        });
    }

    let suite_key = key.suite_key(header.suite)?;
    // The associated data must be the bytes actually on disk, not a header we
    // rebuild from expected values — rebuilding would hide a tampered byte.
    let (header_bytes, body) = blob.split_at(crate::crypto::format::HEADER_LEN);

    let mut cipher = Aes256Siv::new(cipher_key(&suite_key)?);
    let plaintext = cipher
        .decrypt([header_bytes], body)
        .map_err(|_| Error::Crypto("authentication failed; the file has been altered".into()))?;

    Ok((header.flags, plaintext))
}

/// The key fingerprint a blob claims, without needing the key itself.
///
/// Used by `status` and by `unlock` to check the key *before* touching a single
/// file, so a wrong key fails loudly instead of half-way through.
///
/// # Errors
///
/// [`Error::Format`] when the blob is not one of ours.
pub fn blob_key_id(blob: &[u8]) -> Result<[u8; KEY_ID_LEN]> {
    Ok(Header::parse(blob)?.key_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::format::{FLAG_LF_NORMALIZED, OVERHEAD};
    use crate::crypto::key::MASTER_KEY_LEN;

    fn key() -> MasterKey {
        MasterKey::from_bytes([42u8; MASTER_KEY_LEN])
    }

    fn samples() -> Vec<Vec<u8>> {
        vec![
            Vec::new(),
            b"x".to_vec(),
            b"api_key = do-not-commit-me\n".to_vec(),
            (0u8..=255).cycle().take(4096).collect(),
        ]
    }

    #[test]
    fn round_trips_every_shape_of_input() {
        for plaintext in samples() {
            let blob = encrypt(&key(), 0, &plaintext).expect("encryption must succeed");
            let (flags, recovered) = decrypt(&key(), &blob).expect("decryption must succeed");
            assert_eq!(flags, 0);
            assert_eq!(recovered, plaintext);
        }
    }

    #[test]
    fn encryption_is_deterministic() {
        for plaintext in samples() {
            let first = encrypt(&key(), 0, &plaintext).expect("encryption must succeed");
            let second = encrypt(&key(), 0, &plaintext).expect("encryption must succeed");
            assert_eq!(first, second, "the same plaintext must give the same bytes");
        }
    }

    proptest::proptest! {
        // `zalozenia.md` §Jakość i testy asks for these two as *properties*, not
        // as a list: `decrypt(encrypt(x)) == x` and `encrypt(x) == encrypt(x)`.
        // The hand-written samples above stay because they name the shapes that
        // once broke — empty, one byte, every byte value — and a generator that
        // happens not to draw them would quietly stop covering them.
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn decrypting_what_we_encrypted_gives_the_plaintext_back(
            plaintext in proptest::collection::vec(proptest::num::u8::ANY, 0..8192),
            flags in proptest::prelude::prop_oneof![
                proptest::prelude::Just(0u8),
                proptest::prelude::Just(FLAG_LF_NORMALIZED),
            ],
        ) {
            let blob = encrypt(&key(), flags, &plaintext).expect("encryption must succeed");
            let (recovered_flags, recovered) =
                decrypt(&key(), &blob).expect("decryption must succeed");
            proptest::prop_assert_eq!(recovered_flags, flags);
            proptest::prop_assert_eq!(&recovered, &plaintext);
            // The frozen overhead, on arbitrary input rather than on four shapes.
            proptest::prop_assert_eq!(blob.len(), plaintext.len() + OVERHEAD);
        }

        #[test]
        fn encrypting_the_same_bytes_twice_gives_the_same_blob(
            plaintext in proptest::collection::vec(proptest::num::u8::ANY, 0..8192),
        ) {
            let first = encrypt(&key(), 0, &plaintext).expect("encryption must succeed");
            let second = encrypt(&key(), 0, &plaintext).expect("encryption must succeed");
            proptest::prop_assert_eq!(first, second);
        }
    }

    /// The module doc's claim, exercised on the one byte that can test it.
    ///
    /// "Flipping the suite or flag byte invalidates the tag" — but a flipped
    /// suite or version is refused by `Header::parse` before any cipher runs,
    /// so the only header byte that reaches the tag with a *valid* parse is
    /// `flags`, flipped between its two legal values. That flip is exactly the
    /// one that decides whether a checked-out file gets a CRLF conversion, so
    /// it must fail authentication rather than quietly change the answer.
    #[test]
    fn a_flipped_flags_byte_fails_the_tag_instead_of_changing_the_conversion() {
        let blob = encrypt(&key(), 0, b"one\ntwo\n").expect("encryption must succeed");
        let mut flipped = blob.clone();
        flipped[13] ^= FLAG_LF_NORMALIZED;
        assert!(
            crate::crypto::format::Header::parse(&flipped).is_ok(),
            "the flipped byte must still parse, or this test asks nothing of \
             the tag"
        );
        assert!(
            matches!(decrypt(&key(), &flipped), Err(crate::Error::Crypto(_))),
            "a header byte was altered and the tag did not notice"
        );
    }

    /// RFC 5297 Appendix A.1 — the specification's own vector.
    ///
    /// It pins the crate, not our wrapper: `aes-siv` has never been audited, so
    /// the cheapest available substitute is proving it computes what the RFC
    /// says. The vector uses AES-128-SIV (a 256-bit key in two halves) while we
    /// ship AES-256-SIV, but the S2V and CTR construction under test is the same.
    #[test]
    fn the_crate_matches_rfc_5297_appendix_a1() {
        use aes_siv::siv::Aes128Siv;

        let key = hex_bytes("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let associated_data = hex_bytes("101112131415161718191a1b1c1d1e1f2021222324252627");
        let plaintext = hex_bytes("112233445566778899aabbccddee");
        let expected = hex_bytes("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");

        let mut cipher = Aes128Siv::new(key.as_slice().try_into().expect("a 32-byte RFC key"));
        let sealed = cipher
            .encrypt([associated_data.as_slice()], plaintext.as_slice())
            .expect("the RFC vector must encrypt");
        assert_eq!(sealed, expected, "aes-siv diverged from RFC 5297");

        let mut cipher = Aes128Siv::new(key.as_slice().try_into().expect("a 32-byte RFC key"));
        let recovered = cipher
            .decrypt([associated_data.as_slice()], sealed.as_slice())
            .expect("the RFC vector must decrypt");
        assert_eq!(recovered, plaintext);
    }

    /// Parses a hex string in a test. Panics on malformed input by design.
    fn hex_bytes(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2), "hex needs an even length");
        (0..text.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&text[index..index + 2], 16).expect("test vectors must be hex")
            })
            .collect()
    }
}
