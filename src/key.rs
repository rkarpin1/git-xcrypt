//! The repository key and everything derived from it.
//!
//! The key file holds a 32-byte **master key**, never a cipher key. Different
//! ciphers take keys of different lengths — AES-256-SIV wants 64 bytes,
//! AES-256-GCM-SIV and XChaCha20 want 32 — and the key file is as frozen as the
//! data format once it sits in a user's backups. Deriving per suite is what
//! keeps a future suite from stranding it.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::format::{KEY_ID_LEN, SUITE_AES_256_SIV};
use crate::{Error, Result};

/// Length of the master key stored in the key file.
pub const MASTER_KEY_LEN: usize = 32;

/// Length of the key AES-256-SIV expects: an S2V half and a CTR half.
pub const SIV_KEY_LEN: usize = 64;

/// Domain separation for the key fingerprint carried by every file.
const INFO_KEY_ID: &[u8] = b"git-xcrypt key-id v1";

/// Domain separation for the AES-256-SIV working key.
const INFO_SUITE_AES_256_SIV: &[u8] = b"git-xcrypt suite 0x01 aes-256-siv";

/// The repository key.
///
/// Deliberately has no `Debug`, `Display` or `Clone`: the only ways out are
/// [`MasterKey::expose_bytes`], whose name is meant to be uncomfortable at a
/// call site, and the derivations below.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; MASTER_KEY_LEN]);

impl MasterKey {
    /// Draws a fresh key from the operating system's entropy source.
    ///
    /// # Errors
    ///
    /// [`Error::Entropy`] when the platform refuses to provide randomness.
    /// Falling back to anything weaker would be worse than failing.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; MASTER_KEY_LEN];
        let drawn = getrandom::fill(&mut bytes).map_err(|err| Error::Entropy(err.to_string()));
        let key = drawn.map(|()| Self(bytes));
        // The staging array is a second copy of the key; the one inside
        // `MasterKey` is the only one allowed to outlive this call.
        bytes.zeroize();
        key
    }

    /// Wraps key material that came from a key file.
    #[must_use]
    pub fn from_bytes(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw key material.
    ///
    /// Named to make every call site read like the disclosure it is. Only the
    /// key file writer and `export-key` have any business calling it.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }

    /// The fingerprint stored in every encrypted file's header.
    ///
    /// Identifies the *key*, not the suite, so it survives a future change of
    /// cipher and keeps `unlock` and `export-key` working across
    /// one.
    ///
    /// # Panics
    ///
    /// Never in practice: [`KEY_ID_LEN`] is eight bytes against HKDF's ceiling
    /// of 8160, so the expansion cannot fail. Handing back half-derived material
    /// instead would put a wrong `key_id` into a file header for good.
    #[must_use]
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        let mut key_id = [0u8; KEY_ID_LEN];
        self.expand(INFO_KEY_ID, &mut key_id);
        key_id
    }

    /// The working key for `suite`.
    ///
    /// # Errors
    ///
    /// [`Error::Format`] for a suite this build cannot key.
    pub fn suite_key(&self, suite: u8) -> Result<SuiteKey> {
        if suite != SUITE_AES_256_SIV {
            return Err(Error::Format(format!(
                "cipher suite {suite:#04x} needs a newer git-xcrypt"
            )));
        }
        let mut key = SuiteKey([0u8; SIV_KEY_LEN]);
        self.expand(INFO_SUITE_AES_256_SIV, &mut key.0);
        Ok(key)
    }

    /// HKDF-SHA-256 expansion with no salt and a domain-separating `info`.
    ///
    /// # Panics
    ///
    /// Never for the call sites in this module: both output lengths are
    /// compile-time constants far below HKDF's ceiling of 8160 bytes, and the
    /// only documented failure is an out-of-range length. Aborting is
    /// deliberate — the alternative shapes (a zeroed buffer, a half-filled one)
    /// would encrypt real content under a predictable key and say nothing,
    /// which is the one failure mode this codebase refuses everywhere else.
    fn expand(&self, info: &[u8], out: &mut [u8]) {
        const HKDF_SHA256_MAX_OUTPUT: usize = 255 * 32;
        assert!(
            out.len() <= HKDF_SHA256_MAX_OUTPUT,
            "HKDF output length is out of range"
        );

        let hkdf = Hkdf::<Sha256>::new(None, &self.0);
        hkdf.expand(info, out)
            .expect("HKDF cannot fail for a length already checked above");
    }
}

/// A working key derived for one cipher suite.
///
/// Separate type so a suite key can never be mistaken for the master key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SuiteKey([u8; SIV_KEY_LEN]);

impl SuiteKey {
    /// The raw key material, for handing to the cipher.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; SIV_KEY_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> MasterKey {
        MasterKey::from_bytes([7u8; MASTER_KEY_LEN])
    }

    #[test]
    fn key_id_is_stable_for_the_same_key() {
        assert_eq!(fixed_key().key_id(), fixed_key().key_id());
    }

    #[test]
    fn the_suite_key_is_not_the_master_key() {
        let key = fixed_key();
        let suite = key.suite_key(SUITE_AES_256_SIV).expect("known suite");
        assert_ne!(&suite.expose_bytes()[..MASTER_KEY_LEN], key.expose_bytes());
    }

    #[test]
    fn the_suite_key_does_not_start_with_the_key_id() {
        // Both come from the same master key; domain separation must keep them
        // independent rather than sharing a prefix.
        let key = fixed_key();
        let suite = key.suite_key(SUITE_AES_256_SIV).expect("known suite");
        assert_ne!(&suite.expose_bytes()[..KEY_ID_LEN], &key.key_id());
    }

    #[test]
    fn an_unknown_suite_has_no_key() {
        assert!(fixed_key().suite_key(0xff).is_err());
    }
}
