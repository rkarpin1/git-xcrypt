//! The on-disk format of an encrypted file.
//!
//! Bytes `0..22` are frozen forever and are fed to the cipher as associated
//! data, so nothing in the header can be altered without invalidating the tag.
//! Everything from offset 22 onwards is defined by `suite`, which is what lets a
//! future cipher, a chunked mode or compression arrive without a format version
//! bump and without breaking existing repositories.
//!
//! ```text
//! offset  len  field
//!      0   11  magic \x00GITXCRYPT\x00
//!     11    1  format_version
//!     12    1  suite
//!     13    1  flags
//!     14    8  key_id
//!     22   16  synthetic IV      <- suite-defined
//!     38   ..  ciphertext        <- suite-defined
//! ```

use crate::{Error, Result};

/// Leading bytes identifying our format.
///
/// The leading NUL makes git's own heuristics treat the blob as binary, so
/// `git diff` reports `Binary files differ` instead of dumping noise.
pub const MAGIC: [u8; 11] = *b"\0GITXCRYPT\0";

/// The only format version written today.
pub const FORMAT_VERSION: u8 = 1;

/// AES-256-SIV (RFC 5297).
pub const SUITE_AES_256_SIV: u8 = 1;

/// Bit 0 of `flags`: the plaintext was normalised to LF before encryption.
pub const FLAG_LF_NORMALIZED: u8 = 0b0000_0001;

/// Every flag bit we understand. Anything else must be refused.
const KNOWN_FLAGS: u8 = FLAG_LF_NORMALIZED;

/// Length of the key fingerprint carried by every file.
pub const KEY_ID_LEN: usize = 8;

/// Length of the frozen header, all of which is authenticated.
pub const HEADER_LEN: usize = 22;

/// Length of the synthetic IV produced by AES-SIV.
pub const SIV_LEN: usize = 16;

/// Constant number of bytes an encrypted file adds to its plaintext.
pub const OVERHEAD: usize = HEADER_LEN + SIV_LEN;

/// The parsed header of an encrypted file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Format version; only [`FORMAT_VERSION`] is accepted today.
    pub version: u8,
    /// Cipher suite; only [`SUITE_AES_256_SIV`] is accepted today.
    pub suite: u8,
    /// Conversion flags recorded at encryption time.
    pub flags: u8,
    /// Fingerprint of the master key this file was encrypted with.
    pub key_id: [u8; KEY_ID_LEN],
}

impl Header {
    /// Builds a header for the suite and version we write today.
    #[must_use]
    pub fn new(flags: u8, key_id: [u8; KEY_ID_LEN]) -> Self {
        Self {
            version: FORMAT_VERSION,
            suite: SUITE_AES_256_SIV,
            flags,
            key_id,
        }
    }

    /// Serialises the header exactly as it appears at the start of a file.
    #[must_use]
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..MAGIC.len()].copy_from_slice(&MAGIC);
        bytes[11] = self.version;
        bytes[12] = self.suite;
        bytes[13] = self.flags;
        bytes[14..HEADER_LEN].copy_from_slice(&self.key_id);
        bytes
    }

    /// Parses the header at the start of `blob`, refusing anything unknown.
    ///
    /// Fail closed is the rule here: an older binary meeting a newer file must
    /// stop rather than guess. That covers an unknown format version, an
    /// unknown suite and any reserved flag bit being set.
    ///
    /// # Errors
    ///
    /// [`Error::Format`] when the blob is too short, lacks the magic, or names
    /// a version, suite or flag bit this build does not understand.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        if blob.len() < OVERHEAD {
            return Err(Error::Format(
                "the file is shorter than an empty encrypted file".into(),
            ));
        }
        if !blob.starts_with(&MAGIC) {
            return Err(Error::Format("the file does not carry our magic".into()));
        }

        let version = blob[11];
        if version != FORMAT_VERSION {
            return Err(Error::Format(format!(
                "format version {version} needs a newer git-xcrypt"
            )));
        }

        let suite = blob[12];
        if suite != SUITE_AES_256_SIV {
            return Err(Error::Format(format!(
                "cipher suite {suite:#04x} needs a newer git-xcrypt"
            )));
        }

        let flags = blob[13];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Error::Format(format!(
                "flags {flags:#010b} set a reserved bit; this file needs a newer git-xcrypt"
            )));
        }

        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&blob[14..HEADER_LEN]);

        Ok(Self {
            version,
            suite,
            flags,
            key_id,
        })
    }
}

/// Whether `content` carries our magic.
///
/// This is the cheap check every path starts with — the filter, `status` and
/// the history scan all decide on these eleven bytes alone.
#[must_use]
pub fn looks_encrypted(content: &[u8]) -> bool {
    content.starts_with(&MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ID: [u8; KEY_ID_LEN] = [0x3f, 0xa9, 0x12, 0x0b, 0x7e, 0xc4, 0x55, 0x8a];

    /// A blob whose header is valid and whose body is long enough to parse.
    fn blob_with(version: u8, suite: u8, flags: u8) -> Vec<u8> {
        let mut header = Header::new(flags, KEY_ID).to_bytes();
        header[11] = version;
        header[12] = suite;
        let mut blob = header.to_vec();
        blob.extend_from_slice(&[0u8; SIV_LEN]);
        blob
    }

    #[test]
    fn magic_starts_with_nul_so_git_sees_binary() {
        assert_eq!(MAGIC[0], 0);
        assert_eq!(MAGIC[MAGIC.len() - 1], 0);
    }

    #[test]
    fn overhead_is_thirty_eight_bytes() {
        assert_eq!(OVERHEAD, 38);
        assert_eq!(Header::new(0, KEY_ID).to_bytes().len(), HEADER_LEN);
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let blob = blob_with(FORMAT_VERSION + 1, SUITE_AES_256_SIV, 0);
        assert!(Header::parse(&blob).is_err());
    }

    #[test]
    fn an_unknown_suite_is_refused() {
        let blob = blob_with(FORMAT_VERSION, SUITE_AES_256_SIV + 1, 0);
        assert!(Header::parse(&blob).is_err());
    }

    #[test]
    fn a_reserved_flag_bit_is_refused() {
        for bit in 1..8 {
            let blob = blob_with(FORMAT_VERSION, SUITE_AES_256_SIV, 1 << bit);
            assert!(
                Header::parse(&blob).is_err(),
                "flag bit {bit} must be refused until it means something"
            );
        }
    }
}
