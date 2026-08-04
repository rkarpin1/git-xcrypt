//! Exit codes, in one place.
//!
//! Git only distinguishes zero from non-zero, but a person reading a CI log or
//! scripting around the tool needs to tell "no key" from "bad format" from "this
//! repository is exposed". The set is frozen in
//! `context/foundation/zalozenia.md` §Integracja z git.

/// Everything went as asked.
pub const SUCCESS: u8 = 0;

/// The command line made no sense, or something failed for an unclassified reason.
pub const USAGE: u8 = 1;

/// Configuration or a state conflict: not a git repository, a clash during
/// `init`, or a dirty working tree during `lock`.
pub const CONFIG: u8 = 2;

/// The repository key is missing.
pub const NO_KEY: u8 = 3;

/// The content is not something this build can read: magic, version, suite, a
/// reserved flag bit, a foreign key or a failed authentication tag.
pub const FORMAT: u8 = 4;

/// `status` found an exposure — plaintext where ciphertext was expected.
///
/// Distinct from the error codes so a CI gate can tell "the tool broke" from
/// "the repository has a problem".
pub const EXPOSED: u8 = 5;
