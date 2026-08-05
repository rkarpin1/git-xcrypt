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
///
/// Since 2026-08-05 it is also what `status` answers when git is not set up to
/// enforce the declarations — an unregistered filter, a missing catch-all line,
/// a missing `.git-xcrypt` — and it outranks both [`EXPOSED`] and
/// [`UNDETERMINED`]. **Configuration comes before data:** without a
/// configuration that enforces anything the data in the repository is worth
/// nothing, and `5` was telling repositories that had never run `init` to go and
/// rotate a secret they had never exposed. No new code was minted for it; this
/// is the existing meaning, applied.
pub const CONFIG: u8 = 2;

/// The repository key is missing.
pub const NO_KEY: u8 = 3;

/// The content is not something this build can read: magic, version, suite, a
/// reserved flag bit, a foreign key or a failed authentication tag.
pub const FORMAT: u8 = 4;

/// `status` found an exposure — plaintext where ciphertext was expected.
///
/// Distinct from the error codes so a CI gate can tell "the tool broke" from
/// "the repository has a problem". Since 2026-08-04 it means **only** that:
/// see [`UNDETERMINED`].
pub const EXPOSED: u8 = 5;

/// `status` could not answer the question it was asked.
///
/// A shallow or partial clone, an index that will not parse, a reference store
/// that will not enumerate. Nothing was found and nothing is ruled out. (A
/// missing `.git-xcrypt` was in this list until 2026-08-05 and is now [`CONFIG`]
/// — it is a configuration that enforces nothing, and it still puts everything
/// the run then skipped in `undetermined`.)
///
/// **Added 2026-08-04, and it widens a table this project had frozen.** The
/// reason is measured: `5` used to carry both answers, so a perfectly healthy
/// `git clone --depth 1` — what `actions/checkout` produces unless it is given
/// `fetch-depth: 0` — failed the gate with the same code as a repository
/// holding a plaintext secret. A gate that cries wolf on its default setup is a
/// gate that gets switched off, and the two answers ask different things of
/// whoever reads them: `5` says fix the repository, `6` says fix the checkout
/// and ask again. Widening the table costs nothing before the first release —
/// no consumer exists yet — and after it would cost a breaking change.
pub const UNDETERMINED: u8 = 6;
