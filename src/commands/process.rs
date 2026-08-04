//! `git-xcrypt process` — the entry point git itself calls.
//!
//! Registered by `init` as `filter.git-xcrypt.process`. Everything it writes to
//! `stdout` is protocol; diagnostics go to `stderr` and nowhere else.

use std::io;

use crate::Result;
use crate::filter::{self, Context};
use crate::repo::Repo;

/// Serves git's filter protocol until the stream closes.
///
/// # Errors
///
/// [`crate::Error::Config`] when the repository or `.git-xcrypt` cannot be read,
/// [`crate::Error::Io`] on a broken pipe.
pub fn run() -> Result<()> {
    let repo = Repo::discover_from_cwd()?;
    let context = Context::load(&repo)?;

    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    filter::run(&context, &mut input, &mut output)
}
