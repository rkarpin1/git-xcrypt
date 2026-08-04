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
    let mut context = Context::load(&repo)?;

    let mut input = io::stdin().lock();
    // `BufWriter`, not the bare lock: `StdoutLock` is line buffered, and
    // ciphertext is uniformly random, so roughly one byte in 256 is `\n` and
    // would force a syscall. This is the path whose entire justification is the
    // 22× measurement. `pktline::write_flush` still forces the real flush at
    // every point the protocol requires one.
    let mut output = io::BufWriter::new(io::stdout().lock());
    filter::run(&mut context, &mut input, &mut output)
}
