//! The user-facing commands.
//!
//! Each one returns a [`crate::Result`]; the binary turns an error into the
//! matching exit code. Nothing here writes to `stdout` unless the command's
//! whole purpose is to produce output.

pub mod init;
pub mod process;
