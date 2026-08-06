//! The cipher, the two frozen file formats, and the key they share.
//!
//! Grouped because they move together or not at all: [`format`] is frozen with
//! the data on disk, [`keyfile`] with the copies users hold, and [`cipher`] is
//! what makes both mean anything. A change here rewrites bytes that already
//! exist in someone's history, which is why `CHANGELOG.md` lists them under
//! their own heading rather than among ordinary changes.

pub mod cipher;
pub mod format;
pub mod key;
pub mod keyfile;
