//! Everything that reads git, reproduces git, or talks to git.
//!
//! The rule this crate lives by is that git's behaviour is measured, never
//! assumed — so each of these reproduces one thing git does and is answerable to
//! it: [`attributes`] to `git check-attr`, [`config`] to the configuration
//! cascade, [`index`] to the index format, [`history`] to reachability, and
//! [`pktline`] to the long-running filter protocol. [`repo`] is where a
//! repository's directories are worked out, which git does differently for a
//! linked worktree than for anything else.

pub mod attributes;
pub mod config;
pub mod history;
pub mod index;
pub mod pktline;
pub mod repo;
