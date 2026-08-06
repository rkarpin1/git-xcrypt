//! The two things every command needs and neither owns.
//!
//! [`atomic`] writes a file in one step or not at all — the key file and the
//! filter registration both go through it, and a half-written one of either
//! leaves a repository that stores plaintext. [`exit`] holds the frozen exit
//! codes, which are as much a part of this tool's interface as its commands:
//! a CI gate reads nothing else.

pub mod atomic;
pub mod exit;
