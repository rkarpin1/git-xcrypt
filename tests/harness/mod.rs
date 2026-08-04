//! Drives a real git repository in a temporary directory.
//!
//! Only git's stored objects prove that content left the working tree in the
//! shape we intended, so every assertion here goes through real `git` calls and
//! compares raw bytes. Nothing on this path may become a `String`: ciphertext is
//! not valid UTF-8.

// Each integration test file compiles its own copy of this module, so helpers
// used by only one of them would otherwise trip `-D warnings`.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

/// The binary under test, as built by cargo for this integration test run.
const BIN: &str = env!("CARGO_BIN_EXE_git-xcrypt");

/// A git repository living in a temporary directory that is removed on drop.
pub struct TestRepo {
    // Held for its Drop: removing the directory tree when the test ends.
    _dir: TempDir,
    path: PathBuf,
}

impl TestRepo {
    /// Creates an empty repository with a committer identity set locally.
    ///
    /// The rest of the git configuration is deliberately inherited from the
    /// machine — see the plan's Open Risks.
    pub fn init() -> Self {
        require_git();

        let dir = TempDir::new().expect("could not create a temporary directory");
        let path = dir.path().to_path_buf();
        let repo = Self { _dir: dir, path };

        repo.git_ok(["init", "-q", "-b", "main"]);
        repo.git_ok(["config", "user.name", "git-xcrypt tests"]);
        repo.git_ok(["config", "user.email", "tests@git-xcrypt.invalid"]);
        repo
    }

    /// The working tree root.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs `git-xcrypt` in this repository and returns the full output.
    pub fn xcrypt<I, S>(&self, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Command::new(BIN)
            .current_dir(&self.path)
            .args(args)
            .output()
            .expect("could not run git-xcrypt")
    }

    /// Runs `git-xcrypt` and panics unless it succeeded.
    pub fn xcrypt_ok<I, S>(&self, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.xcrypt(args);
        assert!(
            output.status.success(),
            "git-xcrypt failed with {:?}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Sets the repository up exactly as a user would: one command.
    pub fn init_xcrypt(&self) {
        self.xcrypt_ok(["init"]);
    }

    /// Writes the versioned list of what to encrypt.
    pub fn write_xcrypt_config(&self, contents: &str) {
        self.write_file(".git-xcrypt", contents.as_bytes());
    }

    /// Points the filter at a binary that does not exist.
    ///
    /// Git cannot start it, so the filter fails — which is what proves that
    /// `required = true` aborts the operation instead of letting the content
    /// through. The product no longer ships a way to fail on purpose, and it
    /// should not.
    pub fn break_filter(&self) {
        let missing = self.path.join("no-such-binary");
        self.git_ok([
            "config",
            "filter.git-xcrypt.process",
            &format!("'{}' process", missing.display()),
        ]);
        self.git_ok(["config", "filter.git-xcrypt.required", "true"]);
    }

    /// What git itself says one attribute resolves to for `relative_path`.
    ///
    /// The generated lines are only worth anything if git agrees with them, and
    /// git is the only authority on its own pattern syntax — the two files do
    /// not spell patterns the same way.
    pub fn check_attr(&self, attribute: &str, relative_path: &str) -> String {
        let output = self.git_ok(["check-attr", attribute, "--", relative_path]);
        let text = String::from_utf8(output.stdout).expect("git printed non-UTF-8 attributes");
        text.rsplit(": ")
            .next()
            .expect("check-attr always prints a value")
            .trim()
            .to_string()
    }

    /// Writes `contents` to `relative_path`, creating parent directories.
    pub fn write_file(&self, relative_path: &str, contents: &[u8]) {
        let target = self.path.join(relative_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("could not create parent directories");
        }
        fs::write(&target, contents).expect("could not write the file");
    }

    /// Stages everything and commits.
    pub fn commit_all(&self, message: &str) {
        self.git_ok(["add", "-A"]);
        self.git_ok(["commit", "-q", "-m", message]);
    }

    /// Raw bytes of the blob stored for `relative_path` at `HEAD`.
    pub fn blob_bytes(&self, relative_path: &str) -> Vec<u8> {
        let output = self.git_ok(["cat-file", "blob", &format!("HEAD:{relative_path}")]);
        output.stdout
    }

    /// Raw bytes of `relative_path` in the working tree.
    pub fn worktree_bytes(&self, relative_path: &str) -> Vec<u8> {
        fs::read(self.path.join(relative_path)).expect("could not read the working tree file")
    }

    /// Whether the object database holds a blob with exactly `contents`.
    ///
    /// Used to prove that a failed filter left no plaintext behind. The content
    /// goes in over stdin rather than through a scratch file: writing the
    /// plaintext we are hunting for into the working tree — even briefly —
    /// would put it one `git add -A` away from the commit this very test says
    /// must never happen.
    pub fn object_exists_for(&self, contents: &[u8]) -> bool {
        let hashed = self.git_with_stdin(["hash-object", "-t", "blob", "--stdin"], contents);
        assert!(
            hashed.status.success(),
            "git hash-object failed: {}",
            String::from_utf8_lossy(&hashed.stderr)
        );

        let hash = String::from_utf8(hashed.stdout).expect("git printed a non-UTF-8 hash");
        self.git(["cat-file", "-e", &format!("{}^{{blob}}", hash.trim())])
            .status
            .success()
    }

    /// Clones this repository into a fresh temporary directory.
    ///
    /// The clone inherits `.gitattributes` through history but not `.git/config`,
    /// so no filter is registered in it — exactly the state a teammate or a
    /// second machine sees before unlocking.
    pub fn clone_without_filter(&self) -> Self {
        let dir = TempDir::new().expect("could not create a temporary directory");
        let path = dir.path().join("clone");

        let output = Command::new("git")
            .arg("clone")
            .arg("-q")
            .arg(&self.path)
            .arg(&path)
            .output()
            .expect("could not run git clone");
        assert!(
            output.status.success(),
            "git clone failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let clone = Self { _dir: dir, path };
        clone.git_ok(["config", "user.name", "git-xcrypt tests"]);
        clone.git_ok(["config", "user.email", "tests@git-xcrypt.invalid"]);
        clone
    }

    /// Runs git in this repository and returns the full output, failure included.
    pub fn git<I, S>(&self, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Command::new("git")
            .current_dir(&self.path)
            .args(args)
            .output()
            .expect("could not run git")
    }

    /// Runs git with `input` on stdin and returns the full output.
    pub fn git_with_stdin<I, S>(&self, args: I, input: &[u8]) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = Command::new("git")
            .current_dir(&self.path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("could not run git");
        child
            .stdin
            .take()
            .expect("git stdin was not captured")
            .write_all(input)
            .expect("could not write to git stdin");
        child
            .wait_with_output()
            .expect("could not collect git output")
    }

    /// Runs git and panics unless it succeeded.
    pub fn git_ok<I, S>(&self, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.git(args);
        assert!(
            output.status.success(),
            "git command failed with {:?}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Asserts `git status` reports nothing — the proof that a checkout
    /// reproduced the committed content exactly.
    pub fn assert_status_clean(&self) {
        let output = self.git_ok(["status", "--porcelain"]);
        assert!(
            output.stdout.is_empty(),
            "expected a clean working tree, git reported:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// Asserts the stored blob differs from the working tree file.
    pub fn assert_blob_differs_from_worktree(&self, relative_path: &str) {
        let blob = self.blob_bytes(relative_path);
        let worktree = self.worktree_bytes(relative_path);
        assert_ne!(
            blob, worktree,
            "{relative_path}: the blob is identical to the working tree file, \
             so the filter never ran"
        );
    }

    /// Asserts the working tree file matches `expected` byte for byte.
    pub fn assert_worktree_eq(&self, relative_path: &str, expected: &[u8]) {
        assert_bytes_eq(&self.worktree_bytes(relative_path), expected, relative_path);
    }

    /// Asserts the stored blob matches `expected` byte for byte.
    pub fn assert_blob_eq(&self, relative_path: &str, expected: &[u8]) {
        assert_bytes_eq(&self.blob_bytes(relative_path), expected, relative_path);
    }

    /// Asserts `relative_path` is absent from the index.
    pub fn assert_not_staged(&self, relative_path: &str) {
        let output = self.git_ok(["ls-files", "--stage", "--", relative_path]);
        assert!(
            output.stdout.is_empty(),
            "{relative_path} reached the index although the filter failed"
        );
    }
}

/// Compares byte buffers and reports where they diverge.
///
/// Printing whole buffers would be unreadable for binary content, so the
/// message carries lengths and the first differing offset instead.
fn assert_bytes_eq(actual: &[u8], expected: &[u8], label: &str) {
    if actual == expected {
        return;
    }

    let divergence = actual
        .iter()
        .zip(expected)
        .position(|(a, b)| a != b)
        .map_or_else(
            || {
                format!(
                    "one is a prefix of the other at offset {}",
                    actual.len().min(expected.len())
                )
            },
            |offset| format!("first difference at offset {offset}"),
        );

    panic!(
        "{label}: content mismatch — {} bytes vs {} expected, {divergence}",
        actual.len(),
        expected.len()
    );
}

/// Fails loudly when git is missing.
///
/// Skipping silently would hide the absence of coverage, and these tests have
/// no meaning without a real git.
fn require_git() {
    let available = Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    assert!(
        available,
        "git was not found on PATH; the integration tests cannot run without it"
    );
}
