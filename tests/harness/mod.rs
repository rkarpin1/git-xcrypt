//! Drives a real git repository in a temporary directory.
//!
//! Only git's stored objects prove that content left the working tree in the
//! shape we intended, so every assertion here goes through real `git` calls and
//! compares raw bytes. Nothing on this path may become a `String`: ciphertext is
//! not valid UTF-8.

// Each integration test file compiles its own copy of this module, so helpers
// used by only one of them would otherwise trip `-D warnings`.
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
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
    /// Environment applied to every `git` and `git-xcrypt` this repository runs.
    ///
    /// Empty by default, because the rest of the configuration is inherited from
    /// the machine on purpose. A scenario about a source git resolves *outside*
    /// the repository cannot inherit it: `~/.config/git/attributes` belongs to
    /// whoever is running the suite, so a test that read theirs would pass or
    /// fail for reasons unrelated to the code — and would edit a developer's
    /// home directory to set itself up. See [`TestRepo::with_home`].
    ///
    /// `None` as a value removes the variable rather than setting it, which is
    /// the only way to say "this machine has no `XDG_CONFIG_HOME`".
    env: Vec<(OsString, Option<OsString>)>,
}

impl TestRepo {
    /// Creates an empty repository with a committer identity set locally.
    ///
    /// The rest of the git configuration is deliberately inherited from the
    /// machine — see the plan's Open Risks.
    pub fn init() -> Self {
        Self::init_with(&[])
    }

    /// Creates an empty SHA-256 repository.
    ///
    /// Every path that reads an object id has to be told which hash to expect:
    /// `gix-odb` asserts on it rather than adapting, so a build that guesses
    /// SHA-1 panics here — and a panic on the filter path aborts every git
    /// operation in the repository.
    pub fn init_sha256() -> Self {
        Self::init_with(&["--object-format=sha256"])
    }

    /// Creates an empty repository, passing `extra` to `git init`.
    pub fn init_with(extra: &[&str]) -> Self {
        require_git();

        let dir = TempDir::new().expect("could not create a temporary directory");
        let path = dir.path().to_path_buf();
        let repo = Self {
            _dir: dir,
            path,
            env: Vec::new(),
        };

        let mut args = vec!["init", "-q", "-b", "main"];
        args.extend_from_slice(extra);
        repo.git_ok(args);
        repo.git_ok(["config", "user.name", "git-xcrypt tests"]);
        repo.git_ok(["config", "user.email", "tests@git-xcrypt.invalid"]);
        repo
    }

    /// The working tree root.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Gives this repository its own home directory.
    ///
    /// Both `git` and `git-xcrypt` then resolve `~`, the global configuration
    /// and `$HOME/.config/git/attributes` inside `home`, so a scenario can own
    /// a source that lives outside the repository. `XDG_CONFIG_HOME` is removed
    /// rather than pointed somewhere, because leaving the caller's value in
    /// place would send git to a third directory the test never wrote.
    ///
    /// `HOMEDRIVE` and `HOMEPATH` go too: on Windows git assembles a home from
    /// that pair, so setting `HOME` alone would leave the two disagreeing about
    /// where `~` is — and the assertion would then be about the runner, not the
    /// code.
    #[must_use]
    pub fn with_home(mut self, home: &Path) -> Self {
        fs::create_dir_all(home).expect("could not create the home directory");
        self.env
            .push(("HOME".into(), Some(home.as_os_str().to_owned())));
        self.env
            .push(("USERPROFILE".into(), Some(home.as_os_str().to_owned())));
        self.env.push(("XDG_CONFIG_HOME".into(), None));
        self.env.push(("HOMEDRIVE".into(), None));
        self.env.push(("HOMEPATH".into(), None));
        self
    }

    /// Applies [`Self::env`] to a command about to run.
    fn with_environment<'c>(&self, command: &'c mut Command) -> &'c mut Command {
        for (name, value) in &self.env {
            match value {
                Some(value) => command.env(name, value),
                None => command.env_remove(name),
            };
        }
        command
    }

    /// Runs `git-xcrypt` in this repository and returns the full output.
    pub fn xcrypt<I, S>(&self, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.with_environment(Command::new(BIN).current_dir(&self.path).args(args))
            .output()
            .expect("could not run git-xcrypt")
    }

    /// Runs `git-xcrypt` with `input` on stdin and returns the full output.
    ///
    /// The only way to drive an interactive confirmation the way a user does,
    /// which for `lock` is the branch that stands between a mistyped command and
    /// a deleted key.
    pub fn xcrypt_with_stdin<I, S>(&self, args: I, input: &[u8]) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = self
            .with_environment(Command::new(BIN).current_dir(&self.path).args(args))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("could not run git-xcrypt");
        child
            .stdin
            .take()
            .expect("git-xcrypt stdin was not captured")
            .write_all(input)
            .expect("could not write to git-xcrypt stdin");
        child
            .wait_with_output()
            .expect("could not collect git-xcrypt output")
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
    ///
    /// **It deliberately does not set `filter.git-xcrypt.required` itself.** It
    /// used to, and that made the two tests AGENTS.md names as the guard on that
    /// flag guard nothing at all: they set up the very condition they were meant
    /// to observe `init` establishing. Measured — with the `required` line
    /// removed from `init::register_driver`, both still passed. They fail now,
    /// which is the point: the only thing standing between a failing filter and
    /// a stored plaintext here is what `init` wrote.
    pub fn break_filter(&self) {
        let missing = self.path.join("no-such-binary");
        self.git_ok([
            "config",
            "filter.git-xcrypt.process",
            &format!("'{}' process", missing.display()),
        ]);
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

    /// Pushes `branch` to a bare repository standing in for the hosting service.
    ///
    /// The founding document's acceptance criteria are written about a *remote*
    /// — "the blobs in the remote repository are encrypted" — and nothing else
    /// in this suite exercises the transport at all. `receive-pack` re-reads and
    /// re-packs every object it accepts, so a repository that looks right
    /// locally has still not been shown to arrive right.
    pub fn push_to(&self, remote: &BareRemote, branch: &str) {
        self.git_ok(["push", "-q", &remote.url(), &format!("{branch}:{branch}")]);
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

        let clone = Self {
            _dir: dir,
            path,
            env: self.env.clone(),
        };
        clone.git_ok(["config", "user.name", "git-xcrypt tests"]);
        clone.git_ok(["config", "user.email", "tests@git-xcrypt.invalid"]);
        clone
    }

    /// Clones only the tip commit, the way CI checkouts do.
    ///
    /// A shallow clone is an ordinary, healthy state whose history genuinely
    /// stops at a graft point — which must not be mistaken for a damaged object
    /// database.
    pub fn clone_shallow(&self) -> Self {
        let dir = TempDir::new().expect("could not create a temporary directory");
        let path = dir.path().join("clone");

        let output = Command::new("git")
            .arg("clone")
            .arg("-q")
            .arg("--depth")
            .arg("1")
            .arg(format!("file://{}", self.path.display()))
            .arg(&path)
            .output()
            .expect("could not run git clone");
        assert!(
            output.status.success(),
            "git clone --depth 1 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let clone = Self {
            _dir: dir,
            path,
            env: self.env.clone(),
        };
        clone.git_ok(["config", "user.name", "git-xcrypt tests"]);
        clone.git_ok(["config", "user.email", "tests@git-xcrypt.invalid"]);
        clone
    }

    /// Adds a linked worktree and returns it as a repository in its own right.
    ///
    /// Linked worktrees are the case where "the git directory" and "the
    /// directory git reads configuration from" stop being the same place.
    pub fn add_worktree(&self, name: &str) -> Self {
        let dir = TempDir::new().expect("could not create a temporary directory");
        let path = dir.path().join(name);

        self.git_ok(["worktree", "add", "-q", "-b", name, &path.to_string_lossy()]);

        Self {
            _dir: dir,
            path,
            env: self.env.clone(),
        }
    }

    /// Runs git in this repository and returns the full output, failure included.
    pub fn git<I, S>(&self, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.with_environment(Command::new("git").current_dir(&self.path).args(args))
            .output()
            .expect("could not run git")
    }

    /// Runs git with `input` on stdin and returns the full output.
    pub fn git_with_stdin<I, S>(&self, args: I, input: &[u8]) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = self
            .with_environment(Command::new("git").current_dir(&self.path).args(args))
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

    /// Sets one git configuration key locally.
    pub fn set_config(&self, key: &str, value: &str) {
        self.git_ok(["config", key, value]);
    }

    /// Sets the pair the smudge path reads, together.
    ///
    /// The two are one setting in practice — `core.eol` only gets a say while
    /// `core.autocrlf` is false — so a helper that took one of them would invite
    /// a matrix that never reaches the interesting half of the table.
    pub fn set_eol_config(&self, autocrlf: &str, eol: &str) {
        self.set_config("core.autocrlf", autocrlf);
        self.set_config("core.eol", eol);
    }

    /// Adopts a key minted elsewhere, then sets the repository up.
    ///
    /// The order matters and is the one a second machine uses: the key has to be
    /// in place before `init` looks for one, or `init` mints a second one and
    /// every `key_id` in the headers stops matching.
    pub fn init_xcrypt_with(&self, key: &SharedKey) {
        self.xcrypt_ok(["import-key", &key.as_arg()]);
        self.init_xcrypt();
    }

    /// Deletes `relative_path` and checks it back out through the smudge filter.
    ///
    /// The only way to observe what smudge writes: git will not re-run it for a
    /// file it believes is already correct in the working tree.
    pub fn recheckout(&self, relative_path: &str) {
        fs::remove_file(self.path.join(relative_path)).expect("could not remove the file");
        self.git_ok(["checkout", "--", relative_path]);
    }

    /// Whether the blob at `HEAD` carries our magic.
    pub fn blob_is_encrypted(&self, relative_path: &str) -> bool {
        self.blob_bytes(relative_path).starts_with(MAGIC)
    }

    /// Whether the stored header records that the plaintext was normalised.
    ///
    /// Bit 0 of the `flags` byte, at offset 13 of the frozen header. It is the
    /// only place the text/binary verdict is observable from outside, and it is
    /// what smudge later reads instead of asking `.git-xcrypt` again.
    pub fn blob_records_normalisation(&self, relative_path: &str) -> bool {
        let blob = self.blob_bytes(relative_path);
        assert!(
            blob.starts_with(MAGIC),
            "{relative_path} is not encrypted, so it records no verdict"
        );
        blob[13] & 1 == 1
    }

    /// Fetches and merges `branch` from `remote`.
    pub fn pull_from(&self, remote: &BareRemote, branch: &str) {
        self.git_ok(["pull", "-q", "--ff-only", &remote.url(), branch]);
    }
}

/// Our file header's magic, and the fixed cost of wearing it.
pub const MAGIC: &[u8] = b"\0GITXCRYPT\0";

/// Header plus synthetic IV. SIV encrypts in CTR mode, so a stored file is
/// exactly this much longer than the plaintext that went in — which makes the
/// length a usable assertion about *which* plaintext that was.
pub const OVERHEAD: usize = 38;

/// One repository key, minted once and carried into every repository a test
/// needs.
///
/// Not a convenience. `key_id` is in the authenticated header, so two
/// repositories that minted their own keys store different bytes for the same
/// content — and a test comparing blobs across them would be asserting nothing
/// while looking like it asserts determinism.
pub struct SharedKey {
    _dir: TempDir,
    path: PathBuf,
}

impl SharedKey {
    /// Mints a key in a throwaway repository and exports it.
    pub fn minted() -> Self {
        let dir = TempDir::new().expect("could not create a temporary directory");
        let path = dir.path().join("shared.key");

        let source = TestRepo::init();
        source.init_xcrypt();
        source.xcrypt_ok(["export-key", &path.to_string_lossy()]);

        Self { _dir: dir, path }
    }

    /// The key file itself.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The key file as a command-line argument.
    pub fn as_arg(&self) -> String {
        self.path.to_string_lossy().into_owned()
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

/// A bare repository, standing in for the remote a user actually pushes to.
///
/// Bare on purpose rather than "another clone": a hosting service has no
/// working tree, runs no filters, and its object database is the only thing a
/// user's secrets can be judged by once they have left the machine.
pub struct BareRemote {
    _dir: TempDir,
    path: PathBuf,
}

impl BareRemote {
    /// Creates an empty bare repository.
    pub fn new() -> Self {
        require_git();

        let dir = TempDir::new().expect("could not create a temporary directory");
        let path = dir.path().join("remote.git");

        let output = Command::new("git")
            .args(["init", "-q", "--bare", "-b", "main"])
            .arg(&path)
            .output()
            .expect("could not run git init --bare");
        assert!(
            output.status.success(),
            "git init --bare failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Self { _dir: dir, path }
    }

    /// The URL a push or clone should use.
    pub fn url(&self) -> String {
        self.path.display().to_string()
    }

    /// The bare repository's own directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs `git-xcrypt` **inside** the bare repository.
    ///
    /// A hosting service's own directory is a git repository with no working
    /// tree, and every command here filters, encrypts or decrypts one. Running
    /// them there has to end in a refusal rather than a panic or a guess.
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

    /// Raw bytes of the blob this repository stores for `relative_path`.
    pub fn blob_bytes(&self, revision: &str, relative_path: &str) -> Vec<u8> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .args(["cat-file", "blob", &format!("{revision}:{relative_path}")])
            .output()
            .expect("could not run git cat-file");
        assert!(
            output.status.success(),
            "git cat-file blob {revision}:{relative_path} failed in the remote: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    /// Whether the remote's object database holds a blob with exactly `contents`.
    ///
    /// The plaintext goes in over stdin, never through a file, for the reason
    /// [`TestRepo::object_exists_for`] gives.
    pub fn object_exists_for(&self, contents: &[u8]) -> bool {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .args(["hash-object", "-t", "blob", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("could not run git hash-object");
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(contents)
            .expect("could not write to git hash-object");
        let hashed = child
            .wait_with_output()
            .expect("git hash-object never ended");
        assert!(
            hashed.status.success(),
            "git hash-object failed: {}",
            String::from_utf8_lossy(&hashed.stderr)
        );

        let hash = String::from_utf8(hashed.stdout).expect("git printed a non-UTF-8 hash");
        Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .args(["cat-file", "-e", &format!("{}^{{blob}}", hash.trim())])
            .output()
            .expect("could not run git cat-file -e")
            .status
            .success()
    }

    /// Clones this remote into a fresh temporary directory, as a second machine
    /// would.
    pub fn clone_to(&self) -> TestRepo {
        let dir = TempDir::new().expect("could not create a temporary directory");
        let path = dir.path().join("clone");

        let output = Command::new("git")
            .args(["clone", "-q"])
            .arg(&self.path)
            .arg(&path)
            .output()
            .expect("could not run git clone");
        assert!(
            output.status.success(),
            "git clone from the bare remote failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let clone = TestRepo {
            _dir: dir,
            path,
            env: Vec::new(),
        };
        clone.git_ok(["config", "user.name", "git-xcrypt tests"]);
        clone.git_ok(["config", "user.email", "tests@git-xcrypt.invalid"]);
        clone
    }
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
