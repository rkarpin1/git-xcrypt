//! `git diff` on the decrypted content — the third decryption path.
//!
//! These have to run against real git, because the mechanism is entirely git's:
//! whether a `textconv` driver is consulted at all, what it is handed and what
//! happens when it refuses are answers only git can give. Measured on git 2.55,
//! and two of them are counter-intuitive enough to be worth naming here:
//!
//! * git materialises each side of a diff through the **smudge filter** before
//!   handing it to `textconv`, so the driver usually receives plaintext and the
//!   decrypting branch is a fallback rather than the common case. What the
//!   driver's presence buys is that git compares the converted content as text
//!   instead of reporting `Binary files differ` on the raw ciphertext.
//! * because of that, registering the driver in a repository with **no key**
//!   would drag the failing smudge filter into every `git log -p`. Hence
//!   `lock` takes the registration back out, and the test below holds it there.

mod harness;

use std::fs;

use git_xcrypt::format::MAGIC;
use git_xcrypt::repo::Repo;
use harness::TestRepo;

/// A repository set up the way a user would, with `*.env` declared.
fn prepared() -> TestRepo {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.xcrypt_ok(["sync"]);
    repo
}

/// Whether `haystack` contains our magic anywhere — the proof that no
/// ciphertext reached the user's screen.
fn carries_magic(haystack: &[u8]) -> bool {
    haystack.windows(MAGIC.len()).any(|window| window == MAGIC)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn git_diff_shows_the_plaintext_of_a_changed_secret() {
    let repo = prepared();
    repo.write_file("a.env", b"api_key = one\nshared line\n");
    repo.commit_all("first");
    repo.write_file("a.env", b"api_key = two\nshared line\n");

    let output = repo.git_ok(["--no-pager", "diff", "--", "a.env"]);
    let diff = text(&output.stdout);

    assert!(diff.contains("-api_key = one"), "{diff}");
    assert!(diff.contains("+api_key = two"), "{diff}");
    assert!(
        !diff.contains("Binary files"),
        "the diff driver was never consulted: {diff}"
    );
    assert!(
        !carries_magic(&output.stdout),
        "ciphertext reached the diff output"
    );
}

#[test]
fn git_show_displays_the_plaintext_of_a_commit() {
    let repo = prepared();
    repo.write_file("a.env", b"api_key = one\n");
    repo.commit_all("first");
    repo.write_file("a.env", b"api_key = two\n");
    repo.commit_all("second");

    let output = repo.git_ok(["--no-pager", "show", "HEAD", "--", "a.env"]);
    let shown = text(&output.stdout);

    assert!(shown.contains("-api_key = one"), "{shown}");
    assert!(shown.contains("+api_key = two"), "{shown}");
    assert!(!carries_magic(&output.stdout));
}

#[test]
fn git_log_p_covers_history_from_before_the_repository_was_configured() {
    // The case the plan calls out: a file committed in the clear, long before
    // any pattern named it. Refusing that content would break `git log -p` for
    // the whole repository, not just for the one commit.
    let repo = TestRepo::init();
    repo.write_file("a.env", b"was here first\n");
    repo.commit_all("before git-xcrypt");

    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("a.env", b"now a secret\n");
    repo.commit_all("after git-xcrypt");

    let output = repo.git_ok(["--no-pager", "log", "-p", "--", "a.env"]);
    let log = text(&output.stdout);

    assert!(log.contains("was here first"), "{log}");
    assert!(log.contains("now a secret"), "{log}");
    assert!(!carries_magic(&output.stdout));
}

#[test]
fn a_file_without_our_magic_is_printed_byte_for_byte() {
    let repo = prepared();
    let content: Vec<u8> = (0u8..=255).filter(|byte| *byte != 0).collect();
    repo.write_file("plain.bin", &content);

    let output = repo.xcrypt_ok(["diff", "plain.bin"]);

    assert_eq!(output.stdout, content, "pass-through altered the content");
}

#[test]
fn our_ciphertext_is_printed_as_the_plaintext_it_was_made_from() {
    // Straight at the driver, without git in between: this is the branch git
    // only reaches when the smudge filter did not run first.
    let repo = prepared();
    repo.write_file("a.env", b"api_key = hunter2\n");
    repo.commit_all("first");
    repo.write_file("stored.bin", &repo.blob_bytes("a.env"));

    let output = repo.xcrypt_ok(["diff", "stored.bin"]);

    assert_eq!(output.stdout, b"api_key = hunter2\n");
}

#[test]
fn without_a_key_the_driver_refuses_rather_than_printing_noise() {
    let repo = prepared();
    repo.write_file("a.env", b"api_key = hunter2\n");
    repo.commit_all("first");
    repo.write_file("stored.bin", &repo.blob_bytes("a.env"));

    let discovered = Repo::discover(repo.path()).expect("discovery");
    fs::remove_file(discovered.key_path()).expect("removing the key");

    let output = repo.xcrypt(["diff", "stored.bin"]);

    assert_eq!(
        output.status.code(),
        Some(i32::from(git_xcrypt::exit::NO_KEY)),
        "stderr: {}",
        text(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "a refusal still printed something to stdout"
    );
}

#[test]
fn tampered_ciphertext_is_refused_with_the_format_code() {
    let repo = prepared();
    repo.write_file("a.env", b"api_key = hunter2\n");
    repo.commit_all("first");

    let mut stored = repo.blob_bytes("a.env");
    let last = stored.len() - 1;
    stored[last] ^= 0x01;
    repo.write_file("stored.bin", &stored);

    let output = repo.xcrypt(["diff", "stored.bin"]);

    assert_eq!(
        output.status.code(),
        Some(i32::from(git_xcrypt::exit::FORMAT)),
        "stderr: {}",
        text(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn init_registers_the_diff_driver_and_leaves_the_cache_off() {
    // A cache would keep every decrypted file in a notes ref inside `.git/`,
    // where it would outlive `lock`.
    let repo = prepared();

    let registered = text(
        &repo
            .git_ok(["config", "--get", "diff.git-xcrypt.textconv"])
            .stdout,
    );
    assert!(
        registered.trim_end().ends_with(" diff"),
        "registered `{registered}`"
    );
    assert!(
        !repo
            .git(["config", "--get", "diff.git-xcrypt.cachetextconv"])
            .status
            .success(),
        "the textconv cache was switched on"
    );
}

#[test]
fn a_locked_repository_can_still_be_read_with_git_log() {
    // Measured: with the driver registered and no key, git materialises each
    // diff side through the smudge filter, which refuses — and `required = true`
    // turns that into `fatal: smudge filter git-xcrypt failed`, killing
    // `git log -p` for the whole repository. `lock` therefore takes the
    // registration out again.
    let repo = prepared();
    repo.write_file("a.env", b"api_key = hunter2\n");
    repo.commit_all("first");
    repo.xcrypt_ok(["lock", "--yes"]);

    assert!(
        !repo
            .git(["config", "--get", "diff.git-xcrypt.textconv"])
            .status
            .success(),
        "lock left a diff driver that has no key behind it"
    );

    let output = repo.git(["--no-pager", "log", "-p", "--", "a.env"]);
    assert!(
        output.status.success(),
        "a locked repository lost `git log -p`: {}",
        text(&output.stderr)
    );
    assert!(
        text(&output.stdout).contains("Binary files"),
        "expected git's own answer for content nobody can read: {}",
        text(&output.stdout)
    );
}

#[test]
fn unlocking_puts_the_diff_driver_back() {
    let repo = prepared();
    repo.write_file("a.env", b"api_key = hunter2\n");
    repo.commit_all("first");

    let holder = tempfile::TempDir::new().expect("temporary directory");
    let key = holder.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key.to_string_lossy()]);
    repo.xcrypt_ok(["lock", "--yes"]);
    repo.xcrypt_ok(["unlock", &key.to_string_lossy()]);

    assert!(
        repo.git(["config", "--get", "diff.git-xcrypt.textconv"])
            .status
            .success(),
        "unlock left the repository without a diff driver"
    );

    repo.write_file("a.env", b"api_key = rotated\n");
    let diff = text(&repo.git_ok(["--no-pager", "diff", "--", "a.env"]).stdout);
    assert!(diff.contains("+api_key = rotated"), "{diff}");
}
