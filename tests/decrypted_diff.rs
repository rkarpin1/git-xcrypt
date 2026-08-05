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

use git_xcrypt::format::MAGIC;
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
