//! Reviewing changes to a secret — FR-006, as a day's work rather than a
//! command.
//!
//! The requirement is that the user reads *their own content* when they look at
//! what changed. Nothing in the product is called for that to happen: git is,
//! through the `textconv` driver `init` registers and the `diff=git-xcrypt`
//! attribute `sync` renders. So the scenario is the whole review loop — edit,
//! `git diff`, commit, `git log -p`, `git show`, a diff between two historical
//! commits — and the assertion is always the same two things: the plaintext
//! lines are there, and our magic is nowhere on the screen.
//!
//! Measured on git 2.55, and both halves are counter-intuitive enough to state:
//!
//! * git materialises **each side of a diff through the smudge filter** before
//!   handing it to `textconv`, so in a healthy repository the driver receives
//!   plaintext and never decrypts anything. What its presence buys is that git
//!   compares the converted text at all — with the driver unregistered the very
//!   same repository answers `Binary files ... differ` and the user sees nothing.
//! * the decrypting branch is reached in exactly one state, and it is a state
//!   this product already calls a finding: a foreign attribute line takes the
//!   filter off a declared path, so git has nothing to smudge with and hands the
//!   driver the stored ciphertext. The last section drives it, because a branch
//!   no test reaches is a branch that can be deleted without a single red line —
//!   measured, with `convert` reduced to a pass-through the whole suite stayed
//!   green.
//! * and in a repository with no key at all, the registration has to be *gone*,
//!   or the failing smudge filter drags `git log -p` down with it.

mod harness;

use git_xcrypt::format::MAGIC;
use harness::TestRepo;

const FIRST: &[u8] = b"api_key = one\nshared line\n";
const SECOND: &[u8] = b"api_key = two\nshared line\n";
const THIRD: &[u8] = b"api_key = three\nshared line\n";

/// A repository set up the way a user would, with `secrets/` declared.
fn prepared() -> TestRepo {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
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

/// Runs a git command and grades its output as a review of plaintext.
///
/// `wanted` are the lines the user must be able to read. The two negative
/// checks are the ones that catch a silent regression: `Binary files` is what
/// git falls back to when the driver is not consulted, and the magic is what
/// reaches the screen when it is consulted and does nothing.
fn review(repo: &TestRepo, arguments: &[&str], wanted: &[&str]) {
    let output = repo.git_ok(arguments);
    let rendered = text(&output.stdout);
    let label = arguments.join(" ");

    for line in wanted {
        assert!(
            rendered.contains(line),
            "`git {label}` did not show `{line}`:\n{rendered}"
        );
    }
    assert!(
        !rendered.contains("Binary files"),
        "`git {label}` fell back to git's answer for content it cannot read, so \
         the diff driver was never consulted:\n{rendered}"
    );
    assert!(
        !carries_magic(&output.stdout),
        "`git {label}` put ciphertext on the user's screen"
    );
}

#[test]
fn a_secret_is_reviewed_as_plaintext_at_every_point_a_user_looks_at_it() {
    let repo = prepared();

    // --- The first version, and an edit that is not committed yet. ----------
    repo.write_file("secrets/db.env", FIRST);
    repo.write_file("README.md", b"# ordinary project\n");
    repo.commit_all("declare a secret");
    repo.write_file("secrets/db.env", SECOND);

    // The premise: what git stores is ciphertext, so everything below is the
    // driver's doing rather than a file that was never encrypted.
    assert!(
        repo.blob_is_encrypted("secrets/db.env"),
        "the fixture is not encrypted, so this test grades nothing"
    );

    review(
        &repo,
        &["--no-pager", "diff", "--", "secrets/db.env"],
        &["-api_key = one", "+api_key = two", " shared line"],
    );

    // --- Committed, the same edit is read back out of history. --------------
    repo.commit_all("rotate the key");

    review(
        &repo,
        &["--no-pager", "show", "HEAD", "--", "secrets/db.env"],
        &["-api_key = one", "+api_key = two"],
    );
    review(
        &repo,
        &["--no-pager", "log", "-p", "--", "secrets/db.env"],
        &["+api_key = one", "-api_key = one", "+api_key = two"],
    );

    // --- And between two commits neither of which is in the working tree. ---
    repo.write_file("secrets/db.env", THIRD);
    repo.commit_all("rotate it again");
    repo.assert_status_clean();

    review(
        &repo,
        &[
            "--no-pager",
            "diff",
            "HEAD~2",
            "HEAD~1",
            "--",
            "secrets/db.env",
        ],
        &["-api_key = one", "+api_key = two"],
    );

    // An undeclared file is git's own business and must read exactly as it
    // always did.
    repo.write_file("README.md", b"# a better project\n");
    review(
        &repo,
        &["--no-pager", "diff", "--", "README.md"],
        &["-# ordinary project", "+# a better project"],
    );
    repo.git_ok(["checkout", "--", "README.md"]);
}

#[test]
fn a_declared_path_git_stopped_filtering_is_still_reviewed_as_plaintext() {
    // The one state where the driver is handed the stored bytes instead of a
    // smudged copy, and it is not hypothetical: a foreign attribute line below
    // the managed section takes `filter` off a declared path, git takes the last
    // match, and from then on it has nothing to convert the blobs with. Measured
    // on git 2.55 — `git check-attr filter` answers `unset`, `diff` still
    // answers `git-xcrypt`, and the driver receives ciphertext.
    //
    // `status` calls this a setup gap and fails the gate over it, which is the
    // right response. It is also precisely why the driver must still decrypt:
    // the user who is about to be told to fix their attributes has to be able to
    // read what their history holds while they do it.
    let repo = prepared();
    repo.write_file("secrets/db.env", FIRST);
    repo.commit_all("declare a secret");
    repo.write_file("secrets/db.env", SECOND);
    repo.commit_all("rotate the key");

    let mut attributes = repo.worktree_bytes(".gitattributes");
    attributes.extend_from_slice(b"secrets/** -filter\n");
    repo.write_file(".gitattributes", &attributes);
    repo.git_ok(["add", ".gitattributes"]);
    repo.git_ok(["commit", "-q", "-m", "a foreign line takes the filter off"]);

    // The premise, asked of git rather than assumed.
    assert_eq!(
        repo.check_attr("filter", "secrets/db.env"),
        "unset",
        "the fixture no longer takes the filter off the declared path"
    );
    assert_eq!(
        repo.check_attr("diff", "secrets/db.env"),
        "git-xcrypt",
        "the fixture no longer leaves the diff driver on"
    );

    review(
        &repo,
        &[
            "--no-pager",
            "diff",
            "HEAD~2",
            "HEAD~1",
            "--",
            "secrets/db.env",
        ],
        &["-api_key = one", "+api_key = two"],
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
    repo.write_file("secrets/db.env", FIRST);
    repo.commit_all("first");
    repo.xcrypt_ok(["lock", "--yes"]);

    assert!(
        !repo
            .git(["config", "--get", "diff.git-xcrypt.textconv"])
            .status
            .success(),
        "lock left a diff driver that has no key behind it"
    );

    let output = repo.git(["--no-pager", "log", "-p", "--", "secrets/db.env"]);
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
