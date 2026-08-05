//! Carrying the repository key to another machine, end to end through the
//! binary and a real git repository.
//!
//! The guardrail these tests exist for is PRD FR-007: the command that hands a
//! key over is the shortest route to a leak, so the key must reach the file it
//! was asked for and nothing else — not `stdout`, not the working tree.

mod harness;

use std::fs;

use harness::TestRepo;
use tempfile::TempDir;

/// A directory outside every repository, to export into.
fn elsewhere() -> TempDir {
    TempDir::new().expect("could not create a temporary directory")
}

#[cfg(unix)]
#[test]
fn an_exported_key_is_readable_only_by_its_owner() {
    use std::os::unix::fs::PermissionsExt as _;

    let repo = TestRepo::init();
    repo.init_xcrypt();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");

    repo.xcrypt_ok(["export-key", &destination.to_string_lossy()]);

    let mode = fs::metadata(&destination)
        .expect("the export must exist")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// A repository with a secret committed and an exported key beside it.
///
/// The first four steps of PRD §Success Criteria, in one helper.
fn repository_with_a_secret(secret: &[u8]) -> (TestRepo, TempDir, std::path::PathBuf) {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n*.env\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", secret);
    repo.write_file("README.md", b"public\n");
    repo.commit_all("a secret and a readme");

    assert!(
        repo.blob_bytes("secrets/db.env").starts_with(MAGIC),
        "the secret reached the object database in the clear"
    );
    repo.assert_blob_eq("README.md", b"public\n");

    let outside = elsewhere();
    let key = outside.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key.to_string_lossy()]);
    (repo, outside, key)
}

/// The leading bytes of our format, as seen from outside the crate.
const MAGIC: &[u8] = b"\0GITXCRYPT\0";

#[test]
fn unlock_with_the_wrong_key_leaves_the_clone_exactly_as_it_was() {
    let (origin, _outside, _key) = repository_with_a_secret(b"api_key = mine\n");

    // A key belonging to a different repository entirely.
    let stranger = TestRepo::init();
    stranger.init_xcrypt();
    let elsewhere = elsewhere();
    let wrong_key = elsewhere.path().join("stranger.key");
    stranger.xcrypt_ok(["export-key", &wrong_key.to_string_lossy()]);

    let clone = origin.clone_without_filter();
    let before = clone.worktree_bytes("secrets/db.env");

    let output = clone.xcrypt(["unlock", &wrong_key.to_string_lossy()]);

    assert_eq!(
        output.status.code(),
        Some(4),
        "expected a format error, stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("secrets/db.env"),
        "the message must name the file it stopped on: {stderr}"
    );
    assert_eq!(
        clone.worktree_bytes("secrets/db.env"),
        before,
        "a refused unlock still rewrote a file"
    );
    assert!(
        !clone.path().join(".git/git-xcrypt/keys/default").exists(),
        "a refused unlock installed the wrong key anyway"
    );
    clone.assert_status_clean();
}

#[test]
fn a_clone_whose_origin_never_committed_gitattributes_still_gets_the_catch_all() {
    // `init` writes `.gitattributes` but does not commit it, so a repository set
    // up with `git add .git-xcrypt secrets/` reaches its clones without the
    // `* filter=git-xcrypt` line. Registering the driver there is not enough:
    // git treats a missing attribute exactly like a missing driver, so the next
    // commit stored the plaintext `unlock` had just written, with exit code 0
    // and no warning. Measured on git 2.55.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    // Keep `.gitattributes` out of the commit without deleting it, the way a
    // user's own ignore rules or a selective `git add` would.
    fs::write(
        repo.path().join(".git").join("info").join("exclude"),
        b".gitattributes\n",
    )
    .expect("writing the exclude file");
    repo.write_file("secrets/db.env", b"api_key = mine\n");
    repo.commit_all("a secret, with no attributes file behind it");
    assert!(repo.blob_bytes("secrets/db.env").starts_with(MAGIC));

    let outside = elsewhere();
    let key = outside.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key.to_string_lossy()]);

    let clone = repo.clone_without_filter();
    assert!(
        !clone.path().join(".gitattributes").exists(),
        "the fixture is wrong: the clone inherited the attributes file"
    );

    clone.xcrypt_ok(["unlock", &key.to_string_lossy()]);

    clone.assert_worktree_eq("secrets/db.env", b"api_key = mine\n");
    clone.write_file("secrets/db.env", b"api_key = changed\n");
    clone.commit_all("a second secret from the clone");

    assert!(
        clone.blob_bytes("secrets/db.env").starts_with(MAGIC),
        "the clone committed the secret in the clear"
    );
}
