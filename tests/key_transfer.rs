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

/// The base64 line of an exported key file — the secret itself.
fn key_material(path: &std::path::Path) -> String {
    let text = fs::read_to_string(path).expect("the export must be readable text");
    text.lines()
        .nth(1)
        .expect("an export has a header and a key")
        .to_string()
}

#[test]
fn export_key_writes_the_key_to_the_file_and_nothing_to_stdout() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");

    let output = repo.xcrypt_ok(["export-key", &destination.to_string_lossy()]);

    assert!(
        output.stdout.is_empty(),
        "export-key wrote to stdout, which a redirect would capture: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(destination.is_file(), "the key never reached the file");

    let secret = key_material(&destination);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !stderr.contains(&secret),
        "the key itself appeared in the command's own diagnostics"
    );
    assert!(
        stderr.contains("wrote key"),
        "the user was told nothing: {stderr}"
    );
}

#[test]
fn export_key_refuses_to_write_inside_the_working_tree() {
    let repo = TestRepo::init();
    repo.init_xcrypt();

    // Exactly the mistake FR-007 names: run it while standing in the repository
    // and give it a bare filename.
    let output = repo.xcrypt(["export-key", "repo.key"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected a state conflict, stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !repo.path().join("repo.key").exists(),
        "the refusal still left a key in the working tree"
    );
}

#[test]
fn export_key_reports_a_missing_key_rather_than_inventing_one() {
    // A plain git repository: `init` was never run, so there is nothing to
    // export. Code 3 is the frozen "no key" code.
    let repo = TestRepo::init();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");

    let output = repo.xcrypt(["export-key", &destination.to_string_lossy()]);

    assert_eq!(output.status.code(), Some(3));
    assert!(!destination.exists());
}

#[test]
fn export_key_refuses_to_replace_a_file_unless_told_to() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");
    fs::write(&destination, b"another repository's key\n").expect("writing");

    let refused = repo.xcrypt(["export-key", &destination.to_string_lossy()]);
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        fs::read(&destination).expect("reading"),
        b"another repository's key\n",
        "a mistyped path destroyed a key file"
    );

    repo.xcrypt_ok(["export-key", "--force", &destination.to_string_lossy()]);
    assert!(
        fs::read_to_string(&destination)
            .expect("reading")
            .starts_with("git-xcrypt-key-v1 ")
    );
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
fn a_clone_unlocked_with_the_carried_key_gives_the_original_bytes_back() {
    // US-01 end to end, and PRD §Success Criteria steps 1 through 6.
    let secret = b"api_key = do-not-commit-me\npassword = hunter2\n";
    let (origin, _outside, key) = repository_with_a_secret(secret);

    let clone = origin.clone_without_filter();

    // Step 5, first half: without the key the clone shows ciphertext.
    assert!(
        clone.worktree_bytes("secrets/db.env").starts_with(MAGIC),
        "a clone without a key showed the secret in the clear"
    );

    clone.xcrypt_ok(["unlock", &key.to_string_lossy()]);

    // Step 5, second half, and step 6.
    clone.assert_worktree_eq("secrets/db.env", secret);
    clone.assert_worktree_eq("README.md", b"public\n");
    clone.assert_status_clean();

    // The registration a clone cannot inherit, and the proof it works: a new
    // secret committed from here has to reach the object database encrypted.
    let process = clone.git_ok(["config", "--get", "filter.git-xcrypt.process"]);
    assert!(
        !process.stdout.is_empty(),
        "unlock left the clone with no filter, so the next `git add` would leak"
    );
    let required = clone.git_ok(["config", "--get", "filter.git-xcrypt.required"]);
    assert_eq!(
        String::from_utf8_lossy(&required.stdout).trim(),
        "true",
        "without required = true a failing filter commits the plaintext"
    );

    clone.write_file("secrets/second.env", b"token = another-secret\n");
    clone.commit_all("a second secret, from the clone");
    assert!(clone.blob_bytes("secrets/second.env").starts_with(MAGIC));
    clone.assert_worktree_eq("secrets/second.env", b"token = another-secret\n");
}

#[test]
fn unlocking_twice_in_a_row_changes_nothing() {
    let secret = b"api_key = do-not-commit-me\n";
    let (origin, _outside, key) = repository_with_a_secret(secret);
    let clone = origin.clone_without_filter();
    clone.xcrypt_ok(["unlock", &key.to_string_lossy()]);

    // The second run takes no key: the repository already holds one.
    let output = clone.xcrypt_ok(["unlock"]);

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("nothing was encrypted"),
        "a settled working tree was converted again: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    clone.assert_worktree_eq("secrets/db.env", secret);
    clone.assert_status_clean();
}

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
fn a_clone_can_be_unlocked_by_importing_the_key_first() {
    let secret = b"api_key = do-not-commit-me\n";
    let (origin, _outside, key) = repository_with_a_secret(secret);
    let clone = origin.clone_without_filter();

    clone.xcrypt_ok(["import-key", &key.to_string_lossy()]);
    clone.xcrypt_ok(["unlock"]);

    clone.assert_worktree_eq("secrets/db.env", secret);
    clone.assert_status_clean();
}

#[test]
fn import_key_is_empty_for_the_same_key_and_refuses_a_different_one() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    let outside = elsewhere();
    let mine = outside.path().join("mine.key");
    repo.xcrypt_ok(["export-key", &mine.to_string_lossy()]);

    let again = repo.xcrypt_ok(["import-key", &mine.to_string_lossy()]);
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("nothing to import"),
        "re-importing the same key must be an empty success"
    );

    let stranger = TestRepo::init();
    stranger.init_xcrypt();
    let theirs = outside.path().join("theirs.key");
    stranger.xcrypt_ok(["export-key", &theirs.to_string_lossy()]);

    let refused = repo.xcrypt(["import-key", &theirs.to_string_lossy()]);
    assert_eq!(refused.status.code(), Some(2));

    // The original key survived the refusal, byte for byte.
    let check = outside.path().join("check.key");
    repo.xcrypt_ok(["export-key", &check.to_string_lossy()]);
    assert_eq!(
        fs::read(&check).expect("reading"),
        fs::read(&mine).expect("reading"),
        "a refused import replaced the key anyway"
    );
}

#[test]
fn a_real_edit_after_unlock_is_still_reported_as_a_change() {
    // `unlock` clears the size git cached for each file it rewrote, so that git
    // compares content instead of trusting a stale stat. The danger of that edit
    // is the opposite one: git must not come out of it blind.
    let secret = b"api_key = do-not-commit-me\n";
    let (origin, _outside, key) = repository_with_a_secret(secret);
    let clone = origin.clone_without_filter();
    clone.xcrypt_ok(["unlock", &key.to_string_lossy()]);
    clone.assert_status_clean();

    clone.write_file("secrets/db.env", b"api_key = changed-by-hand\n");

    let status = clone.git_ok(["status", "--porcelain"]);
    assert_eq!(
        String::from_utf8_lossy(&status.stdout).trim(),
        "M secrets/db.env",
        "a real edit went unnoticed after unlock touched the index"
    );

    // And the change still round-trips through the filter.
    clone.commit_all("an edit");
    assert!(clone.blob_bytes("secrets/db.env").starts_with(MAGIC));
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

#[test]
fn unlock_without_a_key_anywhere_reports_a_missing_key() {
    let (origin, _outside, _key) = repository_with_a_secret(b"api_key = mine\n");
    let clone = origin.clone_without_filter();

    let output = clone.xcrypt(["unlock"]);

    assert_eq!(output.status.code(), Some(3));
    assert!(clone.worktree_bytes("secrets/db.env").starts_with(MAGIC));
}

#[test]
fn a_key_file_from_a_future_version_is_refused_rather_than_guessed() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &destination.to_string_lossy()]);

    let text = fs::read_to_string(&destination).expect("reading");
    let from_the_future = outside.path().join("future.key");
    fs::write(
        &from_the_future,
        text.replace("git-xcrypt-key-v1", "git-xcrypt-key-v2"),
    )
    .expect("writing");

    // Nothing reads a key file yet except `export-key`'s own round trip, so the
    // refusal is asserted where it is decided; `import-key` and `unlock` pick it
    // up in the next phase.
    assert!(
        git_xcrypt::keyfile::read_portable(&from_the_future).is_err(),
        "a newer key format must fail closed"
    );
}
