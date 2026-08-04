//! Cases the format and the filter have to survive.

mod harness;

use harness::TestRepo;

const SECRET: &[u8] = b"api_key = do-not-commit-me\n";

/// A repository holding one committed secret.
fn repo_with_secret() -> TestRepo {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.write_file("secrets.env", SECRET);
    repo.commit_all("add a secret");
    repo
}

#[test]
fn checkout_restores_the_content_and_leaves_status_clean() {
    let repo = repo_with_secret();

    std::fs::remove_file(repo.path().join("secrets.env")).expect("could not remove the file");
    repo.git_ok(["checkout", "--", "secrets.env"]);

    repo.assert_worktree_eq("secrets.env", SECRET);
    repo.assert_status_clean();
}

#[test]
fn a_clone_without_the_key_shows_the_stored_bytes() {
    let repo = repo_with_secret();
    let stored = repo.blob_bytes("secrets.env");

    let clone = repo.clone_without_filter();

    clone.assert_worktree_eq("secrets.env", &stored);
    assert_ne!(stored, SECRET, "the clone would have exposed the plaintext");
}

#[test]
fn an_empty_file_survives_the_round_trip() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.write_file("empty.env", b"");
    repo.commit_all("add an empty file");

    // 38 bytes of header and synthetic IV, and not one byte more.
    assert_eq!(repo.blob_bytes("empty.env").len(), 38);

    std::fs::remove_file(repo.path().join("empty.env")).expect("could not remove the file");
    repo.git_ok(["checkout", "--", "empty.env"]);

    repo.assert_worktree_eq("empty.env", b"");
    repo.assert_status_clean();
}

#[test]
fn a_binary_file_survives_the_round_trip() {
    let content: Vec<u8> = (0u8..=255).cycle().take(4096).collect();

    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.write_file("binary.env", &content);
    repo.commit_all("add a binary file");

    repo.assert_blob_differs_from_worktree("binary.env");

    std::fs::remove_file(repo.path().join("binary.env")).expect("could not remove the file");
    repo.git_ok(["checkout", "--", "binary.env"]);

    repo.assert_worktree_eq("binary.env", &content);
    repo.assert_status_clean();
}

#[test]
fn the_same_content_always_gives_the_same_blob() {
    let repo = repo_with_secret();
    let first = repo.blob_bytes("secrets.env");

    repo.write_file("secrets.env", b"something else\n");
    repo.commit_all("change it");
    repo.write_file("secrets.env", SECRET);
    repo.commit_all("change it back");

    assert_eq!(
        repo.blob_bytes("secrets.env"),
        first,
        "the same plaintext produced different ciphertext, so git status would never settle"
    );
    repo.assert_status_clean();
}

#[test]
fn a_failing_filter_aborts_the_add() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.break_filter();
    repo.write_file("secrets.env", SECRET);

    let output = repo.git(["add", "secrets.env"]);

    assert!(
        !output.status.success(),
        "git add succeeded although the filter failed — \
         the plaintext would have been committed"
    );
    repo.assert_not_staged("secrets.env");
}

#[test]
fn a_failing_filter_leaves_no_plaintext_object_behind() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.break_filter();
    repo.write_file("secrets.env", SECRET);

    let _ = repo.git(["add", "secrets.env"]);

    assert!(
        !repo.object_exists_for(SECRET),
        "the object database holds the plaintext although the filter failed"
    );
}

#[test]
fn a_second_init_never_replaces_the_key() {
    let repo = repo_with_secret();
    let before = std::fs::read(repo.path().join(".git/git-xcrypt/keys/default"))
        .expect("the key must exist");

    repo.xcrypt_ok(["init"]);

    let after = std::fs::read(repo.path().join(".git/git-xcrypt/keys/default"))
        .expect("the key must still exist");
    assert_eq!(before, after, "a repeated init replaced the repository key");
    repo.assert_status_clean();
}

#[test]
fn init_refuses_in_a_clone_that_has_no_key() {
    let repo = repo_with_secret();
    let clone = repo.clone_without_filter();

    let output = clone.xcrypt(["init"]);

    assert!(
        !output.status.success(),
        "init generated a fresh key in a clone, stranding every existing blob"
    );
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("unlock") || message.contains("import-key"),
        "the refusal must point somewhere useful, got: {message}"
    );
}
