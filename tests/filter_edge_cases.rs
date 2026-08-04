//! Cases the file format will have to survive once S-01 replaces the
//! placeholder transform with a real cipher.

mod harness;

use harness::TestRepo;

const SECRET: &[u8] = b"api_key = do-not-commit-me\n";
const ATTRIBUTES: &str = "secrets.env filter=git-crypt -text\nempty.env filter=git-crypt -text\nbinary.env filter=git-crypt -text\n";

/// Sets up a repository holding one committed secret.
fn repo_with_secret() -> TestRepo {
    let repo = TestRepo::init();
    repo.register_filter("git-crypt");
    repo.write_attributes(ATTRIBUTES);
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
fn a_clone_without_the_filter_shows_the_stored_bytes() {
    let repo = repo_with_secret();
    let stored = repo.blob_bytes("secrets.env");

    let clone = repo.clone_without_filter();

    clone.assert_worktree_eq("secrets.env", &stored);
    assert_ne!(stored, SECRET, "the clone would have exposed the plaintext");
}

#[test]
fn an_empty_file_survives_the_round_trip() {
    let repo = TestRepo::init();
    repo.register_filter("git-crypt");
    repo.write_attributes(ATTRIBUTES);
    repo.write_file("empty.env", b"");
    repo.commit_all("add an empty file");

    // The blob does equal the working tree here: reversing nothing yields
    // nothing. What matters is that the filter neither errors nor adds padding.
    repo.assert_blob_eq("empty.env", b"");

    std::fs::remove_file(repo.path().join("empty.env")).expect("could not remove the file");
    repo.git_ok(["checkout", "--", "empty.env"]);

    repo.assert_worktree_eq("empty.env", b"");
    repo.assert_status_clean();
}

#[test]
fn a_binary_file_survives_the_round_trip() {
    let content: Vec<u8> = (0u8..=255).cycle().take(4096).collect();

    let repo = TestRepo::init();
    repo.register_filter("git-crypt");
    repo.write_attributes(ATTRIBUTES);
    repo.write_file("binary.env", &content);
    repo.commit_all("add a binary file");

    repo.assert_blob_differs_from_worktree("binary.env");

    std::fs::remove_file(repo.path().join("binary.env")).expect("could not remove the file");
    repo.git_ok(["checkout", "--", "binary.env"]);

    repo.assert_worktree_eq("binary.env", &content);
    repo.assert_status_clean();
}

#[test]
fn a_failing_filter_aborts_the_add() {
    let repo = TestRepo::init();
    repo.register_failing_filter("git-crypt");
    repo.write_attributes(ATTRIBUTES);
    repo.write_file("secrets.env", SECRET);

    let output = repo.git(["add", "secrets.env"]);

    assert!(
        !output.status.success(),
        "git add succeeded although the clean filter failed — \
         the plaintext would have been committed"
    );
    repo.assert_not_staged("secrets.env");
}

#[test]
fn a_failing_filter_leaves_no_plaintext_object_behind() {
    let repo = TestRepo::init();
    repo.register_failing_filter("git-crypt");
    repo.write_attributes(ATTRIBUTES);
    repo.write_file("secrets.env", SECRET);

    let _ = repo.git(["add", "secrets.env"]);

    assert!(
        !repo.object_exists_for(SECRET),
        "the object database holds the plaintext although the filter failed"
    );
}
