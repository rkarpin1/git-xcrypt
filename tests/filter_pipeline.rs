//! The vertical slice: one `init`, one pattern, and git stores ciphertext.

mod harness;

use harness::TestRepo;

const SECRET: &[u8] = b"api_key = do-not-commit-me\n";

/// The whole user-facing setup, as the product promises it.
fn configured_repo() -> TestRepo {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\nsecrets/\n");
    repo
}

#[test]
fn a_committed_secret_is_stored_encrypted() {
    let repo = configured_repo();
    repo.write_file("secrets.env", SECRET);

    repo.commit_all("add a secret");

    repo.assert_worktree_eq("secrets.env", SECRET);
    let blob = repo.blob_bytes("secrets.env");
    assert!(
        blob.starts_with(b"\0GITXCRYPT\0"),
        "the stored blob does not carry our magic, so the filter never ran"
    );
    assert!(
        !blob.windows(SECRET.len()).any(|window| window == SECRET),
        "the plaintext is present in the object database"
    );
}

#[test]
fn unmatched_files_are_stored_verbatim() {
    let repo = configured_repo();
    repo.write_file("readme.md", b"public\n");
    repo.write_file("assets/logo.bin", &(0u8..=255).collect::<Vec<u8>>());

    repo.commit_all("add public files");

    repo.assert_blob_eq("readme.md", b"public\n");
    repo.assert_blob_eq("assets/logo.bin", &(0u8..=255).collect::<Vec<u8>>());
}

#[test]
fn the_bootstrap_files_are_never_encrypted() {
    let repo = configured_repo();
    repo.write_file("secrets.env", SECRET);

    repo.commit_all("add a secret");

    // If either of these were encrypted, nothing could bootstrap: git needs
    // .gitattributes to call us at all, and we need .git-xcrypt to know what to do.
    assert!(repo.blob_bytes(".gitattributes").starts_with(b"#"));
    assert!(repo.blob_bytes(".git-xcrypt").starts_with(b"*.env"));
}

#[test]
fn a_negated_path_stays_in_the_clear() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n!secrets/README.md\n");
    repo.write_file("secrets/password", SECRET);
    repo.write_file("secrets/README.md", b"how to use this directory\n");

    repo.commit_all("add secrets with an exception");

    assert!(
        repo.blob_bytes("secrets/password")
            .starts_with(b"\0GITXCRYPT\0")
    );
    repo.assert_blob_eq("secrets/README.md", b"how to use this directory\n");
}

#[test]
fn one_filter_process_serves_a_whole_operation() {
    let repo = configured_repo();
    for index in 0..25 {
        repo.write_file(&format!("secrets/file{index}.txt"), SECRET);
    }

    repo.commit_all("add many secrets");

    for index in 0..25 {
        assert!(
            repo.blob_bytes(&format!("secrets/file{index}.txt"))
                .starts_with(b"\0GITXCRYPT\0"),
            "file{index} was not encrypted"
        );
    }
}
