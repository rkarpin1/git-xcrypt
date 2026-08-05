//! Closing a repository, end to end through the binary and a real git.
//!
//! `lock` deletes the only copy of a repository's key, so the properties worth
//! proving here are mostly the ones about *not* acting: that a refusal changes
//! nothing, that unsaved work stops the command with or without `--yes`, and
//! that no key material ever leaves through a stream a redirect could capture.
//!
//! The one property about acting is the round trip. `unlock` → `lock` → `unlock`
//! has to give the original bytes back and leave `git status` clean at every
//! step, because that is what proves `lock` writes the same bytes the check-in
//! path already committed rather than merely something that decrypts.

mod harness;

use std::fs;

use harness::TestRepo;
use tempfile::TempDir;

/// The leading bytes of our format, as seen from outside the crate.
const MAGIC: &[u8] = b"\0GITXCRYPT\0";

/// A directory outside every repository, to export into.
fn elsewhere() -> TempDir {
    TempDir::new().expect("could not create a temporary directory")
}

/// A repository holding committed secrets, plus its key exported outside it.
fn repository_with_secrets() -> (TestRepo, TempDir, std::path::PathBuf) {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    // `-text` on the script is the interesting case: its CRLF endings have to
    // survive verbatim, which only holds if lock and the check-in path make the
    // same conversion decision from the same declaration.
    repo.write_xcrypt_config("secrets/\n*.env\nsecrets/deploy.sh -text\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", b"api_key = do-not-commit-me\n");
    repo.write_file("secrets/deploy.sh", b"#!/bin/sh\r\necho hi\r\n");
    repo.write_file("secrets/blob.bin", &(0u8..=255).collect::<Vec<u8>>());
    repo.write_file("secrets/empty.env", b"");
    repo.write_file("README.md", b"public\n");
    repo.commit_all("secrets and a readme");

    assert!(repo.blob_bytes("secrets/db.env").starts_with(MAGIC));
    repo.assert_blob_eq("README.md", b"public\n");

    let outside = elsewhere();
    let key = outside.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key.to_string_lossy()]);
    (repo, outside, key)
}

#[test]
fn another_checkout_of_the_same_repository_stops_lock() {
    // Every worktree reads the key from the common directory, and the walk only
    // ever sees one checkout. Measured before this refusal existed: `lock` in
    // the main worktree left the linked one holding plaintext and deleted the
    // key both depended on, and `lock` there then failed with code 3 — a working
    // tree in the clear with no key left to close it, reached on the success
    // path.
    let (repo, _outside, _key) = repository_with_secrets();
    let linked = repo.add_worktree("side");

    let output = repo.xcrypt(["lock", "--yes"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected a state conflict, stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        repo.path().join(".git/git-xcrypt/keys/default").exists(),
        "the shared key went while another checkout still needed it"
    );
    repo.assert_worktree_eq("secrets/db.env", b"api_key = do-not-commit-me\n");

    // And from the other side, naming the main checkout it would have stranded.
    let from_linked = linked.xcrypt(["lock", "--yes"]);
    assert_eq!(from_linked.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&from_linked.stderr).contains("other checkout"),
        "the message must say why: {}",
        String::from_utf8_lossy(&from_linked.stderr)
    );

    // Removing the worktree clears the way, which is what the message says.
    repo.git_ok([
        "worktree",
        "remove",
        "--force",
        &linked.path().to_string_lossy(),
    ]);
    repo.xcrypt_ok(["lock", "--yes"]);
    assert!(repo.worktree_bytes("secrets/db.env").starts_with(MAGIC));
}

/// A declared file the working-tree walk cannot see under the name the index
/// gives it, which is a checkout `lock` must not close over.
///
/// Measured on git 2.55 and APFS before this refused. `.git-xcrypt` declares
/// `secrets/`, the file is committed as ciphertext, and then the directory is
/// renamed by case alone — one `mv`, and on a case-insensitive filesystem the
/// two names are the same directory, so `git status` stays **clean** and gives
/// the user no signal at all:
///
/// ```text
/// git ls-files              →  secrets/db.env      (the index keeps its spelling)
/// ls -d                     →  Secrets             (the disk keeps the other)
/// git status --porcelain    →  (nothing)
/// git-xcrypt lock --yes     →  "locked; no file here is declared for encryption"
///                              exit 0, key deleted
/// cat Secrets/db.env        →  HUNTER2-SECRET      ← in the clear, no key left
/// ```
///
/// That is the state AGENTS.md names as the one this module exists to make
/// impossible — the key gone and a live checkout still in the clear — and it was
/// reached on the *success* path, not by interruption. `src/gitindex.rs` already
/// described this exact case and claimed the consequence was "on the safe side
/// for `lock`, which then refuses rather than proceeds". It did not refuse.
///
/// The check is deliberately about content, not about spelling: after the
/// encryption pass, every declared path the index tracks that still exists on
/// disk must hold ciphertext. That says nothing about what a pattern *ought* to
/// mean on such a filesystem — open decision 13 — and everything about whether
/// this command has done what it is about to promise.
#[test]
fn lock_refuses_to_delete_the_key_over_a_declared_file_it_left_in_the_clear() {
    let repo = TestRepo::init();
    repo.git_ok(["config", "core.ignorecase", "true"]);
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", b"hunter2-secret\n");
    repo.commit_all("a secret");
    assert!(repo.blob_bytes("secrets/db.env").starts_with(MAGIC));

    let outside = elsewhere();
    let key = outside.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key.to_string_lossy()]);

    fs::rename(repo.path().join("secrets"), repo.path().join("Secrets"))
        .expect("renaming a directory by case must be possible");
    // The premise: git sees nothing at all, so nothing else would warn either.
    // On a case-sensitive filesystem this is a real rename and git says so —
    // the assertion is what keeps this test honest about which platform it is
    // proving something on.
    let moved = repo.git_ok(["status", "--porcelain"]).stdout;
    let case_insensitive = moved.is_empty();

    let output = repo.xcrypt(["lock", "--yes"]);

    if case_insensitive {
        assert_eq!(
            output.status.code(),
            Some(2),
            "lock closed a repository over a declared file it had left in the \
             clear:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            repo.path().join(".git/git-xcrypt/keys/default").exists(),
            "the key was deleted anyway, which is the half that cannot be undone"
        );
        assert_eq!(
            fs::read(repo.path().join("Secrets/db.env")).expect("reading"),
            b"hunter2-secret\n",
            "the file is unchanged, so the user can rename it back and re-run"
        );
        let message = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            message.contains("secrets/db.env"),
            "the refusal does not name the file to look at:\n{message}"
        );
    } else {
        // A case-sensitive filesystem: the rename is a rename, git reports the
        // deletion, and there is no plaintext left at the declared path.
        assert!(
            !moved.is_empty(),
            "a case-sensitive checkout must report the rename"
        );
    }
}
