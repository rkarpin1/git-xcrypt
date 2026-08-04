//! The founding document's acceptance criteria, as one test.
//!
//! `context/foundation/zalozenia.md` §Kryteria akceptacji and `prd.md`
//! §Success Criteria → Primary both state the same six steps and both say the
//! product counts as working when they pass **automatically**. Every step was
//! covered somewhere before this file existed, but never in one run and never
//! across a push: the suite compared blobs in the repository the filter had
//! just written and cloned from a working tree, so `receive-pack` — which
//! re-reads, re-packs and re-writes every object it accepts — was never once
//! exercised. "The blobs in the remote repository are encrypted" is a claim
//! about a remote.
//!
//! Kept apart from the per-command files on purpose. Those test a command;
//! this tests the promise, and it has to keep failing for the right reason if
//! any one of them regresses.

mod harness;

use harness::{BareRemote, TestRepo};

/// The two files the criteria name, from the two patterns they name.
const PASSWORD: &[u8] = b"correct horse battery staple\n";
const DOTENV: &[u8] = b"DATABASE_URL=postgres://user:hunter2@localhost/app\n";

#[test]
fn the_six_step_acceptance_scenario_passes_end_to_end() {
    // 1. `git init` plus `git-xcrypt init` in a new repository.
    let repo = TestRepo::init();
    repo.init_xcrypt();

    // 2. `secrets/` and `*.env` written into `.git-xcrypt`.
    repo.write_xcrypt_config("secrets/\n*.env\n");
    repo.xcrypt_ok(["sync"]);

    // 3. Commit `secrets/password.txt` and `.env`, then push to a remote.
    repo.write_file("secrets/password.txt", PASSWORD);
    repo.write_file(".env", DOTENV);
    repo.write_file("README.md", b"# ordinary project\n");
    repo.commit_all("a secret and a dotenv");

    let remote = BareRemote::new();
    repo.push_to(&remote, "main");

    // 4. The blobs in the *remote* are ciphertext; `.git-xcrypt` and
    //    `.gitattributes` stay readable there.
    for (path, plaintext) in [("secrets/password.txt", PASSWORD), (".env", DOTENV)] {
        let stored = remote.blob_bytes("main", path);
        assert!(
            stored.starts_with(b"\0GITXCRYPT\0"),
            "{path} did not arrive at the remote encrypted"
        );
        assert_eq!(
            stored.len(),
            plaintext.len() + 38,
            "{path}: the remote's blob is not header plus content"
        );
        assert!(
            !remote.object_exists_for(plaintext),
            "{path}: the plaintext itself is an object in the remote"
        );
    }
    for path in [".git-xcrypt", ".gitattributes", "README.md"] {
        let stored = remote.blob_bytes("main", path);
        assert!(
            !stored.starts_with(b"\0GITXCRYPT\0"),
            "{path} must stay readable in the remote: without it a clone cannot \
             bootstrap, and the criteria say so explicitly"
        );
    }

    // The key must not have travelled with any of it.
    let key = std::fs::read(repo.path().join(".git/git-xcrypt/keys/default"))
        .expect("the repository key must be on disk");
    assert!(
        !remote.object_exists_for(&key),
        "the key file reached the remote's object database"
    );

    // 5. A clone on a second machine, unlocked with the carried key, gives the
    //    original bytes back.
    let carried = TestRepo::init(); // somewhere outside either repository
    let key_file = carried.path().join("carried.key");
    repo.xcrypt_ok(["export-key", &key_file.to_string_lossy()]);

    let clone = remote.clone_to();
    assert_eq!(
        clone.worktree_bytes("secrets/password.txt")[..11],
        *b"\0GITXCRYPT\0",
        "before `unlock` a clone must show ciphertext, not plaintext"
    );

    clone.xcrypt_ok(["unlock", &key_file.to_string_lossy()]);
    clone.assert_worktree_eq("secrets/password.txt", PASSWORD);
    clone.assert_worktree_eq(".env", DOTENV);
    clone.assert_worktree_eq("README.md", b"# ordinary project\n");

    // 6. `git status` after `unlock` is clean — the determinism proof.
    clone.assert_status_clean();

    // And the loop closes: re-adding the decrypted files reproduces the blobs
    // the remote already holds, which is the property step 6 is a proxy for.
    clone.git_ok(["add", "-A"]);
    clone.assert_status_clean();
}

#[test]
fn a_clone_without_the_key_reports_it_readably_rather_than_panicking() {
    // US-01's first acceptance criterion, whose second half — "a readable
    // error, not a panic" — was asserted only as an exit code. A panic exits
    // 101, so the code alone rules one out; it says nothing about whether the
    // user is told anything they can act on.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/password.txt", PASSWORD);
    repo.commit_all("secret");

    let remote = BareRemote::new();
    repo.push_to(&remote, "main");
    let clone = remote.clone_to();

    // Ciphertext, and only ciphertext.
    let seen = clone.worktree_bytes("secrets/password.txt");
    assert!(seen.starts_with(b"\0GITXCRYPT\0"));
    assert!(
        !seen.windows(PASSWORD.len()).any(|w| w == PASSWORD),
        "the plaintext is visible in a clone that holds no key"
    );

    let output = clone.xcrypt(["unlock"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(3),
        "the frozen table gives a missing key its own code:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "a missing key must not be a panic:\n{stderr}"
    );
    assert!(
        stderr.contains("key"),
        "the message must at least name what is missing:\n{stderr}"
    );
    assert!(
        stderr.contains("unlock") || stderr.contains("import-key") || stderr.contains("export-key"),
        "the message must point at the command that fixes it, or it is a \
         diagnosis with no cure:\n{stderr}"
    );
}
