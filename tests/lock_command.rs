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

/// The base64 line of an exported key file — the secret itself.
fn key_material(path: &std::path::Path) -> String {
    let text = fs::read_to_string(path).expect("the export must be readable text");
    text.lines()
        .nth(1)
        .expect("an export has a header and a key")
        .to_string()
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

/// The working-tree files this fixture cares about and their original bytes.
fn originals() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("secrets/db.env", b"api_key = do-not-commit-me\n".to_vec()),
        ("secrets/deploy.sh", b"#!/bin/sh\r\necho hi\r\n".to_vec()),
        ("secrets/blob.bin", (0u8..=255).collect()),
        ("secrets/empty.env", Vec::new()),
        ("README.md", b"public\n".to_vec()),
    ]
}

#[test]
fn unlock_lock_unlock_gives_the_original_bytes_back_and_stays_clean_throughout() {
    let (repo, _outside, key) = repository_with_secrets();
    repo.assert_status_clean();

    // Locking a repository whose working tree is already in the clear.
    repo.xcrypt_ok(["lock", "--yes"]);

    for name in ["secrets/db.env", "secrets/deploy.sh", "secrets/blob.bin"] {
        assert!(
            repo.worktree_bytes(name).starts_with(MAGIC),
            "{name} was left in the clear by lock"
        );
        // The proof that lock wrote what the check-in path would have written:
        // anything else and this would differ, whatever it decrypted to.
        assert_eq!(
            repo.worktree_bytes(name),
            repo.blob_bytes(name),
            "{name}: lock wrote bytes the repository does not store"
        );
    }
    assert_eq!(
        repo.worktree_bytes("README.md"),
        b"public\n",
        "an undeclared file was rewritten"
    );
    assert!(
        !repo.path().join(".git/git-xcrypt/keys/default").exists(),
        "lock left the key behind"
    );
    repo.assert_status_clean();

    // And back again, with the copy that was made before the key went.
    repo.xcrypt_ok(["unlock", &key.to_string_lossy()]);
    for (name, expected) in originals() {
        repo.assert_worktree_eq(name, &expected);
    }
    repo.assert_status_clean();

    // A third pass, to show neither direction drifts.
    repo.xcrypt_ok(["lock", "--yes"]);
    repo.assert_status_clean();
    repo.xcrypt_ok(["unlock", &key.to_string_lossy()]);
    for (name, expected) in originals() {
        repo.assert_worktree_eq(name, &expected);
    }
    repo.assert_status_clean();
}

#[test]
fn lock_writes_nothing_to_stdout_and_never_names_the_key() {
    let (repo, _outside, key) = repository_with_secrets();

    let output = repo.xcrypt_ok(["lock", "--yes"]);

    assert!(
        output.stdout.is_empty(),
        "lock wrote to stdout, which a redirect would capture: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !stderr.contains(&key_material(&key)),
        "the key itself appeared in the command's own diagnostics"
    );

    // The fingerprint, on the other hand, has to be there: it is what tells the
    // user which exported file will open this repository again.
    let key_id = fs::read_to_string(&key)
        .expect("reading the export")
        .lines()
        .next()
        .expect("a header")
        .rsplit(' ')
        .next()
        .expect("a fingerprint")
        .to_string();
    assert!(
        stderr.contains(&key_id),
        "the warning did not say which key is being deleted: {stderr}"
    );
    assert!(
        stderr.contains("WILL NOT UNDO"),
        "the warning did not say that unlock cannot undo this: {stderr}"
    );
    assert!(
        stderr.contains("export-key"),
        "the warning did not say how to keep a copy: {stderr}"
    );
}

#[test]
fn an_unsaved_change_stops_lock_with_and_without_yes() {
    for arguments in [vec!["lock"], vec!["lock", "--yes"]] {
        let (repo, _outside, _key) = repository_with_secrets();
        repo.write_file("secrets/db.env", b"api_key = changed-by-hand\n");

        let output = repo.xcrypt(arguments.clone());

        assert_eq!(
            output.status.code(),
            Some(2),
            "{arguments:?}: expected a state conflict, stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("secrets/db.env"),
            "{arguments:?}: the message must name the file: {stderr}"
        );
        assert_eq!(
            repo.worktree_bytes("secrets/db.env"),
            b"api_key = changed-by-hand\n",
            "{arguments:?}: a refused lock rewrote the file"
        );
        assert!(
            repo.path().join(".git/git-xcrypt/keys/default").exists(),
            "{arguments:?}: a refused lock deleted the key anyway"
        );
    }
}

#[test]
fn an_untracked_declared_file_stops_lock() {
    let (repo, _outside, _key) = repository_with_secrets();
    repo.write_file("secrets/new.env", b"token = never added\n");

    let output = repo.xcrypt(["lock", "--yes"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        repo.worktree_bytes("secrets/new.env"),
        b"token = never added\n"
    );
    assert!(repo.path().join(".git/git-xcrypt/keys/default").exists());
}

#[test]
fn the_interactive_question_needs_the_word_yes() {
    for answer in ["no\n", "y\n", "YES\n", "\n", ""] {
        let (repo, _outside, _key) = repository_with_secrets();

        let output = repo.xcrypt_with_stdin(["lock"], answer.as_bytes());

        assert_eq!(
            output.status.code(),
            Some(1),
            "answering {answer:?} went ahead anyway; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            repo.path().join(".git/git-xcrypt/keys/default").exists(),
            "answering {answer:?} deleted the key"
        );
        repo.assert_worktree_eq("secrets/db.env", b"api_key = do-not-commit-me\n");
        repo.assert_status_clean();
    }
}

#[test]
fn the_interactive_question_accepts_the_word_yes() {
    let (repo, _outside, key) = repository_with_secrets();

    let output = repo.xcrypt_with_stdin(["lock"], b"yes\n");

    assert!(
        output.status.success(),
        "typing yes did not lock: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "the prompt went to stdout");
    assert!(repo.worktree_bytes("secrets/db.env").starts_with(MAGIC));
    assert!(!repo.path().join(".git/git-xcrypt/keys/default").exists());
    repo.assert_status_clean();

    repo.xcrypt_ok(["unlock", &key.to_string_lossy()]);
    repo.assert_worktree_eq("secrets/db.env", b"api_key = do-not-commit-me\n");
}

#[test]
fn locking_twice_reports_a_missing_key_rather_than_touching_anything() {
    let (repo, _outside, _key) = repository_with_secrets();
    repo.xcrypt_ok(["lock", "--yes"]);
    let after = repo.worktree_bytes("secrets/db.env");

    let output = repo.xcrypt(["lock", "--yes"]);

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        repo.worktree_bytes("secrets/db.env"),
        after,
        "a second lock rewrote an already encrypted file"
    );
}

#[test]
fn lock_in_a_repository_that_never_had_a_key_reports_one_missing() {
    let repo = TestRepo::init();
    let output = repo.xcrypt(["lock", "--yes"]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn a_locked_repository_refuses_to_commit_a_new_secret_rather_than_leaking_it() {
    // With the key gone the clean path cannot encrypt, and `required = true`
    // turns that into an aborted `git add`. The alternative — git treating the
    // failure as harmless — is exactly the plaintext-in-the-object-database
    // failure the whole construction exists to prevent.
    let (repo, _outside, _key) = repository_with_secrets();
    repo.xcrypt_ok(["lock", "--yes"]);

    repo.write_file("secrets/fresh.env", b"token = leaked?\n");
    let added = repo.git(["add", "secrets/fresh.env"]);

    assert!(
        !added.status.success(),
        "git add succeeded in a locked repository: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    repo.assert_not_staged("secrets/fresh.env");
    assert!(
        !repo.object_exists_for(b"token = leaked?\n"),
        "the plaintext reached the object database from a locked repository"
    );
}

#[test]
fn residue_from_a_killed_run_does_not_survive_lock() {
    // A killed `unlock` leaves a decrypted secret beside the file it was
    // rewriting, under a name `*.env` does not cover. Leaving it there would let
    // a later `git add -A` commit the plaintext lock was meant to remove.
    let (repo, _outside, _key) = repository_with_secrets();
    repo.write_file(
        "secrets/db.env.git-xcrypt-a1b2c3d4e5f60718.tmp",
        b"api_key = do-not-commit-me\n",
    );

    let output = repo.xcrypt_ok(["lock", "--yes"]);

    assert!(
        !repo
            .path()
            .join("secrets/db.env.git-xcrypt-a1b2c3d4e5f60718.tmp")
            .exists(),
        "a decrypted leftover survived lock"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("interrupted run"),
        "the sweep went unmentioned: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    repo.assert_status_clean();
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

#[test]
fn a_checkout_whose_back_pointer_is_broken_still_stops_lock() {
    // A worktree moved with `mv` rather than `git worktree move` is fully alive
    // while its `gitdir` back-pointer names nothing. Measured before this: lock
    // read that as a stale registration, deleted the key, and left the moved
    // checkout holding plaintext it could no longer close.
    let (repo, _outside, _key) = repository_with_secrets();
    let linked = repo.add_worktree("side");
    let moved = linked.path().with_file_name("side-moved");
    fs::rename(linked.path(), &moved).expect("moving the checkout");

    let output = repo.xcrypt(["lock", "--yes"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "a live checkout was treated as a stale registration: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("worktree prune"),
        "the message must name the way out: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(repo.path().join(".git/git-xcrypt/keys/default").exists());
    assert_eq!(
        fs::read(moved.join("secrets/db.env")).expect("reading"),
        b"api_key = do-not-commit-me\n"
    );
}

#[test]
fn a_cosmetic_drift_in_gitattributes_does_not_dirty_the_tree() {
    // `.git-xcrypt` is the source of truth and its `.gitattributes` lines are
    // cosmetic, so drift is the documented normal state and `sync` is what
    // resolves it. Rewriting the section here left `git status` dirty behind a
    // command that reported success and had already deleted the key.
    let (repo, _outside, _key) = repository_with_secrets();
    repo.write_xcrypt_config("secrets/\n*.env\nsecrets/deploy.sh -text\n*.pem\n");
    repo.commit_all("a pattern sync has not seen");
    repo.assert_status_clean();

    repo.xcrypt_ok(["lock", "--yes"]);

    repo.assert_status_clean();
}

#[test]
fn a_second_lock_after_an_interrupted_one_leaves_a_clean_tree() {
    // The first run's files are already ciphertext, so the second skips them —
    // and passing only the files it rewrote to the stat-cache patch left the
    // first run's output reported as modified for good.
    let (repo, _outside, _key) = repository_with_secrets();
    // Make one file unwritable so the first run stops part way through.
    let blocked = repo.path().join("secrets/sub");
    fs::create_dir_all(&blocked).expect("directories");
    repo.write_file("secrets/sub/late.env", b"token = second\n");
    repo.commit_all("a second secret");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o555)).expect("chmod");

        let first = repo.xcrypt(["lock", "--yes"]);
        assert!(
            !first.status.success(),
            "the fixture did not interrupt lock"
        );
        assert!(
            String::from_utf8_lossy(&first.stderr).contains("late.env"),
            "the failure did not name the file: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert!(
            repo.path().join(".git/git-xcrypt/keys/default").exists(),
            "a part-way failure deleted the key"
        );

        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).expect("chmod");
        repo.xcrypt_ok(["lock", "--yes"]);
        repo.assert_status_clean();
    }
}

#[test]
fn a_tracked_file_shaped_like_our_residue_is_not_deleted() {
    // The sweep is a deletion list, so its false positives cost a user their
    // file. Residue of ours is never tracked; anything that is belongs to them.
    let (repo, _outside, _key) = repository_with_secrets();
    repo.write_file(
        "secrets/db.env.git-xcrypt-deadbeefcafef00d.tmp",
        b"a file the user committed\n",
    );
    repo.commit_all("a file with an unfortunate name");

    let output = repo.xcrypt_ok(["lock", "--yes"]);

    let name = "secrets/db.env.git-xcrypt-deadbeefcafef00d.tmp";
    assert!(
        repo.path().join(name).exists(),
        "lock deleted a tracked file of the user's"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("it is tracked"),
        "the skip went unmentioned: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Kept means kept in the selection too: `secrets/` covers this path, so
    // git's filter encrypts it, and lock must agree or the tree comes out dirty.
    assert_eq!(
        repo.worktree_bytes(name),
        repo.blob_bytes(name),
        "lock and the check-in path disagreed about this file"
    );
    repo.assert_status_clean();
}

#[test]
fn the_sweep_is_disclosed_before_the_question_not_after_it() {
    // Deleting an untracked file cannot be undone, so naming it only in the
    // closing summary is not a disclosure.
    let (repo, _outside, _key) = repository_with_secrets();
    repo.write_file(
        "secrets/db.env.git-xcrypt-a1b2c3d4e5f60718.tmp",
        b"api_key = do-not-commit-me\n",
    );

    let refused = repo.xcrypt_with_stdin(["lock"], b"no\n");

    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("will be deleted")
            && stderr.contains("db.env.git-xcrypt-a1b2c3d4e5f60718.tmp"),
        "the prompt did not say what it was about to delete: {stderr}"
    );
    assert!(
        repo.path()
            .join("secrets/db.env.git-xcrypt-a1b2c3d4e5f60718.tmp")
            .exists(),
        "a refused lock deleted it anyway"
    );
}

#[test]
fn lock_repairs_the_registration_it_is_about_to_depend_on() {
    // It is the last command before the key is gone, and a locked repository
    // needs the filter more than an unlocked one: there the clean path is what
    // turns "no key" into a refused `git add` instead of a stored plaintext.
    // Measured before this: with the catch-all line gone, `git add` on a secret
    // in a locked repository exited 0 and stored the plaintext.
    let (repo, _outside, _key) = repository_with_secrets();
    repo.git_ok(["config", "--remove-section", "filter.git-xcrypt"]);
    fs::write(repo.path().join(".gitattributes"), b"# nothing of ours\n")
        .expect("clobbering the attributes");

    repo.xcrypt_ok(["lock", "--yes"]);

    let process = repo.git_ok(["config", "--get", "filter.git-xcrypt.process"]);
    assert!(
        !process.stdout.is_empty(),
        "lock left the repository with no filter registered"
    );
    let attributes =
        fs::read_to_string(repo.path().join(".gitattributes")).expect("reading the attributes");
    assert!(
        attributes.contains("* filter=git-xcrypt"),
        "lock left the repository with no catch-all line: {attributes}"
    );

    repo.write_file("secrets/fresh.env", b"token = leaked?\n");
    assert!(!repo.git(["add", "secrets/fresh.env"]).status.success());
    assert!(!repo.object_exists_for(b"token = leaked?\n"));
}

#[test]
fn a_secret_stored_in_the_clear_is_named_as_an_exposure_not_as_an_edit() {
    // The exact state S-06 exists for: committed before the pattern covered it.
    // "Commit or stash it" would be useless advice — the file is unmodified.
    let repo = TestRepo::init();
    repo.write_file("secrets/db.env", b"api_key = leaked-long-ago\n");
    repo.commit_all("a secret, in the clear");
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.commit_all("start encrypting");
    // Pin the index back to the plaintext blob. `git add -A` above may or may
    // not have re-cleaned the file depending on whether its timestamp landed in
    // git's racy-clean window, and this test is about the state where it did
    // not: the exposure still standing.
    let plain = repo.git_with_stdin(
        ["hash-object", "-w", "--stdin"],
        b"api_key = leaked-long-ago\n",
    );
    assert!(plain.status.success(), "git hash-object failed");
    let oid = String::from_utf8(plain.stdout).expect("git printed a hash");
    repo.git_ok([
        "update-index",
        "--cacheinfo",
        &format!("100644,{},secrets/db.env", oid.trim()),
    ]);

    let output = repo.xcrypt(["lock", "--yes"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("stored in the clear") && stderr.contains("rotate the secret"),
        "the refusal misdiagnosed an exposure as an unsaved edit: {stderr}"
    );
    assert!(
        repo.path().join(".git/git-xcrypt/keys/default").exists(),
        "a refused lock deleted the key"
    );
}

#[test]
fn a_declaration_that_matches_nothing_is_said_out_loud() {
    // One typo in `.git-xcrypt`, and "locked" would otherwise be reported over a
    // working tree whose secrets are all still readable.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("sekrety/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", b"api_key = still-in-the-clear\n");
    repo.commit_all("a secret nothing matches");

    let output = repo.xcrypt_ok(["lock", "--yes"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Nothing in this working tree matches"),
        "the warning did not say the declaration matches nothing: {stderr}"
    );
    assert!(
        stderr.contains("no file here is declared"),
        "the closing line claimed a state that does not hold: {stderr}"
    );
    repo.assert_worktree_eq("secrets/db.env", b"api_key = still-in-the-clear\n");
}

#[test]
fn a_clone_that_never_unlocked_can_still_be_locked_into_shape() {
    // A clone checked out without a key already holds ciphertext, so there is
    // nothing to encrypt — but the command must not invent a reason to fail, and
    // must still say the key is gone rather than that it was never there.
    let (origin, _outside, key) = repository_with_secrets();
    let clone = origin.clone_without_filter();
    clone.xcrypt_ok(["import-key", &key.to_string_lossy()]);

    let output = clone.xcrypt_ok(["lock", "--yes"]);

    // The closing line has to say "already encrypted" rather than a bare zero:
    // "0 written" also describes a declaration that matches nothing, which is a
    // repository whose secrets are still in the clear.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("were already encrypted"),
        "already-closed files were rewritten, or reported as nothing: {stderr}"
    );
    assert!(
        !stderr.contains("no file here is declared"),
        "an already-closed tree was reported as an empty declaration: {stderr}"
    );
    assert!(!clone.path().join(".git/git-xcrypt/keys/default").exists());
    clone.assert_status_clean();
}
