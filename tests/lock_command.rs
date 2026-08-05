//! The one refusal in `lock` that only a case-insensitive filesystem can reach.
//!
//! Everything else `lock` refuses over is driven as a day's work in
//! `tests/lock_unlock.rs` — the unsaved edit, the other checkout, the file that
//! appears while the prompt waits. This one is here on its own because its
//! premise is the *filesystem*, not the user: on APFS and on NTFS the index and
//! the directory can disagree about a name with no signal anywhere, and on a
//! case-sensitive filesystem the same steps are an ordinary rename that git
//! reports. The test asserts whichever of the two it is standing on, so it says
//! something true on all three platforms rather than being skipped on two.

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
        // The **on-disk** spelling, since 2026-08-05. Selection folds ASCII case
        // now, so the walk of the working tree recognises `Secrets/db.env` as
        // declared and the refusal moves from "the index names a path this walk
        // never saw" to "this declared file is not tracked under this name".
        // Both refuse with the same code over the same state; this one names the
        // spelling the user has to act on, which is the one on disk.
        assert!(
            message.contains("Secrets/db.env"),
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
