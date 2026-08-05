//! The `lock` / `unlock` cycle as a day's work, not as a pair of commands.
//!
//! `lock` deletes the only copy of the repository key, so the two directions
//! deliberately lean opposite ways: `unlock` skips what it cannot read and says
//! so, while `lock` refuses over anything it cannot account for. That asymmetry
//! is only observable in sequence — open the repository, work in it, close it,
//! carry the key back and open it again — which is what this file does.
//!
//! The refusal in the middle is the one that matters. `lock` replaces working
//! files with their encrypted form, so an uncommitted edit exists in no blob
//! anywhere and would be destroyed by the command that promised only to close
//! the repository. `--yes` waives the question about the key; it does not waive
//! this one, because losing unsaved work and losing the key are different risks
//! and deserve separate decisions.

mod harness;

use std::fs;

use harness::{MAGIC, TestRepo};
use tempfile::TempDir;

const PASSWORD: &[u8] = b"correct horse battery staple\n";
const DOTENV: &[u8] = b"DATABASE_URL=postgres://user:hunter2@localhost/app\n";
const EDITED: &[u8] = b"DATABASE_URL=postgres://user:swordfish@db/app\n";

/// The base64 line of an exported key file — the secret itself.
fn key_material(path: &std::path::Path) -> String {
    let text = fs::read_to_string(path).expect("the export must be readable text");
    text.lines()
        .nth(1)
        .expect("an export has a header and a key")
        .to_string()
}

#[test]
fn a_repository_opened_worked_in_closed_and_opened_again_gives_every_byte_back() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n*.env\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/password.txt", PASSWORD);
    repo.write_file("db.env", DOTENV);
    repo.write_file("README.md", b"# ordinary project\n");
    repo.commit_all("a secret and a dotenv");
    repo.assert_status_clean();

    // The copy that makes the rest of this survivable. Outside the working
    // tree, because `export-key` refuses to write anywhere else.
    let vault = TempDir::new().expect("could not create a temporary directory");
    let key_file = vault.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key_file.to_string_lossy()]);
    let secret = key_material(&key_file);
    let key_path = repo.path().join(".git/git-xcrypt/keys/default");
    assert!(key_path.is_file(), "the repository must hold its key");

    // --- Ordinary work: the files are plaintext and stay that way. ----------
    repo.xcrypt_ok(["unlock"]);
    repo.assert_worktree_eq("secrets/password.txt", PASSWORD);
    repo.assert_status_clean();

    repo.write_file("db.env", EDITED);

    // --- `lock` refuses over the unsaved edit, with and without `--yes`. ----
    for arguments in [vec!["lock"], vec!["lock", "--yes"]] {
        let refused = repo.xcrypt(&arguments);
        let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();

        assert_eq!(
            refused.status.code(),
            Some(2),
            "`{}` did not refuse over an unsaved change:\n{stderr}",
            arguments.join(" ")
        );
        assert!(
            stderr.contains("db.env"),
            "the refusal must name the file that would be destroyed:\n{stderr}"
        );
        assert!(
            key_path.is_file(),
            "`{}` deleted the key even though it refused",
            arguments.join(" ")
        );
        assert_eq!(
            repo.worktree_bytes("db.env"),
            EDITED,
            "the refusal still overwrote the unsaved edit"
        );
    }

    // --- Committed, the same command goes through. --------------------------
    repo.commit_all("rotate the database password");
    repo.assert_status_clean();

    let locked = repo.xcrypt_ok(["lock", "--yes"]);
    let stderr = String::from_utf8_lossy(&locked.stderr).into_owned();

    assert!(
        locked.stdout.is_empty(),
        "`lock` wrote to stdout, which a redirect inside the repository would \
         capture into the working tree: {}",
        String::from_utf8_lossy(&locked.stdout)
    );
    assert!(
        !stderr.contains(&secret),
        "the key itself appeared in `lock`'s own warning"
    );
    assert!(
        stderr.contains("export-key"),
        "the warning must point at the command that makes a copy:\n{stderr}"
    );
    assert!(
        !key_path.exists(),
        "`lock` reported success and left the key behind"
    );

    // The working tree is closed: every declared file is ciphertext, the
    // undeclared one is untouched, and git sees no change at all.
    for path in ["secrets/password.txt", "db.env"] {
        assert!(
            repo.worktree_bytes(path).starts_with(MAGIC),
            "{path} was left in the clear behind a command that deleted the key"
        );
    }
    repo.assert_worktree_eq("README.md", b"# ordinary project\n");
    repo.assert_status_clean();

    // --- And without the key there is no way back in. -----------------------
    let stranded = repo.xcrypt(["unlock"]);
    assert_eq!(
        stranded.status.code(),
        Some(3),
        "a locked repository with no key must report the key missing:\n{}",
        String::from_utf8_lossy(&stranded.stderr)
    );

    // --- The carried copy opens it again, byte for byte. --------------------
    repo.xcrypt_ok(["import-key", &key_file.to_string_lossy()]);
    repo.xcrypt_ok(["unlock"]);

    repo.assert_worktree_eq("secrets/password.txt", PASSWORD);
    repo.assert_worktree_eq("db.env", EDITED);
    repo.assert_worktree_eq("README.md", b"# ordinary project\n");
    repo.assert_status_clean();

    // The determinism proof at the end of the loop: re-cleaning what `unlock`
    // wrote reproduces the blobs already stored.
    repo.git_ok(["add", "-A"]);
    repo.assert_status_clean();

    // And the history from before the lock is still readable, which is the
    // whole reason the key had to be carried rather than regenerated.
    let old = repo.git_ok(["show", "HEAD~1:db.env"]).stdout;
    assert!(old.starts_with(MAGIC), "the old blob is not ours");
}
