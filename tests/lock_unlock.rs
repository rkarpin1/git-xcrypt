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

    // Nor is there a way to commit a new secret into it by accident. This is
    // the ordinary mistake — a locked repository looks like any other, and the
    // next declared file gets written into it as plain text — and it is the one
    // place the whole guarantee rests on a single configuration key.
    //
    // Measured on git 2.55: a clean filter that exits non-zero is *ignored*
    // unless `filter.git-xcrypt.required` is true. Without it `git add` exits 0,
    // the plaintext becomes an object, and the only sign is an `error:` line in
    // the noise. Nothing here sets that flag — the only thing standing between
    // this file and a stored secret is what `init` wrote.
    const FORGOTTEN: &[u8] = b"API_TOKEN=written-into-a-locked-repository\n";
    repo.write_file("secrets/forgotten.txt", FORGOTTEN);

    let added = repo.git(["add", "secrets/forgotten.txt"]);
    assert!(
        !added.status.success(),
        "`git add` succeeded in a repository whose filter cannot run, so the \
         plaintext was committed: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(
        !repo.object_exists_for(FORGOTTEN),
        "the object database holds the plaintext of a secret added while the \
         repository was locked"
    );
    repo.assert_not_staged("secrets/forgotten.txt");
    fs::remove_file(repo.path().join("secrets/forgotten.txt")).expect("could not remove");

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

/// What stands between `lock` and the state AGENTS.md exists to make
/// impossible: the key gone, and a live checkout still in the clear.
///
/// Both of these were reached on the *success* path before the refusals existed,
/// and neither is exotic. A linked worktree is one `git worktree add`, and a
/// file appearing during the prompt is an editor saving, a build script running,
/// or the user themself in the next terminal — the window is however long the
/// human takes to type a word.
///
/// The lean is the opposite of `unlock`'s on purpose: whatever this command
/// cannot account for, it refuses over, because a skip here leaves a plaintext
/// secret behind the command that promised to remove it.
#[test]
fn lock_refuses_over_every_checkout_and_every_file_it_cannot_account_for() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", PASSWORD);
    repo.commit_all("a secret");

    let vault = TempDir::new().expect("could not create a temporary directory");
    let key_file = vault.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key_file.to_string_lossy()]);
    let key_path = repo.path().join(".git/git-xcrypt/keys/default");

    // --- Another checkout of the same repository. ---------------------------
    //
    // Every worktree reads the key from the common directory, and the walk only
    // ever sees one of them. Measured: `lock` in the main checkout left the
    // linked one holding plaintext and deleted the key both depended on, and
    // `lock` there then failed with code 3 — no key left to close it with.
    let linked = repo.add_worktree("side");

    for (label, from) in [("the main checkout", &repo), ("the linked one", &linked)] {
        let refused = from.xcrypt(["lock", "--yes"]);
        let complaint = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert_eq!(
            refused.status.code(),
            Some(2),
            "`lock` in {label} closed a repository another checkout is reading \
             from:\n{complaint}"
        );
        assert!(
            key_path.is_file(),
            "`lock` in {label} deleted the shared key anyway"
        );
        assert!(
            complaint.contains("other checkout"),
            "`lock` in {label} did not say why:\n{complaint}"
        );
    }
    repo.assert_worktree_eq("secrets/db.env", PASSWORD);

    repo.git_ok([
        "worktree",
        "remove",
        "--force",
        &linked.path().to_string_lossy(),
    ]);

    // --- The same question, unanswerable. -----------------------------------
    //
    // That refusal rests entirely on being able to list `.git/worktrees`, so a
    // listing that fails must refuse too — an empty answer and an unobtainable
    // one are the same bytes here, and only one of them means "no other
    // checkout". Measured before this: `chmod 000 .git/worktrees` over the
    // repository above took `lock --yes` to "locked; key … has been deleted",
    // left the linked checkout reading `correct horse battery staple`, and
    // `unlock` there answered "no repository key".
    //
    // Provoked with a *file* where the directory belongs rather than with a
    // permission bit, so the arm runs on all three platforms: `chmod` is
    // Unix-only, while every platform refuses to enumerate a regular file. What
    // is being checked is the branch, not the errno.
    let registrations = repo.path().join(".git/worktrees");
    if registrations.exists() {
        fs::remove_dir_all(&registrations).expect("the registration directory must be removable");
    }
    fs::write(&registrations, b"not a directory\n").expect("writing over the registrations");

    let blinded = repo.xcrypt(["lock", "--yes"]);
    let complaint = String::from_utf8_lossy(&blinded.stderr).into_owned();
    assert_eq!(
        blinded.status.code(),
        Some(2),
        "`lock` could not tell whether another checkout shares this key and \
         deleted it anyway:\n{complaint}"
    );
    assert!(
        key_path.is_file(),
        "`lock` deleted the shared key over a question it could not answer"
    );
    repo.assert_worktree_eq("secrets/db.env", PASSWORD);

    fs::remove_file(&registrations).expect("removing the blockage");

    // --- A declared file that appears while the prompt is waiting. ----------
    //
    // The prompt is the whole point of the interactive path, and it is also an
    // unbounded wait in the middle of a command that is about to delete a key.
    // Measured before this refusal: a file created 1.5 s into the prompt was not
    // in the survey, survived a successful lock in the clear, and the key was
    // gone.
    const LATE: &[u8] = b"API_TOKEN=saved-while-the-prompt-was-waiting\n";

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_git-xcrypt"))
        .current_dir(repo.path())
        .arg("lock")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("could not run git-xcrypt");

    // Synchronised on the prompt itself rather than on a sleep: the file has to
    // appear *after* the survey, and a timer would sometimes put it before.
    let mut stderr = child.stderr.take().expect("stderr was piped");
    let seen = read_until(&mut stderr, "Type `yes`");

    repo.write_file("secrets/late.env", LATE);

    use std::io::Write as _;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(b"yes\n")
        .expect("could not answer the prompt");
    let finished = child.wait_with_output().expect("git-xcrypt never ended");
    let complaint = format!("{seen}{}", String::from_utf8_lossy(&finished.stderr));

    assert_eq!(
        finished.status.code(),
        Some(2),
        "`lock` deleted the key over a secret it had never looked at:\n{complaint}"
    );
    assert!(
        key_path.is_file(),
        "the key went while a declared file nobody surveyed lay in the clear"
    );
    repo.assert_worktree_eq("secrets/late.env", LATE);
    repo.assert_worktree_eq("secrets/db.env", PASSWORD);

    // And once the tree is settled, the same command goes through — the refusal
    // is about not knowing, not about the file.
    std::fs::remove_file(repo.path().join("secrets/late.env")).expect("could not remove");
    repo.xcrypt_ok(["lock", "--yes"]);
    assert!(
        repo.worktree_bytes("secrets/db.env").starts_with(MAGIC),
        "the secret was left in the clear behind a successful lock"
    );
    assert!(
        !key_path.exists(),
        "`lock` reported success and kept the key"
    );
}

/// Reads `stream` until `marker` shows up, and returns everything read.
///
/// The prompt carries no newline, so a line-oriented read would block on it
/// forever. End of input before the marker means the command never got that far,
/// and what it did say is the only useful thing to report.
fn read_until(stream: &mut impl std::io::Read, marker: &str) -> String {
    let mut seen = String::new();
    let mut byte = [0u8; 1];
    while !seen.contains(marker) {
        match stream.read(&mut byte) {
            Ok(0) => panic!("`lock` ended without ever asking for confirmation:\n{seen}"),
            Ok(_) => seen.push_str(&String::from_utf8_lossy(&byte)),
            Err(err) => panic!("could not read what `lock` was saying ({err}):\n{seen}"),
        }
    }
    seen
}
