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

    // --- But it is still a repository, not a wall. --------------------------
    //
    // `lock` keeps the filter registered — it has to, as the `git add` above
    // just proved — so every checkout in a locked repository goes through
    // smudge with no key behind it. Refusing there protects nothing: the bytes
    // git hands over are the stored ciphertext and the bytes it would write are
    // the same ciphertext, which is exactly what `lock` itself left here. What
    // it costs is measured, on git 2.55, before this was fixed: `git checkout
    // <branch>` and `git checkout -- <path>` alike exited **128**, and because
    // git removes the old file before it calls the filter, the declared file
    // was simply **gone** from the working tree — with neither
    // `git checkout --` nor `git reset --hard` able to put it back, since both
    // take the same path and fail the same way. A locked repository could not
    // restore its own files or switch branches, for good, without the key that
    // had just been deleted.
    for path in ["secrets/password.txt", "db.env"] {
        repo.recheckout(path);
        assert!(
            repo.worktree_bytes(path).starts_with(MAGIC),
            "{path} did not come back as the ciphertext `lock` left here"
        );
    }
    repo.assert_status_clean();

    // --- The carried copy opens it again, byte for byte. --------------------
    repo.xcrypt_ok(["unlock", &key_file.to_string_lossy()]);

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
    // The rest from the handle `read_until` is holding: `wait_with_output`
    // cannot collect a stream that was already taken, so everything the command
    // says *after* the prompt — the refusal itself — would otherwise be lost,
    // and a red CI run would report an exit code with no reason attached.
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut stderr, &mut rest).expect("could not read the rest");
    let finished = child.wait_with_output().expect("git-xcrypt never ended");
    let complaint = format!("{seen}{}", String::from_utf8_lossy(&rest));

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

    // --- A whole checkout that appears while the prompt is waiting. ---------
    //
    // The two windows above, at once. The worktree refusal runs before the
    // question, so it fails fast — and that leaves the same unbounded wait
    // between the answer and the deletion, with a much larger thing able to
    // appear in it than a file: `git worktree add` checks the new tree out
    // *through the smudge filter*, so every declared file lands there in the
    // clear, and the walk cannot see any of it because it walks this tree.
    //
    // Measured before this refusal, git 2.55: the worktree added 1.5 s into the
    // prompt, `yes` typed at 3 s. `lock` exited **0**, reported "1 file(s) are
    // now encrypted and key … has been deleted", and left the new checkout
    // reading `hunter2` with no key left anywhere to close it.
    std::fs::remove_file(repo.path().join("secrets/late.env")).expect("could not remove");

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_git-xcrypt"))
        .current_dir(repo.path())
        .arg("lock")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("could not run git-xcrypt");

    let mut stderr = child.stderr.take().expect("stderr was piped");
    let seen = read_until(&mut stderr, "Type `yes`");

    // Added after the survey, exactly as a second terminal would.
    let late = repo.add_worktree("late");
    assert_eq!(
        std::fs::read(late.path().join("secrets/db.env")).expect("the new checkout has the file"),
        PASSWORD,
        "the fixture no longer reproduces the shape it exists to catch: the new \
         checkout did not come out in the clear"
    );

    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(b"yes\n")
        .expect("could not answer the prompt");
    // The rest from the handle `read_until` is holding: `wait_with_output`
    // cannot collect a stream that was already taken, so everything the command
    // says *after* the prompt — the refusal itself — would otherwise be lost,
    // and a red CI run would report an exit code with no reason attached.
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut stderr, &mut rest).expect("could not read the rest");
    let finished = child.wait_with_output().expect("git-xcrypt never ended");
    let complaint = format!("{seen}{}", String::from_utf8_lossy(&rest));

    assert_eq!(
        finished.status.code(),
        Some(2),
        "`lock` deleted the key over a checkout that appeared while it was \
         asking:\n{complaint}"
    );
    assert!(
        key_path.is_file(),
        "the key went while a whole checkout lay in the clear:\n{complaint}"
    );
    assert_eq!(
        std::fs::read(late.path().join("secrets/db.env")).expect("reading the new checkout"),
        PASSWORD,
        "the late checkout was left holding plain text behind a finished command"
    );
    assert!(
        complaint.contains("late"),
        "the refusal does not name the checkout that stopped it:\n{complaint}"
    );

    // And once the tree is settled, the same command goes through — every
    // refusal here is about not knowing, not about the file or the checkout.
    drop(late);
    repo.git_ok(["worktree", "prune"]);
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

/// A stat-cache refresh that fails must not eat the news that files are open.
///
/// The refresh runs after the decryption pass, so by the time it can fail the
/// working tree already holds plaintext. Returning the bare error threw the
/// whole report away — the user was never told a single file was decrypted, the
/// exit code said the command failed, and a second run could not say it either,
/// because the files are plain by then and the walk no longer selects them.
///
/// Provoked with a directory where the index belongs rather than a permission
/// bit, so the branch runs on all three platforms — what is checked is the
/// branch, not the errno. A held `index.lock` and a split index take the
/// `Skipped` arm, which already warns; this is the arm for a read that fails.
#[test]
fn a_failed_stat_refresh_still_reports_what_unlock_decrypted() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", DOTENV);
    repo.commit_all("a secret");

    let vault = TempDir::new().expect("could not create a temporary directory");
    let key_file = vault.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key_file.to_string_lossy()]);
    repo.xcrypt_ok(["lock", "--yes"]);

    let index = repo.path().join(".git/index");
    fs::remove_file(&index).expect("removing the index");
    fs::create_dir(&index).expect("a directory where the index belongs");

    let output = repo.xcrypt(["unlock", &key_file.to_string_lossy()]);
    let said = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "unlock decrypted the tree and then reported failure over the stat \
         cache:\n{said}"
    );
    repo.assert_worktree_eq("secrets/db.env", DOTENV);
    assert!(
        said.contains("decrypted secrets/db.env"),
        "the report of what changed on disk was thrown away:\n{said}"
    );
    assert!(
        said.contains("git add --renormalize"),
        "the warning must carry the remedy for the stale stat cache:\n{said}"
    );
}

/// The sweep deletes exactly the residue it can prove is ours, and nothing else.
///
/// Two files share the temporary-name shape; only one may go. The untracked one
/// beside a declared target is residue of an interrupted run and may hold that
/// file's decrypted secret, so it is deleted and the deletion announced. The
/// *tracked* one belongs to the user, however unlikely its name — deleting it
/// would destroy their file and leave `git status` reporting a deletion nobody
/// asked for (measured, per `sweepable`'s own record). The 2026-08-05 test
/// reduction left this rule with no integration guard at all: mutating the
/// tracked-file check away turned no suite red.
#[test]
fn the_sweep_takes_residue_and_leaves_the_users_tracked_file_alone() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", DOTENV);
    // Tracked, and temp-shaped only by its unlucky name.
    repo.write_file("secrets/build.git-xcrypt-deadbeefcafef00d.tmp", PASSWORD);
    repo.commit_all("a secret, and a user file with an unlucky name");

    // Residue: untracked, beside a declared target, holding a decrypted copy.
    repo.write_file(
        "secrets/db.env.git-xcrypt-0123456789abcdef.tmp",
        b"leftover plaintext of an interrupted run\n",
    );

    let output = repo.xcrypt_ok(["lock", "--yes"]);
    let said = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        !repo
            .path()
            .join("secrets/db.env.git-xcrypt-0123456789abcdef.tmp")
            .exists(),
        "the residue of an interrupted run was left holding a decrypted secret"
    );
    assert!(
        said.contains("removed secrets/db.env.git-xcrypt-0123456789abcdef.tmp"),
        "deleting an untracked file must be announced, not silent:\n{said}"
    );
    assert!(
        repo.worktree_bytes("secrets/build.git-xcrypt-deadbeefcafef00d.tmp")
            .starts_with(MAGIC),
        "the user's tracked file must survive the sweep, encrypted like any \
         other declared file"
    );
    assert!(
        said.contains("tracked, so it was left alone"),
        "leaving the tracked look-alike alone must be said out loud:\n{said}"
    );
    repo.assert_status_clean();
}

/// The false-refusal side of the worktree gate, on the shape that provoked it.
///
/// A bare store whose only checkout is a linked worktree is how a hosting-style
/// layout looks locally, and git spells booleans four ways: `1`, `yes` and `on`
/// are `true` to it. Measured on git 2.55 before the fix: with `core.bare = 1`
/// the main-checkout probe read the store as *not* bare, went looking for a
/// main checkout that does not exist, and `lock` refused with exit 2 over "the
/// main checkout, whose location this build could not determine" — while the
/// identical repository spelled `core.bare = true` locked at 0. A refusal is
/// this command's safe direction, but a refusal over a checkout that cannot
/// exist is an outage with no way out.
#[test]
fn a_bare_stores_sole_worktree_locks_whatever_spelling_bare_uses() {
    let store = TestRepo::init_with(&["--bare"]);
    store.git_ok(["config", "core.bare", "1"]);

    let elsewhere = TempDir::new().expect("could not create a temporary directory");
    let work = elsewhere.path().join("work");
    store.git_ok(["worktree", "add", "-q", &work.to_string_lossy()]);

    let xcrypt = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_git-xcrypt"))
            .current_dir(&work)
            .args(args)
            .output()
            .expect("could not run git-xcrypt")
    };
    let ok = |args: &[&str]| {
        let output = xcrypt(args);
        assert!(
            output.status.success(),
            "`git-xcrypt {}` failed with {:?}:\n{}",
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    ok(&["init"]);
    fs::write(work.join(".git-xcrypt"), b"secrets/\n").expect("declaring");
    ok(&["sync"]);
    fs::create_dir_all(work.join("secrets")).expect("the secrets directory");
    fs::write(work.join("secrets/db.env"), PASSWORD).expect("the secret");
    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .current_dir(&work)
            .args(args)
            .output()
            .expect("could not run git");
        assert!(
            output.status.success(),
            "`git {}` failed:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "a secret in the only checkout"]);

    // The assertion: `core.bare = 1` is bare to git, so there is no main
    // checkout to refuse over and the lock must go through.
    ok(&["lock", "--yes"]);
    assert!(
        fs::read(work.join("secrets/db.env"))
            .expect("reading")
            .starts_with(MAGIC),
        "lock reported success and left the secret in the clear"
    );
    assert!(
        !store.path().join("git-xcrypt/keys/default").exists(),
        "lock reported success and kept the key"
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

/// Residue whose name hit the length ceiling: `lock` refuses instead of guessing.
///
/// The temporary name a run leaves behind is `<target>.git-xcrypt-<hex>.tmp`, and
/// the suffix is 32 bytes against a 255-byte `NAME_MAX`. Above 223 bytes the
/// target part is cut to make room — which is a fix, not a flaw: before it, a
/// repository holding such a file could not be locked at all, `lock` failing
/// identically for ever with `ENAMETOOLONG` while the secret stayed in the clear.
///
/// What it costs is that the name no longer identifies its target, and `lock`
/// decided what to do with the file by reconstructing exactly that. Measured on
/// this build before the fix, declaring `*.env` with a 230-byte file name: `lock`
/// said `nothing declares its target, so it was left alone`, deleted the key, and
/// **exited 0** over `AWS_SECRET=hunter2` still sitting in the working tree —
/// untracked, and no longer matching `*.env`, so the next `git add -A` would have
/// committed it in the clear. That contradicts this command's own rule, the one
/// every other refusal here follows: everything it cannot verify, it refuses over.
///
/// **Both halves are asserted and the quiet one is the harder constraint.** A
/// gate that fired on any temp-shaped file with an undeclared target would refuse
/// over a user's own file, and a refusal from `lock` is an outage: the repository
/// cannot be closed until the user finds and moves whatever provoked it.
#[test]
fn residue_whose_name_was_cut_short_refuses_and_an_ordinary_look_alike_does_not() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", DOTENV);
    repo.commit_all("one ordinary secret");

    // The quiet half first, so the loud one cannot be what makes it pass: a
    // temp-shaped name whose target nothing declares, at an ordinary length.
    // `notes.txt` is not selected, so this is somebody's own file.
    repo.write_file(
        "notes.txt.git-xcrypt-0123456789abcdef.tmp",
        b"a file that merely looks like ours\n",
    );

    // The loud half. Only Rust ever creates this name — git is never asked to
    // track it — because a 255-byte component pushes the absolute path past
    // what some Windows configurations accept, and the point here is the
    // ceiling, not the platform's path handling.
    let cut = "c".repeat(223);
    let residue = format!("{cut}.git-xcrypt-0123456789abcdef.tmp");
    assert_eq!(
        residue.len(),
        255,
        "the fixture must sit exactly on NAME_MAX, or it is not the shape at issue"
    );
    repo.write_file(&residue, b"AWS_SECRET=hunter2\n");

    let refused = repo.xcrypt(["lock", "--yes"]);
    let said = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert_eq!(
        refused.status.code(),
        Some(CONFIG_ERROR),
        "lock proceeded over a file it cannot identify:\n{said}"
    );
    assert!(
        said.contains("may hold the decrypted content"),
        "the refusal has to say what is at stake, not just that it stopped:\n{said}"
    );
    assert!(
        said.contains("Nothing has been changed"),
        "a refusal before any work must say so, or the user cannot tell whether \
         the tree was half-rewritten:\n{said}"
    );

    // The two things a refusal is worth nothing without.
    assert!(
        repo.path().join(".git/git-xcrypt/keys/default").exists(),
        "the key was deleted by a run that refused"
    );
    assert_eq!(
        repo.worktree_bytes("secrets/db.env"),
        DOTENV,
        "the tree was rewritten by a run that refused"
    );

    // Dealing with the file is the way out, and it has to lead somewhere.
    fs::remove_file(repo.path().join(&residue)).expect("could not remove the residue");
    let locked = repo.xcrypt_ok(["lock", "--yes"]);
    let said = String::from_utf8_lossy(&locked.stderr).into_owned();
    assert!(
        repo.worktree_bytes("secrets/db.env").starts_with(MAGIC),
        "lock did not finish its job once the unidentifiable file was gone"
    );
    assert!(
        said.contains("nothing declares its target, so it was left alone"),
        "the ordinary look-alike must be reported and left, not swept and not \
         refused over:\n{said}"
    );
    assert!(
        repo.path()
            .join("notes.txt.git-xcrypt-0123456789abcdef.tmp")
            .exists(),
        "a file that is not ours was deleted"
    );
}

/// The exit code a state conflict gets, per the frozen table.
const CONFIG_ERROR: i32 = 2;
