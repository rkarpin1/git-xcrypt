//! The key never leaves, under the conditions of ordinary work.
//!
//! PRD §Guardrails states it without exceptions: the key never reaches the
//! working tree, a commit, or `stdout` outside an explicit `export-key`. The
//! per-command tests each guard one door; this walks the routes a person
//! actually takes, and the two that were measured leaking are both here — a
//! `diff` driver deciding by *location* rather than by content, and a filter
//! that says anything at all on the channel git reads as file content.

mod harness;

use std::fs;

use harness::{MAGIC, OVERHEAD, TestRepo};
use tempfile::TempDir;

const SECRET: &[u8] = b"api_key = do-not-commit-me\n";

/// The base64 line of an exported key file — the secret itself.
fn key_material(path: &std::path::Path) -> String {
    let text = fs::read_to_string(path).expect("the export must be readable text");
    text.lines()
        .nth(1)
        .expect("an export has a header and a key")
        .to_string()
}

#[test]
fn the_key_survives_every_route_out_of_the_repository_that_ordinary_work_takes() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", SECRET);
    repo.commit_all("a secret");

    let vault = TempDir::new().expect("could not create a temporary directory");
    let exported = vault.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &exported.to_string_lossy()]);
    let material = key_material(&exported);

    // --- `export-key` will not write anywhere git can pick it up. -----------
    //
    // The working tree first: the exact mistake FR-007 names — run it while
    // standing in the repository and give it a bare filename.
    let inside = repo.xcrypt(["export-key", "repo.key"]);
    assert_eq!(
        inside.status.code(),
        Some(2),
        "export-key wrote into the working tree:\n{}",
        String::from_utf8_lossy(&inside.stderr)
    );
    assert!(
        !repo.path().join("repo.key").exists(),
        "the refusal still left a key one `git add -A` from a commit"
    );

    // And a *neighbouring checkout* of the same repository, which is a working
    // tree git will happily commit from and which no check on "am I inside my
    // own directory" would ever see.
    let linked = repo.add_worktree("side");
    let into_neighbour = linked.path().join("repo.key");
    let sideways = repo.xcrypt(["export-key", &into_neighbour.to_string_lossy()]);
    assert_eq!(
        sideways.status.code(),
        Some(2),
        "export-key wrote into another checkout of the same repository:\n{}",
        String::from_utf8_lossy(&sideways.stderr)
    );
    assert!(
        !into_neighbour.exists(),
        "the key landed in a checkout somebody else is going to commit from"
    );

    // And the git directory, which is the other place a key must not be put:
    // `lock` deletes what it finds there, and a copy stored inside the
    // repository it protects is not a copy at all.
    let into_git_dir = repo.path().join(".git/exported.key");
    let inwards = repo.xcrypt(["export-key", &into_git_dir.to_string_lossy()]);
    assert_eq!(
        inwards.status.code(),
        Some(2),
        "export-key wrote into the git directory:\n{}",
        String::from_utf8_lossy(&inwards.stderr)
    );
    assert!(
        !into_git_dir.exists(),
        "the refusal still left a key inside the repository's own directory"
    );

    // --- And a mistyped destination never overwrites what is there. ---------
    //
    // The file being replaced is somebody's only way back into a repository, so
    // the second export has to say so rather than take the path at its word.
    // `--force` is the sentence where the user says they meant it.
    let other = vault.path().join("some-other-project.key");
    fs::write(&other, b"the only copy of another repository's key\n").expect("writing");

    let clobber = repo.xcrypt(["export-key", &other.to_string_lossy()]);
    assert_eq!(
        clobber.status.code(),
        Some(2),
        "export-key replaced an existing file without being asked:\n{}",
        String::from_utf8_lossy(&clobber.stderr)
    );
    assert_eq!(
        fs::read(&other).expect("reading"),
        b"the only copy of another repository's key\n",
        "the refusal still overwrote the file"
    );
    assert!(
        String::from_utf8_lossy(&clobber.stderr).contains("--force"),
        "the refusal must name the flag that means it:\n{}",
        String::from_utf8_lossy(&clobber.stderr)
    );

    repo.xcrypt_ok(["export-key", "--force", &other.to_string_lossy()]);
    assert_eq!(
        key_material(&other),
        material,
        "`--force` did not write this repository's key"
    );

    // --- A key that did reach the working tree is still never printed. ------
    //
    // Copied in by hand rather than by `export-key`, which is how it happens:
    // under a declared pattern, so git renders it through our own `textconv`
    // driver, and named something no path rule would recognise.
    let raw = fs::read(&exported).expect("the export must exist");
    repo.write_file("secrets/notes.txt", &raw);

    // And the same key wearing the annotation it picks up on the way through a
    // password manager or an email body: a comment line, a blank line, an
    // indent. `import-key` accepts all three, so a refusal that looked at the
    // first byte instead of the first line answered "not a key file" and
    // `git-xcrypt diff` printed the master key in base64 with exit code 0.
    let annotated = format!(
        "# my laptop\n\n  {}\n",
        String::from_utf8(raw.clone())
            .expect("an export is text")
            .trim()
            .replace('\n', "\n  ")
    );
    repo.write_file("secrets/annotated.txt", annotated.as_bytes());

    // The premise, proved rather than assumed: this shape really is a working
    // key, which is what makes printing it a leak rather than a curiosity.
    let adopter = TestRepo::init();
    let carried = vault.path().join("annotated.key");
    fs::write(&carried, annotated.as_bytes()).expect("writing");
    adopter.xcrypt_ok(["import-key", &carried.to_string_lossy()]);

    repo.commit_all("a key nobody meant to commit");

    for arguments in [
        vec!["--no-pager", "log", "-p"],
        vec!["--no-pager", "show", "HEAD"],
        vec!["--no-pager", "diff", "HEAD~1", "HEAD"],
    ] {
        let output = repo.git(&arguments);
        let rendered = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            !rendered.contains(&material),
            "`git {}` printed the repository key",
            arguments.join(" ")
        );
    }

    // The driver called directly, on all three copies, and from **outside every
    // repository** — the first version of this guard checked the path, and from
    // here it fell silent.
    let key_path = repo.path().join(".git/git-xcrypt/keys/default");
    for target in [
        key_path.clone(),
        exported.clone(),
        carried.clone(),
        repo.path().join("secrets/notes.txt"),
        repo.path().join("secrets/annotated.txt"),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_git-xcrypt"))
            .current_dir(vault.path())
            .arg("diff")
            .arg(&target)
            .output()
            .expect("could not run git-xcrypt");

        assert_eq!(
            output.status.code(),
            Some(2),
            "{}: the driver did not refuse:\n{}",
            target.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "a key reached stdout from {}",
            target.display()
        );
    }

    // --- Nothing the key file is stored as leaks it either. -----------------
    for path in ["secrets/notes.txt", "secrets/annotated.txt"] {
        assert!(
            !repo
                .blob_bytes(path)
                .windows(material.len())
                .any(|window| window == material.as_bytes()),
            "{path}: the committed copy of the key is readable in the object \
             database"
        );
    }
}

#[test]
fn the_filter_puts_nothing_but_content_on_the_channel_git_reads_as_content() {
    // The filter's `stdout` *is* the file. A `println!` there does not produce a
    // stray line in a log, it corrupts the user's data — and the corruption is
    // silent, because git stores whatever it is handed.
    //
    // Driven through the one path that guarantees the filter has something to
    // say: a file `HEAD` already holds in the clear is warned about the first
    // time it is encrypted. If that warning went to `stdout` it would be inside
    // the blob, and the assertion below is what says it is not.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", SECRET);
    repo.commit_all("committed before it was declared");

    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);

    let added = repo.git(["add", "--renormalize", "."]);
    assert!(
        added.status.success(),
        "the add failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    let stderr = String::from_utf8_lossy(&added.stderr).into_owned();
    assert!(
        stderr.contains("HEAD already holds"),
        "the fixture must actually make the filter speak, or this test cannot \
         tell where it spoke:\n{stderr}"
    );

    repo.git_ok(["commit", "-q", "-m", "declare it"]);

    let blob = repo.blob_bytes("secrets/db.env");
    assert!(blob.starts_with(MAGIC), "the filter did not encrypt");
    assert_eq!(
        blob.len(),
        OVERHEAD + SECRET.len(),
        "the blob is not header plus content: the filter put a diagnostic on \
         stdout and git stored it as part of the file"
    );

    // And the other direction: what smudge writes is the plaintext and nothing
    // else, which a warning on `stdout` would also break.
    repo.recheckout("secrets/db.env");
    repo.assert_worktree_eq("secrets/db.env", SECRET);
    repo.assert_status_clean();
}

/// The same refusal where the working-tree check has nothing to say: a
/// repository whose git directory is somewhere else entirely.
///
/// `git init --separate-git-dir` leaves a `.git` *file* in the working tree and
/// puts the real directory elsewhere — the arrangement dotfile setups and some
/// tools produce. The key lives in that directory, so writing an export next to
/// it is the one destination that is neither "outside the repository" nor
/// inside any working tree, and the check that covers it is a separate one.
/// Measured: with that check removed, the working-tree refusal answers every
/// other route out and this one goes through.
///
/// Portable on purpose — no symlinks, no permissions, no unusual names.
#[test]
fn export_key_refuses_a_git_directory_that_sits_outside_the_working_tree() {
    let elsewhere = TempDir::new().expect("could not create a temporary directory");
    let work_tree = elsewhere.path().join("work");
    let git_dir = elsewhere.path().join("git-dir");

    let init = std::process::Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .arg(format!("--separate-git-dir={}", git_dir.display()))
        .arg(&work_tree)
        .output()
        .expect("could not run git init");
    assert!(
        init.status.success(),
        "git init --separate-git-dir failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let xcrypt = |arguments: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_git-xcrypt"))
            .current_dir(&work_tree)
            .args(arguments)
            .output()
            .expect("could not run git-xcrypt")
    };

    let prepared = xcrypt(&["init"]);
    assert!(
        prepared.status.success(),
        "git-xcrypt init failed in a separate-git-dir repository: {}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    assert!(
        git_dir.join("git-xcrypt/keys/default").is_file(),
        "the premise is wrong: the key is not in the separate git directory"
    );

    let destination = git_dir.join("exported.key");
    let refused = xcrypt(&["export-key", &destination.to_string_lossy()]);

    assert_eq!(
        refused.status.code(),
        Some(2),
        "export-key wrote a key next to the one it protects:\n{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !destination.exists(),
        "the refusal still left a key inside the git directory"
    );
}

/// The one property of an exported key that only a Unix filesystem can state.
///
/// `export-key` writes the file `0600`, because the whole command exists to put
/// a key somewhere the user will keep it and "somewhere" is often a shared
/// machine. On Windows the equivalent is an ACL and this assertion cannot be
/// written at all, so the gate below is a platform that is genuinely
/// unreachable rather than one that was skipped.
#[cfg(unix)]
#[test]
fn an_exported_key_is_readable_only_by_its_owner() {
    use std::os::unix::fs::PermissionsExt as _;

    let repo = TestRepo::init();
    repo.init_xcrypt();
    let vault = TempDir::new().expect("could not create a temporary directory");
    let destination = vault.path().join("repo.key");

    repo.xcrypt_ok(["export-key", &destination.to_string_lossy()]);

    let mode = fs::metadata(&destination)
        .expect("the export must exist")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
