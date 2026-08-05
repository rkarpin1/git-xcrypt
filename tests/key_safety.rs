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

    // --- A key that did reach the working tree is still never printed. ------
    //
    // Copied in by hand rather than by `export-key`, which is how it happens:
    // under a declared pattern, so git renders it through our own `textconv`
    // driver, and named something no path rule would recognise.
    repo.write_file(
        "secrets/notes.txt",
        &fs::read(&exported).expect("the export must exist"),
    );
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
        repo.path().join("secrets/notes.txt"),
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
    assert!(
        !repo
            .blob_bytes("secrets/notes.txt")
            .windows(material.len())
            .any(|window| window == material.as_bytes()),
        "the committed copy of the key is readable in the object database"
    );
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
