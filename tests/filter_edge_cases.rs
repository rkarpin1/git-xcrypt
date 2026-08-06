//! Cases the format and the filter have to survive.

mod harness;

use harness::TestRepo;

const SECRET: &[u8] = b"api_key = do-not-commit-me\n";

/// A repository holding one committed secret.
fn repo_with_secret() -> TestRepo {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.write_file("secrets.env", SECRET);
    repo.commit_all("add a secret");
    repo
}

/// A per-worktree configuration git has been told about but not yet written.
///
/// `extensions.worktreeConfig = true` is the command git's own documentation
/// gives for enabling per-worktree configuration, and `config.worktree` does not
/// appear until the first `git config --worktree` writes it. Git reads the
/// extension as permission to look, not as a promise the file is there.
///
/// `gix-config` reads it as a promise. Measured on git 2.55, 2026-08-05: git ran
/// `add`, `commit` and `status` at exit 0 in that state while this build could
/// not start its filter — and with `required = true`, that is **every git
/// operation in the repository** failing, `git add` exiting 128 with `could not
/// read git configuration`. Fail-closed, so nothing was stored in the clear; an
/// outage all the same, and one a documented git command walks straight into.
///
/// Both directions, because the tolerance has to stop at "missing": a file that
/// is *there* and does not parse must still abort, or a repository whose
/// `filter.git-xcrypt.required` cannot be read would pass for one that has it.
#[test]
fn a_per_worktree_config_git_has_not_written_yet_does_not_stop_the_filter() {
    let repo = repo_with_secret();
    repo.git_ok(["config", "extensions.worktreeConfig", "true"]);
    assert!(
        !repo.path().join(".git/config.worktree").exists(),
        "the fixture no longer reproduces the shape it exists to catch: git \
         wrote the per-worktree file by itself"
    );

    repo.write_file("second.env", b"api_key = also-a-secret\n");
    let added = repo.git(["add", "-A"]);
    assert!(
        added.status.success(),
        "the filter could not start over a per-worktree config git has not \
         written yet, so every git operation in this repository fails: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    repo.commit_all("a secret, with the extension enabled and no file yet");
    assert!(
        repo.blob_is_encrypted("second.env"),
        "the repository kept working but stopped encrypting, which is worse \
         than the outage this replaced"
    );

    // The other direction. A file that exists and is broken is an answer this
    // build must not guess at.
    std::fs::write(repo.path().join(".git/config.worktree"), b"[unterminated\n")
        .expect("could not write the per-worktree config");
    repo.write_file("third.env", b"api_key = one-more\n");
    let refused = repo.git(["add", "-A"]);
    let complaint = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(
        !refused.status.success(),
        "`git add` went through over a per-worktree config nothing could parse"
    );
    assert!(
        complaint.contains("config.worktree"),
        "the refusal does not name the file nobody could parse:\n{complaint}"
    );
    // No `assert_not_staged` here, and the reason is the finding itself: with a
    // broken file in the cascade **git** refuses before reaching any filter, so
    // every later git command fails too and there is nothing left to ask. That
    // is the correct outcome — it just cannot be observed through git.
}

#[test]
fn a_failing_filter_aborts_the_add() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.break_filter();
    repo.write_file("secrets.env", SECRET);

    let output = repo.git(["add", "secrets.env"]);

    assert!(
        !output.status.success(),
        "git add succeeded although the filter failed — \
         the plaintext would have been committed"
    );
    repo.assert_not_staged("secrets.env");
}

#[test]
fn a_failing_filter_leaves_no_plaintext_object_behind() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.break_filter();
    repo.write_file("secrets.env", SECRET);

    let _ = repo.git(["add", "secrets.env"]);

    assert!(
        !repo.object_exists_for(SECRET),
        "the object database holds the plaintext although the filter failed"
    );
}

#[test]
fn a_second_init_never_replaces_the_key() {
    let repo = repo_with_secret();
    // No `sync` needed to settle the section first, and that is new since
    // 2026-08-06: the default section says nothing about the declaration, so a
    // repository whose patterns were written after the first `init` no longer
    // gains a line here. A dirty file at the end of this test can therefore
    // only be the key changing, which is what it is about.
    let before = std::fs::read(repo.path().join(".git/git-xcrypt/keys/default"))
        .expect("the key must exist");

    repo.xcrypt_ok(["init"]);

    let after = std::fs::read(repo.path().join(".git/git-xcrypt/keys/default"))
        .expect("the key must still exist");
    assert_eq!(before, after, "a repeated init replaced the repository key");
    repo.assert_status_clean();
}

#[test]
fn deleting_the_declaration_stops_the_commit_instead_of_leaking() {
    // The worst failure mode reachable by one command: with `.git-xcrypt` gone
    // the filter used to have nothing to match against, so every selected path
    // sailed into the object database in the clear, exit code 0.
    let repo = repo_with_secret();
    std::fs::remove_file(repo.path().join(".git-xcrypt")).expect("could not remove the config");
    repo.write_file("another.env", b"api_key = second-secret\n");

    let output = repo.git(["add", "another.env"]);

    assert!(
        !output.status.success(),
        "git add succeeded without a declaration, so the plaintext was committed"
    );
    assert!(
        !repo.object_exists_for(b"api_key = second-secret\n"),
        "the object database holds the plaintext"
    );
    repo.assert_not_staged("another.env");
}

#[test]
fn a_dos_end_of_file_marker_is_classified_the_way_git_classifies_it() {
    // The last text/binary parity gap against git, closed 2026-08-04 as roadmap
    // item S-08 and deliberately before the first release: `looks_binary` is
    // frozen with the format, so afterwards this would rewrite the ciphertext of
    // every file it moves across the boundary rather than fix anything.
    //
    // git's `gather_stats` takes a trailing `SUB` (0x1a, the DOS end-of-file
    // marker) back off the non-printable count. Asked of a real git rather than
    // asserted from the source: the reference repository below is the authority,
    // and this test fails if either side ever moves.
    let shapes: [(&str, &[u8]); 4] = [
        ("a trailing SUB", b"a\r\n\x1a"),
        ("two trailing SUBs", b"a\r\n\x1a\x1a"),
        ("a SUB in the middle", b"a\x1ab\r\n"),
        ("a trailing SUB spent on a control", b"a\x01\r\n\x1a"),
    ];

    for (label, content) in shapes {
        // What git itself does with the content, under the attribute our
        // default mode reproduces.
        let reference = TestRepo::init();
        reference.write_file(".gitattributes", b"* text=auto\n");
        reference.git_ok(["config", "core.autocrlf", "true"]);
        reference.write_file("subject.txt", content);
        reference.commit_all("the subject");
        let stored = reference.blob_bytes("subject.txt");
        let git_called_it_text = stored != content;

        // And what we do with the same bytes, all the way through the filter.
        let ours = TestRepo::init();
        ours.init_xcrypt();
        ours.write_xcrypt_config("*.env\n");
        ours.write_file("subject.env", content);
        ours.commit_all("the subject");
        let blob = ours.blob_bytes("subject.env");

        assert!(
            blob.starts_with(b"\0GITXCRYPT\0"),
            "{label}: the filter did not run"
        );
        // Bit 0 of the header's `flags` byte records whether the plaintext was
        // normalised, which is precisely the verdict under test.
        let we_called_it_text = blob[13] & 1 == 1;
        assert_eq!(
            we_called_it_text,
            git_called_it_text,
            "{label}: git says {}, git-xcrypt says {} — the boundary has moved",
            if git_called_it_text { "text" } else { "binary" },
            if we_called_it_text { "text" } else { "binary" }
        );
        assert_eq!(
            blob.len(),
            38 + stored.len(),
            "{label}: the encrypted plaintext is not the plaintext git would store"
        );

        // The whole point of agreeing: the working tree comes back unchanged.
        std::fs::remove_file(ours.path().join("subject.env")).expect("could not remove");
        ours.git_ok(["checkout", "--", "subject.env"]);
        ours.assert_status_clean();
    }
}

/// A file name no `String` can hold, driven end to end through a real git.
///
/// AGENTS.md makes "a path is bytes, never a `String`" a hard rule, and names
/// the two bugs that bought it: a `trim_end()` on a name that legally ends in a
/// space, and a `from_utf8_lossy` on the filter's `pathname=`. Both matched a
/// file under a name it did not have, and in the pass-through direction that
/// stores a secret in the clear. Every module now carries a byte-preserving
/// conversion for this — `filter`, `config::decide`, `gitindex`, `history`,
/// `lock`, `unlock`, `status` — and until this test **not one of them had ever
/// seen such a name arrive from a filesystem.** The unit tests pin the
/// conversions in isolation; the CI note in `.github/workflows/ci.yml` says so
/// outright.
///
/// `#[cfg(target_os = "linux")]` because ext4 is where the case exists: any byte
/// string without `/` or NUL is a legal name there. APFS rejects it at `open`,
/// and a Windows name is UTF-16 and cannot express it at all — so this is not a
/// case those platforms handle differently, it is one they cannot reach.
///
/// The whole life cycle, because each stage reaches the bytes by a different
/// route: `git add` hands them over in the filter protocol, `status` reads them
/// out of the index and the trees, and `lock`/`unlock` build them from
/// `read_dir`. A lossy step anywhere shows up as a plaintext blob, a false
/// finding, or a file left in the clear behind a command that deleted the key.
#[cfg(target_os = "linux")]
#[test]
fn a_file_name_that_is_not_utf8_survives_the_whole_life_cycle() {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    const NAME: &[u8] = b"secrets/pa\xffssword.env";

    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);

    let path = repo.path().join(OsStr::from_bytes(NAME));
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("could not create secrets/");
    std::fs::write(&path, SECRET).expect("ext4 must accept this name");

    repo.commit_all("a secret whose name is not text");

    // The blob, asked for by the same bytes git was given.
    let mut spec = OsString::from_vec(b"HEAD:".to_vec());
    spec.push(OsStr::from_bytes(NAME));
    let blob = repo
        .git_ok([OsStr::new("cat-file"), OsStr::new("blob"), &spec])
        .stdout;
    assert!(
        blob.starts_with(b"\0GITXCRYPT\0"),
        "the filter judged the file under a name it does not have, and the \
         plaintext was committed"
    );
    assert_eq!(blob.len(), 38 + SECRET.len());
    assert_eq!(
        std::fs::read(&path).expect("reading"),
        SECRET,
        "the working tree must still hold the plain text"
    );

    // `status` reads the same name out of the index, resolves git's attribute
    // stack for it and walks it through history. Nothing is exposed, so the
    // gate has to be green — a lossy read here invents a declared path that no
    // blob answers for.
    let status = repo.xcrypt(["status"]);
    assert_eq!(
        status.status.code(),
        Some(0),
        "status did not come back clean:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );

    // `lock` and `unlock` reach the same file through `read_dir` instead. `lock`
    // is the direction where a miss is unrecoverable: it deletes the key, so a
    // file it failed to select stays plaintext with nothing left to close it.
    let vault = tempfile::TempDir::new().expect("could not create a temporary directory");
    let key = vault.path().join("repo.key");
    repo.xcrypt_ok([OsStr::new("export-key"), key.as_os_str()]);

    repo.xcrypt_ok(["lock", "--yes"]);
    assert!(
        std::fs::read(&path)
            .expect("reading")
            .starts_with(b"\0GITXCRYPT\0"),
        "lock left the file in the clear and deleted the key over it"
    );

    repo.xcrypt_ok([OsStr::new("unlock"), key.as_os_str()]);
    assert_eq!(
        std::fs::read(&path).expect("reading"),
        SECRET,
        "unlock did not find the file it had just encrypted"
    );
    repo.assert_status_clean();
}
