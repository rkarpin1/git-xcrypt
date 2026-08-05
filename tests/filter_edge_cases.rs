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

#[test]
fn checkout_restores_the_content_and_leaves_status_clean() {
    let repo = repo_with_secret();

    std::fs::remove_file(repo.path().join("secrets.env")).expect("could not remove the file");
    repo.git_ok(["checkout", "--", "secrets.env"]);

    repo.assert_worktree_eq("secrets.env", SECRET);
    repo.assert_status_clean();
}

/// A backslash in the binary's own path must not be rewritten into a separator.
///
/// `init` writes the filter command into `.git/config`, converting the native
/// separator into the forward slashes git wants on Windows. The conversion used
/// to run unconditionally — so on Unix, where a backslash is an ordinary
/// character in a file name, a binary under `a\b/` was registered under `a/b/`,
/// a path that does not exist. `init` still exited 0, and with
/// `required = true` every later git operation in the repository aborted.
///
/// `#[cfg(unix)]` because the case cannot exist on Windows: a backslash there
/// *is* the separator and cannot appear in a name. The Windows half of the same
/// rewrite is covered from any platform by
/// `init::tests::the_registered_command_rewrites_a_separator_and_never_a_file_name`.
#[cfg(unix)]
#[test]
fn a_binary_whose_path_holds_a_backslash_still_registers_a_filter_git_can_run() {
    let scratch = tempfile::TempDir::new().expect("could not create a temporary directory");
    let awkward = scratch.path().join(r"tools\v2");
    std::fs::create_dir_all(&awkward).expect("could not create the directory");

    let binary = awkward.join("git-xcrypt");
    std::fs::copy(env!("CARGO_BIN_EXE_git-xcrypt"), &binary).expect("could not copy the binary");

    let repo = TestRepo::init();
    let init = std::process::Command::new(&binary)
        .arg("init")
        .current_dir(repo.path())
        .output()
        .expect("could not run git-xcrypt");
    assert!(init.status.success(), "init failed: {init:?}");

    // The registered command has to name a file that is actually there.
    let registered = String::from_utf8(repo.git_ok(["config", "filter.git-xcrypt.process"]).stdout)
        .expect("git printed a non-UTF-8 config value");
    let named = registered
        .trim()
        .trim_end_matches(" process")
        .trim_matches('\'');
    assert!(
        std::path::Path::new(named).is_file(),
        "init registered `{named}`, which is not a file — every git operation \
         in this repository would abort"
    );

    // And the proof that matters: git can run it, so a secret is still stored
    // as ciphertext rather than refused or passed through.
    repo.write_xcrypt_config("*.env\n");
    repo.write_file("secrets.env", SECRET);
    repo.commit_all("a secret committed through the awkward path");
    assert_ne!(
        repo.blob_bytes("secrets.env"),
        SECRET,
        "the filter never ran, so the plaintext was committed"
    );
}

#[test]
fn a_clone_without_the_key_shows_the_stored_bytes() {
    let repo = repo_with_secret();
    let stored = repo.blob_bytes("secrets.env");

    let clone = repo.clone_without_filter();

    clone.assert_worktree_eq("secrets.env", &stored);
    assert_ne!(stored, SECRET, "the clone would have exposed the plaintext");
}

#[test]
fn an_empty_file_survives_the_round_trip() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.write_file("empty.env", b"");
    repo.commit_all("add an empty file");

    // 38 bytes of header and synthetic IV, and not one byte more.
    assert_eq!(repo.blob_bytes("empty.env").len(), 38);

    std::fs::remove_file(repo.path().join("empty.env")).expect("could not remove the file");
    repo.git_ok(["checkout", "--", "empty.env"]);

    repo.assert_worktree_eq("empty.env", b"");
    repo.assert_status_clean();
}

#[test]
fn a_binary_file_survives_the_round_trip() {
    let content: Vec<u8> = (0u8..=255).cycle().take(4096).collect();

    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\n");
    repo.write_file("binary.env", &content);
    repo.commit_all("add a binary file");

    repo.assert_blob_differs_from_worktree("binary.env");

    std::fs::remove_file(repo.path().join("binary.env")).expect("could not remove the file");
    repo.git_ok(["checkout", "--", "binary.env"]);

    repo.assert_worktree_eq("binary.env", &content);
    repo.assert_status_clean();
}

#[test]
fn the_same_content_always_gives_the_same_blob() {
    let repo = repo_with_secret();
    let first = repo.blob_bytes("secrets.env");

    repo.write_file("secrets.env", b"something else\n");
    repo.commit_all("change it");
    repo.write_file("secrets.env", SECRET);
    repo.commit_all("change it back");

    assert_eq!(
        repo.blob_bytes("secrets.env"),
        first,
        "the same plaintext produced different ciphertext, so git status would never settle"
    );
    repo.assert_status_clean();
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
    // `init` renders the cosmetic section from `.git-xcrypt`, so a repository
    // whose declarations were written after the first `init` legitimately gains
    // a line here. Settle that first, or the dirty file at the end of this test
    // would be the section catching up rather than the key changing.
    repo.xcrypt_ok(["sync"]);
    repo.commit_all("bring the attributes up to date");

    let before = std::fs::read(repo.path().join(".git/git-xcrypt/keys/default"))
        .expect("the key must exist");

    repo.xcrypt_ok(["init"]);

    let after = std::fs::read(repo.path().join(".git/git-xcrypt/keys/default"))
        .expect("the key must still exist");
    assert_eq!(before, after, "a repeated init replaced the repository key");
    repo.assert_status_clean();
}

#[test]
fn init_in_a_linked_worktree_registers_where_git_actually_reads() {
    // A linked worktree's git dir is `.git/worktrees/<name>`, and git ignores
    // the `config` file there unless `extensions.worktreeConfig` says otherwise.
    // Registering the driver in it left git with no filter at all: measured on
    // git 2.55, `git add` on a secret exited 0 and stored the plaintext while
    // `init` reported success.
    let repo = TestRepo::init();
    repo.write_file("readme.txt", b"first commit\n");
    repo.commit_all("something to branch from");

    let worktree = repo.add_worktree("side");
    worktree.xcrypt_ok(["init"]);

    let registered = worktree.git_ok(["config", "--get", "filter.git-xcrypt.process"]);
    assert!(
        !registered.stdout.is_empty(),
        "git cannot see the filter registration, so nothing will be encrypted here"
    );

    worktree.write_xcrypt_config("*.env\n");
    worktree.write_file("secrets.env", SECRET);
    worktree.commit_all("add a secret from a linked worktree");

    assert_ne!(
        worktree.blob_bytes("secrets.env"),
        SECRET,
        "the secret was stored in the clear"
    );
    assert!(
        !worktree.object_exists_for(SECRET),
        "the plaintext reached the object database"
    );
}

#[test]
fn init_refuses_in_a_clone_that_has_no_key() {
    let repo = repo_with_secret();
    let clone = repo.clone_without_filter();

    let output = clone.xcrypt(["init"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "a state conflict is exit code 2 in the frozen table; \
         init generated a fresh key in a clone, stranding every existing blob"
    );
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("unlock") || message.contains("import-key"),
        "the refusal must point somewhere useful, got: {message}"
    );
}

#[test]
fn init_outside_a_repository_reports_a_state_conflict() {
    let elsewhere = tempfile::TempDir::new().expect("temporary directory");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_git-xcrypt"))
        .arg("init")
        .current_dir(elsewhere.path())
        .output()
        .expect("could not run git-xcrypt");

    assert_eq!(
        output.status.code(),
        Some(2),
        "not being a git repository is exit code 2"
    );
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
fn the_declaration_can_still_be_restored_after_it_is_deleted() {
    // The refusal above must not be a dead end. Check-out is unaffected by a
    // missing declaration — smudge decides from each file's own header — so the
    // recovery the error message names actually works.
    let repo = repo_with_secret();
    std::fs::remove_file(repo.path().join(".git-xcrypt")).expect("could not remove the config");

    repo.git_ok(["checkout", "--", ".git-xcrypt"]);

    repo.assert_status_clean();
    repo.write_file("another.env", b"api_key = second-secret\n");
    repo.commit_all("add another secret once the declaration is back");
    assert!(
        repo.blob_bytes("another.env").starts_with(b"\0GITXCRYPT\0"),
        "encryption did not resume after the declaration was restored"
    );
}

#[test]
fn a_file_whose_name_ends_in_a_space_is_still_encrypted() {
    // The pathname arrives as `pathname=<name>\n`; trimming more than that one
    // newline matched this file against the wrong pattern and stored it plain.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n!secrets/README.md\n");
    repo.write_file("secrets/README.md ", SECRET);

    repo.commit_all("add a file whose name ends in a space");

    let blob = repo.blob_bytes("secrets/README.md ");
    assert!(
        blob.starts_with(b"\0GITXCRYPT\0"),
        "`secrets/README.md ` does not match the negation, so it must be encrypted"
    );
}

#[test]
fn crlf_content_round_trips_under_every_autocrlf_setting() {
    // `zalozenia.md` §Jakość i testy asks for a regression scenario with
    // `core.autocrlf=true`, and the string did not appear anywhere in `tests/`.
    // The table it comes from was reproduced only as a unit test that is handed
    // the configuration values as arguments — so the bridge from git's actual
    // configuration to `resolve_output` was never crossed by a test at all, and
    // a filter that read the wrong key would have looked fine.
    //
    // The invariant being measured is the one the whole asymmetry exists for:
    // clean normalises to LF whatever the machine says, smudge writes back
    // whatever the machine asks for, and the next clean normalises again — so
    // the blob is identical across settings and `git status` stays quiet.
    let content = b"first\r\nsecond\r\nthird\r\n";
    let mut blobs = Vec::new();

    // One key across every repository, or the `key_id` in the header would make
    // the blobs differ for a reason that has nothing to do with line endings.
    let scratch = tempfile::TempDir::new().expect("could not create a temporary directory");
    let key_file = scratch.path().join("shared.key");
    let source = TestRepo::init();
    source.init_xcrypt();
    source.xcrypt_ok(["export-key", &key_file.to_string_lossy()]);

    for autocrlf in ["true", "false", "input"] {
        for eol in ["", "lf", "crlf", "native"] {
            let repo = TestRepo::init();
            repo.git_ok(["config", "core.autocrlf", autocrlf]);
            if !eol.is_empty() {
                repo.git_ok(["config", "core.eol", eol]);
            }
            repo.xcrypt_ok(["import-key", &key_file.to_string_lossy()]);
            repo.init_xcrypt();
            repo.write_xcrypt_config("secrets/\n");
            repo.write_file("secrets/db.env", content);
            repo.commit_all("a secret with CRLF in it");

            let label = format!("core.autocrlf={autocrlf} core.eol={eol:?}");

            // The stored blob must not depend on the machine, or the same file
            // encrypts differently on Windows and Linux.
            let blob = repo.blob_bytes("secrets/db.env");
            assert!(
                blob.starts_with(b"\0GITXCRYPT\0"),
                "{label}: the filter did not run"
            );
            assert_eq!(
                blob.len(),
                content.len() - 3 + 38,
                "{label}: the plaintext was not normalised to LF before encryption"
            );
            blobs.push((label.clone(), blob));

            // And the working tree survives a checkout without going dirty,
            // whatever line ending git asked us to write.
            std::fs::remove_file(repo.path().join("secrets/db.env")).expect("could not remove");
            repo.git_ok(["checkout", "--", "secrets/db.env"]);
            repo.assert_status_clean();

            let seen = repo.worktree_bytes("secrets/db.env");
            let wants_crlf = autocrlf == "true"
                || (autocrlf == "false" && eol == "crlf")
                || (autocrlf == "false" && eol == "native" && cfg!(windows));
            assert_eq!(
                seen.windows(2).filter(|w| *w == b"\r\n").count() > 0,
                wants_crlf,
                "{label}: the checked-out line endings are not what git's own \
                 table says this configuration asks for"
            );
        }
    }

    let (first_label, first) = &blobs[0];
    for (label, blob) in &blobs[1..] {
        assert_eq!(
            blob, first,
            "{label} stored different bytes than {first_label}: determinism \
             across machines is gone"
        );
    }
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
