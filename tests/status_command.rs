//! `git-xcrypt status` against real repositories.
//!
//! The question this command answers is only ever true or false about a real
//! git: whether git would run the filter, and whether the objects git already
//! holds carry ciphertext. Both are settled by driving git itself.

mod harness;

use harness::TestRepo;

/// The exit code the frozen table gives to "an exposure was found".
const EXPOSED: i32 = 5;

/// Everything `status` printed to `stdout`, which is where the report belongs.
fn report(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_repository_that_was_just_initialised_passes() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");

    let output = repo.xcrypt(["status"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "status failed on a healthy repository:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_fresh_clone_that_was_never_unlocked_is_reported_as_unfiltered() {
    // The failure mode nothing else catches: the clone carries the catch-all
    // line through history and has no driver behind it, so git filters nothing
    // and the next `git add` on a secret exits 0 with the plaintext stored.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");

    let clone = repo.clone_without_filter();
    let output = clone.xcrypt(["status"]);

    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "a clone with no filter registration must fail the gate:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("filter.git-xcrypt.process"),
        "the report must name what is missing:\n{text}"
    );
    assert!(
        text.contains("unlock"),
        "a clone has no key, so the way out is `unlock`:\n{text}"
    );
}

#[test]
fn dropping_the_required_flag_is_caught() {
    // Measured on git 2.55: without it a failing clean filter leaves `git add`
    // exiting 0 and the plaintext in the object database.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.git_ok(["config", "filter.git-xcrypt.required", "false"]);

    let output = repo.xcrypt(["status"]);

    assert_eq!(output.status.code(), Some(EXPOSED));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("filter.git-xcrypt.required"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn removing_the_catch_all_line_is_caught() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file(".gitattributes", b"# mine only\n");

    let output = repo.xcrypt(["status"]);

    assert_eq!(output.status.code(), Some(EXPOSED));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("* filter=git-xcrypt"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn status_in_a_linked_worktree_reads_the_configuration_git_actually_reads() {
    // A linked worktree has a `config` file of its own that git ignores unless
    // `extensions.worktreeConfig` is set — the same resolution `init` had to be
    // taught. Reading the wrong one would report a healthy checkout as broken.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.commit_all("setup");

    let linked = repo.add_worktree("side");
    let output = linked.xcrypt(["status"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "a linked worktree shares the registration:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn status_outside_a_repository_reports_a_configuration_error_not_an_exposure() {
    // Code 2 and code 5 mean different things to a CI gate: one is "the tool
    // could not run", the other is "this repository has a problem".
    let dir = tempfile::TempDir::new().expect("temporary directory");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_git-xcrypt"))
        .current_dir(dir.path())
        .arg("status")
        .output()
        .expect("could not run git-xcrypt");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "a failure must not print a report"
    );
}

#[test]
fn a_secret_committed_before_the_pattern_existed_is_found_in_history() {
    // The failure mode the whole element exists for. Nothing in the working
    // tree shows it, and the blob is still at the hosting provider.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("before anyone declared anything");

    repo.write_xcrypt_config("secrets/\n");
    let output = repo.xcrypt(["status"]);

    assert_eq!(output.status.code(), Some(EXPOSED));
    let text = report(&output);
    assert!(text.contains("leaked in history"), "{text}");
    assert!(text.contains("secrets/db.env"), "{text}");
}

#[test]
fn the_history_report_puts_rotation_before_rewriting() {
    // The wording is part of the safeguard: a rewrite cleans the repository and
    // does not revoke the leak, so rotation has to come first and say why.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("leak");
    repo.write_xcrypt_config("secrets/\n");

    let text = report(&repo.xcrypt(["status"]));

    let rotate = text
        .find("ROTATE THE SECRET")
        .unwrap_or_else(|| panic!("no rotation step:\n{text}"));
    let rewrite = text
        .find("git filter-repo")
        .unwrap_or_else(|| panic!("no rewriting command:\n{text}"));
    assert!(
        rotate < rewrite,
        "rewriting was offered before rotation:\n{text}"
    );
    assert!(
        text.contains("does NOT undo this"),
        "the report must not let a rewrite read as a fix:\n{text}"
    );
    assert!(
        text.contains("--path 'secrets/db.env'"),
        "the ready-made command must name the path:\n{text}"
    );
}

#[test]
fn a_secret_deleted_from_head_is_still_found() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("the secret");

    std::fs::remove_file(repo.path().join("secrets/db.env")).expect("removing");
    repo.write_xcrypt_config("secrets/\n");
    repo.commit_all("and gone again");

    let output = repo.xcrypt(["status"]);

    assert_eq!(output.status.code(), Some(EXPOSED));
    assert!(report(&output).contains("secrets/db.env"));
}

#[test]
fn a_repository_encrypted_from_the_first_commit_passes() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n*.env\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.write_file("README.md", b"public\n");
    repo.commit_all("all encrypted");

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(text.contains("encrypted: 1 declared path"), "{text}");
    assert!(!text.contains("leaked in history"), "{text}");
}

#[test]
fn a_file_no_pattern_reaches_is_never_reported() {
    // The documented boundary. A secret nobody declared is invisible here, and
    // the report says so rather than implying a clean repository is a safe one.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("notes/passwords.txt", b"nobody declared this\n");
    repo.commit_all("undeclared");

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(!text.contains("passwords.txt"), "{text}");
    assert!(
        text.contains("not whether"),
        "the boundary must be stated:\n{text}"
    );
}

#[test]
fn a_negated_path_is_listed_apart_and_does_not_fail_the_gate() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n!secrets/README.md\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.write_file("secrets/README.md", b"public on purpose\n");
    repo.commit_all("with an exception");

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(text.contains("in the clear by choice"), "{text}");
    assert!(text.contains("secrets/README.md"), "{text}");
    assert!(!text.contains("leaked in history"), "{text}");
}

#[test]
fn a_declared_file_staged_in_the_clear_is_reported_as_such() {
    // A clone that was never unlocked stages plain text with exit code 0. The
    // index is the thing that says what the next commit would push.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.commit_all("setup");

    let clone = repo.clone_without_filter();
    clone.write_file("secrets/db.env", b"hunter2\n");
    clone.git_ok(["add", "-A"]);

    let output = clone.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(EXPOSED), "{text}");
    assert!(text.contains("in the clear:"), "{text}");
    assert!(text.contains("secrets/db.env"), "{text}");
}

#[test]
fn a_missing_declaration_is_reported_as_undetermined_rather_than_clean() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    std::fs::remove_file(repo.path().join(".git-xcrypt")).expect("removing");

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(EXPOSED), "{text}");
    assert!(text.contains("undetermined"), "{text}");
}

#[test]
fn a_locked_repository_can_still_be_scanned() {
    // No key, no decryption: the scan reads eleven bytes of magic per blob, so
    // it works exactly where a user is least able to look for themselves.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");
    repo.xcrypt_ok(["lock", "--yes"]);

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(text.contains("encrypted: 1 declared path"), "{text}");
}

/// A repository with `secrets/db.env` committed in the clear before anything
/// declared it — the state `--fix` and the filter warning both exist for.
fn leaked_before_the_declaration() -> TestRepo {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("before anyone declared anything");
    repo.write_xcrypt_config("secrets/\n");
    repo
}

#[test]
fn fix_re_stages_the_declared_file_and_the_next_commit_stores_ciphertext() {
    // The property that matters is not what the index says, it is what `git
    // commit` writes. Measured before this worked: the index pointed at the new
    // blob, `git diff-index --cached HEAD` reported no change at all, and the
    // commit put the plaintext straight back — because the cache tree still
    // named the old directory tree. `status --fix` reported success over it.
    let repo = leaked_before_the_declaration();

    let output = repo.xcrypt(["status", "--fix"]);
    assert_eq!(output.status.code(), Some(EXPOSED), "{}", report(&output));

    let staged =
        String::from_utf8_lossy(&repo.git_ok(["status", "--porcelain"]).stdout).into_owned();
    assert!(
        staged.contains("M  secrets/db.env"),
        "the re-stage did not reach the index:\n{staged}"
    );

    // The declaration itself changed in the fixture and has to travel with the
    // commit, or the tree is left dirty for a reason that has nothing to do
    // with the fix.
    repo.git_ok(["add", ".git-xcrypt"]);
    repo.git_ok(["commit", "-q", "-m", "after fix"]);
    let blob = repo.blob_bytes("secrets/db.env");
    assert!(
        blob.starts_with(b"\0GITXCRYPT\0"),
        "the commit stored {} bytes that are not ciphertext",
        blob.len()
    );
    repo.assert_worktree_eq("secrets/db.env", b"hunter2\n");
    repo.assert_status_clean();
}

#[test]
fn fix_says_it_changed_nothing_about_the_past() {
    let repo = leaked_before_the_declaration();

    let text = report(&repo.xcrypt(["status", "--fix"]));

    assert!(text.contains("NO HISTORY WAS REWRITTEN"), "{text}");
    assert!(text.contains("nothing was un-leaked"), "{text}");
    assert!(
        text.contains("rotate the secret"),
        "the only remedy that revokes anything must be named:\n{text}"
    );
}

#[test]
fn the_history_finding_survives_fix() {
    // `--fix` repairs the future. Reporting the repository as clean afterwards
    // would be the exact misreading the wording guards against, so the gate has
    // to keep failing.
    let repo = leaked_before_the_declaration();
    repo.xcrypt(["status", "--fix"]);

    let output = repo.xcrypt(["status"]);

    assert_eq!(output.status.code(), Some(EXPOSED));
    assert!(report(&output).contains("leaked in history"));
}

#[test]
fn fix_leaves_the_working_tree_readable() {
    // Encrypting in place is what `lock` does. Doing it here would take a user's
    // own secrets away from them in the name of a repair.
    let repo = leaked_before_the_declaration();
    repo.write_file("secrets/other.env", b"second\n");
    repo.git_ok(["add", "-A"]);

    repo.xcrypt(["status", "--fix"]);

    repo.assert_worktree_eq("secrets/db.env", b"hunter2\n");
    repo.assert_worktree_eq("secrets/other.env", b"second\n");
}

#[test]
fn fix_without_a_key_refuses_rather_than_pretending() {
    // A locked repository, reached the only way this state is reachable here:
    // `lock` itself refuses over a file stored in the clear, which is the very
    // state under test.
    let repo = leaked_before_the_declaration();
    std::fs::remove_file(repo.path().join(".git/git-xcrypt/keys/default")).expect("removing");

    let output = repo.xcrypt(["status", "--fix"]);

    assert_eq!(
        output.status.code(),
        Some(3),
        "a missing key has its own code:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_first_encryption_of_a_file_head_holds_in_the_clear_is_warned_about() {
    let repo = leaked_before_the_declaration();

    let output = repo.git(["add", "secrets/db.env"]);

    assert!(
        output.status.success(),
        "the warning aborted `git add`: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("HEAD already holds it in the clear"),
        "no warning on the check-in path:\n{stderr}"
    );
    assert!(
        stderr.contains("git-xcrypt status"),
        "the warning must point at the command that explains it:\n{stderr}"
    );
}

#[test]
fn the_warning_does_not_stop_the_content_from_being_encrypted() {
    // It is a warning, not a refusal. With `required = true` a non-zero exit
    // would abort the whole operation.
    let repo = leaked_before_the_declaration();

    repo.commit_all("now encrypted");

    let blob = repo.blob_bytes("secrets/db.env");
    assert!(blob.starts_with(b"\0GITXCRYPT\0"), "{} bytes", blob.len());
}

#[test]
fn a_file_that_is_not_in_head_is_encrypted_without_a_warning() {
    // Every file in the repository goes through the filter, so a warning that is
    // not gated is a warning nobody reads.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("README.md", b"public\n");
    repo.commit_all("start");
    repo.write_file("secrets/fresh.env", b"brand new\n");

    let output = repo.git(["add", "-A"]);

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("HEAD already holds"),
        "a file that was never committed in the clear was reported as one:\n{stderr}"
    );
}

#[test]
fn one_git_command_warns_once_per_path() {
    // Measured on git 2.55: a single `git status` cleans the same file four
    // times. Four copies of a message teach a reader to skip it.
    let repo = leaked_before_the_declaration();

    let output = repo.git(["status", "--porcelain"]);

    let warnings = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| line.contains("HEAD already holds"))
        .count();
    assert_eq!(warnings, 1, "{}", String::from_utf8_lossy(&output.stderr));
}
