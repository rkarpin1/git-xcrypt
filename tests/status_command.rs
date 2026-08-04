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
///
/// The file is rewritten after the declaration, deliberately. Git decides
/// whether to re-run the clean filter from the `stat` it cached, and only
/// within the same second does its racy-clean rule make it re-read anyway — so
/// a fixture that left the file untouched would exercise the check-in path only
/// when the test happened to run fast enough. What the untouched case really
/// does has a test of its own below, and is the reason `--fix` exists at all.
fn leaked_before_the_declaration() -> TestRepo {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("before anyone declared anything");
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
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
fn fix_without_a_key_says_so_without_throwing_the_report_away() {
    // A locked repository, reached the only way this state is reachable here:
    // `lock` itself refuses over a file stored in the clear, which is the very
    // state under test.
    //
    // The repair needs a key; the diagnosis does not. Propagating the missing
    // key as an error would leave a user who typed one flag too many with less
    // information than if they had not typed it at all.
    let repo = leaked_before_the_declaration();
    std::fs::remove_file(repo.path().join(".git/git-xcrypt/keys/default")).expect("removing");

    let output = repo.xcrypt(["status", "--fix"]);
    let text = report(&output);

    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("--fix needs the repository key"), "{text}");
    assert!(text.contains("unlock"), "{text}");
    assert!(
        text.contains("leaked in history"),
        "the diagnosis was thrown away with the repair:\n{text}"
    );
    assert!(!text.contains("fixed:"), "nothing was fixed:\n{text}");
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
    // Rewritten so the cached `stat` no longer matches and git has to run the
    // clean filter rather than take its shortcut — otherwise this test would
    // pass by never exercising the path at all.
    repo.write_file("secrets/db.env", b"hunter2\n");

    let output = repo.git(["status", "--porcelain"]);

    let warnings = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| line.contains("HEAD already holds"))
        .count();
    assert_eq!(warnings, 1, "{}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn a_sha256_repository_is_scanned_and_fixed_rather_than_crashed_on() {
    // Measured before `objects()` was given the hash: `gix-odb` asserts on the
    // id length rather than adapting, so `status` panicked with exit 101 — and
    // so did the filter on the check-in path, where `required = true` turns a
    // panic into "every git operation in this repository fails".
    let repo = TestRepo::init_sha256();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("leak");
    repo.write_xcrypt_config("secrets/\n");

    let output = repo.xcrypt(["status"]);
    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        report(&output).contains("leaked in history"),
        "{}",
        report(&output)
    );

    let fixed = repo.xcrypt(["status", "--fix"]);
    assert_eq!(
        fixed.status.code(),
        Some(EXPOSED),
        "stderr: {}",
        String::from_utf8_lossy(&fixed.stderr)
    );

    repo.git_ok(["add", ".git-xcrypt"]);
    repo.git_ok(["commit", "-q", "-m", "after fix"]);
    assert!(
        repo.blob_bytes("secrets/db.env")
            .starts_with(b"\0GITXCRYPT\0")
    );
    repo.assert_status_clean();
}

#[test]
fn a_split_index_is_reported_as_undetermined_rather_than_silently_skipped() {
    // `features.manyFiles=true` turns this on wholesale, so it is not exotic.
    // The history scan needs no index and still runs; what must not happen is
    // "nothing found" over an index this build could not read.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");
    repo.git_ok(["update-index", "--split-index"]);

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(EXPOSED), "{text}");
    assert!(text.contains("undetermined"), "{text}");
    assert!(text.contains("split index"), "{text}");
}

#[test]
fn packed_objects_are_scanned_as_well_as_loose_ones() {
    // A repository anyone has cloned or garbage-collected keeps its history in
    // pack files. A scan that only read loose objects would report the oldest
    // and most exposed history as clean.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("leak");
    repo.git_ok(["gc", "--quiet", "--aggressive", "--prune=now"]);
    repo.write_xcrypt_config("secrets/\n");

    let output = repo.xcrypt(["status"]);

    assert_eq!(output.status.code(), Some(EXPOSED));
    assert!(
        report(&output).contains("leaked in history"),
        "{}",
        report(&output)
    );
}

#[test]
fn a_repository_with_no_commits_yet_reports_nothing_alarming() {
    // Between `git init` and the first commit, `HEAD` is symbolic and points at
    // a branch that does not exist. That is every new repository, and greeting
    // it with "HEAD could not be resolved" is a bug report waiting to be filed.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");

    let output = repo.xcrypt(["status"]);

    assert_eq!(output.status.code(), Some(0), "{}", report(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("could not be resolved"),
        "an unborn branch was reported as a failure:\n{stderr}"
    );
    assert!(report(&output).contains("scanned 0 commit(s)"));
}

#[test]
fn a_declaration_added_later_does_not_reach_an_untouched_file_and_status_says_so() {
    // The gap this whole command exists to close, measured rather than assumed.
    // Git decides whether to re-run the clean filter from its cached `stat`, so
    // adding a pattern for a file that is already committed and is not then
    // edited changes nothing: `git add -A` skips it, the next commit stores the
    // plain text again, and the exit code is 0 with no warning anywhere.
    //
    // `.git-xcrypt` really is read on every `git add` — the filter does consult
    // it — but git never asks the filter about a file it has decided is
    // unchanged. So `status` has to catch this, and `--fix` has to repair it.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("before anyone declared anything");

    // Past git's racy-clean window, where it re-reads regardless of the stat.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    repo.git_ok(["update-index", "--refresh"]);
    repo.write_xcrypt_config("secrets/\n");
    repo.commit_all("declared, but the file itself did not change");

    assert_eq!(
        repo.blob_bytes("secrets/db.env"),
        b"hunter2\n",
        "this test is documenting git's stat shortcut; if the blob is now \
         ciphertext, git changed and the note in status.rs needs revisiting"
    );

    // Which is exactly what this command is for.
    let output = repo.xcrypt(["status"]);
    let text = report(&output);
    assert_eq!(output.status.code(), Some(EXPOSED), "{text}");
    assert!(text.contains("in the clear:"), "{text}");
    assert!(text.contains("leaked in history"), "{text}");

    let fixed = repo.xcrypt(["status", "--fix"]);
    assert_eq!(fixed.status.code(), Some(EXPOSED), "{}", report(&fixed));
    repo.git_ok(["commit", "-q", "-m", "after fix"]);
    assert!(
        repo.blob_bytes("secrets/db.env")
            .starts_with(b"\0GITXCRYPT\0"),
        "--fix did not repair what git's shortcut left behind"
    );
}

#[test]
fn a_tracked_symlink_is_left_alone_by_fix() {
    // Measured on the build that read index entries without their mode: a
    // symlink's blob is its target string, which carries no magic, so it was
    // reported "in the clear"; `--fix` then followed the link with `fs::read`,
    // encrypted the file it pointed at — one no pattern selected — and left the
    // entry at mode 120000 with ciphertext behind it. A clone got a symlink
    // whose target was the first NUL of that ciphertext.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("target.txt", b"NOT DECLARED\n");
    std::fs::create_dir_all(repo.path().join("secrets")).expect("directories");
    std::os::unix::fs::symlink("../target.txt", repo.path().join("secrets/link.env"))
        .expect("symlink");
    repo.commit_all("a link");

    let before = repo.blob_bytes("secrets/link.env");
    let output = repo.xcrypt(["status", "--fix"]);
    let text = report(&output);

    assert!(!text.contains("link.env"), "a symlink was judged:\n{text}");
    assert_eq!(
        repo.blob_bytes("secrets/link.env"),
        before,
        "the symlink was rewritten"
    );
    assert_eq!(before, b"../target.txt", "the blob is the link target");
    repo.assert_status_clean();
}

#[test]
fn references_that_cannot_be_read_fail_the_gate_instead_of_reading_as_clean() {
    // A store that cannot be enumerated yields no tips, so the walk visits
    // nothing and finds nothing. Measured before this: a repository with a
    // plaintext blob in its history reported clean and exited 0, with only a
    // line on stderr — and a CI gate reads the exit code.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("leak");
    repo.write_xcrypt_config("secrets/\n");
    repo.git_ok(["pack-refs", "--all"]);

    // Unreadable rather than absent: absent is an ordinary, honest state.
    let packed = repo.path().join(".git/packed-refs");
    let mut permissions = std::fs::metadata(&packed).expect("metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o000);
    std::fs::set_permissions(&packed, permissions).expect("chmod");

    let output = repo.xcrypt(["status"]);

    let mut restore = std::fs::metadata(&packed).expect("metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut restore, 0o644);
    std::fs::set_permissions(&packed, restore).expect("chmod");

    let text = report(&output);
    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "an unscannable repository reported clean:\n{text}"
    );
    assert!(text.contains("undetermined"), "{text}");
}

#[test]
fn a_tag_on_something_that_is_not_a_commit_does_not_fail_the_gate() {
    // `junio-gpg-pub` in git.git is a tag on a blob. Queuing it as a commit made
    // the walk fail to read a "commit" that never was one, which counted as an
    // unreadable object — a permanently red gate advising `git fsck`, which
    // would then report nothing wrong.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");

    let hashed = repo.git_with_stdin(["hash-object", "-w", "--stdin"], b"a public key\n");
    let blob = String::from_utf8(hashed.stdout).expect("a hash");
    repo.git_ok(["tag", "keyring", blob.trim()]);

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(!text.contains("undetermined"), "{text}");
}

#[test]
fn a_shallow_clone_is_named_as_such_rather_than_reported_as_corruption() {
    // Measured before the graft points were honoured: the walk queued the
    // parents git deliberately did not fetch, failed to read them, and told the
    // user "1 object(s) could not be read ... `git fsck` says what is missing".
    // `git fsck` is perfectly happy with a shallow clone. The finding is right —
    // a history that was never fetched cannot be vouched for — but the reason
    // given was not, and it sent the user after a problem that is not there.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("one");
    repo.write_file("README.md", b"two\n");
    repo.commit_all("two");

    let clone = repo.clone_shallow();
    let output = clone.xcrypt(["status"]);
    let text = report(&output);

    assert!(text.contains("shallow clone"), "{text}");
    assert!(text.contains("--unshallow"), "{text}");
    assert!(
        !text.contains("git fsck"),
        "a graft point was reported as a missing object:\n{text}"
    );
}
