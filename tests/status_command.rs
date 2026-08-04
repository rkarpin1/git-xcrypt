//! `git-xcrypt status` against real repositories.
//!
//! The question this command answers is only ever true or false about a real
//! git: whether git would run the filter, and whether the objects git already
//! holds carry ciphertext. Both are settled by driving git itself.

mod harness;

use harness::TestRepo;

/// The exit code the frozen table gives to "an exposure was found".
const EXPOSED: i32 = 5;

/// The exit code for "this run could not answer the question".
///
/// Added 2026-08-04. Before it, both answers came out as `5`, so a perfectly
/// healthy `git clone --depth 1` — what `actions/checkout` produces by default —
/// failed the gate with the same code as a repository holding a plaintext
/// secret. The two ask different things of whoever reads them.
const UNDETERMINED: i32 = 6;

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

    assert_eq!(output.status.code(), Some(UNDETERMINED), "{text}");
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
    assert!(
        text.contains("Nothing was \n  un-leaked") || text.contains("un-leaked"),
        "{text}"
    );
    assert!(
        text.contains("rotate the secret"),
        "the only remedy that revokes anything must be named:\n{text}"
    );
    assert!(
        text.contains("working-tree"),
        "--fix stages the working-tree content, unstaged edits included, and the \
         report has to say so:\n{text}"
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

    assert_eq!(output.status.code(), Some(UNDETERMINED), "{text}");
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
    // Declared and re-committed, so the index holds ciphertext and the only
    // thing left to find is in history — which is exactly what the unreadable
    // reference store hides. Without this the index carried a finding of its
    // own and the test could not tell the two verdicts apart.
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.commit_all("declare");
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
        Some(UNDETERMINED),
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

/// A source repository and a key file that opens it, for the clone tests below.
fn source_and_key() -> (TestRepo, tempfile::TempDir, std::path::PathBuf) {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("one");
    repo.write_file("README.md", b"two\n");
    repo.commit_all("two");

    let elsewhere = tempfile::TempDir::new().expect("a directory outside the repository");
    let key = elsewhere.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key.to_string_lossy()]);
    (repo, elsewhere, key)
}

#[test]
fn a_healthy_shallow_clone_is_undetermined_rather_than_exposed() {
    // The measurement that forced the new code: `actions/checkout` clones with
    // `--depth 1` unless told otherwise, so the default CI setup could not pass
    // this gate. Nothing here is wrong with the repository — a history that was
    // never fetched simply cannot be vouched for — and "I could not check" has
    // to be distinguishable from "I found a secret" by the exit code alone,
    // because that is all a CI gate reads.
    let (repo, _elsewhere, key) = source_and_key();

    let clone = repo.clone_shallow();
    clone.xcrypt_ok(["unlock", &key.to_string_lossy()]);
    let output = clone.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(
        output.status.code(),
        Some(UNDETERMINED),
        "a healthy shallow clone must not report an exposure:\n{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("shallow clone"), "{text}");
    assert!(
        text.contains("could not be checked"),
        "the verdict has to say it could not check, not that it found something:\n{text}"
    );
    assert!(
        !text.contains("leaked in history"),
        "nothing was found, so nothing may be reported as found:\n{text}"
    );
}

#[test]
fn a_partial_clone_is_undetermined_rather_than_exposed() {
    // `extensions.partialclone` is what a `--filter=blob:none` clone carries,
    // and it means an absent object is a design decision rather than damage.
    // Same verdict as the shallow case and for the same reason: unjudged, not
    // guilty.
    let (repo, _elsewhere, key) = source_and_key();

    let clone = repo.clone_without_filter();
    clone.xcrypt_ok(["unlock", &key.to_string_lossy()]);
    clone.git_ok(["config", "extensions.partialclone", "origin"]);
    let output = clone.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(
        output.status.code(),
        Some(UNDETERMINED),
        "a partial clone must not report an exposure:\n{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("partial clone"), "{text}");
    assert!(text.contains("could not be checked"), "{text}");
}

#[cfg(unix)]
#[test]
fn an_index_that_cannot_be_read_is_undetermined_when_nothing_else_was_found() {
    // The twin of `an_index_that_cannot_be_read_still_leaves_a_report_and_a_verdict`,
    // which has a real finding beside it and therefore still exits 5. With no
    // finding, all this run established is that it could not look.
    use std::os::unix::fs::PermissionsExt as _;

    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");

    let index = repo.path().join(".git").join("index");
    let restore = std::fs::metadata(&index).expect("index").permissions();
    std::fs::set_permissions(&index, std::fs::Permissions::from_mode(0o000)).expect("closing");

    let output = repo.xcrypt(["status"]);
    std::fs::set_permissions(&index, restore).expect("reopening");

    let text = report(&output);
    assert_eq!(
        output.status.code(),
        Some(UNDETERMINED),
        "an unreadable index is not an exposure:\n{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("undetermined"), "{text}");
}

#[test]
fn a_real_finding_outranks_anything_that_could_not_be_checked() {
    // Precedence, stated as a test because the whole value of the new code is
    // that `5` never gets weaker. A run that both found a leak and could not
    // read the index has found a leak.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("the leak");
    repo.write_xcrypt_config("secrets/\n");
    repo.git_ok(["update-index", "--split-index"]);

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "an exposure beside an unanswerable question is still an exposure:\n{text}"
    );
    assert!(text.contains("leaked in history"), "{text}");
    assert!(text.contains("undetermined"), "{text}");
}

#[test]
fn the_verdict_comes_before_the_wall_of_good_news() {
    // Measured on the build without it: a repository with 300 encrypted paths
    // and one leak put the leak — and the instruction to rotate it — 300 lines
    // below the fold, under a solid wall of green. The founding document is
    // explicit that the wording here is the safeguard.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    for index in 0..30 {
        repo.write_file(&format!("secrets/f{index}.env"), b"value\n");
    }
    repo.commit_all("leak");
    repo.write_xcrypt_config("secrets/\n");

    let text = report(&repo.xcrypt(["status"]));
    let first = text.lines().next().unwrap_or_default();

    assert!(first.starts_with("VERDICT:"), "{text}");
    assert!(first.contains("leaked in history"), "{first}");
}

#[test]
fn a_clean_repository_says_so_on_its_first_line() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");

    let text = report(&repo.xcrypt(["status"]));

    assert!(text.starts_with("VERDICT: no findings."), "{text}");
}

#[test]
fn bootstrap_files_that_were_never_committed_are_a_setup_gap() {
    // `init` creates `.gitattributes` and `.git-xcrypt` and does not commit
    // them. A repository that pushed without them looks perfectly configured
    // from inside and publishes nothing that enforces anything — the clone
    // finds out, the machine that pushed does not.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.git_ok(["add", "secrets/db.env"]);

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(EXPOSED), "{text}");
    assert!(text.contains(".gitattributes is not committed"), "{text}");
    assert!(text.contains(".git-xcrypt is not committed"), "{text}");
}

#[test]
fn a_line_that_turns_the_filter_off_is_named() {
    // Git takes the LAST matching attribute line, so one below the managed
    // section can unset `filter` for a declared path. Measured: `git check-attr`
    // then says `unset`, `git add` stores the plaintext, and a build that only
    // looked for the catch-all line called the repository healthy.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    let mut attributes = std::fs::read_to_string(repo.path().join(".gitattributes"))
        .expect("reading .gitattributes");
    attributes.push_str("secrets/** -filter\n");
    repo.write_file(".gitattributes", attributes.as_bytes());
    repo.commit_all("with an override");

    let text = report(&repo.xcrypt(["status"]));

    assert!(text.contains("set or unset `filter`"), "{text}");
    assert!(text.contains("secrets/** -filter"), "{text}");
    assert!(text.contains("check-attr"), "{text}");
}

#[test]
fn a_declared_path_git_would_not_filter_is_a_setup_gap_not_a_note() {
    // The last route to a green report on a repository that stores plaintext.
    // Measured on git 2.55: `git check-attr filter -- secrets/db.env` answers
    // `unset`, the next `git add` stores `hunter2` in the clear with exit code
    // 0, and every other check in this command passes. Naming the file was not
    // enough — a note does not fail a CI gate.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");
    repo.write_file("secrets/.gitattributes", b"* -filter\n");
    repo.commit_all("the override");

    assert_eq!(
        repo.check_attr("filter", "secrets/db.env"),
        "unset",
        "the fixture must really take the filter off the declared path"
    );

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "a repository git does not filter must fail the gate:\n{text}"
    );
    assert!(
        text.contains("setup: git is NOT filtering"),
        "the finding belongs in the setup section:\n{text}"
    );
    assert!(
        text.contains("secrets/db.env"),
        "the report has to name the path git leaves unfiltered:\n{text}"
    );
    assert!(
        text.contains("`unset`"),
        "the report has to quote what git resolves instead:\n{text}"
    );
}

#[test]
fn an_info_attributes_file_that_turns_the_filter_off_fails_the_gate() {
    // `$GIT_DIR/info/attributes` is not versioned and outranks every
    // `.gitattributes`, so it is the source an audit is least likely to look at
    // — and the one a reviewer of a pull request cannot see at all.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");
    std::fs::create_dir_all(repo.path().join(".git").join("info")).expect("directories");
    std::fs::write(
        repo.path().join(".git").join("info").join("attributes"),
        b"secrets/** -filter\n",
    )
    .expect("writing");

    assert_eq!(repo.check_attr("filter", "secrets/db.env"), "unset");

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(EXPOSED), "{text}");
    assert!(text.contains("secrets/db.env"), "{text}");
}

#[test]
fn a_macro_that_takes_the_filter_off_is_followed_through() {
    // `[attr]` indirection is the shape a reader is least likely to follow by
    // hand, and the reason resolving beats pattern-spotting: nothing on the
    // line that reaches `secrets/` mentions `filter` at all.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");

    let attributes = std::fs::read_to_string(repo.path().join(".gitattributes"))
        .expect("reading .gitattributes");
    repo.write_file(
        ".gitattributes",
        format!("[attr]plain -filter\n{attributes}secrets/** plain\n").as_bytes(),
    );
    repo.commit_all("a macro");

    assert_eq!(
        repo.check_attr("filter", "secrets/db.env"),
        "unset",
        "the fixture must really take the filter off through the macro"
    );

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(EXPOSED), "{text}");
    assert!(
        text.contains("setup: git is NOT filtering"),
        "the macro has to be followed, not merely spotted:\n{text}"
    );
    assert!(text.contains("secrets/db.env"), "{text}");
}

#[test]
fn a_foreign_filter_on_paths_no_pattern_reaches_does_not_fail_the_gate() {
    // `*.psd filter=lfs` below the managed section is entirely ordinary. A
    // build that alarmed on the presence of a foreign `filter` line would fail
    // the gate in every repository using LFS, which is the fastest way to teach
    // a user to ignore this command.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    let attributes = std::fs::read_to_string(repo.path().join(".gitattributes"))
        .expect("reading .gitattributes");
    repo.write_file(
        ".gitattributes",
        format!("{attributes}*.psd filter=lfs\n").as_bytes(),
    );
    repo.commit_all("with lfs");

    assert_eq!(
        repo.check_attr("filter", "secrets/db.env"),
        "git-xcrypt",
        "git still runs our filter for the declared path"
    );

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(
        output.status.code(),
        Some(0),
        "an unrelated LFS line must not fail the gate:\n{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("*.psd filter=lfs"),
        "the line is still worth naming, as a note:\n{text}"
    );
    assert!(
        text.contains("nothing tracked is unprotected"),
        "the note has to say the resolution came out clean:\n{text}"
    );
}

#[test]
fn a_repository_with_no_foreign_filter_lines_says_nothing_about_them() {
    // The note used to fire on the mere presence of a line. This is the other
    // half of that fix: silence when there is nothing to say.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");

    let text = report(&repo.xcrypt(["status"]));

    assert!(
        !text.contains("set or unset `filter`"),
        "a healthy repository must not carry the note:\n{text}"
    );
}

#[test]
fn an_intent_to_add_entry_is_not_claimed_as_fixed() {
    // `git add -N` records the empty blob at mode 100644, so it reads as
    // content in the clear — and repointing it announced a repair the next
    // commit did not make, because git still treats the path as unstaged.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("README.md", b"public\n");
    repo.commit_all("start");
    repo.write_file("secrets/new.env", b"brand new\n");
    repo.git_ok(["add", "-N", "secrets/new.env"]);

    let text = report(&repo.xcrypt(["status", "--fix"]));

    assert!(
        !text.contains("fixed:"),
        "an intent-to-add entry was claimed as re-staged:\n{text}"
    );
}

#[test]
fn a_file_under_refs_that_is_not_a_reference_does_not_fail_the_gate() {
    // Git prints `warning: ignoring broken ref` and carries on. Such a file
    // names no history, so nothing goes unscanned because of it.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");
    std::fs::write(repo.path().join(".git/refs/heads/crashed"), b"").expect("writing");

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(!text.contains("undetermined"), "{text}");
}

#[test]
fn a_reference_that_will_not_resolve_is_named_not_merely_counted() {
    // "1 reference(s) could not be resolved" in a CI log gives an operator
    // nothing to act on.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");
    std::fs::write(
        repo.path().join(".git/refs/heads/dangling"),
        b"0000000000000000000000000000000000000001\n",
    )
    .expect("writing");

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    // Undetermined rather than exposed: a branch whose history was never walked
    // is a question left unanswered, not a secret found.
    assert_eq!(output.status.code(), Some(UNDETERMINED), "{text}");
    assert!(text.contains("refs/heads/dangling"), "{text}");
}

#[test]
fn an_attributes_file_below_the_root_that_turns_the_filter_off_is_named() {
    // Git resolves attributes from every directory on a path, then from
    // `.git/info/attributes`, with the LAST match winning. Looking only at the
    // root file made `status` print `setup: git is configured to run the filter
    // in this repository` and exit 0 for a repository where
    // `git check-attr filter -- secrets/db.env` answered `unset` and the next
    // `git add` stored the plaintext — measured on git 2.55.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");
    repo.write_file("secrets/.gitattributes", b"* -filter\n");

    assert_eq!(
        repo.check_attr("filter", "secrets/db.env"),
        "unset",
        "the fixture must really take the filter off the declared path"
    );

    let text = report(&repo.xcrypt(["status"]));

    assert!(
        text.contains("secrets/.gitattributes"),
        "the file that overrides the catch-all went unmentioned:\n{text}"
    );
}

#[test]
fn an_info_attributes_file_that_turns_the_filter_off_is_named() {
    // `$GIT_DIR/info/attributes` is not versioned and outranks every
    // `.gitattributes`, so it is the one an audit is least likely to look at.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");
    std::fs::create_dir_all(repo.path().join(".git").join("info")).expect("directories");
    std::fs::write(
        repo.path().join(".git").join("info").join("attributes"),
        b"secrets/** -filter\n",
    )
    .expect("writing");

    assert_eq!(repo.check_attr("filter", "secrets/db.env"), "unset");

    let text = report(&repo.xcrypt(["status"]));

    assert!(
        text.contains("info/attributes"),
        "the highest-precedence attributes file went unmentioned:\n{text}"
    );
}

#[cfg(unix)]
#[test]
fn an_index_that_cannot_be_read_still_leaves_a_report_and_a_verdict() {
    // Both index calls used to be a bare `?`, so an I/O failure propagated out
    // of `run` and `status` printed nothing at all and exited 1 — "usage error
    // or unclassified" — for a repository that was genuinely exposed. A `.git`
    // written by `sudo git`, or a read-only mount, reaches it.
    use std::os::unix::fs::PermissionsExt as _;

    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("README.md", b"public\n");
    repo.commit_all("start");
    // A secret committed before the pattern reached it: the history scan has a
    // real finding to deliver, and it is the thing that must not go missing.
    repo.write_xcrypt_config("*.pem\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("the leak");
    repo.write_xcrypt_config("secrets/\n");

    let index = repo.path().join(".git").join("index");
    let restore = std::fs::metadata(&index).expect("index").permissions();
    std::fs::set_permissions(&index, std::fs::Permissions::from_mode(0o000)).expect("closing");

    let output = repo.xcrypt(["status"]);
    std::fs::set_permissions(&index, restore).expect("reopening");

    let text = report(&output);
    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "an unreadable index must not hide the history finding:\n{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("leaked in history"),
        "the finding that matters most went missing:\n{text}"
    );
    assert!(
        text.contains("undetermined"),
        "the unreadable index must be said out loud:\n{text}"
    );
}

#[test]
fn an_empty_required_value_is_reported_as_the_off_switch_git_reads_it_as() {
    // `git config filter.git-xcrypt.required ""` writes `required = `, which git
    // reads as **false** — measured on 2.55 with `git config --type=bool`, and
    // measured end to end: a failing filter is then ignored, `git add` exits 0
    // and the plaintext lands in the object database. `gix-config` reports that
    // line and the value-less `required` identically once flattened, so calling
    // the empty string true made this gate report `setup: git is configured to
    // run the filter in this repository` and exit 0 over exactly that.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file("secrets/db.env", b"hunter2\n");
    repo.commit_all("secret");
    repo.git_ok(["config", "filter.git-xcrypt.required", ""]);

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "the flag git reads as off must fail the gate:\n{text}"
    );
    assert!(
        text.contains("filter.git-xcrypt.required"),
        "the gap must name the key:\n{text}"
    );
}

#[test]
fn a_stale_section_is_reported_as_the_corruption_it_risks_not_as_a_tidiness_nag() {
    // A pattern added to `.git-xcrypt` takes effect for *selection* at once —
    // the filter reads that file, not `.gitattributes` — so it is easy to read
    // the managed lines as decoration and never run `sync`. They are not.
    //
    // Measured on git 2.55 and reproduced below: in that state, any other
    // attribute source declaring the same path `text` makes git run its own
    // CRLF conversion over the *ciphertext*. `git add` exits 0, the damaged
    // blob is committed, and the file is gone at checkout — permanently, since
    // nothing can authenticate the stored bytes again.
    //
    // The note used to say only that a clone's `unlock` would leave `git
    // status` dirty. The wording is part of the safeguard here, so it has to
    // name the outcome that actually costs something.
    let secret: Vec<u8> = (0..2 * 1024 * 1024u32)
        .map(|index| u8::try_from(index % 251).expect("a byte"))
        .collect();

    let repo = TestRepo::init();
    repo.init_xcrypt();
    // A pattern the managed section does not know about yet: `init` rendered
    // the section for an empty declaration, and `sync` is deliberately not run.
    repo.write_xcrypt_config("secrets/\n");

    let attributes = repo.worktree_bytes(".gitattributes");
    let mut with_user_line = b"secrets/** text\n".to_vec();
    with_user_line.extend_from_slice(&attributes);
    repo.write_file(".gitattributes", &with_user_line);

    repo.write_file("secrets/deep.env", &secret);
    repo.commit_all("a secret committed before the section caught up");

    // First: the risk is real, not a story the message tells.
    assert_ne!(
        repo.blob_bytes("secrets/deep.env").len(),
        38 + secret.len(),
        "this test no longer reproduces the corruption it exists to describe; \
         if git stopped converting here, the note below should be re-examined \
         rather than kept"
    );
    std::fs::remove_file(repo.path().join("secrets/deep.env")).expect("could not remove");
    let checkout = repo.git(["checkout", "--", "secrets/deep.env"]);
    assert!(
        !repo.path().join("secrets/deep.env").is_file(),
        "the damaged blob must fail to check out:\n{}",
        String::from_utf8_lossy(&checkout.stderr)
    );

    // Second: `status` says so, in those terms.
    let output = repo.xcrypt(["status"]);
    let text = report(&output);
    assert!(
        text.contains("-text"),
        "the note must name the attribute whose absence does the damage:\n{text}"
    );
    assert!(
        text.contains("corrupt"),
        "the note must name corruption, not only a dirty `git status`:\n{text}"
    );
    assert!(
        text.contains("git-xcrypt sync"),
        "the note must say what settles it:\n{text}"
    );
}
