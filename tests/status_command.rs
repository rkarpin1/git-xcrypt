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
