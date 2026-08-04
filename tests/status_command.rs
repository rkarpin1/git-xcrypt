//! `git-xcrypt status` against real repositories.
//!
//! The question this command answers is only ever true or false about a real
//! git: whether git would run the filter, and whether the objects git already
//! holds carry ciphertext. Both are settled by driving git itself.

mod harness;

use harness::TestRepo;

/// The exit code the frozen table gives to "an exposure was found".
const EXPOSED: i32 = 5;

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
