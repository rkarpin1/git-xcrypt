//! The two setup checks in `status` that no scenario can put a repository into.
//!
//! Everything else this command answers is driven as a whole run elsewhere: the
//! history scan and `--fix` in `tests/exposure.rs`, the verdict precedence and
//! the unusual repository shapes in `tests/odd_repositories.rs`, the unfiltered
//! declared path in `tests/decrypted_diff.rs`, the unconfigured clone in
//! `tests/second_machine.rs`.
//!
//! What is left are the two states a user reaches by editing configuration by
//! hand — `required` turned off, and the catch-all line taken out of
//! `.gitattributes`. Both are what `init` writes, so a scenario that produced
//! them would have to undo `init` first, and would then be grading its own
//! fixture. Measured: with either check removed from `status`, nothing else in
//! the suite goes red.

mod harness;

use harness::TestRepo;

/// The exit code the frozen table gives to a configuration or state conflict.
///
/// Both states below are setup gaps, and since 2026-08-05 a setup gap is `2`
/// rather than `5`: there is no secret to rotate in a repository whose only
/// problem is that git was never told to run the filter, and `5` sent the
/// operator after one.
const CONFIG: i32 = 2;

#[test]
fn dropping_the_required_flag_is_caught() {
    // Measured on git 2.55: without it a failing clean filter leaves `git add`
    // exiting 0 and the plaintext in the object database.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.git_ok(["config", "filter.git-xcrypt.required", "false"]);

    let output = repo.xcrypt(["status"]);

    assert_eq!(output.status.code(), Some(CONFIG));
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

    assert_eq!(output.status.code(), Some(CONFIG));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("* filter=git-xcrypt"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
