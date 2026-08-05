//! `sync` against a real git, which is the only authority on whether the
//! generated lines mean anything.
//!
//! The lines are called cosmetic because a stale section never stores a secret
//! in the clear — but "cosmetic" has never meant "optional" here. `-text` is
//! what keeps git's own CRLF conversion off the ciphertext, and its absence was
//! measured eating bytes out of a committed blob and costing the file at
//! checkout. The two files also spell patterns differently, so a rendered line
//! git silently ignores would be worse than no line.

mod harness;

use harness::TestRepo;

/// A repository set up the way a user's would be, with `declarations` written
/// and the section brought up to date.
fn synced(declarations: &str) -> TestRepo {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config(declarations);
    repo.xcrypt_ok(["sync"]);
    repo
}

#[test]
fn a_directory_pattern_reaches_the_subtree_at_any_depth() {
    // `.gitignore` floats a pattern that carries no slash of its own, so
    // `secrets/` selects `app/secrets/x` too and the filter encrypts it. The
    // rendered line has to reach exactly as far, or that file is encrypted
    // without `-text` — see the round-trip test below for what that costs.
    let repo = synced("secrets/\n*.env\n");

    for path in [
        "secrets/a.txt",
        "app/secrets/a.txt",
        "a/b/secrets/c/d.txt",
        "deep/one.env",
        "config.env/inner.txt",
    ] {
        assert_eq!(
            repo.check_attr("text", path),
            "unset",
            "{path}: the filter encrypts this path, so git must see -text on it"
        );
    }
    assert_eq!(
        repo.check_attr("text", "notsecrets/a.txt"),
        "unspecified",
        "the line must not reach past what the filter encrypts"
    );
}
