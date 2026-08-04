//! `sync` against a real git, which is the only authority on whether the
//! generated lines mean anything.
//!
//! The lines are cosmetic — a stale section costs a worse `git diff`, never a
//! secret — but "cosmetic" is not "unverified": the two files spell patterns
//! differently, and a line git silently ignores would be worse than no line.

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
fn git_honours_the_generated_lines() {
    let repo = synced("secrets/\n*.env\n/build/id_rsa\nsecrets/key.p12 binary\n");

    for path in ["secrets/password.txt", "secrets/deep/other.txt", "one.env"] {
        assert_eq!(
            repo.check_attr("text", path),
            "unset",
            "{path}: git must see -text, or its own CRLF conversion reaches the ciphertext"
        );
        assert_eq!(repo.check_attr("diff", path), "git-xcrypt");
    }

    assert_eq!(
        repo.check_attr("text", "build/id_rsa"),
        "unset",
        "a rooted pattern must still reach the file it names"
    );
    assert_eq!(
        repo.check_attr("text", "nested/build/id_rsa"),
        "unspecified",
        "dropping the leading slash would apply -text to files that are not encrypted"
    );

    assert_eq!(
        repo.check_attr("diff", "secrets/key.p12"),
        "unset",
        "`binary` means -text -diff in git, and it has to mean that here too — \
         merely leaving `diff=` off would keep the driver the `secrets/**` line set"
    );
    assert_eq!(repo.check_attr("text", "secrets/key.p12"), "unset");
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

#[test]
fn an_encrypted_file_survives_a_users_own_text_attribute() {
    // The failure this guards against, reproduced against git 2.55 before the
    // fix: git applies its CRLF conversion to the *output* of the clean filter,
    // so a path the user marked `text` has the CR bytes eaten out of its
    // ciphertext. `git add` still exits 0, the damaged blob is committed, and
    // the loss surfaces only at the next checkout, as `authentication failed`
    // with the plaintext already gone. `-text` on every encrypted path is what
    // prevents it, and it only lands there if the rendered pattern reaches as
    // far as `.git-xcrypt` does — `app/secrets/…` here, not just `secrets/…`.
    //
    // The file is 2 MiB because the damage needs a `CR LF` pair to appear
    // somewhere in the ciphertext. Ciphertext is uniform, so that is one pair
    // per 64 KiB on average: at this size the expected count is around 32 and
    // the chance of seeing none is far below any other cause of a red build.
    let secret: Vec<u8> = (0..2 * 1024 * 1024u32)
        .map(|index| u8::try_from(index % 251).expect("a byte"))
        .collect();

    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);

    // An ordinary line in a user's own attributes file, above our section.
    let attributes = repo.worktree_bytes(".gitattributes");
    let mut with_user_line = b"*.env text\n".to_vec();
    with_user_line.extend_from_slice(&attributes);
    repo.write_file(".gitattributes", &with_user_line);

    repo.write_file("app/secrets/deep.env", &secret);
    repo.commit_all("add a secret in a nested directory");

    assert_eq!(
        repo.blob_bytes("app/secrets/deep.env").len(),
        38 + secret.len(),
        "the stored blob is not the exact size of header plus content, \
         so git's line-ending conversion has eaten bytes out of the ciphertext"
    );

    std::fs::remove_file(repo.path().join("app/secrets/deep.env")).expect("could not remove");
    repo.git_ok(["checkout", "--", "app/secrets/deep.env"]);
    repo.assert_worktree_eq("app/secrets/deep.env", &secret);
    repo.assert_status_clean();
}

#[test]
fn a_negated_path_gets_gits_defaults_back() {
    // The file is stored in the clear, so leaving `-text` on it would stop git
    // managing its line endings, and `diff=git-xcrypt` would point the diff
    // driver at plaintext once S-05 registers one.
    let repo = synced("secrets/\n!secrets/README.md\n");

    assert_eq!(repo.check_attr("text", "secrets/README.md"), "unspecified");
    assert_eq!(repo.check_attr("diff", "secrets/README.md"), "unspecified");
    assert_eq!(
        repo.check_attr("filter", "secrets/README.md"),
        "git-xcrypt",
        "the catch-all must still reach it; only the cosmetic attributes go"
    );
    assert_eq!(
        repo.check_attr("text", "secrets/other.md"),
        "unset",
        "the negation must not spill onto its neighbours"
    );
}

#[test]
fn a_negation_a_later_pattern_overrules_keeps_the_attributes_of_an_encrypted_file() {
    // Selection is last match in `.git-xcrypt` and in `.gitattributes` alike, so
    // a negation written *above* the pattern that re-selects the path must not
    // be the line git ends on. Rendering all negations at the bottom left this
    // encrypted file without `-text`.
    let repo = synced("!secrets/README.md\nsecrets/\n");

    assert_eq!(
        repo.check_attr("text", "secrets/README.md"),
        "unset",
        "this path is encrypted, so git must see -text on it"
    );
    assert_eq!(repo.check_attr("diff", "secrets/README.md"), "git-xcrypt");
}

#[test]
fn a_broad_pattern_leaves_the_bootstrap_files_to_git() {
    // `.gitattributes` at any depth, `.git-xcrypt` and the envelope directory
    // are stored in the clear whatever the patterns say, so `-text` on them
    // would stop git managing their line endings for no reason at all.
    let repo = synced("*\n");

    for path in [
        ".gitattributes",
        "app/.gitattributes",
        ".git-xcrypt",
        ".git-xcrypt-keys/robert.age",
    ] {
        assert_eq!(
            repo.check_attr("text", path),
            "unspecified",
            "{path} is never encrypted, so it must keep git's defaults"
        );
        assert_eq!(repo.check_attr("diff", path), "unspecified");
    }
    assert_eq!(
        repo.check_attr("text", "anything-else.txt"),
        "unset",
        "the exclusions must not reach past the bootstrap files"
    );
}

#[test]
fn a_character_class_pattern_stays_a_pattern() {
    // `[attr]x` opens the line the way a macro definition does, and git checks
    // for that before it unquotes, so the spelling — not the quoting — is what
    // keeps the line a pattern.
    let repo = synced("[attr]x\n");

    assert_eq!(repo.check_attr("text", "ax"), "unset");
    assert_eq!(repo.check_attr("text", "sub/tx"), "unset");
    assert_eq!(repo.check_attr("text", "bx"), "unspecified");
}

#[test]
fn a_pattern_with_a_space_survives_the_trip_through_git() {
    // `.gitattributes` ends a pattern at the first blank unless the whole
    // pattern is C-quoted; the `\ ` escape `.git-xcrypt` inherits from
    // `.gitignore` means nothing there.
    let repo = synced("docs/READ\\ ME.md\n");

    assert_eq!(repo.check_attr("text", "docs/READ ME.md"), "unset");
    assert_eq!(repo.check_attr("diff", "docs/READ ME.md"), "git-xcrypt");
}

#[test]
fn a_new_pattern_reaches_the_section_and_a_second_run_does_not() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");

    let first = repo.xcrypt_ok(["sync"]);
    assert!(
        String::from_utf8_lossy(&first.stderr).contains("updated"),
        "the message has to say the file changed"
    );
    let after_first = repo.worktree_bytes(".gitattributes");

    let second = repo.xcrypt_ok(["sync"]);
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("nothing changed"),
        "the message has to say the file did not change"
    );
    assert_eq!(
        after_first,
        repo.worktree_bytes(".gitattributes"),
        "a settled section must not be rewritten"
    );
}

#[test]
fn check_is_a_gate_that_writes_nothing() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    let before = repo.worktree_bytes(".gitattributes");

    let stale = repo.xcrypt(["sync", "--check"]);
    assert_eq!(
        stale.status.code(),
        Some(1),
        "a stale section has to fail a CI gate"
    );
    assert_eq!(
        before,
        repo.worktree_bytes(".gitattributes"),
        "--check must never touch the working tree"
    );

    repo.xcrypt_ok(["sync"]);
    assert_eq!(
        repo.xcrypt(["sync", "--check"]).status.code(),
        Some(0),
        "a current section has to pass"
    );
}

#[test]
fn init_lands_the_same_section_sync_would() {
    let declarations = "secrets/\n*.env\nsecrets/key.p12 binary\n!secrets/README.md\n";

    let by_sync = synced(declarations);

    // The same declarations, settled by `init` instead. `init` renders the
    // section with the very code `sync` runs, so the two files have to come out
    // identical — otherwise the command that repairs a repository would undo
    // the command that maintains it.
    let by_init = TestRepo::init();
    by_init.init_xcrypt();
    by_init.write_xcrypt_config(declarations);
    by_init.xcrypt_ok(["init"]);

    assert_eq!(
        by_sync.worktree_bytes(".gitattributes"),
        by_init.worktree_bytes(".gitattributes")
    );
}

#[test]
fn a_broken_managed_section_stops_sync_with_a_state_conflict() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.write_file(
        ".gitattributes",
        b"# mine\n# >>> git-xcrypt >>>\n* filter=git-xcrypt\n",
    );

    let output = repo.xcrypt(["sync"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "guessing where the section ends would destroy the user's own attributes"
    );
    assert_eq!(
        repo.worktree_bytes(".gitattributes"),
        b"# mine\n# >>> git-xcrypt >>>\n* filter=git-xcrypt\n",
        "the refusal must leave the file exactly as it was"
    );
}

#[test]
fn sync_refuses_when_the_declarations_are_gone() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    std::fs::remove_file(repo.path().join(".git-xcrypt")).expect("could not remove the file");

    let output = repo.xcrypt(["sync"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("init"),
        "the refusal must point somewhere useful"
    );
}

#[test]
fn the_catch_all_line_survives_every_regeneration() {
    // Everything else in the section is cosmetic; this line is not.
    let repo = synced("secrets/\n");
    let attributes = String::from_utf8(repo.worktree_bytes(".gitattributes"))
        .expect("the attributes file is text");

    assert!(attributes.contains("* filter=git-xcrypt"));
    assert_eq!(
        repo.check_attr("filter", "anything-at-all.txt"),
        "git-xcrypt",
        "the filter has to keep running for every file in the repository"
    );
}

#[test]
fn encryption_still_works_with_the_generated_lines_in_place() {
    // The cosmetic lines sit in the same file as the catch-all, so a mistake
    // there could plausibly reach the filter. It must not.
    let secret = b"api_key = do-not-commit-me\r\nsecond = line\r\n";
    let repo = synced("secrets/\n");
    repo.write_file("secrets/token.txt", secret);
    repo.commit_all("add a secret");

    repo.assert_blob_differs_from_worktree("secrets/token.txt");
    assert!(
        repo.blob_bytes("secrets/token.txt")
            .starts_with(b"\x00GITXCRYPT\x00"),
        "the blob is not encrypted"
    );

    std::fs::remove_file(repo.path().join("secrets/token.txt")).expect("could not remove the file");
    repo.git_ok(["checkout", "--", "secrets/token.txt"]);
    repo.assert_status_clean();
}
