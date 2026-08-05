//! The `.git-xcrypt` attribute vocabulary, driven through a real git.
//!
//! `.git-xcrypt` takes over git's *whole* conversion dictionary — `text`,
//! `-text`, `binary`, `text=auto`, `eol=lf|crlf|native` — because the managed
//! `-text` line takes `text` and `eol` away from the user on exactly the paths
//! where they would be needed. Each attribute therefore has to show up in three
//! places at once, and this file checks all three in one run:
//!
//! 1. **the header's `flags` bit 0**, which is what smudge later obeys instead
//!    of asking the declaration again;
//! 2. **the rendered `.gitattributes` line**, graded by what real
//!    `git check-attr` answers rather than by what the syntax looks like — the
//!    two files do not spell patterns the same way, and the rendering is the
//!    risky half;
//! 3. **the round trip**, byte for byte where the declaration promises one.
//!
//! The second test is the failure mode the rendering exists to prevent, from
//! the other side: a foreign line that puts `text` back on an encrypted path.
//! Measured on git 2.55, that eats `CR` bytes out of the ciphertext, `git add`
//! exits 0, the commit succeeds and the file is unrecoverable at checkout.

mod harness;

use std::fs;

use harness::{MAGIC, OVERHEAD, TestRepo};
use tempfile::TempDir;

/// Text content with CRLF throughout, so normalisation is observable.
const CRLF: &[u8] = b"line one\r\nline two\r\n";

/// The same content after normalisation — what clean must store.
const LF: &[u8] = b"line one\nline two\n";

/// Content no rule can call text: a NUL, plus CRLF pairs so "left alone" means
/// something.
const BINARY: &[u8] = b"\x00\x90raw\r\nbytes\r\n\x00";

/// One declared path and everything the declaration promises about it.
struct Case {
    path: &'static str,
    /// What is written into the working tree.
    written: &'static [u8],
    /// The plaintext clean must encrypt.
    stored: &'static [u8],
    /// Whether the header records "this was normalised to LF".
    normalised: bool,
    /// What `git check-attr diff` must answer.
    diff: &'static str,
    /// What a checkout must put back, when the declaration pins it.
    checked_out: &'static [u8],
}

#[test]
fn every_declared_attribute_reaches_the_header_the_rendered_line_and_the_round_trip() {
    // `core.autocrlf=false` with `core.eol=lf` pins the two rows whose answer
    // would otherwise be the machine's to give (`text` and `text=auto` with no
    // `eol=`), so this test asserts the same bytes on all three platforms. The
    // configuration-driven half of the table is `tests/line_endings.rs`.
    let repo = TestRepo::init();
    repo.set_eol_config("false", "lf");
    repo.init_xcrypt();
    repo.write_xcrypt_config(
        "secrets/\n\
         secrets/always.txt   text\n\
         secrets/never.bin    -text\n\
         secrets/store.p12    binary\n\
         secrets/auto.txt     text=auto\n\
         secrets/unix.sh      text eol=lf\n\
         secrets/dos.ps1      text eol=crlf\n\
         !secrets/README.md\n",
    );
    repo.xcrypt_ok(["sync"]);

    let cases = [
        Case {
            // `text`: normalise whatever the content looks like.
            path: "secrets/always.txt",
            written: CRLF,
            stored: LF,
            normalised: true,
            diff: "git-xcrypt",
            checked_out: LF,
        },
        Case {
            // `-text`: never convert, in either direction.
            path: "secrets/never.bin",
            written: CRLF,
            stored: CRLF,
            normalised: false,
            diff: "git-xcrypt",
            checked_out: CRLF,
        },
        Case {
            // `binary`: `-text` plus "leave the diff driver off", the way git's
            // own `binary` macro means `-text -diff`.
            path: "secrets/store.p12",
            written: BINARY,
            stored: BINARY,
            normalised: false,
            diff: "unset",
            checked_out: BINARY,
        },
        Case {
            // `text=auto` on content that is text: the default, spelled out.
            path: "secrets/auto.txt",
            written: CRLF,
            stored: LF,
            normalised: true,
            diff: "git-xcrypt",
            checked_out: LF,
        },
        Case {
            // `text=auto` on content that is not: same declaration, opposite
            // verdict, decided by content alone.
            path: "secrets/keystore.env",
            written: BINARY,
            stored: BINARY,
            normalised: false,
            diff: "git-xcrypt",
            checked_out: BINARY,
        },
        Case {
            // `eol=lf`: the working tree gets LF whatever the machine says.
            path: "secrets/unix.sh",
            written: CRLF,
            stored: LF,
            normalised: true,
            diff: "git-xcrypt",
            checked_out: LF,
        },
        Case {
            // `eol=crlf`: and CRLF, likewise — this is the row a Unix machine
            // would otherwise never see, since it is the declaration rather
            // than the platform that decides.
            path: "secrets/dos.ps1",
            written: CRLF,
            stored: LF,
            normalised: true,
            diff: "git-xcrypt",
            checked_out: CRLF,
        },
    ];

    for case in &cases {
        repo.write_file(case.path, case.written);
    }
    // The negation: declared out of the encrypted set by the last matching
    // line, so it must stay readable — and git must be handed it back.
    repo.write_file("secrets/README.md", b"nothing secret here\n");
    repo.commit_all("one file per attribute");
    repo.assert_status_clean();

    for case in &cases {
        let path = case.path;

        // 1. The header.
        let blob = repo.blob_bytes(path);
        assert!(blob.starts_with(MAGIC), "{path}: the filter did not run");
        assert_eq!(
            blob.len(),
            OVERHEAD + case.stored.len(),
            "{path}: the encrypted plaintext is not what the declaration asks \
             clean to store"
        );
        assert_eq!(
            repo.blob_records_normalisation(path),
            case.normalised,
            "{path}: the header records the wrong verdict, so smudge will \
             convert a file it must not — or fail to convert one it must"
        );

        // 2. The rendered line, graded by git itself. `-text` is what keeps
        //    git's own CRLF conversion off the ciphertext; without it a 2 MB
        //    blob loses `CR` bytes and the file is unrecoverable at checkout.
        assert_eq!(
            repo.check_attr("filter", path),
            "git-xcrypt",
            "{path}: git would not run the filter for a declared path"
        );
        assert_eq!(
            repo.check_attr("text", path),
            "unset",
            "{path}: git may convert this ciphertext, which destroys it"
        );
        assert_eq!(
            repo.check_attr("diff", path),
            case.diff,
            "{path}: the rendered diff attribute is not what the declaration says"
        );

        // 3. The round trip.
        repo.recheckout(path);
        assert_eq!(
            repo.worktree_bytes(path),
            case.checked_out,
            "{path}: the checkout did not honour the declaration"
        );
    }

    // The negation, in all three places: readable in the object database, and
    // handed back to git's own defaults rather than carrying our attributes.
    let readable = repo.blob_bytes("secrets/README.md");
    assert!(
        !readable.starts_with(MAGIC),
        "a negated path was encrypted anyway"
    );
    assert_eq!(readable, b"nothing secret here\n");
    assert_eq!(
        repo.check_attr("text", "secrets/README.md"),
        "unspecified",
        "a file stored in the clear must be git's to manage, `-text` included"
    );
    assert_eq!(
        repo.check_attr("diff", "secrets/README.md"),
        "unspecified",
        "a decrypting diff driver has nothing to do on a plaintext file"
    );

    repo.assert_status_clean();
    repo.git_ok(["add", "-A"]);
    repo.assert_status_clean();
}

/// The paths a floating declaration selects, and what git must answer for each.
///
/// Every one of these is a path the *filter* encrypts, because `.gitignore`
/// floats a pattern that carries no slash of its own and `*.env` can name a
/// directory as readily as a file. The rendered section has to reach exactly
/// this far and no further: narrower leaves ciphertext without `-text`, which
/// was measured costing a 2 MB file at checkout; broader puts `-text` on files
/// stored in the clear.
const REACHED: &[&str] = &[
    "secrets/a.txt",
    "app/secrets/a.txt",
    "a/b/secrets/c/d.txt",
    "deep/one.env",
    "config.env/inner.txt",
];

/// And the path next door, which the same declaration must not touch.
const UNTOUCHED: &str = "notsecrets/a.txt";

#[test]
fn a_forgotten_sync_fails_the_gate_and_running_it_reaches_the_whole_subtree() {
    // The flow FR-003 is written about: a pattern is added, `sync` is forgotten,
    // and CI is the thing that says so. Then the section is regenerated and has
    // to reach every path the filter reaches — including the nested ones, which
    // are the half that no root-level declaration can tell apart. Measured in
    // S-02: a directory pattern rendered as `secrets/**` instead of
    // `**/secrets/**` looks right, agrees with every root-level check, and drops
    // `-text` from exactly the deep paths it was protecting.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);

    let checked = repo.xcrypt(["sync", "--check"]);
    assert_eq!(
        checked.status.code(),
        Some(0),
        "a section that was just written must satisfy its own check:\n{}",
        String::from_utf8_lossy(&checked.stderr)
    );

    // --- A second pattern is declared, and `sync` is forgotten. -------------
    let before = repo.worktree_bytes(".gitattributes");
    repo.write_xcrypt_config("secrets/\n*.env\n");

    let stale = repo.xcrypt(["sync", "--check"]);
    assert_eq!(
        stale.status.code(),
        Some(1),
        "a stale section passed the gate, so CI would never notice:\n{}",
        String::from_utf8_lossy(&stale.stderr)
    );
    assert_eq!(
        repo.worktree_bytes(".gitattributes"),
        before,
        "`--check` wrote to the working tree, which is the one thing a check \
         must never do"
    );

    // The filter, meanwhile, is already encrypting under the new pattern:
    // selection is immediate and the section is what lags behind.
    repo.write_file("deep/one.env", b"api_key = deep\n");
    repo.commit_all("a secret under the undeclared-in-gitattributes pattern");
    assert!(
        repo.blob_is_encrypted("deep/one.env"),
        "the filter reads `.git-xcrypt` directly, so this must not wait for sync"
    );

    // --- `sync` closes it. ---------------------------------------------------
    repo.xcrypt_ok(["sync"]);
    assert_eq!(
        repo.xcrypt(["sync", "--check"]).status.code(),
        Some(0),
        "`sync` left a section its own check still calls stale"
    );

    // --- And git agrees, at every depth. ------------------------------------
    for path in REACHED {
        assert_eq!(
            repo.check_attr("filter", path),
            "git-xcrypt",
            "{path}: the filter encrypts this path, so git must run it here"
        );
        assert_eq!(
            repo.check_attr("text", path),
            "unset",
            "{path}: the filter encrypts this path and the rendered line does \
             not reach it, so git may convert its ciphertext and destroy it"
        );
    }
    assert_eq!(
        repo.check_attr("text", UNTOUCHED),
        "unspecified",
        "{UNTOUCHED}: the line reaches past what the filter encrypts, so a file \
         stored in the clear is carrying `-text`"
    );

    // The reach is not a claim about attributes alone: a nested secret has to
    // make the whole round trip.
    for path in REACHED {
        repo.write_file(path, b"api_key = nested\n");
    }
    repo.write_file(UNTOUCHED, b"nothing secret here\n");
    repo.commit_all("one secret per depth");
    repo.assert_status_clean();

    for path in REACHED {
        assert!(
            repo.blob_is_encrypted(path),
            "{path}: a declared path was stored in the clear"
        );
        repo.recheckout(path);
        repo.assert_worktree_eq(path, b"api_key = nested\n");
    }
    assert!(
        !repo.blob_is_encrypted(UNTOUCHED),
        "{UNTOUCHED}: an undeclared path was encrypted"
    );
    repo.assert_status_clean();
}

/// A secret worth spelling out, so a plaintext blob is recognisable on sight.
const SECRET: &[u8] = b"AWS_SECRET=hunter2\n";

/// Paths spelled in a case no line of `.git-xcrypt` uses, and what selects them.
///
/// One spelling per directory, deliberately: on APFS and on NTFS `mkdir secrets`
/// and `mkdir Secrets` make **one** directory, so a fixture holding two spellings
/// of the same name cannot exist on two of the three platforms. One file whose
/// spelling differs from the pattern's is enough, and it is portable.
const OTHER_SPELLINGS: &[&str] = &[
    // The directory pattern `secrets/`, reached through a directory whose name
    // is spelled differently. `.txt` rather than `.env` so nothing but the
    // directory pattern can select it.
    "SEcrets/db.txt",
    // The floating pattern `*.env`, reached through the extension.
    "top.ENV",
    // …and at depth, so the `**/` the renderer adds is exercised too.
    "app/nested/Deploy.Env",
];

#[test]
fn a_pattern_reaches_every_ascii_spelling_of_a_name_and_the_rendered_line_keeps_up() {
    // Open decision 13, settled on 2026-08-05: pattern matching folds ASCII case,
    // unconditionally. The measured failure it closes: `.git-xcrypt` declares
    // `secrets/`, the user creates `Secrets/db.env`, and on APFS and NTFS those
    // are *one* directory — `cd secrets` enters `Secrets`, `ls` shows a single
    // entry, and there is no way to see the mistake. The filter left the file
    // alone, `git add` exited 0 and `AWS_SECRET=hunter2` went into the object
    // database in the clear.
    //
    // Both axes are asserted for every spelling, because closing one alone opens
    // the other. Selection folding without the rendering folding means the filter
    // encrypts a path the managed `-text` does not reach — measured elsewhere in
    // this file as 34 `CR` bytes eaten out of a ciphertext and the file
    // unrecoverable at checkout.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config(
        "secrets/\n\
         *.env\n\
         !secrets/README.md\n\
         \u{142}\u{105}ka/\n",
    );
    repo.xcrypt_ok(["sync"]);

    for path in OTHER_SPELLINGS {
        repo.write_file(path, SECRET);
    }
    // The negation, spelled differently too: a hole punched in a declaration has
    // to stay a hole whichever way the file is spelled, or the file the user
    // deliberately kept readable becomes unreadable instead.
    repo.write_file("SEcrets/README.MD", b"nothing secret here\n");
    // The name next door, which no pattern reaches in any spelling.
    repo.write_file("notsecrets/a.txt", b"nothing secret here\n");
    // The documented boundary: folding is ASCII, exactly as far as git folds.
    // Measured on git 2.55 with `core.ignorecase=true` — `łąka/**` matches
    // neither `ŁĄKA/a.env` nor `Łąka/a.env`. It cannot be pushed further from
    // here either: `.gitattributes` matches bytes, so `[łŁ]` is a set of four
    // bytes rather than two characters and matches no spelling at all. This row
    // pins the boundary so nobody closes it by accident on one side only.
    repo.write_file(
        "\u{141}\u{104}KA/a.env.txt",
        b"outside the ASCII boundary\n",
    );
    repo.commit_all("one file per spelling");
    repo.assert_status_clean();

    for path in OTHER_SPELLINGS {
        assert!(
            repo.blob_is_encrypted(path),
            "{path}: a declared path spelled in another case was stored in the \
             clear, which is the whole failure open decision 13 closed"
        );
        assert!(
            !repo.object_exists_for(SECRET),
            "{path}: the plaintext of a declared secret reached the object database"
        );
    }
    assert!(
        !repo.blob_is_encrypted("SEcrets/README.MD"),
        "a negation stopped applying because the file is spelled differently"
    );
    assert!(
        !repo.blob_is_encrypted("notsecrets/a.txt"),
        "the folded pattern reached past what it declares"
    );
    assert!(
        !repo.blob_is_encrypted("\u{141}\u{104}KA/a.env.txt"),
        "folding reached beyond ASCII, which git does not do and \
         `.gitattributes` cannot express"
    );

    // The second axis. `core.ignorecase=false` first, and that is what makes this
    // half mean anything: with it true git folds the managed section's patterns
    // itself, so a renderer that emits nothing of the sort still answers `unset`
    // and the assertion proves nothing. False leaves the rendered spelling as the
    // only thing that can reach these paths — measured on git 2.55, a plain
    // `**/secrets/**` answers `unspecified` for `SEcrets/db.txt` there.
    //
    // Then true, because the rendered line must not depend on a setting that is
    // not versioned and that git decides for itself by probing the filesystem.
    for ignore_case in ["false", "true"] {
        repo.set_config("core.ignorecase", ignore_case);

        for path in OTHER_SPELLINGS {
            assert_eq!(
                repo.check_attr("filter", path),
                "git-xcrypt",
                "{path}: with core.ignorecase={ignore_case} git would not run the \
                 filter for a path the filter encrypts"
            );
            assert_eq!(
                repo.check_attr("text", path),
                "unset",
                "{path}: with core.ignorecase={ignore_case} the rendered line does \
                 not reach a path the filter encrypts, so git may convert its \
                 ciphertext and destroy it"
            );
            assert_eq!(
                repo.check_attr("diff", path),
                "git-xcrypt",
                "{path}: with core.ignorecase={ignore_case} `git diff` would show \
                 ciphertext for a path the filter encrypts"
            );
        }

        assert_eq!(
            repo.check_attr("text", "SEcrets/README.MD"),
            "unspecified",
            "with core.ignorecase={ignore_case} a file stored in the clear by a \
             negation is carrying `-text`"
        );
        assert_eq!(
            repo.check_attr("text", "notsecrets/a.txt"),
            "unspecified",
            "with core.ignorecase={ignore_case} the rendered line reaches past \
             what the filter encrypts"
        );
        assert_eq!(
            repo.check_attr("text", "\u{141}\u{104}KA/a.env.txt"),
            "unspecified",
            "with core.ignorecase={ignore_case} the rendered line folds beyond \
             ASCII while the filter does not, so a file stored in the clear is \
             carrying `-text`"
        );
    }
    repo.set_config("core.ignorecase", "false");

    // And the round trip, because an encrypted path is only encrypted if it comes
    // back byte for byte.
    for path in OTHER_SPELLINGS {
        repo.recheckout(path);
        repo.assert_worktree_eq(path, SECRET);
    }
    repo.assert_status_clean();
}

/// 2 MB whose bytes cover the whole range.
///
/// The plaintext shape barely matters — what git would convert is the
/// *ciphertext*, which is pseudorandom and so carries a `CRLF` pair every 64 KiB
/// or so. The size is what makes the damage certain rather than probable.
fn two_megabytes() -> Vec<u8> {
    (0..2 * 1024 * 1024u32)
        .map(|index| u8::try_from(index % 251).expect("a byte"))
        .collect()
}

/// The attribute shapes that make git convert a ciphertext, and nothing else —
/// paired with what `git check-attr text` answers for each, so the fixture can
/// prove it still reproduces the shape it exists to catch.
///
/// All measured on git 2.55 by the only test that settles it — a byte-for-byte
/// round trip through `git add`, `git commit`, `rm` and `git checkout`:
///
/// * `secrets/** text` — `git check-attr text` answers `set`, 32 `CR` bytes are
///   eaten out of the ciphertext and the file is gone at checkout;
/// * `secrets/** !text` with `secrets/** eol=lf` — the one nobody expects, and
///   it is git's own rule, not an accident: an `eol` attribute promotes an
///   undefined `crlf_action` straight to `CRLF_TEXT_INPUT`, and only the
///   `CRLF_AUTO*` actions consult binary detection. Measured the same way, 39
///   bytes short and the file gone;
/// * `secrets/** text=input` — the one value besides `auto` that
///   `git_path_check_crlf` recognises, and it converts without binary
///   detection. It used to be read as `text=auto` and pass the gate;
/// * `secrets/** !text` with `secrets/** crlf` — the pre-1.7.2 spelling, which
///   git still honours whenever `text` says nothing. A bare `crlf` below a
///   *current* managed section is neutralised by the managed `-text` (the
///   `text` axis wins), so the dangerous shape needs `text` silenced first —
///   the same structure as the bare-`eol=` row. It used to not be resolved at
///   all.
///
/// `-text`, `binary`, `text=auto`, `text=<junk>`, `-crlf` and `crlf=auto` are
/// exempt, at every `core.autocrlf` value.
const DANGEROUS: [(&[u8], &str); 4] = [
    (b"secrets/** text\n", "set"),
    (b"secrets/** !text\nsecrets/** eol=lf\n", "unspecified"),
    (b"secrets/** text=input\n", "input"),
    (b"secrets/** !text\nsecrets/** crlf\n", "unspecified"),
];

#[test]
fn a_foreign_text_line_below_the_managed_section_is_refused_before_the_file_is_lost() {
    // The managed section is *current* here: `sync` has run and the `-text`
    // line is exactly right. One line below it puts `text` back on, and git
    // takes the last match.
    //
    // Measured on git 2.55: `git check-attr text` answers `set`, git runs its
    // own CRLF conversion over the ciphertext, `CR` bytes are eaten out of the
    // blob, `git add` and `git commit` both exit 0, and the checkout fails the
    // authentication tag and leaves no file at all. Nobody can decrypt what was
    // committed, ever.
    //
    // **Since 2026-08-05 the filter refuses instead.** Git's order leaves room
    // for exactly that: clean runs *before* git converts, so at the moment the
    // filter is asked, nothing is damaged yet and a `status=error` costs a
    // refused `git add` rather than a file. `status` reporting it afterwards was
    // never enough on its own — it only resolves paths the index already knows,
    // so on a *new* file the first warning arrives when the file is already
    // gone.
    for (foreign, expected_text) in DANGEROUS {
        let secret = two_megabytes();

        let repo = TestRepo::init();
        repo.init_xcrypt();
        repo.write_xcrypt_config("secrets/\n");
        repo.xcrypt_ok(["sync"]);

        // Committed while the configuration is still healthy, so there is an
        // intact blob to prove nothing damaged it later — and so the index knows
        // the path, which is what `status` needs to have anything to resolve.
        repo.write_file("secrets/store.p12", &secret);
        repo.commit_all("a secret, while the attributes are still right");
        assert_eq!(
            repo.blob_bytes("secrets/store.p12").len(),
            OVERHEAD + secret.len(),
            "the fixture did not store an intact ciphertext to begin with"
        );

        let mut attributes = repo.worktree_bytes(".gitattributes");
        attributes.extend_from_slice(foreign);
        repo.write_file(".gitattributes", &attributes);

        // The premise really is the failure mode, not a story about one.
        assert_eq!(
            repo.check_attr("text", "secrets/store.p12"),
            expected_text,
            "the fixture no longer reproduces the shape it exists to catch"
        );

        // Touching the file is what puts it back through the filter: git's
        // cached `stat` skips a file it considers unchanged, so the damage can
        // only happen on a path that is cleaned again.
        let mut modified = secret.clone();
        modified.extend_from_slice(b"one more line\r\n");
        repo.write_file("secrets/store.p12", &modified);

        let add = repo.git(["add", "-A"]);
        let complaint = String::from_utf8_lossy(&add.stderr).into_owned();
        assert!(
            !add.status.success(),
            "`git add` stored a ciphertext git is about to convert, and exited \
             {:?}:\n{complaint}",
            add.status.code()
        );
        assert!(
            complaint.contains("secrets/store.p12"),
            "the refusal must name the path it is about:\n{complaint}"
        );
        assert!(
            complaint.contains(".gitattributes:"),
            "the refusal must name the file and line that outrank the managed \
             section, or nobody can find it:\n{complaint}"
        );
        assert!(
            complaint.contains("-text"),
            "the refusal must name the attribute that prevents it:\n{complaint}"
        );

        // Nothing was stored, so nothing is lost: the intact blob is still what
        // `HEAD` holds, and it still checks out byte for byte.
        assert_eq!(
            repo.blob_bytes("secrets/store.p12").len(),
            OVERHEAD + secret.len(),
            "the committed ciphertext was damaged after all"
        );
        std::fs::remove_file(repo.path().join("secrets/store.p12")).expect("could not remove");
        repo.git_ok(["checkout", "--", "secrets/store.p12"]);
        assert_eq!(
            repo.worktree_bytes("secrets/store.p12"),
            secret,
            "the file did not survive the round trip the refusal exists to protect"
        );

        // And `status` still says so, with the exit code a CI gate reads — the
        // refusal stops the damage, it does not repair the configuration.
        let output = repo.xcrypt(["status"]);
        let text = String::from_utf8_lossy(&output.stdout).into_owned();

        // Code `2`, not `5`: since 2026-08-05 a setup gap is a configuration
        // finding, and the remedy here is an attribute line, not a rotated
        // secret. Nothing was stored in the clear over this — what it costs is
        // the ciphertext — so the exit code and the wording have to agree.
        assert_eq!(
            output.status.code(),
            Some(CONFIG_ERROR),
            "a repository whose ciphertext git converts must fail the gate as a \
             configuration problem:\n{text}"
        );
        assert!(
            text.contains("secrets/store.p12"),
            "the report must name the path whose ciphertext git converts:\n{text}"
        );
        assert!(
            text.contains("-text"),
            "the report must name the attribute that prevents it:\n{text}"
        );
    }
}

/// Where a global attributes file can live, and how git is told about it.
///
/// Both are resolved by git and neither is a path we can read verbatim: the
/// first is a default nothing in the configuration mentions, the second needs
/// `~` expanded. Measured on git 2.55 — the third row, an absolute path, always
/// worked and is here so a regression in the other two cannot hide behind it.
const GLOBAL_SOURCES: [&str; 3] = ["xdg-default", "tilde", "absolute"];

#[test]
fn a_text_line_in_the_users_global_attributes_file_is_refused_like_any_other() {
    // The same rule as the test above, from the one source that used to be
    // invisible. `core.attributesFile` was read verbatim, so `~/attrs` looked
    // for a directory literally named `~`, and with the key unset the XDG
    // default was not consulted at all — while git reads both.
    //
    // Measured on git 2.55, 2026-08-05, 2 MB, the line in
    // `~/.config/git/attributes` while the identical line in the tree was
    // already refused: `git add` exited **0**, 27 `CR` bytes were eaten out of
    // the blob, `git commit` exited 0, and the checkout left **no file at all**.
    // `status` said `VERDICT: no findings.` over it. Both halves of the tool
    // that exist to catch this resolve the stack correctly; neither was being
    // handed this file.
    //
    // The declaration is deliberately one `sync` behind, because that is the
    // only state where a global line can win: it sits *below* the tree in git's
    // precedence, so a current managed section's `-text` covers the path and
    // nothing outside can reach it. Forgetting `sync` is what opens the door —
    // and a global `*.sh text eol=lf` is an ordinary thing to have.
    for source in GLOBAL_SOURCES {
        let home = TempDir::new().expect("could not create a home directory");
        let secret = two_megabytes();

        let repo = TestRepo::init().with_home(home.path());
        repo.init_xcrypt();
        repo.write_xcrypt_config("secrets/\n");
        repo.xcrypt_ok(["sync"]);

        // Declared after the last `sync`, so the managed section says nothing
        // about this subtree and the global file is free to.
        repo.write_xcrypt_config("secrets/\nvault/\n");
        repo.write_file("vault/deploy.sh", &secret);
        repo.commit_all("a secret, while nothing yet converts it");
        assert_eq!(
            repo.blob_bytes("vault/deploy.sh").len(),
            OVERHEAD + secret.len(),
            "the fixture did not store an intact ciphertext to begin with"
        );

        let line = b"vault/** text\n";
        // Kept, because the refusal has to name *this* file: a message that
        // merely says one exists leaves the user with nothing to act on.
        let global = match source {
            "xdg-default" => {
                let dir = home.path().join(".config").join("git");
                fs::create_dir_all(&dir).expect("could not create the XDG directory");
                dir.join("attributes")
            }
            "tilde" => {
                repo.git_ok(["config", "--global", "core.attributesFile", "~/attrs"]);
                home.path().join("attrs")
            }
            _ => {
                let path = home.path().join("attrs");
                repo.git_ok([
                    "config",
                    "--global",
                    "core.attributesFile",
                    &path.to_string_lossy(),
                ]);
                path
            }
        };
        fs::write(&global, line).expect("could not write the global attributes file");

        // The premise is the failure mode itself: if git does not resolve `text`
        // to `set` here, this loop is proving nothing about anything.
        assert_eq!(
            repo.check_attr("text", "vault/deploy.sh"),
            "set",
            "[{source}] the fixture no longer reproduces the shape it exists to catch"
        );

        // Git's cached `stat` skips a file it considers unchanged, so only a
        // path that is cleaned again can reach the filter at all.
        let mut modified = secret.clone();
        modified.extend_from_slice(b"one more line\r\n");
        repo.write_file("vault/deploy.sh", &modified);

        let add = repo.git(["add", "-A"]);
        assert!(
            !add.status.success(),
            "[{source}] `git add` stored a ciphertext git is about to convert, \
             and exited {:?}:\n{}",
            add.status.code(),
            String::from_utf8_lossy(&add.stderr)
        );

        // Naming the winning line is the whole remedy: no command of this tool
        // edits a file the user wrote, so the report has to say which one.
        let complaint = String::from_utf8_lossy(&add.stderr).into_owned();
        let named = global.file_name().expect("the global file has a name");
        assert!(
            complaint.contains(&named.to_string_lossy().into_owned()),
            "[{source}] the refusal does not name the file that caused it \
             ({}):\n{complaint}",
            global.display()
        );
        assert!(
            complaint.contains("vault/** text"),
            "[{source}] the refusal does not quote the winning line:\n{complaint}"
        );

        // And the gate agrees, over a path the index already knows.
        let status = repo.xcrypt(["status"]);
        let text = String::from_utf8_lossy(&status.stdout).into_owned();
        assert_eq!(
            status.status.code(),
            Some(CONFIG_ERROR),
            "[{source}] the gate passed a repository whose ciphertext git \
             converts:\n{text}"
        );
        assert!(
            text.contains("vault/deploy.sh"),
            "[{source}] the report must name the path git converts:\n{text}"
        );
    }
}

#[test]
fn a_linked_worktrees_own_config_is_the_one_that_counts() {
    // `config.worktree` is per-checkout: git reads it from `$GIT_DIR`, which for
    // a linked worktree is `…/.git/worktrees/<name>`, not from the common
    // directory. This build read both files from the common directory, so a
    // linked worktree was resolved against the *main* checkout's per-worktree
    // configuration — nobody's configuration.
    //
    // Measured on git 2.55, 2026-08-05, 2 MB: with the linked worktree's
    // `config.worktree` pointing `core.attributesFile` at a file declaring
    // `vault/** text`, `git check-attr text` answered `set` there and
    // `unspecified` in the main checkout. `git add` exited **0**, 40 bytes were
    // eaten out of the blob, and the checkout left no file at all.
    let home = TempDir::new().expect("could not create a home directory");
    let repo = TestRepo::init().with_home(home.path());
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    // Declared after the last `sync`, the only state in which a source below the
    // tree can win — see the global-file scenario above.
    repo.write_xcrypt_config("secrets/\nvault/\n");

    let secret = two_megabytes();
    repo.write_file("vault/deploy.sh", &secret);
    repo.commit_all("a secret, while nothing yet converts it");

    let side = repo.add_worktree("side");
    let attributes = home.path().join("side-attrs");
    fs::write(&attributes, b"vault/** text\n").expect("could not write the attributes file");
    side.git_ok(["config", "extensions.worktreeConfig", "true"]);
    side.git_ok([
        "config",
        "--worktree",
        "core.attributesFile",
        &attributes.to_string_lossy(),
    ]);

    // The premise: git disagrees between the two checkouts, which is the whole
    // point of a per-worktree setting.
    assert_eq!(
        side.check_attr("text", "vault/deploy.sh"),
        "set",
        "the fixture no longer reproduces the shape it exists to catch"
    );
    assert_eq!(
        repo.check_attr("text", "vault/deploy.sh"),
        "unspecified",
        "the per-worktree setting leaked into the main checkout, so this proves \
         nothing about which file was read"
    );

    let mut modified = secret.clone();
    modified.extend_from_slice(b"one more line\r\n");
    side.write_file("vault/deploy.sh", &modified);
    let added = side.git(["add", "-A"]);
    assert!(
        !added.status.success(),
        "`git add` in the linked worktree stored a ciphertext git is about to \
         convert, and exited {:?}:\n{}",
        added.status.code(),
        String::from_utf8_lossy(&added.stderr)
    );

    // And the main checkout, which that line does not reach, keeps working —
    // a refusal that spread to every checkout would be its own outage.
    repo.write_file("vault/deploy.sh", &modified);
    let untouched = repo.git(["add", "-A"]);
    assert!(
        untouched.status.success(),
        "the main checkout was refused over a setting that belongs to another \
         one:\n{}",
        String::from_utf8_lossy(&untouched.stderr)
    );
}

#[test]
fn a_global_attributes_file_that_is_harmless_never_provokes_a_refusal() {
    // The other half, and it carries more weight here than usual. A global
    // attributes file is shared by every repository on the machine, so a
    // predicate one shape too wide does not break one project — it breaks all
    // of them at once, and with `required = true` it breaks *every* git
    // operation in each. `* text=auto` is what people actually have in that
    // file.
    let home = TempDir::new().expect("could not create a home directory");
    let dir = home.path().join(".config").join("git");
    fs::create_dir_all(&dir).expect("could not create the XDG directory");
    fs::write(dir.join("attributes"), b"* text=auto\n*.md text\n")
        .expect("could not write attributes");

    let repo = TestRepo::init().with_home(home.path());
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\nvault/\n");

    let secret = two_megabytes();
    repo.write_file("vault/deploy.sh", &secret);
    repo.commit_all("an ordinary machine with an ordinary global file");

    assert_eq!(
        repo.blob_bytes("vault/deploy.sh").len(),
        OVERHEAD + secret.len(),
        "a harmless global attributes file changed the stored ciphertext"
    );
    repo.recheckout("vault/deploy.sh");
    repo.assert_worktree_eq("vault/deploy.sh", &secret);

    let status = repo.xcrypt(["status"]);
    assert_eq!(
        status.status.code(),
        Some(0),
        "a harmless global attributes file failed the gate:\n{}",
        String::from_utf8_lossy(&status.stdout)
    );
}

#[test]
fn the_shapes_git_leaves_alone_never_provoke_a_refusal() {
    // The other half, and it carries the same weight: with `required = true` a
    // refusal blocks *every* git operation in the repository, so a predicate one
    // shape too wide is its own outage. Every line below is ordinary — this
    // repository has to commit, check out and round-trip exactly as it would
    // with no foreign line at all.
    let repo = TestRepo::init();
    repo.init_xcrypt();
    // `binary` on one declared pattern, plain selection on the other, so the
    // managed section renders both `-text` and the `-diff` variant.
    repo.write_xcrypt_config("secrets/\nvault/  binary\n");
    repo.xcrypt_ok(["sync"]);

    let mut attributes = repo.worktree_bytes(".gitattributes");
    attributes.extend_from_slice(
        // Every line below outranks the managed section, and every one of them
        // is measured harmless.
        b"# `text=auto` winning outright on a declared path: git keeps binary\n\
          # detection, and the leading NUL of our magic answers it\n\
          vault/** text=auto\n\
          # a foreign driver on a path of its own is the ordinary case\n\
          *.psd filter=lfs\n\
          # one restating what the managed section already says\n\
          secrets/** -text\n\
          # and the shape that matters most: a bare `eol=`, the very assignment\n\
          # that is fatal over a ciphertext, on a path stored in the clear,\n\
          # where it is git doing exactly its job. `notes/` is in no declaration,\n\
          # so a gate that asked about every file instead of every *encrypted*\n\
          # file would refuse here and take the repository down with it.\n\
          notes/** eol=lf\n",
    );
    repo.write_file(".gitattributes", &attributes);
    // The machine's own answer taken out of it, then put back the other way
    // round below.
    repo.set_eol_config("true", "");

    let secret = two_megabytes();
    repo.write_file("secrets/store.p12", &secret);
    repo.write_file("vault/keys.bin", BINARY);
    repo.write_file("notes/readme.txt", CRLF);
    repo.commit_all("ordinary attribute lines everywhere");

    // The premises, so this test cannot quietly stop covering what it names.
    assert_eq!(
        repo.check_attr("text", "vault/keys.bin"),
        "auto",
        "`text=auto` no longer wins on the declared path it is here to cover"
    );
    assert_eq!(
        repo.check_attr("eol", "notes/readme.txt"),
        "lf",
        "the bare `eol=` no longer reaches the path stored in the clear"
    );
    assert_eq!(
        repo.check_attr("text", "notes/readme.txt"),
        "unspecified",
        "something now sets `text` on that path, so it is no longer the shape \
         that would be fatal over a ciphertext"
    );

    assert!(
        repo.blob_is_encrypted("secrets/store.p12"),
        "a healthy repository stopped encrypting"
    );
    assert!(
        repo.blob_is_encrypted("vault/keys.bin"),
        "the path `text=auto` reaches stopped being encrypted"
    );
    assert_eq!(
        repo.blob_bytes("vault/keys.bin").len(),
        OVERHEAD + BINARY.len(),
        "the ciphertext under `text=auto` was converted after all"
    );
    assert_eq!(
        repo.blob_bytes("secrets/store.p12").len(),
        OVERHEAD + secret.len(),
        "the ciphertext was converted after all, so one of these lines is not \
         as harmless as it looks"
    );
    repo.recheckout("secrets/store.p12");
    repo.assert_worktree_eq("secrets/store.p12", &secret);
    repo.assert_status_clean();

    // `core.autocrlf=input` too: the gate must not depend on the machine's
    // line-ending configuration, because that configuration cannot reach the
    // ciphertext at all once `-text` is on it.
    repo.set_eol_config("input", "");
    repo.write_file("secrets/store.p12", &secret);
    repo.git_ok(["add", "-A"]);
    repo.assert_status_clean();
}

/// The exit code the frozen table gives to a configuration error.
const CONFIG_ERROR: i32 = 2;

/// A secret under a directory whose name carries a space.
const SPACED: &[u8] = b"DATABASE_URL=postgres://user:hunter2@localhost/app\n";

/// The base64 line of an exported key file.
fn key_material(path: &std::path::Path) -> String {
    let text = std::fs::read_to_string(path).expect("the export must be readable text");
    text.lines()
        .nth(1)
        .expect("an export has a header and a key")
        .to_string()
}

#[test]
fn a_name_with_a_space_is_declared_in_quotes_and_lives_the_whole_cycle() {
    // Whitespace separates a pattern from its attributes, so a name that
    // contains a space needs a way of saying "this space is part of the name".
    // Until 2026-08-05 that was a backslash — which meant the character carried
    // two jobs at once, its own and wildmatch's — and since then it is quotes,
    // the way `.gitattributes` has always spelled it.
    //
    // Every stage of the tool has to agree about which paths that pattern names,
    // and the two that can disagree in silence are the ones this exercises: the
    // filter, which reads `.git-xcrypt`, and the rendered `.gitattributes` line,
    // which has to be quoted again on the way out and is graded here by real
    // `git check-attr`. A pattern that reaches the filter but not the rendered
    // line leaves ciphertext without `-text`, and that was measured destroying a
    // 2 MB file at checkout.
    let repo = TestRepo::init();
    repo.set_eol_config("false", "lf");
    repo.init_xcrypt();

    // --- The line as it used to be written: refused, and told why. ----------
    //
    // Split by today's rule it falls apart into the pattern `my\` and the
    // unknown attribute `secrets/`, so the file is refused either way — but a
    // reader of "unknown attribute" has no way to learn what changed under a
    // file they wrote once and have not opened since.
    repo.write_xcrypt_config("my\\ secrets/\n");
    let refused = repo.xcrypt(["sync"]);
    let complaint = String::from_utf8_lossy(&refused.stderr).into_owned();

    assert_eq!(
        refused.status.code(),
        Some(CONFIG_ERROR),
        "the old spelling was accepted, so a declared path silently stopped \
         being encrypted:\n{complaint}"
    );
    assert!(
        complaint.contains("2026-08-05") && complaint.contains("\"my secrets/\""),
        "the refusal must say that the syntax changed and how the line reads \
         now, or it is indistinguishable from a typo:\n{complaint}"
    );

    // Nor does anything reach the object database while the file is unreadable:
    // a refusal that let `git add` through would be the failure mode this
    // whole product exists to prevent.
    repo.write_file("my secrets/db.env", SPACED);
    let added = repo.git(["add", "-A"]);
    assert!(
        !added.status.success(),
        "`git add` went through on an unparsable declaration:\n{}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(
        !repo.object_exists_for(SPACED),
        "the plaintext of a declared secret reached the object database while \
         the declaration could not be read"
    );

    // Quoting the whole old line instead — pattern and attributes together — is
    // the other way to reach for the new syntax and get it wrong, and it is the
    // dangerous one: the pattern would simply match nothing.
    repo.write_xcrypt_config("\"my secrets/*.sh   text eol=lf\"\n");
    let wrapped = repo.xcrypt(["sync"]);
    let complaint = String::from_utf8_lossy(&wrapped.stderr).into_owned();
    assert_eq!(
        wrapped.status.code(),
        Some(CONFIG_ERROR),
        "an old line quoted whole was accepted as a pattern, so it matches \
         nothing and the path it named is stored in the clear:\n{complaint}"
    );
    assert!(
        complaint.contains("\"my secrets/*.sh\" text eol=lf"),
        "the refusal must show where the quotes belong:\n{complaint}"
    );

    // --- Written the way it is written now. ---------------------------------
    //
    // `"!weird.env"` rides along because quoting is what made it spellable: the
    // parser stopped reading a quoted `!` as the negation marker, so the leading
    // `!` is part of a real file name and the filter encrypts it. The rendered
    // line is where that goes wrong in silence — git discards a `.gitattributes`
    // line opening with `!` (`warning: Negative patterns are ignored`), quoting
    // does not rescue it, and the path is left carrying ciphertext with no
    // `-text`. Measured on git 2.55: 35 CR bytes eaten out of a 2 MB blob, `git
    // add` exit 0, and the file unrecoverable at checkout.
    repo.write_xcrypt_config(
        "\"my secrets/\"\n\
         \"my secrets/*.sh\"   text eol=lf\n\
         !\"my secrets/README.md\"\n\
         \"!weird.env\"\n",
    );
    repo.xcrypt_ok(["sync"]);

    repo.write_file("my secrets/deploy.sh", CRLF);
    repo.write_file("app/my secrets/nested.env", SPACED);
    repo.write_file("my secrets/README.md", b"nothing secret here\n");
    repo.write_file("!weird.env", SPACED);
    repo.commit_all("a secret under a name with a space");
    repo.assert_status_clean();

    for path in [
        "my secrets/db.env",
        "app/my secrets/nested.env",
        "!weird.env",
    ] {
        assert!(
            repo.blob_is_encrypted(path),
            "{path}: a declared path was stored in the clear"
        );
        assert_eq!(
            repo.check_attr("filter", path),
            "git-xcrypt",
            "{path}: git would not run the filter for a declared path"
        );
        assert_eq!(
            repo.check_attr("text", path),
            "unset",
            "{path}: the rendered line does not reach a path the filter \
             encrypts, so git may convert its ciphertext and destroy it"
        );
    }

    // The attribute half of the split, on a quoted pattern: `text eol=lf` has
    // to survive being separated from a pattern that itself contains spaces.
    assert!(repo.blob_records_normalisation("my secrets/deploy.sh"));
    assert_eq!(
        repo.blob_bytes("my secrets/deploy.sh").len(),
        OVERHEAD + LF.len(),
        "the CRLF was not normalised, so the attributes were lost behind the \
         quotes"
    );

    // And the negation, whose `!` stands outside the quotes.
    assert!(
        !repo.blob_is_encrypted("my secrets/README.md"),
        "a negated path was encrypted anyway"
    );
    assert_eq!(
        repo.check_attr("text", "my secrets/README.md"),
        "unspecified"
    );

    // --- Closed and opened again, byte for byte. ----------------------------
    let vault = TempDir::new().expect("could not create a temporary directory");
    let key_file = vault.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &key_file.to_string_lossy()]);
    let secret = key_material(&key_file);

    let locked = repo.xcrypt_ok(["lock", "--yes"]);
    assert!(
        !String::from_utf8_lossy(&locked.stderr).contains(&secret),
        "the key itself appeared in `lock`'s own warning"
    );
    assert!(
        repo.worktree_bytes("my secrets/db.env").starts_with(MAGIC),
        "a path with a space in it was left in the clear behind a command that \
         deleted the key"
    );

    repo.xcrypt_ok(["import-key", &key_file.to_string_lossy()]);
    repo.xcrypt_ok(["unlock"]);
    repo.assert_worktree_eq("my secrets/db.env", SPACED);
    repo.assert_worktree_eq("my secrets/deploy.sh", LF);
    repo.assert_worktree_eq("app/my secrets/nested.env", SPACED);
    repo.assert_worktree_eq("!weird.env", SPACED);
    repo.assert_status_clean();
}

/// A name that ends in a space, which is the shape a backslash never closed.
///
/// **Unix only, and not for want of trying.** Win32 strips a trailing space from
/// every path it is handed, so the directory cannot be created there and there is
/// nothing to declare — the same reason `AGENTS.md` gives for the other
/// `#[cfg(unix)]` guards. What the quoting itself does is covered on all three
/// platforms by the space in the middle of `my secrets/` above; what only this
/// can show is the shape the old escape could not express at all, because the
/// line had to end `my secrets\ ` and every editor that strips trailing
/// whitespace deleted it without a word.
#[test]
#[cfg(unix)]
fn a_name_that_ends_in_a_space_is_expressible_at_last() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("\"secrets /\"\n");
    repo.xcrypt_ok(["sync"]);

    repo.write_file("secrets /db.env", SPACED);
    // The name next door, one byte shorter, which must stay in the clear: a
    // pattern that quietly loses its trailing space matches this instead.
    repo.write_file("secrets/db.env", b"nothing secret here\n");
    repo.commit_all("a secret under a name that ends in a space");
    repo.assert_status_clean();

    assert!(
        repo.blob_is_encrypted("secrets /db.env"),
        "the trailing space was lost, so the declared path is stored in the clear"
    );
    assert!(
        !repo.blob_is_encrypted("secrets/db.env"),
        "the pattern reached past the name it declares"
    );
    assert_eq!(
        repo.check_attr("text", "secrets /db.env"),
        "unset",
        "the rendered line does not reach the path the filter encrypts, so git \
         may convert its ciphertext and destroy it"
    );
    assert_eq!(
        repo.check_attr("text", "secrets/db.env"),
        "unspecified",
        "the rendered line reaches past what the filter encrypts, so a file \
         stored in the clear is carrying `-text`"
    );

    repo.recheckout("secrets /db.env");
    repo.assert_worktree_eq("secrets /db.env", SPACED);
    repo.assert_status_clean();
}

/// 8 KiB whose bytes cover the whole range.
///
/// The plaintext shape is irrelevant — what git converts is the *ciphertext*,
/// which is pseudorandom, so roughly one byte in 256 is an `LF` and this size
/// carries about 32 of them. A draw with none at all has probability `e^-32`, and
/// the tests below assert the premise anyway rather than trusting the arithmetic.
/// Small enough that five repositories' worth costs nothing, unlike the 2 MB the
/// check-in tests need to make *damage* certain.
fn eight_kilobytes() -> Vec<u8> {
    (0..8 * 1024u32)
        .map(|index| u8::try_from(index % 251).expect("a byte"))
        .collect()
}

/// `LF` bytes not preceded by `CR` — the ones git's check-out conversion expands.
fn lone_line_feeds(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .enumerate()
        .filter(|&(index, &byte)| byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
        .count()
}

/// Git's own `crlf_to_worktree`: every lone `LF` becomes `CRLF`, `CRLF` stays.
///
/// Used to build a blob that already wears the fingerprint of a converted
/// checkout, so a test can hold the fingerprint fixed and vary nothing but which
/// direction git would convert in.
fn expand_lone_line_feeds(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(byte);
    }
    out
}

/// A repository with one 8 KiB secret committed while the attributes are right.
///
/// Returns the plaintext and the intact blob, so every test below can prove both
/// that its fixture started healthy and that it stayed that way.
fn repository_with_one_intact_secret() -> (TestRepo, Vec<u8>, Vec<u8>) {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);

    let secret = eight_kilobytes();
    repo.write_file("secrets/store.p12", &secret);
    repo.commit_all("a secret, while the attributes are still right");

    let blob = repo.blob_bytes("secrets/store.p12");
    assert_eq!(
        blob.len(),
        OVERHEAD + secret.len(),
        "the fixture did not store an intact ciphertext to begin with"
    );
    assert!(
        lone_line_feeds(&blob) > 0,
        "the fixture's ciphertext holds no lone `LF`, so git's check-out \
         conversion would have nothing to expand and the shape under test \
         cannot occur"
    );
    (repo, secret, blob)
}

/// Appends `line` to the managed `.gitattributes`, where git takes it last.
fn append_attribute_line(repo: &TestRepo, line: &[u8]) {
    let mut attributes = repo.worktree_bytes(".gitattributes");
    attributes.extend_from_slice(line);
    repo.write_file(".gitattributes", &attributes);
}

/// Deletes `path` and checks it out again, returning whatever git said.
fn failing_checkout(repo: &TestRepo, path: &str) -> String {
    std::fs::remove_file(repo.path().join(path)).expect("could not remove the file");
    let checkout = repo.git(["checkout", "--", path]);
    let complaint = String::from_utf8_lossy(&checkout.stderr).into_owned();
    assert!(
        !checkout.status.success(),
        "the checkout succeeded, so the fixture no longer reproduces a failing \
         authentication tag:\n{complaint}"
    );
    complaint
}

/// Commits `blob` under `path` byte for byte, with no filter in the way.
///
/// `git hash-object --stdin` takes no path, so no attribute and no filter apply
/// to it: the object database ends up holding exactly these bytes. It is the only
/// way to stage a ciphertext the clean path would refuse — which it does, since
/// 2026-08-05, for every shape this needs.
fn commit_blob_verbatim(repo: &TestRepo, path: &str, blob: &[u8]) {
    let hashed = repo.git_with_stdin(["hash-object", "-w", "-t", "blob", "--stdin"], blob);
    assert!(
        hashed.status.success(),
        "git hash-object failed: {}",
        String::from_utf8_lossy(&hashed.stderr)
    );
    let id = String::from_utf8(hashed.stdout)
        .expect("git prints a hash")
        .trim()
        .to_string();
    repo.git_ok([
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("100644,{id},{path}"),
    ]);
    repo.git_ok(["commit", "-q", "-m", "a ciphertext nobody can decrypt"]);
}

#[test]
fn a_check_out_git_converted_names_the_line_instead_of_accusing_the_file() {
    // The other end of the refusal above, and the one nobody can act on today.
    // Git's check-out order is blob, then git's own conversion, then smudge, so
    // a `text` line that outranks the managed `-text` hands the authentication
    // tag bytes that were never stored: measured on git 2.55 with a filter that
    // copied its stdin aside, a 4118-byte blob holding 18 lone `LF` arrived as
    // 4136 bytes holding 18 `CRLF` and no lone `LF` at all.
    //
    // The tag is right to refuse that, and the file is right to be missing —
    // what was wrong was the sentence. `the file has been altered` over a blob
    // that is intact to the byte reads as "your repository is corrupt and the
    // data is gone", at the exact moment a user is least able to check.
    let (repo, secret, blob) = repository_with_one_intact_secret();

    append_attribute_line(&repo, b"secrets/** text\n");
    // `core.autocrlf=true` is Git for Windows' own default, and it is what turns
    // the `text` line into an expansion rather than a no-op.
    repo.set_eol_config("true", "");
    assert_eq!(
        repo.check_attr("text", "secrets/store.p12"),
        "set",
        "the fixture no longer reproduces the shape it exists to catch"
    );

    let complaint = failing_checkout(&repo, "secrets/store.p12");

    assert!(
        !complaint.contains("the file has been altered"),
        "the checkout still accuses a file that is intact:\n{complaint}"
    );
    assert!(
        complaint.contains("Nothing is lost"),
        "the message must say outright that nothing was lost, because the user \
         has every reason to believe otherwise:\n{complaint}"
    );
    assert!(
        complaint.contains(".gitattributes:") && complaint.contains("secrets/** text"),
        "the message must name the file, the line and the assignment, the same \
         way the check-in refusal does:\n{complaint}"
    );
    assert!(
        complaint.contains("git-xcrypt sync"),
        "the message must say what to do about it:\n{complaint}"
    );

    // The claim the message makes, checked rather than asserted in prose.
    assert_eq!(
        repo.blob_bytes("secrets/store.p12"),
        blob,
        "the blob changed under a checkout, which only reads"
    );

    // And the instruction works: with the line gone the file comes back whole.
    let attributes = repo.worktree_bytes(".gitattributes");
    let repaired = attributes
        .split(|&byte| byte == b'\n')
        .filter(|line| line != b"secrets/** text")
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>()
        .join(&b'\n');
    repo.write_file(".gitattributes", &repaired);
    assert_eq!(
        repo.check_attr("text", "secrets/store.p12"),
        "unset",
        "the repair did not put the managed `-text` back in charge"
    );
    // No `recheckout` here: the failed checkout left no file to delete, which is
    // precisely the state the message has to talk a reader out of panicking over.
    repo.git_ok(["checkout", "--", "secrets/store.p12"]);
    repo.assert_worktree_eq("secrets/store.p12", &secret);
}

#[test]
fn a_ciphertext_that_really_was_altered_is_still_reported_as_altered() {
    // The half that matters more. A wrong "this is only configuration, nothing
    // is lost" over a repository that genuinely lost something is worse than the
    // blunt message it replaces, so every shape below has to keep saying the
    // blunt thing.

    // 1. An altered body under healthy attributes: nothing converts anything,
    //    and the file really is not what was encrypted.
    {
        let (repo, _secret, blob) = repository_with_one_intact_secret();
        let mut altered = blob.clone();
        altered[OVERHEAD + 5] ^= 0xff;
        commit_blob_verbatim(&repo, "secrets/store.p12", &altered);

        let complaint = failing_checkout(&repo, "secrets/store.p12");
        assert!(
            complaint.contains("the file has been altered"),
            "a genuinely altered ciphertext must still be called altered:\n{complaint}"
        );
        assert!(
            !complaint.contains("Nothing is lost"),
            "a genuinely altered ciphertext was reported as safe:\n{complaint}"
        );
    }

    // 2. The same alteration, with `secrets/** text` and `core.autocrlf=true`
    //    in force — but on a ciphertext holding no `LF` at all, so git expands
    //    nothing and the bytes that reached the tag *are* the stored bytes. The
    //    attribute line alone must never be enough to claim the file is safe.
    {
        let (repo, _secret, blob) = repository_with_one_intact_secret();
        let unexpandable: Vec<u8> = blob
            .iter()
            .map(|&byte| if byte == b'\n' { 0x0b } else { byte })
            .collect();
        assert_eq!(
            lone_line_feeds(&unexpandable),
            0,
            "the fixture still holds an `LF`, so git would expand something"
        );
        commit_blob_verbatim(&repo, "secrets/store.p12", &unexpandable);
        append_attribute_line(&repo, b"secrets/** text\n");
        repo.set_eol_config("true", "");

        let complaint = failing_checkout(&repo, "secrets/store.p12");
        assert!(
            complaint.contains("the file has been altered"),
            "a ciphertext git could not have expanded was blamed on git:\n{complaint}"
        );
        assert!(
            !complaint.contains("Nothing is lost"),
            "an altered ciphertext was reported as safe because a `text` line \
             happened to be present:\n{complaint}"
        );
    }

    // 3. The damage already in the blob, under `secrets/** text eol=lf` — a line
    //    that converts on the way *in* and writes the stored bytes out
    //    untouched. Measured on git 2.55 with `core.autocrlf=true`: a blob full
    //    of lone `LF` checks out byte for byte under it.
    //
    //    The blob here is the expanded ciphertext itself, so it wears the exact
    //    fingerprint an expansion leaves — no lone `LF`, plenty of `CRLF` — and
    //    git expands nothing on top of it. Only the check-out *direction* tells
    //    the two apart, which is what makes this the shape that guards it: a
    //    predicate reusing the check-in verdict calls this file safe, and it is
    //    not, because nothing about fixing that line brings its plaintext back.
    {
        let (repo, _secret, blob) = repository_with_one_intact_secret();
        let already_expanded = expand_lone_line_feeds(&blob);
        assert_eq!(
            lone_line_feeds(&already_expanded),
            0,
            "the fixture does not wear the fingerprint it exists to wear"
        );
        commit_blob_verbatim(&repo, "secrets/store.p12", &already_expanded);
        append_attribute_line(&repo, b"secrets/** text eol=lf\n");
        repo.set_eol_config("true", "");
        assert_eq!(
            repo.check_attr("eol", "secrets/store.p12"),
            "lf",
            "the fixture no longer pins the check-out direction"
        );
        assert_eq!(
            repo.check_attr("text", "secrets/store.p12"),
            "set",
            "the fixture no longer makes the check-in verdict say `convert`"
        );

        let complaint = failing_checkout(&repo, "secrets/store.p12");
        assert!(
            complaint.contains("the file has been altered"),
            "an altered ciphertext was blamed on a line that does not convert \
             at check-out:\n{complaint}"
        );
        assert!(
            !complaint.contains("Nothing is lost"),
            "the check-in verdict was reused for the check-out direction, so a \
             file whose plaintext really is gone was reported as safe:\n{complaint}"
        );
    }

    // 4. Another key's file, under the same converting line. Only a failed
    //    authentication tag may be re-explained; a header that belongs to a
    //    different key is not something a `.gitattributes` line can cause.
    {
        let (repo, _secret, blob) = repository_with_one_intact_secret();
        let mut foreign = blob.clone();
        // Byte 14 opens the frozen 8-byte `key_id`, which sits inside the
        // authenticated header.
        foreign[14] ^= 0xff;
        commit_blob_verbatim(&repo, "secrets/store.p12", &foreign);
        append_attribute_line(&repo, b"secrets/** text\n");
        repo.set_eol_config("true", "");

        let complaint = failing_checkout(&repo, "secrets/store.p12");
        assert!(
            complaint.contains("was encrypted with key"),
            "a file belonging to another key must still say so:\n{complaint}"
        );
        assert!(
            !complaint.contains("Nothing is lost"),
            "a foreign key's file was reported as a configuration problem:\n{complaint}"
        );
    }
}
