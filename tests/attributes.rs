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

#[test]
fn a_foreign_text_line_below_the_managed_section_is_caught_before_the_file_is_lost() {
    // The managed section is *current* here: `sync` has run and the `-text`
    // line is exactly right. One line below it puts `text` back on, and git
    // takes the last match.
    //
    // Measured on git 2.55: `git check-attr text` answers `set`, git runs its
    // own CRLF conversion over the ciphertext, `CR` bytes are eaten out of the
    // blob, `git add` and `git commit` both exit 0, and the checkout fails the
    // authentication tag and leaves no file at all. Nobody can decrypt what was
    // committed, ever. This is the one gap that destroys data silently, so
    // `status` has to fail the gate over it.
    let secret = two_megabytes();

    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);

    let mut attributes = repo.worktree_bytes(".gitattributes");
    attributes.extend_from_slice(b"secrets/** text\n");
    repo.write_file(".gitattributes", &attributes);

    repo.write_file("secrets/store.p12", &secret);
    repo.commit_all("a secret under a foreign text line");

    // The premise really is the failure mode, not a story about one.
    assert_eq!(
        repo.check_attr("text", "secrets/store.p12"),
        "set",
        "the fixture no longer puts `text` back on the declared path"
    );
    assert_ne!(
        repo.blob_bytes("secrets/store.p12").len(),
        OVERHEAD + secret.len(),
        "this test no longer reproduces the corruption it exists to catch"
    );
    std::fs::remove_file(repo.path().join("secrets/store.p12")).expect("could not remove");
    repo.git(["checkout", "--", "secrets/store.p12"]);
    assert!(
        !repo.path().join("secrets/store.p12").is_file(),
        "the damaged blob checked out, so the premise is gone"
    );

    // And `status` has to say so, with the exit code a CI gate reads.
    let output = repo.xcrypt(["status"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();

    // Code `2`, not `5`: since 2026-08-05 a setup gap is a configuration
    // finding, and the remedy here is an attribute line, not a rotated secret.
    // Nothing was stored in the clear over this — what it costs is the
    // ciphertext — so the exit code and the wording have to agree on that.
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
        text.contains("secrets/** text"),
        "the report must name the winning line itself, or nobody can find it:\n{text}"
    );
    assert!(
        text.contains("-text"),
        "the report must name the attribute that prevents it:\n{text}"
    );
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
