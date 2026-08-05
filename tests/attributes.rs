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

/// The exit code the frozen table gives to "an exposure was found".
const EXPOSED: i32 = 5;

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

    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "a repository whose ciphertext git converts must fail the gate:\n{text}"
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
