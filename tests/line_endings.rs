//! Line endings across the three platforms, as one matrix.
//!
//! This is the scenario the whole asymmetry in `src/eol.rs` exists for, and the
//! one that has to hold identically on Windows, macOS and Linux:
//!
//! * **clean never reads git's configuration.** The same file must yield the
//!   same plaintext — and therefore the same ciphertext, and therefore the same
//!   blob — on every machine. A blob that moves with `core.autocrlf` is a
//!   repository whose secrets re-encrypt themselves when a colleague clones it.
//! * **smudge does read it.** That is the one moment machines are allowed to
//!   differ, and the table it obeys is measured on git 2.55 and written down in
//!   `context/foundation/zalozenia.md` §Końce linii.
//!
//! The table is **reproduced here rather than imported**: `expected_worktree`
//! below spells out git's rule in this file's own code, so a change to
//! `eol::resolve_output` or `eol::apply` cannot make the test agree with itself.
//! Everything else goes through a real git, since the question is what git and
//! the filter do to each other's output.
//!
//! One key across every repository in the matrix. `key_id` sits in the
//! authenticated header, so repositories that minted their own keys would store
//! different bytes for the same content and the determinism assertion would be
//! comparing nothing.

mod harness;

use harness::{MAGIC, OVERHEAD, SharedKey, TestRepo};

/// A shape of content and what it is, as far as git's text/binary rule cares.
struct Shape {
    /// The declared path, and the label a failure is reported under.
    path: &'static str,
    /// What the user types into the working tree.
    written: &'static [u8],
    /// Whether git — and so the filter — treats this as text.
    text: bool,
}

/// The four shapes, chosen to cover every branch of the conversion.
///
/// `mixed` deliberately has no lone `CR`: one would make the content *binary*
/// by git's own rule, and the point of that row is a text file whose round trip
/// through normalisation is lossy but still settles.
fn shapes() -> Vec<Shape> {
    vec![
        Shape {
            path: "secrets/lf.env",
            written: b"first\nsecond\nthird\n",
            text: true,
        },
        Shape {
            path: "secrets/crlf.env",
            written: b"first\r\nsecond\r\nthird\r\n",
            text: true,
        },
        Shape {
            path: "secrets/mixed.env",
            written: b"first\r\nsecond\nthird\r\n",
            text: true,
        },
        Shape {
            // A NUL makes it binary wherever git looks, and the CRLF pairs are
            // there so "no conversion happened" is an observable claim rather
            // than a vacuous one.
            path: "secrets/keystore.env",
            written: b"\x00\x01binary\r\ncontent\r\n\x1f\x00",
            text: false,
        },
    ]
}

/// `CRLF` → `LF`, reproduced here so the test does not grade the code with it.
fn normalise(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len());
    let mut index = 0;
    while index < content.len() {
        if content[index] == b'\r' && content.get(index + 1) == Some(&b'\n') {
            out.push(b'\n');
            index += 2;
        } else {
            out.push(content[index]);
            index += 1;
        }
    }
    out
}

/// `LF` → `CRLF`, likewise.
fn to_crlf(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len());
    for (index, &byte) in content.iter().enumerate() {
        if byte == b'\n' && (index == 0 || content[index - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(byte);
    }
    out
}

/// What a checkout must leave in the working tree, per the measured table.
///
/// | `core.autocrlf` | `core.eol` | result                         |
/// | --------------- | ---------- | ------------------------------ |
/// | `true`          | anything   | CRLF (`core.eol` ignored)      |
/// | `input`         | anything   | LF (`core.eol` ignored)        |
/// | `false`         | `crlf`     | CRLF                           |
/// | `false`         | `lf`       | LF                             |
/// | `false`         | `native`   | the platform's own             |
///
/// Binary content is written back verbatim whatever any of that says, because
/// its header records that it was never normalised in the first place.
fn expected_worktree(shape: &Shape, autocrlf: &str, eol: &str) -> Vec<u8> {
    if !shape.text {
        return shape.written.to_vec();
    }

    let stored = normalise(shape.written);
    let wants_crlf = match autocrlf {
        "true" => true,
        "input" => false,
        "false" => match eol {
            "crlf" => true,
            "lf" => false,
            // The one answer that is allowed to differ per platform — and the
            // arm that never runs on the development machine, which is exactly
            // why it is asserted rather than skipped.
            "native" => cfg!(windows),
            other => panic!("core.eol={other} is not in the table"),
        },
        other => panic!("core.autocrlf={other} is not in the table"),
    };

    if wants_crlf { to_crlf(&stored) } else { stored }
}

#[test]
fn the_line_ending_matrix_stores_one_blob_and_checks_out_what_each_machine_asks_for() {
    let key = SharedKey::minted();
    let shapes = shapes();

    // Blob per path, from the first configuration, to compare every later one
    // against.
    let mut baseline: Vec<Option<Vec<u8>>> = vec![None; shapes.len()];

    for autocrlf in ["false", "true", "input"] {
        for eol in ["lf", "crlf", "native"] {
            let label = format!("core.autocrlf={autocrlf} core.eol={eol}");

            let repo = TestRepo::init();
            repo.set_eol_config(autocrlf, eol);
            repo.init_xcrypt_with(&key);
            repo.write_xcrypt_config("secrets/\n");
            repo.xcrypt_ok(["sync"]);

            for shape in &shapes {
                repo.write_file(shape.path, shape.written);
            }
            repo.commit_all("secrets in every shape of line ending");
            repo.assert_status_clean();

            for (index, shape) in shapes.iter().enumerate() {
                let blob = repo.blob_bytes(shape.path);
                let stored = normalise(shape.written);
                let plaintext: &[u8] = if shape.text { &stored } else { shape.written };

                // 1. The filter ran, and it stored the plaintext this machine
                //    was never allowed to have an opinion about.
                assert!(
                    blob.starts_with(MAGIC),
                    "{label}: {} was not encrypted",
                    shape.path
                );
                assert_eq!(
                    blob.len(),
                    OVERHEAD + plaintext.len(),
                    "{label}: {} was normalised against the machine's \
                     configuration instead of the frozen rule",
                    shape.path
                );
                assert_eq!(
                    repo.blob_records_normalisation(shape.path),
                    shape.text,
                    "{label}: {} recorded the wrong text/binary verdict in its \
                     header, so smudge will convert the wrong file",
                    shape.path
                );

                // 2. And it is the same blob everywhere. This is the hard rule:
                //    a blob that moves with the machine means the same file
                //    encrypts differently on Windows and on Linux.
                match &baseline[index] {
                    None => baseline[index] = Some(blob),
                    Some(first) => assert_eq!(
                        &blob, first,
                        "{label}: {} stored different bytes than the first \
                         configuration did — determinism across machines is gone",
                        shape.path
                    ),
                }
            }

            // 3. What a checkout writes, per configuration, per shape.
            for shape in &shapes {
                repo.recheckout(shape.path);
                let expected = expected_worktree(shape, autocrlf, eol);
                assert_eq!(
                    repo.worktree_bytes(shape.path),
                    expected,
                    "{label}: {} came back with line endings this configuration \
                     did not ask for",
                    shape.path
                );
            }

            // 4. And the repository settles: whatever smudge wrote, the next
            //    clean normalises back to the very plaintext that was encrypted.
            //    Without this the working tree is permanently dirty on one
            //    platform and clean on another.
            repo.assert_status_clean();
            repo.git_ok(["add", "-A"]);
            repo.assert_status_clean();
        }
    }
}

/// The line whose absence was Open Decision 8, closed 2026-08-06.
///
/// Normalisation maps several working trees onto one plaintext, so for two
/// shapes the original cannot come back. Both are measured against git 2.55 and
/// both were silent here until this test existed:
///
/// * **mixed `CRLF` and lone `LF`** — comes back with one kind of ending, and
///   `git status` stays *clean*, because the new bytes normalise to the
///   plaintext already stored. Nothing whatsoever signalled it.
/// * **`CR` before `CRLF` under an explicit `text`** — loses a byte per pass.
///   Git is silent on this one even with `core.safecrlf=warn`, because its two
///   counters cannot see a lone `CR`.
///
/// The quiet half of this test is the important half. Git's own `safecrlf` asks
/// whether the *bytes change*, so it warns about every LF-only file on a machine
/// with `core.autocrlf=true`; it can afford that because it defaults to off.
/// Ours has no knob, so it asks whether the original is *recoverable* — and a
/// warning that fired on ordinary content would teach the reader to skip the two
/// that matter.
#[test]
fn content_whose_original_cannot_come_back_is_named_and_nothing_else_is() {
    // `core.autocrlf=true` throughout, deliberately: it is the configuration
    // under which git's wider question would warn about nearly every file here,
    // so it is where a predicate copied from git would show up as noise.
    let repo = TestRepo::init();
    repo.set_eol_config("true", "native");
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\nforced/ text\n");
    repo.xcrypt_ok(["sync"]);

    let warning = "do not survive a round trip";

    // The quiet side first. Uniform endings either way, content with no endings
    // at all, an empty file, binary content, and the remedy the message
    // recommends — none of these may produce a line.
    for (path, content) in [
        ("secrets/lf.env", &b"first\nsecond\n"[..]),
        ("secrets/crlf.env", b"first\r\nsecond\r\n"),
        ("secrets/none.env", b"no line ending at all"),
        ("secrets/empty.env", b""),
        ("secrets/binary.env", b"\x00\x01mixed\r\nendings\n\x00"),
        ("forced/lf.env", b"first\nsecond\n"),
        ("forced/crlf.env", b"first\r\nsecond\r\n"),
    ] {
        repo.write_file(path, content);
        let quiet = repo.git(["add", path]);
        let said = String::from_utf8_lossy(&quiet.stderr).into_owned();
        assert!(
            quiet.status.success(),
            "{path}: a healthy file was refused:\n{said}"
        );
        assert!(
            !said.contains(warning),
            "{path}: healthy content was called lossy, which is how a warning \
             stops being read:\n{said}"
        );
    }

    // Mixed endings, under the default mode — no attribute at all, which is what
    // almost every declared path is in.
    repo.write_file("secrets/mixed.env", b"first\r\nsecond\nthird\r\n");
    let mixed = repo.git(["add", "secrets/mixed.env"]);
    let said = String::from_utf8_lossy(&mixed.stderr).into_owned();
    assert!(
        mixed.status.success(),
        "the warning refused a `git add`, which it must never do — with \
         `required = true` that stops every git operation in the repository \
         over content that is converted, not lost:\n{said}"
    );
    assert!(
        said.contains(warning) && said.contains("secrets/mixed.env"),
        "mixed line endings went by unnamed under the default mode:\n{said}"
    );
    assert!(
        said.contains("binary"),
        "the message must name the remedy that is inside this tool:\n{said}"
    );

    // And the shape git itself misses: a lone `CR` in front of a `CRLF`, which
    // only reaches the conversion because an explicit `text` bypasses the
    // binary classifier that would otherwise decline the file.
    repo.write_file("forced/collapse.env", b"first\r\r\nsecond\n");
    let collapsing = repo.git(["add", "forced/collapse.env"]);
    let said = String::from_utf8_lossy(&collapsing.stderr).into_owned();
    assert!(
        collapsing.status.success(),
        "refused rather than warned:\n{said}"
    );
    assert!(
        said.contains(warning) && said.contains("forced/collapse.env"),
        "a `CR` before a `CRLF` under an explicit `text` went by unnamed — this \
         is the shape `core.safecrlf` does not catch either:\n{said}"
    );

    // The claim the warning makes has to be true, so prove the loss rather than
    // trusting the predicate: commit, drop the working tree, check out again.
    repo.commit_all("every shape");
    for (path, written) in [
        ("secrets/mixed.env", &b"first\r\nsecond\nthird\r\n"[..]),
        ("forced/collapse.env", b"first\r\r\nsecond\n"),
    ] {
        repo.recheckout(path);
        assert_ne!(
            repo.worktree_bytes(path),
            written,
            "{path} came back unchanged, so the warning is now false"
        );
    }

    // …and the quiet ones have to be telling the truth too, which is the same
    // assertion pointed the other way.
    for (path, written) in [
        ("secrets/crlf.env", &b"first\r\nsecond\r\n"[..]),
        ("secrets/binary.env", b"\x00\x01mixed\r\nendings\n\x00"),
    ] {
        repo.recheckout(path);
        assert_eq!(
            repo.worktree_bytes(path),
            written,
            "{path} was silently changed and nothing warned about it"
        );
    }
}
