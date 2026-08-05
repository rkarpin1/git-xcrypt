//! A secret committed before anyone declared it — the largest real risk this
//! product carries, followed from the mistake to the end of what can be fixed.
//!
//! `zalozenia.md` §Bezpieczeństwo names it outright: a secret that reached a
//! commit before the pattern existed stays in history in the clear forever, and
//! is already at the hosting provider. Every part of the response is in this one
//! run, in order, because each part is only meaningful next to the others:
//!
//! * `status` finds it at all — a shallow look at `HEAD` would not, since a
//!   secret can be committed and then deleted;
//! * the report puts **rotating the secret before rewriting history**, because a
//!   rewrite cleans the repository and does not revoke the leak;
//! * `--fix` re-stages what is still fixable, so the next commit encrypts it;
//! * and the gate **stays red afterwards**. That last one is the assertion this
//!   file exists for. `--fix` repairs the future; the past is not repairable
//!   from here, and a green gate after it would say the opposite.

mod harness;

use harness::{MAGIC, TestRepo};

/// The exit code the frozen table gives to "an exposure was found".
const EXPOSED: i32 = 5;

const SECRET: &[u8] = b"hunter2\n";

/// Everything `status` printed to `stdout`, which is where the report belongs.
fn report(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The bytes the **index** currently points at for `path`.
///
/// The index is what `--fix` writes, and the only place its work is observable
/// before a commit — after which git's own re-read of a changed file could have
/// produced the same result without it.
fn staged_blob(repo: &TestRepo, path: &str) -> Vec<u8> {
    repo.git_ok(["cat-file", "blob", &format!(":{path}")])
        .stdout
}

#[test]
fn a_secret_committed_before_its_pattern_is_found_fixed_forward_and_still_reported() {
    // --- The mistake: committed while nothing declared it. ------------------
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", SECRET);
    repo.write_file("README.md", b"# ordinary project\n");
    repo.commit_all("before anyone declared anything");

    assert_eq!(
        repo.blob_bytes("secrets/db.env"),
        SECRET,
        "the premise is a plaintext blob; without it this test proves nothing"
    );

    // --- The declaration arrives, too late. ---------------------------------
    //
    // Past git's racy-clean window first, and deliberately. Inside the same
    // second git re-reads every file whatever its cached `stat` says, so a run
    // that stayed inside it would have the clean filter encrypt this file on the
    // next `git add` regardless of the index — and every assertion below would
    // pass with `--fix` removed entirely. That is measured, not theoretical:
    // with `gitindex::restage` reduced to "report success, write nothing", this
    // file was green.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    repo.git_ok(["update-index", "--refresh"]);

    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);

    let found = repo.xcrypt(["status"]);
    let text = report(&found);
    assert_eq!(
        found.status.code(),
        Some(EXPOSED),
        "a plaintext secret in history must fail the gate:\n{text}"
    );
    assert!(
        text.contains("leaked in history"),
        "the finding must say the history is where it is:\n{text}"
    );
    assert!(
        text.contains("secrets/db.env"),
        "the report must name the path:\n{text}"
    );
    assert!(
        text.contains("in the clear:"),
        "the file is still plain text in the index and in HEAD, and that is a \
         separate finding from the history — the two need different repairs:\n{text}"
    );

    // Rotation before rewriting, because a rewrite does not revoke a leak: the
    // secret is in forks, caches, CI logs and every clone that already exists.
    let rotate = text
        .find("ROTATE THE SECRET")
        .unwrap_or_else(|| panic!("the report never says to rotate:\n{text}"));
    let rewrite = text
        .find("git filter-repo")
        .unwrap_or_else(|| panic!("the report never says how to rewrite:\n{text}"));
    assert!(
        rotate < rewrite,
        "rewriting was offered before rotation, which reads as a fix:\n{text}"
    );
    assert!(
        text.contains("does NOT undo this"),
        "a rewrite must not be allowed to read as a fix:\n{text}"
    );

    // --- The gap `--fix` exists for, shown before it is closed. -------------
    //
    // Declaring a pattern reaches the filter immediately, and does *not* reach a
    // file git considers unchanged: `git add -A` consults the cached `stat`,
    // decides there is nothing to do and never asks the filter. The staged blob
    // is still the plaintext one.
    repo.git_ok(["add", "-A"]);
    assert_eq!(
        staged_blob(&repo, "secrets/db.env"),
        SECRET,
        "git re-read the file anyway, so this run is inside the racy-clean \
         window and proves nothing about `--fix`"
    );

    // --- `--fix` repairs what is repairable: the next commit. ---------------
    let fixed = repo.xcrypt(["status", "--fix"]);
    let fixed_text = report(&fixed);
    assert_eq!(
        fixed.status.code(),
        Some(EXPOSED),
        "`--fix` cannot clear a finding it did not fix:\n{fixed_text}"
    );

    // What `--fix` promises is an index entry, so that is what is read back —
    // not a later commit, which git's own re-read could produce on its own.
    assert!(
        staged_blob(&repo, "secrets/db.env").starts_with(MAGIC),
        "`--fix` reported success over an index still pointing at the plaintext"
    );

    // The working tree stays readable — `--fix` touches the index and nothing
    // else, so the user goes on working on plaintext.
    repo.assert_worktree_eq("secrets/db.env", SECRET);

    repo.git_ok(["commit", "-q", "-m", "declare the secret"]);
    assert!(
        repo.blob_is_encrypted("secrets/db.env"),
        "the commit after `--fix` still stored the secret in the clear"
    );
    assert!(
        !repo.blob_is_encrypted("README.md"),
        "an undeclared file must stay readable"
    );
    repo.assert_status_clean();

    // --- And the gate stays red, because the old blob is still there. -------
    let still = repo.xcrypt(["status"]);
    let still_text = report(&still);
    assert_eq!(
        still.status.code(),
        Some(EXPOSED),
        "the plaintext blob is still in history, so the gate must stay red — a \
         green gate here would tell the user the secret is safe:\n{still_text}"
    );
    assert!(
        still_text.contains("leaked in history"),
        "the finding must survive `--fix`:\n{still_text}"
    );
    assert!(
        still_text.contains("secrets/db.env"),
        "the report must still name the path:\n{still_text}"
    );

    // The old blob really is still reachable, which is what the verdict is
    // about — not a leftover message.
    let old = repo.git_ok(["show", "HEAD~1:secrets/db.env"]).stdout;
    assert_eq!(
        old, SECRET,
        "history no longer holds the plaintext, so the finding above would be \
         wrong rather than right"
    );
    assert!(
        !repo.blob_bytes("secrets/db.env").starts_with(SECRET),
        "the current blob is the plaintext"
    );
    assert!(repo.blob_bytes("secrets/db.env").starts_with(MAGIC));
}
