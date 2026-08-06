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

/// The same mistake, made on a branch nobody is standing on.
///
/// A secret does not have to be in `HEAD` to be at the hosting provider: it is
/// pushed with its branch, it is in every clone, and the commit that carries it
/// is reachable for ever. This is the ordinary shape of the mistake — the secret
/// goes in on a feature branch, the branch is left alone, and by the time anyone
/// declares the pattern the file is nowhere in the working tree.
///
/// Which means the scan has to start from **every** reference, not from the
/// checked-out one. Measured: with the walk reduced to the current branch,
/// nothing else in this suite goes red and `status` reports a clean bill of
/// health over a plaintext blob that is one `git push` from public.
#[test]
fn a_secret_left_on_a_branch_nobody_has_checked_out_is_still_found() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("# nothing declared yet\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("README.md", b"# ordinary project\n");
    repo.commit_all("an ordinary start");

    repo.git_ok(["checkout", "-q", "-b", "feature"]);
    repo.write_file("secrets/db.env", SECRET);
    repo.commit_all("wire the database up");
    assert_eq!(
        repo.blob_bytes("secrets/db.env"),
        SECRET,
        "the premise is a plaintext blob on the branch"
    );

    repo.git_ok(["checkout", "-q", "main"]);
    assert!(
        !repo.path().join("secrets/db.env").exists(),
        "the premise is that nothing in the working tree shows this any more"
    );

    // The declaration arrives on `main`, where the file has never been seen.
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.commit_all("declare the secrets directory");

    let output = repo.xcrypt(["status"]);
    let text = report(&output);
    assert_eq!(
        output.status.code(),
        Some(EXPOSED),
        "a plaintext secret on another branch must fail the gate — it is pushed \
         with that branch and it is in every clone:\n{text}"
    );
    assert!(
        text.contains("leaked in history"),
        "the finding must say where it is:\n{text}"
    );
    assert!(
        text.contains("secrets/db.env"),
        "the report must name the path:\n{text}"
    );
}

/// A repository that filters correctly but has not committed its bootstrap.
///
/// `init` writes `.gitattributes` and `.git-xcrypt` into the working tree, and
/// git reads both from there — so *this* checkout enforces the declarations
/// exactly as a committed pair would. The exposure belongs to a clone, which
/// gets neither file and stores every secret in the clear with exit code 0.
///
/// The gap is real (exit 2), and the words carry the remedy: the headline used
/// to say "committing a declared file stores it in the clear", false of this
/// repository and pointing at secrets that were never exposed, while the remedy
/// block offered `init` — which does not commit anything, so following it
/// changed nothing and the report came back identical.
#[test]
fn an_uncommitted_bootstrap_names_the_clones_exposure_not_this_checkouts() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    // The secret committed, the bootstrap not: `git add <path>` instead of
    // `-A` is all it takes, and it is the state the gap exists for — a wholly
    // untracked repository is deliberately left alone, because between
    // `git init` and the first `git add` there is nothing published to warn
    // about.
    repo.write_file("secrets/db.env", SECRET);
    repo.git_ok(["add", "secrets/db.env"]);
    repo.git_ok(["commit", "-q", "-m", "the secret, without its bootstrap"]);
    assert!(
        repo.blob_bytes("secrets/db.env").starts_with(MAGIC),
        "the premise is a correctly filtering checkout; without it this test \
         proves nothing"
    );

    let output = repo.xcrypt(["status"]);
    let text = report(&output);

    assert_eq!(
        output.status.code(),
        Some(2),
        "an uncommitted bootstrap is a setup gap, and the gate must say so:\n{text}"
    );
    assert!(
        !text.contains("stores it in the clear"),
        "this repository filters correctly, and the headline says it does not:\n{text}"
    );
    assert!(
        text.contains("no clone gets them"),
        "the real exposure — the clone's — goes unnamed:\n{text}"
    );
    assert!(
        text.contains("git add"),
        "the one remedy that works, a commit, is not offered:\n{text}"
    );
    assert!(
        !text.contains("git-xcrypt init"),
        "`init` does not commit anything, so offering it here is a loop that \
         changes nothing:\n{text}"
    );
}
