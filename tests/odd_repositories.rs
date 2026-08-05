//! Repositories that are not the shape the happy path assumes.
//!
//! `status` is meant to be a CI gate, so the only thing most of its callers ever
//! read is the exit code. That makes an unusual repository dangerous in a very
//! specific way: a build that cannot walk it must say `6` — "I could not check"
//! — and never `0`. The measured history of this command is a list of ways it
//! said `0` instead: a reference store it could not enumerate yielded no tips,
//! so the walk visited nothing, found nothing, and reported a clean bill of
//! health over a plaintext blob.
//!
//! One test, one configuration per section, and **every assertion names its
//! configuration** — after a red CI run on a machine nobody can reach, a bare
//! `assertion failed: left == right` is a guessing game.
//!
//! Two deliberate choices about portability:
//!
//! * the unreadable reference store is a **directory where the file should be**,
//!   not `chmod 0o000`. Mode bits are a Unix mechanism, and this is the
//!   guarantee that must not be skipped anywhere; opening a directory as a file
//!   fails on every platform (`EISDIR` here, `ERROR_ACCESS_DENIED` on Windows)
//!   and arrives as an ordinary I/O error either way;
//! * nothing here relies on file names, symlinks or permissions, so the whole
//!   matrix runs on Windows, macOS and Linux alike.

mod harness;

use harness::{BareRemote, SharedKey, TestRepo};

/// The frozen exit codes this file is about.
const CLEAN: i32 = 0;
/// Configuration or a state conflict — a bare repository has no working tree.
const CONFIG: i32 = 2;
const EXPOSED: i32 = 5;
const UNDETERMINED: i32 = 6;

const SECRET: &[u8] = b"hunter2\n";

/// Asserts the verdict, naming the configuration that produced it.
fn expect(label: &str, output: &std::process::Output, wanted: i32) {
    let report = String::from_utf8_lossy(&output.stdout);
    let diagnostics = String::from_utf8_lossy(&output.stderr);

    assert!(
        !diagnostics.contains("panicked"),
        "{label}: `status` panicked instead of answering:\n{diagnostics}"
    );
    assert_eq!(
        output.status.code(),
        Some(wanted),
        "{label}: `status` exited {:?} where the frozen table says {wanted}\n\
         --- report ---\n{report}\n--- diagnostics ---\n{diagnostics}",
        output.status.code()
    );
}

/// A healthy repository with one declared, encrypted secret in it.
fn declared(repo: &TestRepo) {
    repo.write_xcrypt_config("secrets/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("secrets/db.env", SECRET);
    repo.write_file("README.md", b"# ordinary project\n");
    repo.commit_all("a declared secret");
}

#[test]
fn every_unusual_repository_gets_an_answer_and_the_right_one() {
    // --- A SHA-256 repository, healthy. -------------------------------------
    //
    // `gix-odb` asserts on the object id length rather than adapting, so a build
    // that assumes SHA-1 panics here — and it panics on the filter path too,
    // where `required = true` turns that into "every git operation in this
    // repository fails".
    let sha256 = TestRepo::init_sha256();
    sha256.init_xcrypt();
    declared(&sha256);
    expect(
        "a SHA-256 repository with nothing wrong with it",
        &sha256.xcrypt(["status"]),
        CLEAN,
    );

    // --- A SHA-256 repository with a leak in its history. -------------------
    //
    // The other half of the same guard: answering `0` everywhere would also
    // satisfy the assertion above, and this is what says the scan really ran.
    let leaky = TestRepo::init_sha256();
    leaky.init_xcrypt();
    leaky.write_xcrypt_config("# nothing declared yet\n");
    leaky.write_file("secrets/db.env", SECRET);
    leaky.commit_all("leak");
    leaky.write_xcrypt_config("secrets/\n");
    let output = leaky.xcrypt(["status"]);
    expect(
        "a SHA-256 repository holding a plaintext secret in history",
        &output,
        EXPOSED,
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("leaked in history"),
        "a SHA-256 repository holding a plaintext secret in history: the finding \
         must name where it is:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // --- A split index. -----------------------------------------------------
    //
    // `features.manyFiles=true` turns this on wholesale, so it is not exotic.
    // The history scan needs no index and still runs; what must not happen is
    // "nothing found" over an index this build could not read.
    let split = TestRepo::init();
    split.init_xcrypt();
    declared(&split);
    split.git_ok(["update-index", "--split-index"]);
    expect(
        "a repository using git's split index",
        &split.xcrypt(["status"]),
        UNDETERMINED,
    );

    // --- A split index over a repository that also leaked. ------------------
    //
    // Precedence, and the only place in this command where getting it backwards
    // is silent: a run that both found a leak and could not read the index has
    // found a leak. `6` says "fix the checkout and ask again", `5` says "rotate
    // the secret" — so letting the unanswered question win would turn a real
    // exposure into a housekeeping note, and the operator would do the wrong
    // thing while the gate stayed technically red.
    let both = TestRepo::init();
    both.init_xcrypt();
    both.write_xcrypt_config("# nothing declared yet\n");
    both.write_file("secrets/db.env", SECRET);
    both.commit_all("the leak");
    both.write_xcrypt_config("secrets/\n");
    both.xcrypt_ok(["sync"]);
    both.git_ok(["update-index", "--split-index"]);

    let output = both.xcrypt(["status"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    expect(
        "a split index over a repository that also leaked a secret",
        &output,
        EXPOSED,
    );
    assert!(
        text.contains("leaked in history"),
        "a split index over a repository that also leaked a secret: the finding \
         must survive being reported next to a question:\n{text}"
    );
    assert!(
        text.contains("undetermined"),
        "a split index over a repository that also leaked a secret: the question \
         must still be reported, or the operator cannot tell the scan was \
         partial:\n{text}"
    );

    // --- A shallow clone, which is what CI produces by default. -------------
    //
    // Nothing is wrong with it. A history that was never fetched simply cannot
    // be vouched for, and `actions/checkout` clones this way unless it is given
    // `fetch-depth: 0` — a gate that cries wolf on its own default setup is a
    // gate that gets switched off.
    let key = SharedKey::minted();
    let source = TestRepo::init();
    source.init_xcrypt_with(&key);
    declared(&source);
    source.write_file("README.md", b"# a second commit\n");
    source.commit_all("two");

    let shallow = source.clone_shallow();
    shallow.xcrypt_ok(["unlock", &key.as_arg()]);
    let output = shallow.xcrypt(["status"]);
    expect(
        "a shallow clone of a healthy repository",
        &output,
        UNDETERMINED,
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("shallow clone"),
        "a shallow clone of a healthy repository: the report must name why it \
         could not answer:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // --- A partial clone, for the same reason. ------------------------------
    let partial = source.clone_without_filter();
    partial.xcrypt_ok(["unlock", &key.as_arg()]);
    partial.set_config("extensions.partialclone", "origin");
    expect(
        "a partial clone, where an absent object is a design decision",
        &partial.xcrypt(["status"]),
        UNDETERMINED,
    );

    // --- A linked worktree. -------------------------------------------------
    //
    // The one configuration where "the git directory" and "the directory git
    // reads configuration from" stop being the same place.
    let main = TestRepo::init();
    main.init_xcrypt();
    declared(&main);
    let linked = main.add_worktree("side");
    expect(
        "a linked worktree of a healthy repository",
        &linked.xcrypt(["status"]),
        CLEAN,
    );

    // And the unhealthy shape, which is the one that place actually costs
    // something. `info/` is on git's common list, so both checkouts resolve the
    // *main* `info/attributes` — measured on git 2.55, `git check-attr filter`
    // answers `unset` in the linked worktree too, and `git add secrets/db.env`
    // there exits 0 and stores the plain text. Asking this checkout's own git
    // directory instead read a file git never consults and missed the one that
    // decides, so `status` from the linked worktree exited 0 over a repository
    // that was storing secrets in the clear.
    std::fs::create_dir_all(main.path().join(".git/info")).expect("the info directory");
    std::fs::write(
        main.path().join(".git/info/attributes"),
        b"secrets/** -filter\n",
    )
    .expect("writing info/attributes");
    expect(
        "a linked worktree whose shared info/attributes turns the filter off",
        &linked.xcrypt(["status"]),
        EXPOSED,
    );
    std::fs::remove_file(main.path().join(".git/info/attributes")).expect("removing it again");

    // --- A reference store that cannot be enumerated. -----------------------
    //
    // The measured failure this section exists for: no tips means the walk
    // visits nothing, finds nothing and exits 0 over a plaintext blob.
    let unreadable = TestRepo::init();
    unreadable.init_xcrypt();
    unreadable.write_xcrypt_config("# nothing declared yet\n");
    unreadable.write_file("secrets/db.env", SECRET);
    unreadable.commit_all("leak");
    // Declared and re-staged through the filter, so the index holds ciphertext
    // and the only thing left to find is in history — which is exactly what the
    // unreadable store hides. `--renormalize` rather than a bare `add -A`:
    // git decides from its cached `stat` whether to call the filter at all.
    unreadable.write_xcrypt_config("secrets/\n");
    unreadable.xcrypt_ok(["sync"]);
    unreadable.git_ok(["add", "--renormalize", "."]);
    unreadable.commit_all("declare");
    unreadable.git_ok(["pack-refs", "--all"]);

    let packed = unreadable.path().join(".git/packed-refs");
    std::fs::remove_file(&packed).expect("removing packed-refs");
    std::fs::create_dir(&packed).expect("a directory where the file was");
    let output = unreadable.xcrypt(["status"]);
    std::fs::remove_dir(&packed).expect("restoring");
    expect(
        "a repository whose reference store cannot be enumerated",
        &output,
        UNDETERMINED,
    );

    // --- And a bare repository, which is what a hosting service holds. ------
    //
    // Not one of the three verdicts: there is no working tree, so there is
    // nothing here to encrypt and no question for the gate to answer. The
    // frozen table calls that a state conflict, and the point is that it is
    // said rather than guessed at or crashed over.
    let remote = BareRemote::new();
    main.push_to(&remote, "main");
    expect(
        "a bare repository, which has no working tree at all",
        &remote.xcrypt(["status"]),
        CONFIG,
    );
}
