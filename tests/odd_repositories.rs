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
/// Configuration or a state conflict.
///
/// Two things at once since 2026-08-05: a bare repository, which has no working
/// tree to answer about, and — new — **any setup gap**. Configuration comes
/// before data, because without a configuration that enforces anything the data
/// in the repository is worth nothing, and `5` on an unconfigured checkout sent
/// operators looking for a secret to rotate where none had been exposed.
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

    // --- A sparse index, with the declared subtree collapsed out of it. -----
    //
    // `git sparse-checkout --cone --sparse-index` replaces a whole directory
    // with **one** entry, so `secrets/db.env` stops existing in the index and in
    // the working tree alike. That reads like the perfect hiding place, and the
    // question it raises is the one this file exists for: does a gate that walks
    // the index still answer for what it can no longer see?
    //
    // Measured on git 2.55, 2026-08-05, three ways. It does, and not by luck:
    // the history scan needs no index at all, and a directory is only allowed to
    // collapse while everything under it is **identical to `HEAD`** — so the
    // collapsed content is exactly the content the scan already covers, and
    // anything staged that differs forces git to expand the directory again.
    let sparse = TestRepo::init();
    sparse.init_xcrypt();
    sparse.write_xcrypt_config("# nothing declared yet\n");
    sparse.write_file("secrets/db.env", SECRET);
    sparse.write_file("keep/readme.md", b"# in the cone\n");
    sparse.commit_all("the leak, before anything encrypted it");
    sparse.write_xcrypt_config("secrets/\n");
    sparse.xcrypt_ok(["sync"]);
    sparse.commit_all("declare it, too late");

    sparse.git_ok(["sparse-checkout", "init", "--cone", "--sparse-index"]);
    sparse.git_ok(["sparse-checkout", "set", "keep"]);
    // The premise, not a story about one: if the subtree is still spelled out
    // entry by entry, this section is proving nothing.
    let listing =
        String::from_utf8_lossy(&sparse.git_ok(["ls-files", "--sparse"]).stdout).into_owned();
    assert!(
        listing.lines().any(|line| line == "secrets/"),
        "a sparse index with the declared subtree collapsed: git did not collapse \
         it, so this configuration is no longer the one being tested:\n{listing}"
    );
    assert!(
        !sparse.path().join("secrets").exists(),
        "a sparse index with the declared subtree collapsed: the directory is \
         still in the working tree, so nothing was excluded"
    );

    let output = sparse.xcrypt(["status"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    expect(
        "a sparse index with a leak collapsed out of it",
        &output,
        EXPOSED,
    );
    assert!(
        text.contains("leaked in history") && text.contains("secrets/db.env"),
        "a sparse index with a leak collapsed out of it: the finding must name \
         the path even though the index no longer spells it:\n{text}"
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

    // --- Configuration before data: the precedence added 2026-08-05. --------
    //
    // A setup gap outranks a finding *and* a question, which reverses the old
    // rule in exactly one place. The reason is that `5` used to be handed to a
    // repository that had never run `init` — "an exposure was found, rotate the
    // secret" over a checkout with nothing in it to rotate — while the one
    // thing actually wrong, that git is not running the filter, read as a
    // detail. `2` says what to do: fix the configuration, then ask again.
    //
    // Nothing is hidden by it. Each case below checks that the sections the
    // other verdicts would have printed are still printed, because a code that
    // silences the report would be worse than the code it replaced.
    let untouched = TestRepo::init();
    untouched.write_file("README.md", b"# a project that never heard of this tool\n");
    untouched.commit_all("an ordinary repository");
    expect(
        "a repository that never ran `git-xcrypt init`",
        &untouched.xcrypt(["status"]),
        CONFIG,
    );

    // A configured repository whose declaration was deleted. Nothing is stored
    // in the clear over this — the check-in path refuses without it — but
    // nothing can be checked either, and the report has to say the scan did not
    // run rather than print a reassuring zero.
    let undeclared = TestRepo::init();
    undeclared.init_xcrypt();
    declared(&undeclared);
    std::fs::remove_file(undeclared.path().join(".git-xcrypt")).expect("removing the declaration");
    let output = undeclared.xcrypt(["status"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    expect(
        "a configured repository whose .git-xcrypt was deleted",
        &output,
        CONFIG,
    );
    assert!(
        text.contains("history was NOT scanned"),
        "a configured repository whose .git-xcrypt was deleted: the run stopped \
         before the scan, and silence about that reads as `nothing found`:\n{text}"
    );

    // A leak in history **and** a setup gap. This is the assertion the whole
    // change turns on: the verdict moves to `2`, and the leak is still named,
    // still counted, and still carries its rotate-first procedure. An operator
    // fixes the configuration, runs again, and gets `5` — the information does
    // not go anywhere, only the order of the work does.
    let both_kinds = TestRepo::init();
    both_kinds.init_xcrypt();
    both_kinds.write_xcrypt_config("# nothing declared yet\n");
    both_kinds.write_file("secrets/db.env", SECRET);
    both_kinds.commit_all("the leak");
    both_kinds.write_xcrypt_config("secrets/\n");
    both_kinds.xcrypt_ok(["sync"]);
    both_kinds.git_ok(["config", "filter.git-xcrypt.required", "false"]);

    let output = both_kinds.xcrypt(["status"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    expect(
        "a repository that both leaked a secret and is misconfigured",
        &output,
        CONFIG,
    );
    assert!(
        text.contains("leaked in history"),
        "a repository that both leaked a secret and is misconfigured: the leak \
         must survive the configuration verdict, or `2` buys its clarity by \
         hiding the finding:\n{text}"
    );
    assert!(
        text.contains("secrets/db.env"),
        "a repository that both leaked a secret and is misconfigured: the leaked \
         path must still be named:\n{text}"
    );
    assert!(
        text.contains("ROTATE THE SECRET"),
        "a repository that both leaked a secret and is misconfigured: the \
         rotate-first procedure must still be printed:\n{text}"
    );
    // And the second half of the promise: once the configuration is settled,
    // the very same repository answers `5`. Nothing was lost, it was ordered.
    both_kinds.git_ok(["config", "filter.git-xcrypt.required", "true"]);
    expect(
        "the same repository once its configuration is fixed",
        &both_kinds.xcrypt(["status"]),
        EXPOSED,
    );

    // A setup gap over a checkout that also could not be scanned: a shallow
    // clone nobody unlocked, which is what a CI job does before it runs
    // anything. `2` again — the missing registration is the thing to fix, and
    // the shallow history is still reported underneath it.
    let never_unlocked = source.clone_shallow();
    let output = never_unlocked.xcrypt(["status"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    expect(
        "a shallow clone nobody unlocked, so both answers apply at once",
        &output,
        CONFIG,
    );
    assert!(
        text.contains("shallow clone"),
        "a shallow clone nobody unlocked: what could not be checked must still \
         be reported under the configuration verdict:\n{text}"
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
    // A setup gap, so `2` since 2026-08-05: the remedy is the attribute line in
    // the shared `info/attributes`, not a rotated secret — nothing has been
    // committed in the clear here yet, and the point of the gate is to say so
    // before something is.
    expect(
        "a linked worktree whose shared info/attributes turns the filter off",
        &linked.xcrypt(["status"]),
        CONFIG,
    );
    std::fs::remove_file(main.path().join(".git/info/attributes")).expect("removing it again");

    // --- One reference that will not parse, among others that do. -----------
    //
    // The store enumerates fine here; a single reference inside it does not.
    // Every such failure used to be filed as "a file under refs/ is not a
    // reference" — true of crash residue, which names no history, and false of
    // the three other things that error there: a ref file that could not be
    // read, a failed traversal, a `packed-refs` line that will not parse. Those
    // are references that exist and were not walked. Measured with `chmod 000
    // .git/refs/heads/leak` over a branch holding a plain-text `secrets/db.env`:
    // `VERDICT: no findings.` and exit 0, under a note calling it "not a
    // reference" while gix had said it "could not be read in full".
    //
    // Provoked through the `packed-refs` line rather than a permission bit, so
    // the arm runs on all three platforms — the two reach the same match arm.
    // The leak is put on a branch of its own and `HEAD` left on `main`, because
    // `HEAD` failing is separately reported and would mask the arm under test.
    let one_bad_ref = TestRepo::init();
    one_bad_ref.init_xcrypt();
    one_bad_ref.write_xcrypt_config("# nothing declared yet\n");
    one_bad_ref.write_file("keep.txt", b"ordinary\n");
    one_bad_ref.commit_all("main has nothing to hide");
    one_bad_ref.git_ok(["checkout", "-q", "-b", "leak"]);
    one_bad_ref.write_file("secrets/db.env", SECRET);
    one_bad_ref.commit_all("the leak, reachable only from this branch");
    one_bad_ref.git_ok(["checkout", "-q", "main"]);
    one_bad_ref.write_xcrypt_config("secrets/\n");
    one_bad_ref.xcrypt_ok(["sync"]);
    one_bad_ref.commit_all("declare");
    one_bad_ref.git_ok(["pack-refs", "--all"]);

    let packed_refs = one_bad_ref.path().join(".git/packed-refs");
    let intact = std::fs::read_to_string(&packed_refs).expect("packed-refs must be readable");
    // Only the line naming the branch that carries the leak: everything else,
    // `HEAD` included, still resolves, so the run turns on this one reference.
    let corrupted: String = intact
        .lines()
        .map(|line| {
            if line.ends_with("refs/heads/leak") {
                "this line names a reference and cannot be read\n".to_string()
            } else {
                format!("{line}\n")
            }
        })
        .collect();
    assert_ne!(intact, corrupted, "the leak branch was not in packed-refs");
    std::fs::write(&packed_refs, corrupted).expect("writing packed-refs");
    expect(
        "a repository with one unreadable reference hiding a leak",
        &one_bad_ref.xcrypt(["status"]),
        UNDETERMINED,
    );

    // And the shape the note is genuinely right about, so the fix above did not
    // buy its honesty by turning crash residue into a permanently red gate:
    // a stray file under `refs/` names no history and git shrugs at it too.
    std::fs::write(&packed_refs, &intact).expect("restoring packed-refs");
    std::fs::write(
        one_bad_ref.path().join(".git/refs/heads/notes.txt"),
        b"this is not a reference\n",
    )
    .expect("writing the stray file");
    expect(
        "a repository with crash residue under refs/",
        &one_bad_ref.xcrypt(["status"]),
        EXPOSED,
    );

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
