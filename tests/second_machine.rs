//! The second machine: clone, carry the key, unlock, and work from both sides.
//!
//! US-01 is the only user story the PRD writes out in full, and it is not about
//! a command — it is about a repository that exists in two places at once. The
//! per-command files each prove one half of it; this drives the whole loop,
//! including the half nothing else does: an edit made on the *second* machine
//! coming back to the first and still matching, byte for byte, with `git status`
//! quiet on both sides.
//!
//! Everything goes through a bare remote rather than a direct clone, because
//! `receive-pack` re-reads and re-packs every object it accepts and a claim
//! about "what the hosting service holds" is not a claim about a local clone.

mod harness;

use harness::{BareRemote, MAGIC, OVERHEAD, TestRepo};
use tempfile::TempDir;

/// The exit code the frozen table gives to a configuration or state conflict.
///
/// A clone nobody has unlocked is exactly that, and since 2026-08-05 it is `2`
/// rather than `5`. Nothing here has leaked yet — the blobs are ciphertext and
/// the working tree holds no plain text at all — so the operator's next move is
/// `unlock`, not rotating a credential.
const CONFIG: i32 = 2;

const FIRST: &[u8] = b"DATABASE_URL=postgres://user:hunter2@localhost/app\n";
const FROM_THE_OTHER_MACHINE: &[u8] = b"DATABASE_URL=postgres://user:swordfish@db/app\n";

#[test]
fn a_clone_becomes_a_working_second_machine_and_its_edits_come_home() {
    // --- The first machine sets the repository up and pushes. ---------------
    let first = TestRepo::init();
    first.init_xcrypt();
    first.write_xcrypt_config("secrets/\n*.env\n");
    first.xcrypt_ok(["sync"]);
    first.write_file("secrets/db.env", FIRST);
    first.write_file("README.md", b"# ordinary project\n");
    first.commit_all("declare a secret");

    let remote = BareRemote::new();
    first.push_to(&remote, "main");
    first.assert_status_clean();

    // --- The second machine clones, and has nothing but ciphertext. ---------
    let second = remote.clone_to();

    let seen = second.worktree_bytes("secrets/db.env");
    assert!(
        seen.starts_with(MAGIC),
        "a clone with no key showed the secret in the clear"
    );
    assert!(
        !seen.windows(FIRST.len()).any(|window| window == FIRST),
        "the plaintext is readable in a clone that holds no key"
    );

    // And it says so rather than looking healthy. `.git/config` is not cloned,
    // so the catch-all line in `.gitattributes` has no driver behind it: git
    // filters nothing here and the next `git add` on a secret would exit 0 with
    // the plaintext stored.
    let unfiltered = second.xcrypt(["status"]);
    let text = String::from_utf8_lossy(&unfiltered.stdout).into_owned();
    assert_eq!(
        unfiltered.status.code(),
        Some(CONFIG),
        "a clone that cannot filter must not pass the gate:\n{text}"
    );
    assert!(
        text.contains("filter.git-xcrypt.process"),
        "the report must name the registration that is missing:\n{text}"
    );
    // The code says "fix the configuration"; the report still has to say what
    // happens if nobody does. This is the one setup gap a user meets by simply
    // cloning, and committing a secret from here stores the plain text with
    // exit code 0 — a message that only talked about configuration would let a
    // reader think this checkout is merely incomplete rather than unsafe.
    assert!(
        text.contains("stores it in the clear"),
        "the report must say what committing from an unconfigured clone does:\n{text}"
    );

    // --- The key is carried across, by hand, as the PRD says it is. ---------
    let courier = TempDir::new().expect("could not create a temporary directory");
    let key_file = courier.path().join("repo.key");
    first.xcrypt_ok(["export-key", &key_file.to_string_lossy()]);

    // The wrong one first, which is what a directory of exported keys makes
    // easy. Every file here is encrypted under a `key_id` this key does not
    // answer for, and the command has to find that out *before* it writes
    // anything: an unlock that installed the key and then gave up would leave a
    // repository whose `.git/config` says one thing and whose blobs say another,
    // and the next commit would be made under a key that decrypts nothing.
    let stranger = TestRepo::init();
    stranger.init_xcrypt();
    let wrong_key = courier.path().join("some-other-project.key");
    stranger.xcrypt_ok(["export-key", &wrong_key.to_string_lossy()]);

    let before = second.worktree_bytes("secrets/db.env");
    let refused = second.xcrypt(["unlock", &wrong_key.to_string_lossy()]);
    let complaint = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert_eq!(
        refused.status.code(),
        Some(4),
        "unlocking with a key from another repository was not refused:\n{complaint}"
    );
    assert!(
        complaint.contains("secrets/db.env"),
        "the refusal must name the file it stopped on:\n{complaint}"
    );
    assert_eq!(
        second.worktree_bytes("secrets/db.env"),
        before,
        "a refused unlock still rewrote a file"
    );
    assert!(
        !second.path().join(".git/git-xcrypt/keys/default").exists(),
        "a refused unlock installed the wrong key anyway"
    );
    second.assert_status_clean();

    // `import-key` must refuse the same evidence the same way. It used to look
    // only for a key already in place — a fresh clone has none, so the wrong
    // key installed cleanly, and from then on every honest answer pointed
    // around the mistake: `unlock` refused over the first file, and importing
    // the *right* key hit the different-key refusal, whose "replacing it would
    // make every file unreadable" warning is false when the key in place has
    // encrypted nothing. The way out was a by-hand deletion the user had no
    // reason to understand. Refusing here is what keeps that state from ever
    // forming.
    let imported = second.xcrypt(["import-key", &wrong_key.to_string_lossy()]);
    let complaint = String::from_utf8_lossy(&imported.stderr).into_owned();
    assert_eq!(
        imported.status.code(),
        Some(4),
        "importing a key every header in the tree contradicts was not refused:\n{complaint}"
    );
    assert!(
        complaint.contains("secrets/db.env"),
        "the refusal must name the file that is the evidence:\n{complaint}"
    );
    assert!(
        !second.path().join(".git/git-xcrypt/keys/default").exists(),
        "a refused import installed the wrong key anyway"
    );
    // And the right key still imports: the evidence agrees with it, so the
    // refusal above cannot be one shape too wide.
    second.xcrypt_ok(["import-key", &key_file.to_string_lossy()]);

    second.xcrypt_ok(["unlock", &key_file.to_string_lossy()]);

    second.assert_worktree_eq("secrets/db.env", FIRST);
    second.assert_worktree_eq("README.md", b"# ordinary project\n");
    second.assert_status_clean();

    let healthy = second.xcrypt(["status"]);
    assert_eq!(
        healthy.status.code(),
        Some(0),
        "an unlocked clone must pass the gate:\n{}\n{}",
        String::from_utf8_lossy(&healthy.stdout),
        String::from_utf8_lossy(&healthy.stderr)
    );

    // --- The second machine does the work now. ------------------------------
    second.write_file("secrets/db.env", FROM_THE_OTHER_MACHINE);
    second.commit_all("rotate the database password");
    second.push_to(&remote, "main");
    second.assert_status_clean();

    let stored = remote.blob_bytes("main", "secrets/db.env");
    assert!(
        stored.starts_with(MAGIC),
        "the second machine pushed the secret in the clear"
    );
    assert_eq!(stored.len(), OVERHEAD + FROM_THE_OTHER_MACHINE.len());
    assert!(
        !remote.object_exists_for(FROM_THE_OTHER_MACHINE),
        "the second machine's plaintext is an object in the remote"
    );

    // --- And the first machine gets it back, unchanged. ---------------------
    first.pull_from(&remote, "main");

    first.assert_worktree_eq("secrets/db.env", FROM_THE_OTHER_MACHINE);
    first.assert_status_clean();

    // The cross-machine determinism claim, made explicit: the first machine
    // re-cleans the content the second machine encrypted, and git sees no
    // change. Two machines that derived different keys, normalised differently
    // or wrote a different header would part company right here — and every
    // other assertion in this file would still pass.
    first.git_ok(["add", "--renormalize", "."]);
    first.assert_status_clean();
    assert_eq!(
        first.blob_bytes("secrets/db.env"),
        stored,
        "the two machines store different bytes for the same secret"
    );

    // Closing the loop the other way: the second machine can still read what
    // the first one wrote before the key ever travelled.
    second.git_ok(["checkout", "-q", "HEAD~1", "--", "secrets/db.env"]);
    second.assert_worktree_eq("secrets/db.env", FIRST);
}

/// A second machine set up from a repository whose `.gitattributes` never
/// reached a commit — and which therefore has to be repaired on arrival.
///
/// `init` writes that file but does not commit it, so a project set up with a
/// selective `git add`, or with `.gitattributes` in somebody's global ignore
/// file, reaches its clones without the `* filter=git-xcrypt` line. Registering
/// the driver in the clone is not enough on its own: git treats a missing
/// attribute exactly like a missing driver, so the next commit stored the very
/// plaintext `unlock` had just written into the working tree — exit code 0, no
/// warning anywhere. Measured on git 2.55.
///
/// Driven to the remote rather than stopping at the local blob, because the
/// claim is about what the hosting service ends up holding.
#[test]
fn a_clone_of_a_repository_that_never_committed_its_attributes_still_encrypts() {
    let first = TestRepo::init();
    first.init_xcrypt();
    first.write_xcrypt_config("secrets/\n");
    // Keeps `.gitattributes` out of the commits without deleting it, the way a
    // user's own ignore rules or a selective `git add` would.
    std::fs::write(
        first.path().join(".git").join("info").join("exclude"),
        b".gitattributes\n",
    )
    .expect("writing the exclude file");
    first.write_file("secrets/db.env", FIRST);
    first.commit_all("a secret, with no attributes file behind it");
    assert!(first.blob_is_encrypted("secrets/db.env"));

    let remote = BareRemote::new();
    first.push_to(&remote, "main");

    let courier = TempDir::new().expect("could not create a temporary directory");
    let key_file = courier.path().join("repo.key");
    first.xcrypt_ok(["export-key", &key_file.to_string_lossy()]);

    let second = remote.clone_to();
    assert!(
        !second.path().join(".gitattributes").exists(),
        "the fixture is wrong: the clone inherited the attributes file"
    );

    second.xcrypt_ok(["unlock", &key_file.to_string_lossy()]);
    second.assert_worktree_eq("secrets/db.env", FIRST);

    // The work the second machine then does has to leave the remote no worse
    // off than the first machine did.
    second.write_file("secrets/db.env", FROM_THE_OTHER_MACHINE);
    second.commit_all("rotate the database password");
    second.push_to(&remote, "main");

    assert!(
        remote
            .blob_bytes("main", "secrets/db.env")
            .starts_with(MAGIC),
        "the clone pushed the secret to the remote in the clear"
    );
    assert!(
        !remote.object_exists_for(FROM_THE_OTHER_MACHINE),
        "the plaintext the clone committed is an object in the remote"
    );
}
