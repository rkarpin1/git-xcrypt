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

use std::fs;

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

    // A file that is not a key file at all, first. Carrying the export through
    // a password manager or an email is exactly where a paste picks up stray
    // characters, and a key file is user input: the convention is a named
    // refusal, never a panic. Measured before the fix: this header's sixteen
    // bytes are six characters, a slice landed inside one, and reading it
    // aborted with `byte index 2 is not a char boundary` — exit 101, no file
    // named. The exit code is the assertion: a panic cannot say `4`.
    let mangled = courier.path().join("mangled.key");
    fs::write(&mangled, "git-xcrypt-key-v1 a€€€€€\nAAAA\n").expect("writing");
    let refused = second.xcrypt(["unlock", "--key-only", &mangled.to_string_lossy()]);
    assert_eq!(
        refused.status.code(),
        Some(4),
        "a mangled key file must be a format refusal, not a crash:\n{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !second.path().join(".git/git-xcrypt/keys/default").exists(),
        "a refused import installed something anyway"
    );

    // The wrong one next, which is what a directory of exported keys makes
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

    // `--key-only` must refuse the same evidence the same way, and this is the
    // half that used to be a separate command. It looked only for a key already
    // in place — a fresh clone has none, so the wrong key installed cleanly, and
    // from then on every honest answer pointed around the mistake: `unlock`
    // refused over the first file, and offering the *right* key hit the
    // different-key refusal, whose "replacing it would make every file
    // unreadable" warning is false when the key in place has encrypted nothing.
    // The way out was a by-hand deletion the user had no reason to understand.
    // Refusing here is what keeps that state from ever forming.
    let imported = second.xcrypt(["unlock", "--key-only", &wrong_key.to_string_lossy()]);
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
    // And the right key still goes in: the evidence agrees with it, so the
    // refusal above cannot be one shape too wide. `--key-only` really does
    // leave the tree alone, which is the whole reason the flag exists.
    let before = second.worktree_bytes("secrets/db.env");
    second.xcrypt_ok(["unlock", "--key-only", &key_file.to_string_lossy()]);
    assert_eq!(
        second.worktree_bytes("secrets/db.env"),
        before,
        "`--key-only` decrypted the working tree anyway"
    );
    assert!(
        second.path().join(".git/git-xcrypt/keys/default").is_file(),
        "`--key-only` did not put the key in place"
    );

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

/// The route a CI job takes, where the key must never reach the disk.
///
/// A file is the wrong shape for a runner: the secret arrives as an environment
/// variable, and writing it out means remembering to delete it from a machine
/// that may not outlive the job. So the two ends meet without a file —
/// `export-key --stdout` pipes the key into whatever holds secrets, and the key
/// comes back either over a pipe into `unlock --key` or, at the cost named
/// below, as `unlock --key-value <text>`.
///
/// **One text, one parser.** The stdout form emits exactly what the file form
/// writes, so the header still verifies the material behind it and a key
/// truncated by a clipboard or a variable is refused rather than installed.
/// Proved here by truncating one, not by trusting the claim.
///
/// **Both routes are exercised, and their costs differ.** `--key-value` puts the
/// material in `argv`, where it is visible in the process list while the command
/// runs and where the shell records it, so the command says so on `stderr` every
/// time — asserted here, because a warning nobody prints is not a warning. The
/// pipe into `--key` pays neither cost and nothing is echoed, so it must *not*
/// carry that sentence: a warning that is false half the time is one people
/// learn to skip.
#[test]
fn a_key_travels_from_stdout_to_the_command_line_without_touching_the_disk() {
    let first = TestRepo::init();
    first.init_xcrypt();
    first.write_xcrypt_config("secrets/\n");
    first.xcrypt_ok(["sync"]);
    first.write_file("secrets/db.env", FIRST);
    first.commit_all("a secret");

    let remote = BareRemote::new();
    first.push_to(&remote, "main");

    // `xcrypt` captures stdout, so this is a pipe — which is the only
    // destination the flag accepts. The terminal arm cannot be arranged
    // portably and is a unit test beside the code instead.
    let exported = first.xcrypt_ok(["export-key", "--stdout"]);
    let material = String::from_utf8(exported.stdout).expect("an export is text");
    assert!(
        material.starts_with("git-xcrypt-key-v1 "),
        "stdout must carry the same text the file form writes: {material:?}"
    );
    assert!(
        !String::from_utf8_lossy(&exported.stderr).contains(material.trim()),
        "the key was echoed to stderr as well, so a CI log would capture it"
    );

    // Damaged in transit, which is what a clipboard or a variable does — two
    // shapes, because they are caught by two different checks and only the
    // second one needs the header.
    let clone = remote.clone_to();
    let (header, body) = material
        .split_once('\n')
        .expect("an export is a header and a key");

    // Cut short: the material no longer decodes to a key-sized secret.
    let truncated = format!("{header}\n{}=\n", &body.trim()[..body.trim().len() - 3]);
    // Whole, valid, and someone else's: only the header can tell, because the
    // material itself is a perfectly good key — just not this repository's.
    let swapped = {
        let stranger = TestRepo::init();
        stranger.init_xcrypt();
        let other = String::from_utf8(stranger.xcrypt_ok(["export-key", "--stdout"]).stdout)
            .expect("an export is text");
        let other_body = other
            .split_once('\n')
            .expect("an export is a header and a key")
            .1;
        format!("{header}\n{other_body}")
    };

    // The expected wording is the assertion, not just the code: both shapes end
    // in `4`, and a working tree full of ciphertext would refuse the swapped key
    // through `refuse_foreign_keys` even if nothing had looked at the header. So
    // each shape has to be caught by the check it exists to exercise.
    for (shape, offered, because) in [
        ("truncated", &truncated, "base64"),
        ("swapped", &swapped, "in transit"),
    ] {
        let refused = clone.xcrypt(["unlock", "--key-value", offered]);
        let complaint = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert_eq!(
            refused.status.code(),
            Some(4),
            "a {shape} key was accepted:\n{complaint}"
        );
        assert!(
            complaint.contains(because),
            "a {shape} key was refused, but by something other than the check              that should have caught it — expected {because:?}:\n{complaint}"
        );
        assert!(
            !clone.path().join(".git/git-xcrypt/keys/default").exists(),
            "a refused {shape} key was installed anyway"
        );
    }

    // And the whole one opens the clone.
    let unlocked = clone.xcrypt_ok(["unlock", "--key-value", &material]);
    let said = String::from_utf8_lossy(&unlocked.stderr).into_owned();
    clone.assert_worktree_eq("secrets/db.env", FIRST);
    clone.assert_status_clean();
    assert!(
        said.contains("process list") && said.contains("shell"),
        "the command did not name what handing it a key on the command line \
         costs:\n{said}"
    );
    assert!(
        !said.contains(material.trim()),
        "the warning printed the key it was warning about"
    );

    // The other end of the same pipe, and the one a runner should reach for:
    // the text arrives on stdin, so it never enters `argv` at all. A fresh
    // clone, because the first one is already open and would prove nothing.
    let piped = remote.clone_to();
    let opened = piped.xcrypt_with_stdin(["unlock", "--key"], material.as_bytes());
    let over_the_pipe = String::from_utf8_lossy(&opened.stderr).into_owned();
    assert_eq!(
        opened.status.code(),
        Some(0),
        "a key sent in on stdin did not open the clone:\n{over_the_pipe}"
    );
    piped.assert_worktree_eq("secrets/db.env", FIRST);
    piped.assert_status_clean();

    // The half that matters more than the success: this route costs neither of
    // the two things the other one costs, so it must not claim to. A warning
    // that fires when it does not apply is one people stop reading, and the
    // sentence above depends on being rare.
    assert!(
        !over_the_pipe.contains("process list"),
        "the pipe route warned about the process list, which it never touches:\n\
         {over_the_pipe}"
    );
    assert!(
        !over_the_pipe.contains("scrollback"),
        "the pipe route warned about a scrollback, but nothing was echoed:\n\
         {over_the_pipe}"
    );
    assert!(
        !over_the_pipe.contains(material.trim()),
        "the key came back out on stderr"
    );
}
