//! Carrying the repository key to another machine, end to end through the
//! binary and a real git repository.
//!
//! The guardrail these tests exist for is PRD FR-007: the command that hands a
//! key over is the shortest route to a leak, so the key must reach the file it
//! was asked for and nothing else — not `stdout`, not the working tree.

mod harness;

use std::fs;

use harness::TestRepo;
use tempfile::TempDir;

/// A directory outside every repository, to export into.
fn elsewhere() -> TempDir {
    TempDir::new().expect("could not create a temporary directory")
}

/// The base64 line of an exported key file — the secret itself.
fn key_material(path: &std::path::Path) -> String {
    let text = fs::read_to_string(path).expect("the export must be readable text");
    text.lines()
        .nth(1)
        .expect("an export has a header and a key")
        .to_string()
}

#[test]
fn export_key_writes_the_key_to_the_file_and_nothing_to_stdout() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");

    let output = repo.xcrypt_ok(["export-key", &destination.to_string_lossy()]);

    assert!(
        output.stdout.is_empty(),
        "export-key wrote to stdout, which a redirect would capture: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(destination.is_file(), "the key never reached the file");

    let secret = key_material(&destination);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !stderr.contains(&secret),
        "the key itself appeared in the command's own diagnostics"
    );
    assert!(
        stderr.contains("wrote key"),
        "the user was told nothing: {stderr}"
    );
}

#[test]
fn export_key_refuses_to_write_inside_the_working_tree() {
    let repo = TestRepo::init();
    repo.init_xcrypt();

    // Exactly the mistake FR-007 names: run it while standing in the repository
    // and give it a bare filename.
    let output = repo.xcrypt(["export-key", "repo.key"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected a state conflict, stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !repo.path().join("repo.key").exists(),
        "the refusal still left a key in the working tree"
    );
}

#[test]
fn export_key_reports_a_missing_key_rather_than_inventing_one() {
    // A plain git repository: `init` was never run, so there is nothing to
    // export. Code 3 is the frozen "no key" code.
    let repo = TestRepo::init();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");

    let output = repo.xcrypt(["export-key", &destination.to_string_lossy()]);

    assert_eq!(output.status.code(), Some(3));
    assert!(!destination.exists());
}

#[test]
fn export_key_refuses_to_replace_a_file_unless_told_to() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");
    fs::write(&destination, b"another repository's key\n").expect("writing");

    let refused = repo.xcrypt(["export-key", &destination.to_string_lossy()]);
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        fs::read(&destination).expect("reading"),
        b"another repository's key\n",
        "a mistyped path destroyed a key file"
    );

    repo.xcrypt_ok(["export-key", "--force", &destination.to_string_lossy()]);
    assert!(
        fs::read_to_string(&destination)
            .expect("reading")
            .starts_with("git-xcrypt-key-v1 ")
    );
}

#[cfg(unix)]
#[test]
fn an_exported_key_is_readable_only_by_its_owner() {
    use std::os::unix::fs::PermissionsExt as _;

    let repo = TestRepo::init();
    repo.init_xcrypt();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");

    repo.xcrypt_ok(["export-key", &destination.to_string_lossy()]);

    let mode = fs::metadata(&destination)
        .expect("the export must exist")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_key_file_from_a_future_version_is_refused_rather_than_guessed() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    let outside = elsewhere();
    let destination = outside.path().join("repo.key");
    repo.xcrypt_ok(["export-key", &destination.to_string_lossy()]);

    let text = fs::read_to_string(&destination).expect("reading");
    let from_the_future = outside.path().join("future.key");
    fs::write(
        &from_the_future,
        text.replace("git-xcrypt-key-v1", "git-xcrypt-key-v2"),
    )
    .expect("writing");

    // Nothing reads a key file yet except `export-key`'s own round trip, so the
    // refusal is asserted where it is decided; `import-key` and `unlock` pick it
    // up in the next phase.
    assert!(
        git_xcrypt::keyfile::read_portable(&from_the_future).is_err(),
        "a newer key format must fail closed"
    );
}
