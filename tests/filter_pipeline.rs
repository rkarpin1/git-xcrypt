//! The vertical slice: one `init`, one pattern, and git stores ciphertext.

mod harness;

use harness::TestRepo;

const SECRET: &[u8] = b"api_key = do-not-commit-me\n";

/// The whole user-facing setup, as the product promises it.
fn configured_repo() -> TestRepo {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("*.env\nsecrets/\n");
    repo
}

#[test]
fn a_committed_secret_is_stored_encrypted() {
    let repo = configured_repo();
    repo.write_file("secrets.env", SECRET);

    repo.commit_all("add a secret");

    repo.assert_worktree_eq("secrets.env", SECRET);
    let blob = repo.blob_bytes("secrets.env");
    assert!(
        blob.starts_with(b"\0GITXCRYPT\0"),
        "the stored blob does not carry our magic, so the filter never ran"
    );
    assert!(
        !blob.windows(SECRET.len()).any(|window| window == SECRET),
        "the plaintext is present in the object database"
    );
}

#[test]
fn unmatched_files_are_stored_verbatim() {
    let repo = configured_repo();
    repo.write_file("readme.md", b"public\n");
    repo.write_file("assets/logo.bin", &(0u8..=255).collect::<Vec<u8>>());

    repo.commit_all("add public files");

    repo.assert_blob_eq("readme.md", b"public\n");
    repo.assert_blob_eq("assets/logo.bin", &(0u8..=255).collect::<Vec<u8>>());
}

#[test]
fn the_bootstrap_files_are_never_encrypted() {
    let repo = configured_repo();
    repo.write_file("secrets.env", SECRET);

    repo.commit_all("add a secret");

    // If either of these were encrypted, nothing could bootstrap: git needs
    // .gitattributes to call us at all, and we need .git-xcrypt to know what to do.
    assert!(repo.blob_bytes(".gitattributes").starts_with(b"#"));
    assert!(repo.blob_bytes(".git-xcrypt").starts_with(b"*.env"));
}

#[test]
fn a_negated_path_stays_in_the_clear() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("secrets/\n!secrets/README.md\n");
    repo.write_file("secrets/password", SECRET);
    repo.write_file("secrets/README.md", b"how to use this directory\n");

    repo.commit_all("add secrets with an exception");

    assert!(
        repo.blob_bytes("secrets/password")
            .starts_with(b"\0GITXCRYPT\0")
    );
    repo.assert_blob_eq("secrets/README.md", b"how to use this directory\n");
}

#[test]
fn the_filter_is_registered_for_the_long_running_protocol_only() {
    // The portable half of the measurement below. `filter.<driver>.process` is
    // what makes git start one process for a whole operation; `clean` and
    // `smudge` are the per-file keys, and git ignores them when `process` is
    // set. A regression that registered the per-file pair *instead* would still
    // encrypt everything correctly — which is exactly why every other test in
    // this file would stay green through it.
    let repo = configured_repo();

    let process = repo.git_ok(["config", "--get", "filter.git-xcrypt.process"]);
    assert!(
        !process.stdout.is_empty(),
        "filter.git-xcrypt.process is unset, so git runs one process per file — \
         measured at 22x slower, which the catch-all construction cannot afford"
    );
    for per_file in ["filter.git-xcrypt.clean", "filter.git-xcrypt.smudge"] {
        let output = repo.git(["config", "--get", per_file]);
        assert!(
            !output.status.success(),
            "{per_file} is set; the product registers the long-running protocol \
             and nothing else"
        );
    }
}

#[cfg(unix)]
#[test]
fn one_filter_process_serves_a_whole_operation() {
    // The test that used to carry this name asserted only that 25 files came
    // out encrypted, which a process-per-file regression passes without a
    // murmur. Nothing in the suite counted processes, so the one measurement
    // that made the long-running protocol a *requirement* rather than an
    // optimisation was unguarded.
    //
    // Counting means seeing git's own spawns, so the registration is pointed at
    // a wrapper that records one line per start and then becomes the real
    // binary. The wrapper and its tally live outside the working tree, or
    // `git add -A` would sweep them into the commit being measured.
    //
    // Unix-only because the wrapper is a shell script. The assertion above
    // covers the same regression on every platform, one step further from the
    // evidence.
    use std::os::unix::fs::PermissionsExt as _;

    let repo = configured_repo();

    let scratch = tempfile::TempDir::new().expect("could not create a temporary directory");
    let tally = scratch.path().join("starts");
    let wrapper = scratch.path().join("counting-filter");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\necho started >> {tally}\nexec {binary} process\n",
            tally = tally.display(),
            binary = env!("CARGO_BIN_EXE_git-xcrypt"),
        ),
    )
    .expect("could not write the wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
        .expect("could not make the wrapper executable");

    repo.git_ok([
        "config",
        "filter.git-xcrypt.process",
        &wrapper.to_string_lossy(),
    ]);

    const FILES: usize = 25;
    for index in 0..FILES {
        repo.write_file(&format!("secrets/file{index}.txt"), SECRET);
    }
    repo.commit_all("add many secrets");

    for index in 0..FILES {
        assert!(
            repo.blob_bytes(&format!("secrets/file{index}.txt"))
                .starts_with(b"\0GITXCRYPT\0"),
            "file{index} was not encrypted, so the wrapper is not serving the filter"
        );
    }

    let starts = std::fs::read_to_string(&tally)
        .expect("the filter never started at all")
        .lines()
        .count();
    assert!(
        starts >= 1,
        "the wrapper recorded no start, so this test is measuring nothing"
    );
    assert!(
        starts < FILES,
        "git started the filter {starts} times for {FILES} files: it is running \
         one process per file, which was measured 22x slower and is the reason \
         the long-running protocol is a hard requirement"
    );
}
