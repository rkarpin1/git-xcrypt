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
