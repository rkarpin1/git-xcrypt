//! The performance requirement, as something that can fail.
//!
//! PRD §Non-Functional Requirements used to say "not noticeably slower", which
//! nobody can check. It now carries two budgets and this file is where they are
//! spent. Everything here is `#[ignore]`d on purpose — see the two reasons under
//! "Why this does not run in CI" below.
//!
//! **The baseline content is incompressible, and that is the whole design.**
//! Measured on 2026-08-06, 2000 files of 46 KB: with ordinary repetitive text
//! the encrypted arm looked 1196 ms slower than the unfiltered one, and 1092 ms
//! of that — **91%** — was git's own zlib, which compresses repetitive text to
//! almost nothing and cannot compress ciphertext at all. That cost is real for a
//! user, but it is not ours: it is what any encryption does to a compressor, and
//! it moves with how compressible the user's files happen to be. Measuring
//! against a random-content baseline puts zlib on both sides of the subtraction
//! and leaves our own cost, which came out 11× smaller. A budget written from
//! the compressible measurement would have been a budget on git.
//!
//! **Why this does not run in CI.** First, the numbers only mean anything in a
//! `--release` build, and `cargo test` is a debug build unless asked otherwise.
//! Second, measured spread on a quiet development machine reached 11% of the
//! baseline — a shared CI runner is worse, and a flaky gate is one people learn
//! to ignore, which is the failure mode this project keeps writing down. So the
//! budgets are enforced by a person, deliberately, when touching the hot path:
//!
//! ```text
//! cargo test --release --test performance -- --ignored --nocapture
//! ```
//!
//! Run it before and after a change to `commands/filter.rs`, `rules/decide.rs`,
//! `crypto/` or `git/attributes.rs`. It prints what it measured, so a run that
//! passes still tells you which way the number moved.
//!
//! **A third trap, recorded 2026-08-07 with the fourth budget:** the attribute
//! stack test builds a tree of tens of thousands of files, and creating that
//! tree costs seconds — orders of magnitude more than the thing being
//! measured. The tree is built once, outside the timed window, and only the
//! resolver's work is inside it. A version that timed from `TestRepo::init`
//! would measure the filesystem, not the stack.

mod harness;

use std::time::Instant;

use harness::TestRepo;

/// The two budgets are measured by two **separate** shapes of repository, each
/// chosen so one cost dominates and the other is noise. An earlier version
/// derived both from one pair of sizes by solving for the slope, and that is
/// recorded here as a mistake rather than deleted: the per-byte figure came out
/// as a difference of differences of four noisy timings, and it bounced between
/// 0.24 and 0.67 ns/B across three runs of the *unchanged* code. A gate whose
/// reading moves 3× on its own cannot report anything smaller than that.
///
/// Many small files: per-file cost dominates, bytes are almost free.
const SMALL_FILES: usize = 2000;
const SMALL_SIZE: usize = 4096;

/// One large blob through `diff`, where the cipher is the whole measurement.
/// The same size the aarch64 backend decision was measured at, so the two
/// numbers can be compared directly.
const CIPHER_BYTES: usize = 8 * 1024 * 1024;

/// Best of this many runs. The **minimum**, not the median: every source of
/// noise here — scheduler, page cache, another process — can only make a run
/// slower, so the fastest run is the one least contaminated by things that are
/// not the code under test.
const RUNS: usize = 5;

/// Deterministic pseudo-random bytes: incompressible, so git's zlib does the
/// same work in the filtered and unfiltered arms, and reproducible, so two
/// invocations measure the same content.
///
/// A plain LCG rather than a crate. It only has to defeat zlib, which the
/// measured object sizes confirm it does, and nothing here depends on its
/// statistical quality.
fn incompressible(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..size)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

/// One timed `git add -A`, in milliseconds.
///
/// `declaration` is what goes into `.git-xcrypt`: `Some("src/")` encrypts every
/// file written below, `Some("nothing/")` registers the filter and encrypts
/// none of them, `None` leaves the repository without git-xcrypt at all.
/// The content is identical on every run, deliberately: a benchmark that
/// regenerates its input each time measures the generator too.
fn timed_add(declaration: Option<&str>, files: usize, size: usize) -> u128 {
    let repo = TestRepo::init();
    repo.git_ok(["config", "core.autocrlf", "false"]);

    if let Some(patterns) = declaration {
        repo.init_xcrypt();
        repo.write_xcrypt_config(&format!("{patterns}\n"));
        repo.xcrypt_ok(["sync"]);
    }

    for index in 0..files {
        repo.write_file(
            &format!("src/f{index:04}.bin"),
            &incompressible(size, index as u64),
        );
    }

    // Only the `git add` is timed. Writing the files is the expensive part of
    // this function and has nothing to do with the filter.
    let started = Instant::now();
    repo.git_ok(["add", "-A"]);
    started.elapsed().as_millis()
}

fn best(declaration: Option<&str>, files: usize, size: usize) -> u128 {
    (0..RUNS)
        .map(|_| timed_add(declaration, files, size))
        .min()
        .expect("RUNS is not zero")
}

/// A file the filter only hands back costs almost nothing.
///
/// This is the budget that guards the whole repository rather than the secrets
/// in it. The catch-all attribute sends **every** file through the filter, so a
/// regression here is charged to every project that uses the tool, on every
/// `git add`, whether or not it encrypts anything.
///
/// Budget: **25 µs per file**. Measured 2026-08-06 at 15 µs, so the headroom is
/// about 1.7×. It is deliberately not looser: the shape of regression this must
/// catch is one more per-file lookup — an index read, an attribute resolution, a
/// second pass over the content — and each of those costs tens of microseconds.
#[test]
#[ignore = "timing; run deliberately with --release, see the module comment"]
fn a_file_that_is_only_passed_through_stays_almost_free() {
    let bare = best(None, SMALL_FILES, SMALL_SIZE);
    let filtered = best(Some("nothing/"), SMALL_FILES, SMALL_SIZE);

    let overhead = filtered.saturating_sub(bare);
    let per_file = overhead as f64 * 1000.0 / SMALL_FILES as f64;
    println!(
        "pass-through: {bare} ms bare, {filtered} ms filtered, \
         {overhead} ms over {SMALL_FILES} files = {per_file:.1} µs/file (budget 25)"
    );

    assert!(
        per_file <= 25.0,
        "passing a file through costs {per_file:.1} µs, over the 25 µs budget \
         in PRD §Non-Functional Requirements. This is charged to every file in \
         every repository, not only to encrypted ones."
    );
}

/// What encrypting costs per **file**, measured where files dominate.
///
/// Budget: **30 µs per file**, against 13 µs measured 2026-08-06 — headroom
/// about 2.3×. Small files are what this tool is for, so this is the number a
/// user with a directory of `.env` files actually pays.
#[test]
#[ignore = "timing; run deliberately with --release, see the module comment"]
fn encrypting_a_small_file_stays_within_its_per_file_budget() {
    let bare = best(None, SMALL_FILES, SMALL_SIZE);
    let encrypted = best(Some("src/"), SMALL_FILES, SMALL_SIZE);

    // The bytes are not subtracted out: at 4 KB and the budgeted rate they are
    // under 4 µs of the total, so leaving them in makes the gate slightly
    // stricter than the budget rather than looser. The direction matters more
    // than the precision.
    let overhead = encrypted.saturating_sub(bare);
    let per_file = overhead as f64 * 1000.0 / SMALL_FILES as f64;
    println!(
        "encrypt per file: {bare} ms bare, {encrypted} ms encrypted, \
         {overhead} ms over {SMALL_FILES} files = {per_file:.1} µs/file (budget 30)"
    );

    assert!(
        per_file <= 30.0,
        "encrypting costs {per_file:.1} µs per file, over the 30 µs budget in \
         PRD §Non-Functional Requirements"
    );
}

/// What the crypto costs per **byte**, measured through `diff` rather than
/// through `git add`.
///
/// **`git add` cannot see this number, and that is measured, not assumed.** At
/// 32 files of 4 MB the unfiltered baseline was 2386 ms and the encrypted arm
/// 2358 ms — *faster*, i.e. the difference vanished into noise. It has to:
/// git's own work on incompressible content ran at about 18 ns/B (read, zlib,
/// write), so our 0.85 ns/B is under 5% of the number being subtracted. No
/// amount of repetition recovers a signal that small. The first version of this
/// test asserted on that difference and passed **vacuously**, reporting
/// `0.00 ns/B`; it is described here so nobody rebuilds it.
///
/// `diff` has no git in the loop — it decrypts a blob and writes it out — so the
/// crypto is the measurement rather than 5% of it. This is the same instrument
/// the aarch64 backend decision used (8 MB in 148 ms software, 9 ms hardware).
///
/// Budget: **2 ns per byte**, about 500 MB/s, against roughly 1.1 ns/B measured
/// on `aarch64-apple-darwin`. Being an absolute rate it is hardware-dependent,
/// which is acceptable for a test a person runs deliberately and not acceptable
/// for CI — one more reason this file is `#[ignore]`d. **It is calibrated for
/// that machine and does not hold everywhere:** on a Windows x86-64 development
/// box the same 8 MB takes ~33 ms, and process spawn plus 8 MB down a pipe is a
/// large share of it, so the number read there is the harness as much as the
/// cipher. Compare a run against the previous run on the *same* machine; the
/// absolute threshold means something on the platform it was measured on.
///
/// The regression it exists for is named and real: `aes` selects its backend
/// per target, so a bump, a target change or a forced `aes_backend="soft"` can
/// silently drop AES to the bitsliced software path. Verified to bite —
/// `RUSTFLAGS='--cfg aes_backend="soft"' cargo test --release …` fails this
/// assertion. Run it after any bump of `aes-siv` or `aes`.
#[test]
#[ignore = "timing; run deliberately with --release, see the module comment"]
fn the_cipher_stays_within_its_per_byte_budget() {
    let repo = TestRepo::init();
    repo.init_xcrypt();
    repo.write_xcrypt_config("src/\n");
    repo.xcrypt_ok(["sync"]);
    repo.write_file("src/big.bin", &incompressible(CIPHER_BYTES, 1));
    repo.commit_all("one large secret");

    // The ciphertext as git stores it, put somewhere `diff` will read it from.
    // The working tree holds plaintext, which `diff` would pass straight
    // through — measuring the pipe instead of the cipher.
    let ciphertext = repo.blob_bytes("src/big.bin");
    assert_eq!(
        ciphertext.len(),
        CIPHER_BYTES + 38,
        "the blob is not ciphertext, so this would time nothing"
    );
    repo.write_file("carrier.bin", &ciphertext);

    let elapsed = (0..RUNS)
        .map(|_| {
            let started = Instant::now();
            let out = repo.xcrypt_ok(["diff", "carrier.bin"]);
            let taken = started.elapsed();
            assert_eq!(out.stdout.len(), CIPHER_BYTES, "diff did not decrypt it");
            taken
        })
        .min()
        .expect("RUNS is not zero");

    let per_byte = elapsed.as_secs_f64() * 1e9 / CIPHER_BYTES as f64;
    println!(
        "cipher: {:.1} ms for {:.0} MB = {per_byte:.2} ns/B (budget 2.00, {:.0} MB/s)",
        elapsed.as_secs_f64() * 1000.0,
        CIPHER_BYTES as f64 / 1048576.0,
        1000.0 / per_byte
    );

    assert!(
        per_byte <= 2.0,
        "the cipher runs at {per_byte:.2} ns/byte ({:.0} MB/s), over the 2 ns \
         budget in PRD §Non-Functional Requirements. Check that `aes` picked a \
         hardware backend on this target — `aes::hardware_accelerated()` \
         answers it — and that the budget was calibrated for this machine.",
        1000.0 / per_byte
    );
}

/// What building the attribute stack costs, measured where the tree's bulk
/// would dominate if anyone walked it.
///
/// The regression this exists for is the one measured on 2026-08-06 and
/// removed on 2026-08-07: `AttributeResolver` used to walk the **whole**
/// working tree looking for `.gitattributes` — one `read_dir` per directory,
/// one `file_type()` per entry — which put a build directory's worth of
/// entries on the hot path of every `git add`. 220 ms instead of 10 ms on a
/// tree with 5281 directories and 480 000 ignored files, the only measured
/// cost in the product that scaled with *untracked* files. Discovery is lazy
/// now: the resolver probes only the ancestor chain of each resolved path, so
/// its cost is the number of ancestors, not the number of entries.
///
/// No git in the loop, like the cipher test: the resolver is built and asked
/// directly, so the walk — if someone brings it back — is the measurement,
/// not a fraction of it. Verified to bite: restoring the walk in
/// `AttributeResolver::new` fails this assertion on this same tree.
///
/// Budget: **10 ms** for construction plus the first resolve, against 0.02 ms
/// measured 2026-08-07 on this tree (3000 directories × 10 files). Headroom
/// is deliberately wider than the 2–4× the other budgets carry: this number
/// is almost pure filesystem I/O, where a cold cache spikes harder than a
/// scheduler does, and the failure it guards sat at 43.6 ms on this same
/// tree when the walk was put back — 4× above the budget, growing linearly
/// with entries while the lazy cost does not grow at all.
#[test]
#[ignore = "timing; run deliberately with --release, see the module comment"]
fn the_attribute_stack_pays_for_ancestors_not_for_the_tree() {
    use git_xcrypt::git::attributes::AttributeResolver;

    let repo = TestRepo::init();
    repo.write_file(".gitattributes", b"* filter=git-xcrypt\n");
    repo.write_file("secrets/db.env", b"api_key = value\n");

    // The bulk: entries the resolver has no business visiting. Built once,
    // outside the timed window — see the module comment's third trap.
    for directory in 0..3000 {
        let path = repo.path().join(format!("bulk/d{directory:04}"));
        std::fs::create_dir_all(&path).expect("bulk directories");
        for file in 0..10 {
            std::fs::write(path.join(format!("f{file}.o")), b"x").expect("bulk files");
        }
    }

    let elapsed = (0..RUNS)
        .map(|_| {
            // A fresh resolver each run: probes are cached per instance, and a
            // warm one would measure the cache instead of the discovery.
            let started = Instant::now();
            let mut resolver = AttributeResolver::new(
                repo.path(),
                &repo.path().join(".git"),
                None,
                false,
                Vec::new(),
            );
            let resolution = resolver.resolve(b"secrets/db.env");
            let taken = started.elapsed();
            assert!(
                resolution.filter.is_ours(),
                "the stack no longer resolves the catch-all, so this would time \
                 a resolver that reads nothing"
            );
            taken
        })
        .min()
        .expect("RUNS is not zero");

    let ms = elapsed.as_secs_f64() * 1000.0;
    println!("attribute stack: {ms:.2} ms to build and answer once (budget 10.00)");

    assert!(
        ms <= 10.0,
        "building the attribute stack took {ms:.2} ms on a tree whose bulk is \
         not on the resolved path's ancestor chain — over the 10 ms budget in \
         PRD §Non-Functional Requirements. The walk of the whole working tree \
         is probably back in `AttributeResolver`."
    );
}
