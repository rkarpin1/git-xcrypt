//! Argument parsing and exit codes. All logic lives in the library.
//!
//! Nothing but file content may reach `stdout` on the filter path: git treats
//! the filter's `stdout` as the file itself, so a stray `println!` corrupts it.

use std::ffi::OsString;
use std::io;
use std::process::ExitCode;

/// Reported for a command line this binary cannot act on.
const EXIT_USAGE: u8 = 64;
/// Reported when the filter path fails and git must abort the operation.
const EXIT_FILTER_FAILED: u8 = 70;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<Option<&str>> = args.iter().map(|arg| arg.to_str()).collect();

    match args.as_slice() {
        [Some("__test-filter")] => run_test_filter(),
        [Some("__test-filter"), Some("--fail")] => fail_on_purpose(),
        _ => {
            eprintln!("git-xcrypt: no usable command given");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Hidden command standing in for the real `clean`/`smudge` filter until S-01.
///
/// It exists so the integration harness has something git can actually run.
/// S-01 must replace it or hide it behind a compile-time flag — a released
/// binary must not expose a transform that looks like encryption but is not.
fn run_test_filter() -> ExitCode {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();

    match git_xcrypt::run_filter(&mut input, &mut output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("git-xcrypt: {err}");
            ExitCode::from(EXIT_FILTER_FAILED)
        }
    }
}

/// Fails without writing anything, so tests can prove git aborts the operation
/// instead of letting unfiltered content through.
fn fail_on_purpose() -> ExitCode {
    eprintln!("git-xcrypt: __test-filter was asked to fail");
    ExitCode::from(EXIT_FILTER_FAILED)
}
