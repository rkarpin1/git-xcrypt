//! Argument parsing and exit codes. All logic lives in the library.
//!
//! Nothing but file content may reach `stdout` on the filter path: git treats
//! the filter's `stdout` as the file itself, so a stray `println!` corrupts it.

use std::io;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use git_xcrypt::repo::Repo;
use git_xcrypt::{Result, commands, exit};

/// Transparent encryption of selected files in a git repository.
#[derive(Debug, Parser)]
#[command(name = "git-xcrypt", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a key and register the filter in this repository.
    Init,

    /// Hidden placeholder standing in for the real filter until S-01 phase 4.
    #[command(name = "__test-filter", hide = true)]
    TestFilter {
        /// Fail without writing anything, so tests can prove git aborts.
        #[arg(long)]
        fail: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => report(run_init()),
        Command::TestFilter { fail } => run_test_filter(fail),
    }
}

/// Turns a command's result into an exit code, reporting failures on `stderr`.
fn report(result: Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("git-xcrypt: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn run_init() -> Result<()> {
    let repo = Repo::discover_from_cwd()?;
    let report = commands::init::run(&repo)?;

    if report.key_created {
        eprintln!(
            "git-xcrypt: generated a repository key in {}",
            repo.key_path().display()
        );
    }
    if report.config_file_created {
        eprintln!(
            "git-xcrypt: created {}",
            repo.xcrypt_config_path().display()
        );
    }
    if report.config_written {
        eprintln!(
            "git-xcrypt: registered the filter in {}",
            repo.config_path().display()
        );
    }
    if report.attributes_written {
        eprintln!("git-xcrypt: updated {}", repo.attributes_path().display());
    }
    if !report.changed_anything() {
        eprintln!("git-xcrypt: already set up; nothing to do");
    }
    Ok(())
}

/// Hidden command standing in for the real `clean`/`smudge` filter until S-01
/// phase 4 replaces it with the long-running protocol.
fn run_test_filter(fail: bool) -> ExitCode {
    if fail {
        eprintln!("git-xcrypt: __test-filter was asked to fail");
        return ExitCode::from(exit::USAGE);
    }

    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();

    match git_xcrypt::run_filter(&mut input, &mut output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("git-xcrypt: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}
