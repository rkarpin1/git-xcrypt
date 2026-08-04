//! Argument parsing and exit codes. All logic lives in the library.
//!
//! Nothing but file content may reach `stdout` on the filter path: git treats
//! the filter's `stdout` as the file itself, so a stray `println!` corrupts it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use git_xcrypt::commands::sync::Outcome;
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

    /// Regenerate the cosmetic `.gitattributes` lines from `.git-xcrypt`.
    Sync {
        /// Report whether the section is out of date instead of writing it.
        ///
        /// Exits 0 when it is current and 1 when it is not, for use as a CI gate.
        #[arg(long)]
        check: bool,
    },

    /// Write the repository key to a file, to carry it to another machine.
    ///
    /// The destination must be outside this repository's working tree. The key
    /// is never printed, so redirecting this command's output captures nothing.
    ExportKey {
        /// Where to write the key. Must lie outside the working tree.
        path: PathBuf,

        /// Replace the destination if it already exists.
        #[arg(long)]
        force: bool,
    },

    /// Serve git's long-running filter protocol. Registered by `init`.
    ///
    /// Not meant to be run by hand: everything it writes to stdout is protocol.
    Process,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => report(run_init()),
        Command::Sync { check } => run_sync(check),
        Command::ExportKey { path, force } => report(run_export_key(&path, force)),
        Command::Process => report(commands::process::run()),
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
    for warning in &report.warnings {
        eprintln!("git-xcrypt: {warning}");
    }
    Ok(())
}

/// Runs `export-key`, reporting where the key went — never what it is.
///
/// The fingerprint is safe to print and is what the user needs in order to tell
/// two exports apart. The key itself goes to the file and nowhere else: this
/// command is the one place the product hands a key over, so `stdout` staying
/// empty is what makes `git-xcrypt export-key > somewhere` capture nothing.
fn run_export_key(path: &std::path::Path, force: bool) -> Result<()> {
    let repo = Repo::discover_from_cwd()?;
    let report = commands::export_key::run(&repo, path, force)?;

    eprintln!(
        "git-xcrypt: wrote key {} to {}",
        git_xcrypt::format_key_id(&report.key_id),
        report.path.display()
    );
    eprintln!(
        "git-xcrypt: this file is the only way back into this repository's history — \
         keep it somewhere you can still read it after this machine is gone"
    );
    Ok(())
}

/// Runs `sync`, whose `--check` mode reports staleness through the exit code.
///
/// It has its own exit path rather than going through [`report`] because a
/// stale section is an answer, not a failure — the command did exactly what it
/// was asked to.
///
/// Code `1` is shared with "usage error or unclassified failure" from the frozen
/// table, so a CI gate cannot tell a stale section from an unreadable file by
/// the code alone; the message says which it is. The table has no spare code and
/// `5` means an exposure, which a cosmetic section is not.
fn run_sync(check: bool) -> ExitCode {
    match sync_and_describe(check) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("git-xcrypt: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn sync_and_describe(check: bool) -> Result<ExitCode> {
    let repo = Repo::discover_from_cwd()?;
    let report = commands::sync::run(&repo, check)?;

    for warning in &report.warnings {
        eprintln!("git-xcrypt: {warning}");
    }

    let attributes = repo.attributes_path().display().to_string();
    Ok(match report.outcome {
        Outcome::Updated => {
            eprintln!("git-xcrypt: updated {attributes}");
            ExitCode::SUCCESS
        }
        Outcome::UpToDate => {
            eprintln!("git-xcrypt: {attributes} was already up to date; nothing changed");
            ExitCode::SUCCESS
        }
        Outcome::Stale => {
            eprintln!(
                "git-xcrypt: {attributes} is out of date with {}; run `git-xcrypt sync`",
                git_xcrypt::repo::CONFIG_FILE
            );
            ExitCode::from(exit::USAGE)
        }
    })
}
