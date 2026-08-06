//! Argument parsing and exit codes. All logic lives in the library.
//!
//! Nothing but file content may reach `stdout` on the filter path: git treats
//! the filter's `stdout` as the file itself, so a stray `println!` corrupts it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use git_xcrypt::commands::status::Verdict;
use git_xcrypt::commands::sync::Outcome;
use git_xcrypt::repo::{Repo, git_spelling};
use git_xcrypt::{Result, commands, exit};

/// The frozen exit-code table, shown under `--help`.
///
/// Here rather than only in the README because the one command most people run
/// unattended is `status`, and what a CI job reads is this number. A table that
/// lives only in prose is a table nobody consults at the moment it matters —
/// and one that lives only in a doc comment drifts, which is exactly what
/// happened to `status`'s own description between 2026-08-05 and 2026-08-06.
const EXIT_CODES: &str = "\
Exit codes:
  0  success
  1  usage error, or a failure with no better code
  2  configuration or a state conflict — including a `status` run that found
     the setup enforcing nothing
  3  no repository key
  4  bad format: magic, key id, unknown flag bit, or a failed tag
  5  `status` found an exposure
  6  `status` could not tell

A CI gate should treat 2, 5 and 6 alike as a failure.";

/// Transparent encryption of selected files in a git repository.
#[derive(Debug, Parser)]
#[command(
    name = "git-xcrypt",
    version,
    about,
    long_about = None,
    after_long_help = EXIT_CODES,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a key and register the filter in this repository.
    Init,

    /// Regenerate the per-pattern `.gitattributes` lines from `.git-xcrypt`.
    ///
    /// Run it after every change to `.git-xcrypt`. Which paths get encrypted
    /// takes effect at once — the filter reads the declaration on every
    /// `git add` — but these lines carry `-text`, and that is what keeps git's
    /// own CRLF conversion off the ciphertext. Without it, any other attribute
    /// calling such a path `text` makes git rewrite the encrypted bytes: `git
    /// add` exits 0, the damaged blob is committed, and the file is
    /// unrecoverable at checkout.
    Sync {
        /// Report whether the section is out of date instead of writing it.
        ///
        /// Exits 0 when it is current and 1 when it is not, for use as a CI gate.
        #[arg(long)]
        check: bool,

        /// Write one line per declared pattern instead of one for everything.
        ///
        /// The default section is a single `* -text diff=git-xcrypt`, which is
        /// correct with no `sync` in the flow at all. Its cost is the diff
        /// driver: git spawns it per blob, so a big review pays for files that
        /// were never encrypted — measured, 1000 files in a diff, 8461 ms
        /// against 23 ms. Splitting the section confines the driver to declared
        /// paths, and makes `sync` part of the flow again: run it after every
        /// change to `.git-xcrypt`, or the lines go stale.
        #[arg(long)]
        per_pattern: bool,

        /// Spell every ASCII letter as a class, so `*.env` becomes `*.[eE][nN][vV]`.
        ///
        /// Only meaningful with `--per-pattern`; the global line covers every
        /// spelling already. Pattern matching in `.git-xcrypt` folds case
        /// whatever this says, so on a case-insensitive filesystem — APFS, NTFS
        /// — a file called `TOP.ENV` is encrypted either way. What the folded
        /// line adds is the `-text` and `diff` that go with it on a
        /// case-*sensitive* one.
        #[arg(long, requires = "per_pattern")]
        ignorecase: bool,
    },

    /// Write the repository key to a file, to carry it to another machine.
    ///
    /// The destination must be outside this repository's working tree. With
    /// `--stdout` the key goes to standard output instead, for piping straight
    /// into a secret store — never to a terminal.
    ExportKey {
        /// Where to write the key. Must lie outside the working tree.
        #[arg(required_unless_present = "stdout", conflicts_with = "stdout")]
        path: Option<PathBuf>,

        /// Print the key to standard output instead of writing a file.
        ///
        /// Refused when standard output is a terminal. A shell redirect is
        /// yours to aim: this cannot see where it points, so the checks that
        /// keep a key out of the working tree do not apply.
        #[arg(long)]
        stdout: bool,

        /// Replace the destination if it already exists.
        #[arg(long)]
        force: bool,
    },

    /// Decrypt this repository's working tree, and register the filter.
    ///
    /// With a key file it installs the key first, which is what a fresh clone
    /// needs. Without one it uses the key already here. Safe to run twice: a
    /// file that is already in the clear is left alone.
    Unlock {
        /// A file written by `export-key`. Omit to use the key already here.
        #[arg(conflicts_with = "key")]
        path: Option<PathBuf>,

        /// The text of such a file, given directly instead of as a path.
        ///
        /// For a CI secret that must never touch the disk. It is visible in the
        /// process list while this runs, and your shell will remember it.
        #[arg(long, value_name = "TEXT")]
        key: Option<String>,

        /// Put the key in place and repair the setup, but decrypt nothing.
        ///
        /// The working tree is left exactly as it is. A key the files here
        /// contradict is still refused.
        #[arg(long)]
        key_only: bool,
    },

    /// Encrypt this repository's working tree and delete its key.
    ///
    /// Irreversible without a copy of the key: `unlock` cannot undo it, because
    /// `.git/` is never pushed and the key file it removes is the only one.
    /// Refuses while any declared file holds content the repository does not
    /// store yet — `--yes` does not waive that.
    Lock {
        /// Do not ask for confirmation. The warning is still printed.
        #[arg(long)]
        yes: bool,
    },

    /// Report whether this repository's declarations are actually enforced.
    ///
    /// Made for a CI gate, so the exit code carries the answer: `2` when the
    /// setup enforces nothing, `5` when something was found in the data, `6`
    /// when the run could not tell, `0` when it checked and found nothing.
    /// Treat `2`, `5` and `6` alike as a failure — they ask for three different
    /// repairs, and only `0` means the question was answered.
    ///
    /// It answers "are my declarations enforced", not "are there secrets here":
    /// a file that never matched a pattern is invisible to it.
    Status {
        /// Re-stage declared files the index holds in the clear.
        ///
        /// What `git add` would do, through the filter, so the next commit
        /// stores them encrypted. It touches the index and nothing else: the
        /// working tree stays readable and no history is rewritten, so nothing
        /// already committed in the clear is un-leaked by it.
        #[arg(long)]
        fix: bool,
    },

    /// Serve git's long-running filter protocol. Registered by `init`.
    ///
    /// Not meant to be run by hand: everything it writes to stdout is protocol.
    Process,

    /// Print a file's decrypted content, for `git diff` to compare.
    ///
    /// Registered by `init` as `diff.git-xcrypt.textconv`. Content that is not
    /// ours is printed unchanged, so `git log -p` still works over history from
    /// before the repository was configured.
    ///
    /// Its own `--help` is switched off, because git passes a repository
    /// relative path with no `./` in front of it: a file named `--help` at the
    /// root would otherwise print usage text to `stdout` and exit 0, and git
    /// would show that as the file's content. `git-xcrypt help diff` still
    /// works, and so does the help for every other subcommand.
    #[command(disable_help_flag = true)]
    Diff {
        /// The file git wants read. Usually one it wrote to a temporary path.
        ///
        /// Never parsed as an option, whatever it is called. Git hands over the
        /// working-tree path verbatim, so a file named `-w.env` would otherwise
        /// abort `git diff` — and one named `--help` was measured printing
        /// clap's usage text to `stdout` with exit code 0, which git then
        /// rendered as that file's content.
        #[arg(allow_hyphen_values = true)]
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    // `Cli::parse()` exits with clap's own code, which is 2 — the code the
    // frozen table gives to "configuration or a state conflict". A gate that
    // pages someone on 2 could not tell a misconfigured repository from a typo.
    // Help and version are a successful request for output, not a failure.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            // Only an explicit `--help` or `--version` is a request that
            // succeeded. Running the binary with no subcommand at all prints
            // help too, but it is a usage error — `git` itself exits 1 there.
            let usage = !matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = err.print();
            return if usage {
                ExitCode::from(exit::USAGE)
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    match cli.command {
        Command::Init => report(run_init()),
        Command::Sync {
            check,
            per_pattern,
            ignorecase,
        } => run_sync(check, per_pattern, ignorecase),
        Command::ExportKey {
            path,
            stdout,
            force,
        } => report(run_export_key(path.as_deref(), stdout, force)),
        Command::Unlock {
            path,
            key,
            key_only,
        } => report(run_unlock(path.as_deref(), key.as_deref(), key_only)),
        Command::Lock { yes } => run_lock(yes),
        Command::Status { fix } => run_status(fix),
        Command::Process => report(commands::process::run()),
        Command::Diff { path } => report(run_diff(&path)),
    }
}

/// Runs the `textconv` driver, whose output belongs on `stdout`.
///
/// The only command in this binary that writes there. It is not the exception it
/// looks like: the rule protects the *filter* path, where git reads `stdout` as
/// the file it is about to store. Here git reads it as one side of a diff, so
/// printing the content is the entire point — and nothing else may join it,
/// which is why the warning below goes to `stderr` like every other message.
fn run_diff(path: &std::path::Path) -> Result<()> {
    use std::io::Write as _;

    let outcome = commands::diff::run(path)?;
    if let Some(warning) = outcome.warning {
        eprintln!("git-xcrypt: {warning}");
    }

    let mut out = std::io::stdout().lock();
    out.write_all(&outcome.content)?;
    // Explicit: a `BufWriter`-free lock still buffers, and git reads this pipe
    // to end-of-file, so an unflushed tail would silently truncate the diff.
    out.flush()?;
    Ok(())
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
fn run_export_key(path: Option<&std::path::Path>, stdout: bool, force: bool) -> Result<()> {
    let repo = Repo::discover_from_cwd()?;

    if stdout {
        let key_id = commands::export_key::to_stdout(&repo)?;
        // On `stderr`, so a pipe carries the key and nothing else. Both halves
        // are said: what just left, and the one check a redirect escapes.
        eprintln!(
            "git-xcrypt: wrote key {} to standard output",
            git_xcrypt::format_key_id(&key_id)
        );
        eprintln!(
            "git-xcrypt: whatever is on the other end of that pipe now holds the only \
             way back into this repository's history. If you redirected it to a file, \
             nothing checked where that file is — a path inside the working tree is one \
             `git add -A` from a commit."
        );
        return Ok(());
    }

    let path = path.expect("clap requires a path unless --stdout is given");
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

/// Runs `unlock` and reports what changed.
///
/// The file list goes to `stderr` like everything else. It names paths, which
/// are not secret — the contents never appear.
fn run_unlock(path: Option<&std::path::Path>, key: Option<&str>, key_only: bool) -> Result<()> {
    let repo = Repo::discover_from_cwd()?;

    if key.is_some() {
        // Every time, not once: the cost is paid at each invocation, and a
        // warning the user has learned to expect is still the only notice they
        // get that the key is now in two places nobody cleans up.
        eprintln!(
            "git-xcrypt: the key was given on the command line, so it is visible in the \
             process list while this runs and your shell has already recorded it. Clear \
             that history entry, or pass a file next time."
        );
    }
    let source = match (path, key) {
        (Some(path), _) => Some(commands::unlock::KeySource::File(path)),
        (None, Some(text)) => Some(commands::unlock::KeySource::Material(text)),
        (None, None) => None,
    };
    let report = commands::unlock::run(&repo, source, key_only)?;

    let key_id = git_xcrypt::format_key_id(&report.key_id);
    if report.key_imported {
        eprintln!("git-xcrypt: imported key {key_id}");
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
    for warning in &report.warnings {
        eprintln!("git-xcrypt: {warning}");
    }

    for path in &report.decrypted {
        eprintln!("git-xcrypt: decrypted {}", git_spelling(path));
    }

    // The closing line has to distinguish "everything" from "everything I could
    // read". A file skipped because it would not open is still ciphertext, and
    // a summary that says only how many succeeded reads as though none were
    // missed.
    let unreadable = match report.unreadable.len() {
        0 => String::new(),
        count => format!(", {count} could not be read and may still be encrypted"),
    };
    if key_only {
        // Never "unlocked": the working tree is untouched, and saying otherwise
        // over a directory still full of ciphertext is the one sentence a user
        // would act on wrongly.
        eprintln!(
            "git-xcrypt: key {key_id} is in place and this repository filters; \
             nothing was decrypted. `git-xcrypt unlock` opens the working tree."
        );
    } else if report.decrypted.is_empty() {
        eprintln!("git-xcrypt: unlocked with key {key_id}; nothing was encrypted{unreadable}");
    } else {
        eprintln!(
            "git-xcrypt: unlocked with key {key_id}; {} file(s) are now in the clear{unreadable}",
            report.decrypted.len()
        );
    }
    Ok(())
}

/// Runs `lock`, whose refusal by the user is an answer rather than a failure.
///
/// It has its own exit path rather than going through [`report`] because
/// declining the question is not an error: the command did exactly what it was
/// asked to and changed nothing, which the frozen table gives code `1`.
///
/// Everything the command says goes to `stderr`, the warning included. `stdout`
/// stays empty, so `git-xcrypt lock > somewhere` captures nothing — the same
/// rule that keeps a key out of a redirect anywhere else in this binary.
fn run_lock(assume_yes: bool) -> ExitCode {
    match lock_and_describe(assume_yes) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("git-xcrypt: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn lock_and_describe(assume_yes: bool) -> Result<ExitCode> {
    use commands::lock::Outcome;

    let repo = Repo::discover_from_cwd()?;

    // `std::io::stderr()` rather than a held `StderrLock`: the guard would still
    // be alive while the eprintln! calls below run.
    let outcome = if assume_yes {
        commands::lock::run(&repo, &mut commands::lock::Assumed::new(std::io::stderr()))?
    } else {
        commands::lock::run(
            &repo,
            &mut commands::lock::Ask::new(std::io::stdin().lock(), std::io::stderr()),
        )?
    };

    let report = match outcome {
        Outcome::Aborted => {
            eprintln!(
                "git-xcrypt: aborted. The key is still here and nothing in the working \
                 tree was changed."
            );
            return Ok(ExitCode::from(exit::USAGE));
        }
        Outcome::Locked(report) => report,
    };

    for warning in &report.warnings {
        eprintln!("git-xcrypt: {warning}");
    }
    if report.config_written {
        eprintln!(
            "git-xcrypt: repaired the filter registration in {}",
            repo.config_path().display()
        );
    }
    if report.diff_driver_removed {
        // Said out loud rather than done quietly: it is a capability the user
        // had a moment ago, and `unlock` is what brings it back.
        eprintln!(
            "git-xcrypt: unregistered the diff driver; `git diff` will report \
             `Binary files differ` until this repository is unlocked again"
        );
    }
    if report.attributes_written {
        eprintln!("git-xcrypt: updated {}", repo.attributes_path().display());
    }
    for path in &report.swept {
        eprintln!(
            "git-xcrypt: removed {}, left behind by an interrupted run",
            git_spelling(path)
        );
    }
    for path in &report.encrypted {
        eprintln!("git-xcrypt: encrypted {}", git_spelling(path));
    }

    // "0 encrypted" has two meanings and only one of them is a repository that
    // is now closed. A clone that was never unlocked reaches it legitimately; a
    // typo in `.git-xcrypt` reaches it with the secrets still in the clear.
    let key_id = git_xcrypt::format_key_id(&report.key_id);
    let already = report.declared - report.encrypted.len();
    let scope = match (report.declared, report.encrypted.len()) {
        (0, _) => "no file here is declared for encryption".to_string(),
        (_, 0) => format!("all {already} declared file(s) were already encrypted"),
        (_, written) => format!("{written} file(s) are now encrypted"),
    };
    eprintln!(
        "git-xcrypt: locked; {scope} and key {key_id} has been deleted from this \
         repository"
    );
    eprintln!(
        "git-xcrypt: run `git-xcrypt unlock <key-file>` with your copy of key {key_id} \
         to open it again"
    );
    Ok(ExitCode::SUCCESS)
}

/// Runs `status`, whose findings are an answer rather than a failure.
///
/// Its own exit path rather than [`report`], because a repository with a problem
/// is not a broken tool: the table gives that its own code, `5`, so a CI gate
/// can tell the two apart without reading the message. A third code, `6`, says
/// the run could not answer — see [`git_xcrypt::exit::UNDETERMINED`].
///
/// The report goes to `stdout` — this is not the filter path, where git reads
/// `stdout` as file content, and a gate that has to be scraped off `stderr` is a
/// gate nobody pipes. Diagnostics that are *about* the run rather than part of
/// the answer still go to `stderr`.
fn run_status(fix: bool) -> ExitCode {
    match status_and_describe(fix) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("git-xcrypt: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn status_and_describe(fix: bool) -> Result<ExitCode> {
    use std::io::Write as _;

    let repo = Repo::discover_from_cwd()?;
    let report = commands::status::run(&repo, fix)?;

    for warning in &report.warnings {
        eprintln!("git-xcrypt: {warning}");
    }

    let mut out = std::io::stdout().lock();
    write!(out, "{report}")?;
    out.flush()?;

    Ok(match report.verdict() {
        Verdict::Clean => ExitCode::SUCCESS,
        // Its own code since 2026-08-04. A CI gate reads nothing but this
        // number, and "I could not check" asks the operator to fix the checkout
        // while "I found something" asks them to rotate a secret.
        Verdict::Undetermined => ExitCode::from(exit::UNDETERMINED),
        Verdict::Exposed => ExitCode::from(exit::EXPOSED),
        // And a third question since 2026-08-05, which outranks both: "fix the
        // configuration". No new code — this is the frozen table's `2`, used
        // exactly as `init` and `lock` already use it, for a repository whose
        // state conflicts with what it is being asked to do. The report is
        // printed in full first, so nothing this code outranks goes unsaid.
        Verdict::Misconfigured => ExitCode::from(exit::CONFIG),
    })
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
fn run_sync(check: bool, per_pattern: bool, ignorecase: bool) -> ExitCode {
    match sync_and_describe(check, per_pattern, ignorecase) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("git-xcrypt: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn sync_and_describe(check: bool, per_pattern: bool, ignorecase: bool) -> Result<ExitCode> {
    let rendering = if per_pattern {
        git_xcrypt::gitattributes::Rendering::PerPattern {
            fold_case: ignorecase,
        }
    } else {
        git_xcrypt::gitattributes::Rendering::Global
    };
    let repo = Repo::discover_from_cwd()?;
    let report = commands::sync::run(&repo, check, rendering)?;

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
