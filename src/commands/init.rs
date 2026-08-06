//! `git-xcrypt init` — make a repository ready to encrypt.
//!
//! The hard part is not setting things up, it is deciding whether to. Four
//! independent pieces of state exist (the key, the filter registration, the
//! config file, the managed attributes section) and getting the decision wrong
//! in one direction destroys the key. Three rules replace the sixteen cases:
//!
//! * a key exists → never touch it, repair the rest;
//! * no key but traces of an earlier setup → refuse, this is a clone or a locked
//!   repository and a fresh key would strand every existing blob forever;
//! * no key and no traces → initialise.

use std::fs;

use crate::config::Config;
use crate::key::MasterKey;
use crate::repo::{DRIVER, Repo};
use crate::{Error, Result, gitattributes, gitconfig, keyfile};

/// What `init` changed, so it can tell the user rather than work in silence.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// A key was generated. False when an existing one was left alone.
    pub key_created: bool,
    /// The filter registration was written or repaired.
    pub config_written: bool,
    /// The managed section in `.gitattributes` was written or repaired.
    pub attributes_written: bool,
    /// The `.git-xcrypt` file was created.
    pub config_file_created: bool,
    /// Lines of `.git-xcrypt` that declare something pointless.
    ///
    /// Carried out rather than printed here so the binary owns every message.
    pub warnings: Vec<String>,
}

impl Report {
    /// Whether anything at all changed.
    #[must_use]
    pub fn changed_anything(&self) -> bool {
        self.key_created
            || self.config_written
            || self.attributes_written
            || self.config_file_created
    }
}

/// The starting contents of `.git-xcrypt`.
///
/// Comments only: an empty file encrypts nothing, which is the safe default, and
/// the comments show the syntax without the user having to find the manual.
const CONFIG_TEMPLATE: &str = "\
# git-xcrypt — which paths leave this machine encrypted, and how line endings
# are handled. Patterns use .gitignore syntax; attributes use .gitattributes
# vocabulary. Without an attribute a path is treated as `text=auto`.
#
# Whitespace ends the pattern, so a name that contains a space is closed with
# quotes, exactly as .gitattributes closes one. A backslash is only what a glob
# says it is, and a negation keeps its `!` outside the quotes.
#
# secrets/
# *.env
# secrets/deploy.ps1     text eol=crlf
# secrets/key.p12        binary
# \"my secrets/\"
# \"my secrets/*.sh\"      text eol=lf
# !secrets/README.md
# !\"my secrets/README.md\"
";

/// Runs `init` in `repo`.
///
/// # Errors
///
/// [`Error::Config`] when the repository carries traces of an earlier setup but
/// no key — generating one would make existing blobs undecryptable forever.
pub fn run(repo: &Repo) -> Result<Report> {
    let mut report = Report::default();

    if !repo.has_key() {
        refuse_if_previously_configured(repo)?;
        keyfile::write(&repo.key_path(), &MasterKey::generate()?)?;
        report.key_created = true;
    }

    report.config_written = register_driver(repo)?;
    report.config_file_created = create_config_file(repo)?;

    // The managed section is rendered by the same code `sync` runs, so a fresh
    // repository and a synchronised one are byte-identical. Doing it here rather
    // than leaving it to a later `sync` is what keeps "run one command" true.
    //
    // A `.git-xcrypt` that cannot be parsed stops `init` at this point, on
    // purpose: the same file stops every `git add` too, and the registration
    // above has already been saved, so the repair still lands and the message
    // names the offending line.
    let config = Config::load(&repo.xcrypt_config_path())?;
    // Whichever shape is already there, because this command was not asked to
    // change it — see `render_lines_as_written`. A fresh repository has none, so
    // it gets the global line: correct with no `sync` in the flow at all, which
    // is the whole point of writing it here.
    let lines = gitattributes::render_lines_as_written(&repo.attributes_path(), &config);
    report.warnings = config.pointless_eol;
    report.warnings.extend(textconv_cache_warning(repo));
    report.attributes_written = gitattributes::write_section(&repo.attributes_path(), &lines)?;

    Ok(report)
}

/// Refuses to generate a key in a repository that already used one.
///
/// The traces we look for are the ones a clone inherits through history: the
/// managed attributes section and the versioned config file. Both survive
/// cloning; the key does not.
fn refuse_if_previously_configured(repo: &Repo) -> Result<()> {
    // A `.gitattributes` we cannot read is not evidence of absence. Treating a
    // read failure as "no traces" is the one direction that generates a fresh
    // key over a repository that already has one — the irreversible outcome
    // this whole function exists to prevent.
    let attributes = match fs::read_to_string(repo.attributes_path()) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(Error::Config(format!(
                "cannot tell whether this repository was already set up: {} could not be \
                 read ({err}). Refusing rather than risk generating a second key.",
                repo.attributes_path().display()
            )));
        }
    };
    let has_section = gitattributes::has_section(&attributes);
    let has_config = repo.xcrypt_config_path().is_file();

    if !has_section && !has_config {
        return Ok(());
    }

    Err(Error::Config(format!(
        "this repository was already set up for git-xcrypt but its key is missing.\n\
         Generating a new one would make every file encrypted so far impossible to \
         read, for good.\n\
         If this is a clone, run `git-xcrypt unlock <key-file>`.\n\
         To put the key in place without decrypting anything, add `--key-only`.\n\
         If this repository never used git-xcrypt and you wrote {} by hand, delete it \
         and run `init` again.\n\
         (found: {})",
        crate::repo::CONFIG_FILE,
        match (has_section, has_config) {
            (true, true) => "a managed .gitattributes section and .git-xcrypt",
            (true, false) => "a managed .gitattributes section",
            _ => ".git-xcrypt",
        }
    )))
}

/// Registers the filter driver, reporting whether anything changed.
///
/// `required = true` is what makes a failing filter abort the operation. Without
/// it git treats the failure as harmless and commits the unfiltered content with
/// exit code 0 — for this product, a secret in the clear.
///
/// The filter is registered as `process`, the long-running protocol: a process
/// per file was measured 22× slower, which the catch-all construction cannot
/// afford.
///
/// The `diff` driver is registered alongside it, so the cosmetic
/// `diff=git-xcrypt` lines S-02 renders have something behind them and `git
/// diff` compares plaintext.
///
/// `cachetextconv` is written as an explicit `false` rather than merely left
/// out. It makes git keep every *decrypted* file as a blob under
/// `refs/notes/textconv/git-xcrypt`, inside `.git/`, where it survives `lock` —
/// the plaintext this product exists to hide, back on disk after the key is
/// gone. Merely unsetting the local key was measured to be no defence at all: a
/// `[diff "git-xcrypt"] cachetextconv = true` in `~/.gitconfig` is inherited,
/// and only a local `false` overrides it. The key is namespaced under our own
/// driver name, so nothing a user configured for anything else is touched.
///
/// Shared with `unlock` rather than copied: a clone has the
/// catch-all line in `.gitattributes` and no driver behind it, and every command
/// that puts a key into such a repository has to close that gap the same way.
///
/// # Errors
///
/// [`Error::Config`] when `.git/config` cannot be read or written.
pub(crate) fn register_driver(repo: &Repo) -> Result<bool> {
    let path = repo.config_path();
    let mut config = gitconfig::open_local(&path)?;
    let binary = current_executable()?;

    let wanted = [
        (
            format!("filter.{DRIVER}.process"),
            format!("{binary} process"),
        ),
        (format!("filter.{DRIVER}.required"), "true".to_string()),
        (format!("diff.{DRIVER}.textconv"), format!("{binary} diff")),
        (format!("diff.{DRIVER}.cachetextconv"), "false".to_string()),
    ];

    let mut changed = false;
    for (key, value) in wanted {
        if gitconfig::get(&config, &key).as_deref() != Some(value.as_str()) {
            gitconfig::set(&mut config, &key, &value)?;
            changed = true;
        }
    }

    if changed {
        gitconfig::save_local(&path, &config)?;
    }
    Ok(changed)
}

/// Settles the registration for a repository that is about to lose its key.
///
/// Registers only what is missing, never repoints a working driver, and takes
/// the diff driver back out.
///
/// **The diff driver has to go.** Measured on git 2.55: `diff.<driver>.textconv`
/// makes git materialise each side of a diff through
/// `convert_to_working_tree` — the smudge filter — before handing it over. In a
/// locked repository that filter has no key, `required = true` turns its refusal
/// into `fatal: smudge filter git-xcrypt failed`, and `git log -p` over any
/// declared path stops working entirely. Without the driver git falls back to
/// `Binary files differ`, which is the honest answer for a repository nobody can
/// read. `unlock` puts it back, through
/// [`register_driver`].
///
/// For `lock`, which is the one command after which the user has no key left to
/// run `unlock` again — and `init` deliberately refuses in a repository that
/// carries traces but no key, so there is no second repair either. Measured:
/// [`register_driver`] rewrites `process` to whatever binary is running, so
/// locking with a copy under `target/debug`, in `~/Downloads` or on a container
/// mount repointed a working registration at a path that then disappeared, and
/// left a repository in which every `git add` aborts and nothing can fix it.
///
/// So an existing `process` value is left exactly as it is, whatever it names.
/// `required` is still set whenever it is not already `true`: that flag is what
/// turns a failing filter into an aborted operation instead of a stored
/// plaintext, and setting it can only ever refuse more.
///
/// # Errors
///
/// [`Error::Config`] when `.git/config` cannot be read or written.
pub(crate) fn register_driver_for_lock(repo: &Repo) -> Result<LockRegistration> {
    let path = repo.config_path();
    let mut config = gitconfig::open_local(&path)?;

    // Kept apart from `repaired` on purpose. This one happens on every healthy
    // lock, and folding it in made the command announce "repaired the filter
    // registration" every single time — noise in the one output a user scans
    // for signs of trouble before the key disappears, and a repair that no
    // longer proves anything if the real one stops working.
    //
    // Only `textconv` goes. The `cachetextconv = false` line stays, because with
    // no driver there is nothing to cache and because removing it would let a
    // `true` in `~/.gitconfig` back through if the repository is ever unlocked
    // by a build that does not write it.
    let mut diff_driver_removed = false;
    let textconv = format!("diff.{DRIVER}.textconv");
    if gitconfig::get(&config, &textconv).is_some() {
        gitconfig::unset(&mut config, &textconv)?;
        diff_driver_removed = true;
    }

    let mut changed = false;
    let process = format!("filter.{DRIVER}.process");
    if gitconfig::get(&config, &process).is_none_or(|value| value.trim().is_empty()) {
        gitconfig::set(
            &mut config,
            &process,
            &format!("{} process", current_executable()?),
        )?;
        changed = true;
    }

    let required = format!("filter.{DRIVER}.required");
    if gitconfig::get(&config, &required).as_deref() != Some("true") {
        gitconfig::set(&mut config, &required, "true")?;
        changed = true;
    }

    if changed || diff_driver_removed {
        gitconfig::save_local(&path, &config)?;
    }
    Ok(LockRegistration {
        repaired: changed,
        diff_driver_removed,
    })
}

/// Warns when a textconv cache is already sitting in this repository.
///
/// `cachetextconv` makes git store every *decrypted* file as a blob under
/// `refs/notes/textconv/git-xcrypt`. [`register_driver`] now writes an explicit
/// `false`, so no new cache can appear — but one made by an earlier build, or by
/// hand, is still there, and it outlives `lock`.
///
/// Reported rather than deleted, deliberately. Removing the ref would leave the
/// objects it points at in the database, so a message saying "cleaned up" would
/// be false; the same reason `status` reports plaintext in history and prints
/// the procedure instead of rewriting it.
pub(crate) fn textconv_cache_warning(repo: &Repo) -> Option<String> {
    let reference = format!("refs/notes/textconv/{DRIVER}");

    let present = repo.common_dir().join(&reference).is_file()
        || fs::read_to_string(repo.common_dir().join("packed-refs"))
            .unwrap_or_default()
            .lines()
            .any(|line| line.split_whitespace().nth(1) == Some(reference.as_str()));

    present.then(|| {
        format!(
            "{reference} exists: git's textconv cache holds decrypted copies of files \
             from this repository in its object database, and they outlive `lock`. \
             Remove them with `git update-ref -d {reference}` followed by \
             `git gc --prune=now`."
        )
    })
}

/// What [`register_driver_for_lock`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LockRegistration {
    /// Something was missing and was put back — the abnormal case.
    pub(crate) repaired: bool,
    /// The diff driver was taken out — the normal case, on every lock.
    pub(crate) diff_driver_removed: bool,
}

/// Creates `.git-xcrypt` if it is absent, reporting whether it did.
fn create_config_file(repo: &Repo) -> Result<bool> {
    let path = repo.xcrypt_config_path();
    if path.exists() {
        return Ok(false);
    }
    fs::write(&path, CONFIG_TEMPLATE)?;
    Ok(true)
}

/// The command git should run, quoted so a space in the path survives.
///
/// Git hands the value to a shell, so a path containing a space or a quote would
/// otherwise be split. Single quotes stop the shell expanding anything; a
/// literal quote is closed, escaped and reopened.
/// Only the **native** separator is rewritten, and that is the whole of it.
/// Git wants forward slashes in a value it hands to a shell on Windows, but on
/// Unix a backslash is an ordinary character in a file name — rewriting one
/// there names a different file, exactly as `repo::git_spelling` says.
fn current_executable() -> Result<String> {
    Ok(shell_quoted(
        &std::env::current_exe()?,
        crate::repo::NATIVE_SEPARATOR,
    ))
}

/// The platform-independent core, so both spellings are testable from either
/// platform.
fn shell_quoted(path: &std::path::Path, separator: char) -> String {
    let text = crate::repo::with_separator(&path.to_string_lossy(), separator);
    format!("'{}'", text.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_repo() -> TempDir {
        let dir = TempDir::new().expect("temporary directory");
        let ok = Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .expect("git must be on PATH")
            .success();
        assert!(ok, "git init failed");
        dir
    }

    /// Both halves of the filter command's spelling, exercised from any platform.
    ///
    /// The rewrite exists for Windows, where git wants forward slashes in a
    /// config value it hands to a shell. It used to run unconditionally, and on
    /// Unix a backslash is an ordinary character in a file name — so a binary
    /// under `/opt/a\b/git-xcrypt` was registered as `/opt/a/b/git-xcrypt`, a
    /// path that does not exist. `init` still reported success, and with
    /// `required = true` every later `git add`, `git checkout` and `git status`
    /// in that repository aborted with no way to see why from the message.
    ///
    /// `repo::git_spelling` already carried this rule, with a test of its own;
    /// this is the same core, so the two cannot drift.
    #[test]
    fn the_registered_command_rewrites_a_separator_and_never_a_file_name() {
        use std::path::Path;

        // Windows: the separator is a separator, and git gets slashes.
        assert_eq!(
            shell_quoted(Path::new(r"C:\Program Files\xc\git-xcrypt.exe"), '\\'),
            "'C:/Program Files/xc/git-xcrypt.exe'"
        );

        // Unix: a backslash is part of the name and must survive untouched.
        assert_eq!(
            shell_quoted(Path::new(r"/opt/a\b/git-xcrypt"), '/'),
            r"'/opt/a\b/git-xcrypt'",
            "the registered command named a binary that does not exist"
        );

        // A quote is still closed, escaped and reopened, on both.
        assert_eq!(
            shell_quoted(Path::new("/opt/it's/git-xcrypt"), '/'),
            r"'/opt/it'\''s/git-xcrypt'"
        );

        // And whatever this platform is, the real one round-trips: what `init`
        // writes has to name the binary that is running.
        let registered = current_executable().expect("the running binary has a path");
        assert!(registered.starts_with('\'') && registered.ends_with('\''));
    }

    #[test]
    fn the_textconv_cache_is_switched_off_rather_than_merely_left_out() {
        // With `cachetextconv` on, git keeps every decrypted file in a notes ref
        // inside `.git/` — plaintext that outlives `lock`. Measured: unsetting
        // the local key is no defence, because a `true` in `~/.gitconfig` is
        // inherited. Only a local `false` overrides it.
        let dir = init_repo();
        let repo = Repo::discover(dir.path()).expect("discovery");
        run(&repo).expect("first init");

        let path = repo.config_path();
        let key = format!("diff.{DRIVER}.cachetextconv");
        assert_eq!(
            gitconfig::get(&gitconfig::open_local(&path).expect("config"), &key).as_deref(),
            Some("false"),
            "an inherited `true` would go unopposed"
        );

        let mut config = gitconfig::open_local(&path).expect("config");
        gitconfig::set(&mut config, &key, "true").expect("setting");
        gitconfig::save_local(&path, &config).expect("saving");

        let report = run(&repo).expect("init must repair");

        assert!(report.config_written, "the repair went unreported");
        assert_eq!(
            gitconfig::get(&gitconfig::open_local(&path).expect("config"), &key).as_deref(),
            Some("false"),
            "the textconv cache survived init"
        );
    }
}
