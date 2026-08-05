//! Reading and writing git configuration through a library.
//!
//! Spawning `git config` is not an option: git starts a filter process per
//! operation, so it would be N process spawns on the hot path — most expensive
//! on exactly the platform where it hurts most. Writing only ever touches the
//! repository-local file, which is the only one this tool has business changing.

use std::fmt;
use std::path::{Path, PathBuf};

use bstr::ByteSlice as _;
use gix_config::File;
use gix_config::file::Metadata;

use crate::{Error, Result};

/// The global attributes file, resolved the way git resolves it.
///
/// Reading `core.attributesFile` verbatim is not enough, and the gap is not
/// cosmetic: it is a source in git's attribute stack, so a line in it can put
/// `text` back on a path this tool encrypts — and git then converts the
/// ciphertext. Measured on git 2.55, 2 MB, the line living in
/// `~/.config/git/attributes` while the same line in the tree is refused: `git
/// add` exited **0**, 27 `CR` bytes were eaten out of the blob, the commit
/// succeeded and the checkout left **no file at all**. The refusal in
/// [`crate::filter`] and the gate in `status` both resolve the stack correctly;
/// they simply were not being handed this file, so both reported a healthy
/// repository over a destroyed one.
///
/// Git's rule, measured on 2.55 rather than read from the documentation — the
/// five shapes are a table test in this module:
///
/// | `core.attributesFile` | what git reads |
/// | --- | --- |
/// | unset | `$XDG_CONFIG_HOME/git/attributes`, else `$HOME/.config/git/attributes` |
/// | `~/name`, `~user/name` | expanded, exactly as `core.excludesFile` is |
/// | an absolute path | that path |
/// | empty | **nothing** — and no XDG fallback either |
///
/// Returns the path whether or not it exists; a missing file is an empty source
/// to the resolver, which is what git does with one too.
#[must_use]
pub fn global_attributes_file(config: &File) -> Option<PathBuf> {
    global_attributes_file_for(
        config,
        // `HOME` first, then the platform's own answer — git's order, and the
        // reason a Windows user can keep a linux-style home somewhere else.
        gix_path::env::home_dir().as_deref(),
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
    )
}

/// [`global_attributes_file`], with the two environment variables as arguments.
///
/// Split out so the table below can be a test rather than a hope. `HOME` and
/// `XDG_CONFIG_HOME` belong to the *process*, so setting them to exercise a row
/// would need `unsafe` — which `unsafe_code = "forbid"` refuses, and that
/// refusal is worth more than the convenience. Passing the difference in as an
/// argument is the same shape `eol::apply_where` and `repo::with_separator`
/// already use for a platform the test is not running on.
#[must_use]
fn global_attributes_file_for(
    config: &File,
    home: Option<&Path>,
    xdg_config_home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    let Ok(value) = config.raw_value("core.attributesFile") else {
        // Git treats an empty `XDG_CONFIG_HOME` as unset, so `is_empty` is part
        // of the rule and not a defensive extra.
        if let Some(xdg) = xdg_config_home
            && !xdg.is_empty()
        {
            return Some(PathBuf::from(xdg).join("git").join("attributes"));
        }
        return Some(home?.join(".config").join("git").join("attributes"));
    };
    // Set but empty turns the file off; it does **not** fall back to XDG.
    if value.is_empty() {
        return None;
    }
    // `~/`, `~user/` and `%(prefix)/`, through the same crate that parsed the
    // value. Hand-rolling the expansion would be a second spelling of a rule
    // git already has one of.
    gix_config::Path::from(value)
        .interpolate(gix_config::path::interpolate::Context {
            home_dir: home,
            ..Default::default()
        })
        .ok()
}

/// The repository-local configuration, loaded for editing.
///
/// Includes are deliberately not followed: we are about to write this file back,
/// and following includes would fold someone else's file into ours.
///
/// # Errors
///
/// [`Error::Config`] when the file exists but cannot be parsed.
pub fn open_local(path: &Path) -> Result<File> {
    read_optional(path, gix_config::Source::Local)
}

/// One configuration file, where a missing one is empty and a broken one is not.
///
/// The asymmetry is the point: git creates these files lazily, so absence is an
/// ordinary state and saying so costs nothing. A file that is *there* and does
/// not parse is a different answer, and swallowing it would let a repository
/// whose `filter.git-xcrypt.required` cannot be read pass for one that has it.
fn read_optional(path: &Path, source: gix_config::Source) -> Result<File> {
    if !path.exists() {
        return Ok(File::new(Metadata::from(source)));
    }
    File::from_path_no_includes(path.to_path_buf(), source)
        .map_err(|err| Error::Config(format!("could not read {}: {err}", path.display())))
}

/// The configuration git itself would see, for reading only.
///
/// Full precedence: git installation, system, global, repository-local,
/// worktree and `GIT_CONFIG_*` overrides, with `include`/`includeIf` followed.
/// The smudge path needs this rather than `.git/config` alone, because
/// `core.autocrlf` and `core.eol` are almost always set globally — on Windows
/// the installer does it — and reading only the local file would leave the
/// measured line-ending table unreachable on exactly the platform it exists for.
///
/// This assembles the cascade the way `gix_config::File::from_git_dir` does,
/// with **one** difference, and it is the reason it is spelled out here rather
/// than called: that function reads `config.worktree` whenever
/// `extensions.worktreeConfig` is true, and treats the file's absence as an
/// error. Git treats it as empty — the extension is permission to look, not a
/// promise the file exists, and git creates it lazily on the first
/// `git config --worktree`.
///
/// Measured on git 2.55, 2026-08-05: in a repository where
/// `extensions.worktreeConfig` was set and no `config.worktree` had been written
/// yet, git ran `add`, `commit` and `status` at exit 0 while this build could
/// not start its own filter — so with `required = true`, **every git operation
/// in the repository failed**, `git add` exiting 128 with
/// `could not read git configuration`. The trigger is the command git's own
/// documentation gives for enabling per-worktree configuration, and the window
/// is however long it takes to run the next one.
///
/// Fail-closed, so nothing was ever stored in the clear over it — but an outage
/// is exactly what `required = true` turns a configuration read into, and the
/// rest of this crate is careful about that.
///
/// **The two directories are different on purpose, and that is the second
/// difference.** `config` is shared, so it comes from `common_dir`;
/// `config.worktree` is per-checkout and comes from `git_dir`, which for a
/// linked worktree is `…/.git/worktrees/<name>`. Reading both from the common
/// directory — which is what this did, and what `gix-config` does when handed
/// one path — gives a linked worktree the *main* checkout's per-worktree
/// configuration, which is nobody's configuration.
///
/// Measured on git 2.55, 2026-08-05, 2 MB in a linked worktree whose
/// `config.worktree` set `core.attributesFile` to a file declaring `vault/**
/// text`: `git check-attr text` answered `set` there and `unspecified` in the
/// main checkout, `git add` exited **0** because the refusal never saw the file,
/// 40 bytes were eaten out of the blob, and the checkout left **no file at
/// all**. Same shape as an unresolved `~/` in [`global_attributes_file`], one
/// directory further out.
///
/// # Errors
///
/// [`Error::Config`] when a file in the cascade exists and cannot be parsed.
pub fn open_full(git_dir: &Path, common_dir: &Path) -> Result<File> {
    let broken =
        |err: &dyn fmt::Display| Error::Config(format!("could not read git configuration: {err}"));

    let mut local = read_optional(&common_dir.join("config"), gix_config::Source::Local)?;
    // The one file git looks for only conditionally, and the one whose absence
    // must not be an error. `Source::Worktree` rather than `Local`, so it keeps
    // the precedence git gives it: above the local file, below the environment.
    let worktree = get(&local, "extensions.worktreeConfig")
        .is_some_and(|value| is_true(&value))
        .then(|| {
            read_optional(
                &git_dir.join("config.worktree"),
                gix_config::Source::Worktree,
            )
        })
        .transpose()?;

    let home = gix_path::env::home_dir();
    let options = gix_config::file::init::Options {
        includes: gix_config::file::includes::Options::follow(
            gix_config::path::interpolate::Context {
                home_dir: home.as_deref(),
                ..Default::default()
            },
            gix_config::file::includes::conditional::Context {
                git_dir: Some(git_dir),
                branch_name: None,
            },
        ),
        ..Default::default()
    };

    let mut config = File::from_globals().map_err(|err| broken(&err))?;
    config
        .resolve_includes(options)
        .map_err(|err| broken(&err))?;
    local
        .resolve_includes(options)
        .map_err(|err| broken(&err))?;
    config.append(local).map_err(|err| broken(&err))?;
    if let Some(mut worktree) = worktree {
        worktree
            .resolve_includes(options)
            .map_err(|err| broken(&err))?;
        config.append(worktree).map_err(|err| broken(&err))?;
    }
    config
        .append(File::from_environment_overrides().map_err(|err| broken(&err))?)
        .map_err(|err| broken(&err))?;
    Ok(config)
}

/// Writes a configuration file back to disk, replacing it in one step.
///
/// This file carries the driver registration, so a half-written one leaves git
/// with no filter and the next `git add` storing plaintext with exit code 0.
///
/// # Errors
///
/// [`Error::Io`] when the file cannot be written.
pub fn save_local(path: &Path, config: &File) -> Result<()> {
    crate::atomic::write(path, &config.to_bstring())
}

/// Sets a dotted key such as `filter.git-xcrypt.required`, creating what is missing.
///
/// # Errors
///
/// [`Error::Config`] when the key cannot be set.
pub fn set(config: &mut File, key: &str, value: &str) -> Result<()> {
    config
        .set_raw_value(key, value)
        .map(|_| ())
        .map_err(|err| Error::Config(format!("could not set {key}: {err}")))
}

/// Removes a dotted key, if it is there at all.
///
/// # Errors
///
/// [`Error::Config`] when the key names a section that cannot be addressed.
pub fn unset(config: &mut File, key: &str) -> Result<()> {
    let (section_key, name) = key
        .rsplit_once('.')
        .ok_or_else(|| Error::Config(format!("`{key}` is not a dotted configuration key")))?;

    if let Ok(mut section) = config.section_mut_by_key(section_key) {
        while section.remove(name).is_some() {}
    }
    Ok(())
}

/// Reads a dotted key, if present.
///
/// A key written with no value at all — `[core]\n\tautocrlf` — is `true` to git,
/// but has no raw value to return, so it comes back as `Some("true")`: git's own
/// reading of that line, spelled the way every caller already tests for.
///
/// **`Some("true")` rather than `Some("")`, and the difference is a security
/// one.** `gix-config` reports `key` (no `=`) and `key =` (an empty value)
/// identically — the first as `Err(KeyMissing)` from `raw_value`, the second as
/// `Ok("")` — and git does not: measured on git 2.55, `git config --type=bool`
/// reads the first as `true` and the second as **`false`**. Flattening both to
/// the empty string and calling that true made `filter.git-xcrypt.required = `
/// read as enabled, while git ignored the failing filter and stored the
/// plaintext with `git add` exiting 0 — and `status`, the gate that exists to
/// catch exactly that, reported no gap.
#[must_use]
pub fn get(config: &File, key: &str) -> Option<String> {
    if let Ok(value) = config.raw_value(key) {
        // An explicit value, the empty string included. Git reads `key =` as
        // false, so it must not be turned into a spelling of true below.
        return Some(value.to_string());
    }

    let (section_key, name) = key.rsplit_once('.')?;
    let (section, subsection) = match section_key.split_once('.') {
        Some((section, subsection)) => (section, Some(subsection.as_bytes().as_bstr())),
        None => (section_key, None),
    };

    let present = config
        .sections_by_name(section)?
        .filter(|section| section.header().subsection_name() == subsection)
        .any(|section| section.value_names().any(|value_name| value_name == name));

    present.then(|| "true".to_string())
}

/// Whether a value is one of git's spellings of true.
///
/// Git accepts `1`, `yes` and `on` beside `true`, case insensitively. Every
/// caller that branches on a git boolean has to accept the same set, or a
/// perfectly ordinary `required = 1` reads as "off".
///
/// The empty string is **not** in the set. Git reads `key =` as `false`
/// (measured with `git config --type=bool` on 2.55), and the value-less
/// `key` that git does read as true never arrives here as empty — [`get`]
/// returns it as `"true"`.
#[must_use]
pub fn is_true(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// The five shapes of `core.attributesFile`, as measured on git 2.55.
    ///
    /// The scenario in `tests/attributes.rs` proves the two that cost a file;
    /// this proves the whole table, including the two that must resolve to
    /// **nothing**. Over-eager resolution is its own failure mode: with
    /// `required = true`, a global file we invent and the user does not have
    /// would refuse operations in every repository on the machine.
    #[test]
    fn the_global_attributes_file_resolves_where_git_resolves_it() {
        let home = Path::new("/home/user");
        let resolve = |contents: &str, xdg: Option<&str>| {
            let file = File::try_from(contents).expect("the fixture is valid configuration");
            global_attributes_file_for(&file, Some(home), xdg.map(std::ffi::OsStr::new))
        };

        assert_eq!(
            resolve("[core]\n", None),
            Some(home.join(".config").join("git").join("attributes")),
            "unset must fall back to the XDG default, which is where git looks"
        );
        assert_eq!(
            resolve("[core]\n", Some("/xdg")),
            Some(Path::new("/xdg").join("git").join("attributes")),
            "XDG_CONFIG_HOME must win over the $HOME/.config default"
        );
        assert_eq!(
            resolve("[core]\n", Some("")),
            Some(home.join(".config").join("git").join("attributes")),
            "git treats an empty XDG_CONFIG_HOME as unset, so this must too"
        );
        assert_eq!(
            resolve("[core]\n\tattributesFile = ~/attrs\n", None),
            Some(home.join("attrs")),
            "`~/` must be expanded, exactly as git expands `core.excludesFile`"
        );
        assert_eq!(
            resolve(
                "[core]\n\tattributesFile = /elsewhere/attrs\n",
                Some("/xdg")
            ),
            Some(PathBuf::from("/elsewhere/attrs")),
            "an absolute path must be taken as written, XDG or no XDG"
        );
        assert_eq!(
            resolve("[core]\n\tattributesFile = \n", Some("/xdg")),
            None,
            "an empty value turns the file off — and does **not** fall back to XDG"
        );
    }

    #[test]
    fn an_empty_value_is_false_to_git_and_must_be_false_here() {
        // Measured on git 2.55: `git config --type=bool` reads `key` (no `=`) as
        // `true` and `key = ` as `false`. `gix-config` reports the two
        // identically once they are flattened to a string, so this is the one
        // place the difference can be kept. Getting it wrong let
        // `filter.git-xcrypt.required = ` read as enabled while git ignored the
        // failing filter and stored the plaintext, and `status` saw no gap.
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("config");
        std::fs::write(
            &path,
            "[filter \"git-xcrypt\"]\n\trequired = \n[core]\n\tautocrlf =   \n",
        )
        .expect("writing must succeed");

        let config = open_local(&path).expect("valid config");
        for key in ["filter.git-xcrypt.required", "core.autocrlf"] {
            let value = get(&config, key).unwrap_or_else(|| panic!("{key} must read as present"));
            assert!(
                !is_true(&value),
                "{key} = `{value}` was taken for true, which git does not"
            );
        }
    }
}
