//! Reading and writing git configuration through a library.
//!
//! Spawning `git config` is not an option: git starts a filter process per
//! operation, so it would be N process spawns on the hot path — most expensive
//! on exactly the platform where it hurts most. Writing only ever touches the
//! repository-local file, which is the only one this tool has business changing.

use std::path::Path;

use bstr::ByteSlice as _;
use gix_config::File;
use gix_config::file::Metadata;

use crate::{Error, Result};

/// The repository-local configuration, loaded for editing.
///
/// Includes are deliberately not followed: we are about to write this file back,
/// and following includes would fold someone else's file into ours.
///
/// # Errors
///
/// [`Error::Config`] when the file exists but cannot be parsed.
pub fn open_local(path: &Path) -> Result<File> {
    if !path.exists() {
        return Ok(File::new(Metadata::from(gix_config::Source::Local)));
    }
    File::from_path_no_includes(path.to_path_buf(), gix_config::Source::Local)
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
/// # Errors
///
/// [`Error::Config`] when a file in the cascade cannot be parsed.
pub fn open_full(git_dir: &Path) -> Result<File> {
    File::from_git_dir(git_dir.to_path_buf())
        .map_err(|err| Error::Config(format!("could not read git configuration: {err}")))
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
