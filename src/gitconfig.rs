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
/// but has no raw value to return. It comes back as `Some("")` so callers can
/// tell it from an absent key; every git spelling of true includes that one.
#[must_use]
pub fn get(config: &File, key: &str) -> Option<String> {
    if let Ok(value) = config.raw_value(key) {
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

    present.then(String::new)
}

/// Whether a value is one of git's spellings of true.
///
/// Git accepts `1`, `yes` and `on` beside `true`, and a key written with no
/// value at all — which [`get`] reports as `Some("")` — is true as well. Every
/// caller that branches on a git boolean has to accept the same set, or a
/// perfectly ordinary `required = 1` reads as "off".
#[must_use]
pub fn is_true(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1" | ""
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn a_value_round_trips_through_a_file() {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("config");

        let mut config = open_local(&path).expect("an absent file is an empty config");
        set(&mut config, "filter.git-xcrypt.required", "true").expect("setting must succeed");
        save_local(&path, &config).expect("saving must succeed");

        let reloaded = open_local(&path).expect("the file we just wrote must parse");
        assert_eq!(
            get(&reloaded, "filter.git-xcrypt.required").as_deref(),
            Some("true")
        );
    }

    #[test]
    fn an_absent_key_reads_as_none() {
        let dir = TempDir::new().expect("temporary directory");
        let config = open_local(&dir.path().join("config")).expect("empty config");
        assert!(get(&config, "filter.git-xcrypt.process").is_none());
    }

    #[test]
    fn setting_twice_keeps_the_last_value() {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("config");

        let mut config = open_local(&path).expect("empty config");
        set(&mut config, "core.autocrlf", "true").expect("setting must succeed");
        set(&mut config, "core.autocrlf", "input").expect("setting must succeed");
        save_local(&path, &config).expect("saving must succeed");

        let reloaded = open_local(&path).expect("valid config");
        assert_eq!(get(&reloaded, "core.autocrlf").as_deref(), Some("input"));
    }

    #[test]
    fn existing_content_is_preserved() {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("config");
        std::fs::write(&path, "[user]\n\tname = Someone\n").expect("writing must succeed");

        let mut config = open_local(&path).expect("valid config");
        set(&mut config, "filter.git-xcrypt.required", "true").expect("setting must succeed");
        save_local(&path, &config).expect("saving must succeed");

        let reloaded = open_local(&path).expect("valid config");
        assert_eq!(get(&reloaded, "user.name").as_deref(), Some("Someone"));
    }

    #[test]
    fn a_key_written_without_a_value_is_present_not_absent() {
        // `[core]\n\tautocrlf` is true to git. It has no raw value, so reporting
        // it as absent made the whole CRLF table fall through to `core.eol`.
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("config");
        std::fs::write(&path, "[core]\n\tautocrlf\n").expect("writing must succeed");

        let config = open_local(&path).expect("valid config");
        assert_eq!(get(&config, "core.autocrlf").as_deref(), Some(""));
        assert!(get(&config, "core.eol").is_none());
    }

    #[test]
    fn unsetting_removes_a_key_and_leaves_its_neighbours() {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("config");

        let mut config = open_local(&path).expect("empty config");
        set(&mut config, "diff.git-xcrypt.textconv", "gone").expect("setting");
        set(&mut config, "filter.git-xcrypt.required", "true").expect("setting");
        unset(&mut config, "diff.git-xcrypt.textconv").expect("unsetting must succeed");
        save_local(&path, &config).expect("saving must succeed");

        let reloaded = open_local(&path).expect("valid config");
        assert!(get(&reloaded, "diff.git-xcrypt.textconv").is_none());
        assert_eq!(
            get(&reloaded, "filter.git-xcrypt.required").as_deref(),
            Some("true")
        );
    }

    #[test]
    fn unsetting_an_absent_key_is_not_an_error() {
        let dir = TempDir::new().expect("temporary directory");
        let mut config = open_local(&dir.path().join("config")).expect("empty config");
        unset(&mut config, "diff.git-xcrypt.textconv").expect("unsetting must succeed");
    }

    #[test]
    fn a_subsection_key_survives_the_round_trip_with_its_case() {
        // Subsection names are case sensitive in git; `git-xcrypt` must come
        // back exactly as written or the driver stops being found.
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("config");

        let mut config = open_local(&path).expect("empty config");
        set(
            &mut config,
            "filter.git-xcrypt.process",
            "/bin/true process",
        )
        .expect("setting must succeed");
        save_local(&path, &config).expect("saving must succeed");

        let text = std::fs::read_to_string(&path).expect("reading must succeed");
        assert!(text.contains("git-xcrypt"), "written config was:\n{text}");
        let reloaded = open_local(&path).expect("valid config");
        assert_eq!(
            get(&reloaded, "filter.git-xcrypt.process").as_deref(),
            Some("/bin/true process")
        );
    }
}
