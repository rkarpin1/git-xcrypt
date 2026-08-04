//! Reading and writing git configuration through a library.
//!
//! Spawning `git config` is not an option: git starts a filter process per
//! operation, so it would be N process spawns on the hot path — most expensive
//! on exactly the platform where it hurts most. Writing only ever touches the
//! repository-local file, which is the only one this tool has business changing.

use std::path::Path;

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

/// Writes a configuration file back to disk.
///
/// # Errors
///
/// [`Error::Io`] when the file cannot be written.
pub fn save_local(path: &Path, config: &File) -> Result<()> {
    std::fs::write(path, config.to_bstring())?;
    Ok(())
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

/// Reads a dotted key, if present.
#[must_use]
pub fn get(config: &File, key: &str) -> Option<String> {
    config.raw_value(key).ok().map(|value| value.to_string())
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
