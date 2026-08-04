//! Replacing a file without a window in which it is half-written.
//!
//! Two files in this tool decide whether encryption happens at all: the managed
//! section of `.gitattributes`, which carries `* filter=git-xcrypt`, and
//! `.git/config`, which carries the driver registration. `fs::write` truncates
//! first and writes second, so a failure between the two — a full disk, a
//! crash, a power loss — leaves whichever file it hit short or empty. Git then
//! sees no filter at all and treats every path as plain: `git add` on a secret
//! succeeds with exit code 0 and stores the plaintext, with no signal to the
//! user. Truncating `.gitattributes` also loses whatever the user wrote outside
//! our markers, which the section-editing code promises to preserve.
//!
//! Writing a sibling file and renaming it over the target closes that window:
//! `rename` replaces the entry in one step on every platform this tool targets
//! (`MoveFileEx` with `MOVEFILE_REPLACE_EXISTING` on Windows), so a reader sees
//! either the old file or the new one.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Writes `contents` to `path`, replacing it in one step.
///
/// The temporary file lives beside the target, because `rename` across
/// filesystems is not a rename at all and would fall back to a copy.
///
/// # Errors
///
/// [`Error::Io`] when the temporary file cannot be created, written, flushed or
/// renamed. On failure the target is left exactly as it was.
pub fn write(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = temporary_sibling(path)?;

    let result = (|| -> std::io::Result<()> {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(contents)?;
        // Without this the rename can land before the content does, which on a
        // crash leaves an empty file where a complete one is expected.
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();

    if result.is_err() {
        // Best effort: a leftover temporary file is untidy, not dangerous.
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(Error::Io)
}

/// A path next to `path` that no concurrent run of this tool will pick.
fn temporary_sibling(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        Error::Io(std::io::Error::other(format!(
            "{} does not name a file",
            path.display()
        )))
    })?;

    let mut temporary = name.to_os_string();
    temporary.push(format!(".git-xcrypt-{}.tmp", std::process::id()));
    Ok(path.with_file_name(temporary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn a_new_file_is_created() {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join(".gitattributes");

        write(&path, b"* filter=git-xcrypt\n").expect("writing must succeed");

        assert_eq!(
            fs::read(&path).expect("reading must succeed"),
            b"* filter=git-xcrypt\n"
        );
    }

    #[test]
    fn an_existing_file_is_replaced_and_no_temporary_is_left_behind() {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join(".gitattributes");
        fs::write(&path, b"old\n").expect("writing must succeed");

        write(&path, b"new\n").expect("writing must succeed");

        assert_eq!(fs::read(&path).expect("reading"), b"new\n");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("listing")
            .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
            .filter(|name| name != ".gitattributes")
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    #[test]
    fn a_failure_leaves_the_target_untouched() {
        let dir = TempDir::new().expect("temporary directory");
        // A directory in place of the file: creating the temporary sibling
        // succeeds, renaming over a directory does not.
        let path = dir.path().join("occupied");
        fs::create_dir(&path).expect("creating the directory");

        assert!(write(&path, b"anything").is_err());
        assert!(path.is_dir(), "the target was replaced despite the failure");
    }
}
