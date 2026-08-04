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
/// Two limits worth knowing rather than discovering. A target that is a symlink
/// is replaced by a regular file, where `fs::write` would have followed the link
/// — `.gitattributes` under a dotfile manager is the case where that shows. And
/// the temporary file is only cleaned up on a returned error, so a process
/// killed outright can leave one behind; it is attribute text, never a secret.
///
/// # Errors
///
/// [`Error::Io`] when the temporary file cannot be created, written, flushed or
/// renamed. On failure the target is left exactly as it was.
pub fn write(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = temporary_sibling(path)?;

    let result = (|| -> std::io::Result<()> {
        let mut file = fs::File::create(&temporary)?;
        // A fresh file gets 0666 minus the umask, so without this a deliberately
        // narrowed `.git/config` — the one that holds credential helpers and
        // remote URLs — would come back world readable.
        if let Ok(existing) = fs::metadata(path) {
            file.set_permissions(existing.permissions())?;
        }
        file.write_all(contents)?;
        // Without this the rename can land before the content does, which on a
        // crash leaves an empty file where a complete one is expected.
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        sync_directory(path);
        Ok(())
    })();

    if result.is_err() {
        // Best effort: a leftover temporary file is untidy, not dangerous.
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(Error::Io)
}

/// Flushes the directory entry the rename just created.
///
/// Without it the promise above holds only where the target already existed: a
/// crash right after `init` could otherwise leave a repository with a key, a
/// filter registration and no `.gitattributes` at all — which is the state where
/// git stores plaintext and reports success. Best effort, and a no-op on
/// platforms that do not allow opening a directory.
fn sync_directory(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(directory) = fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }
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

    #[cfg(unix)]
    #[test]
    fn a_narrowed_target_keeps_its_permissions() {
        // `.git/config` carries credential helpers and remote URLs, so a user
        // who chmods it to 0600 must not have it widened by a `sync`.
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("config");
        fs::write(&path, b"[core]\n").expect("writing must succeed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

        write(&path, b"[core]\n\tbare = false\n").expect("writing must succeed");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the file was widened by the rewrite");
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
