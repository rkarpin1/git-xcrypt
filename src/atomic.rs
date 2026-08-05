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
//!
//! The key file goes through [`write_owner_only`] rather than [`write`]: it has
//! the same half-written failure — a truncated key file is a repository nobody
//! can decrypt again — but the opposite permission rule, since inheriting a
//! loose mode from whatever was there before is exactly what a key must not do.
//!
//! The temporary file is created with `O_EXCL` and an unguessable name, which is
//! not tidiness. Without `O_EXCL` the name is merely a name: anyone able to
//! write the destination directory could pre-create it as a symlink, and
//! `File::create` would follow the link, write the master key wherever it points
//! and then rename the link over the destination. `export-key ~/keys/repo.key`
//! is a private directory, but `export-key /tmp/repo.key` is not, and the
//! command whose whole job is to hand over a key is the wrong place to rely on
//! the user picking a safe directory.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// How the replacement file's permissions are decided.
#[derive(Debug, Clone, Copy)]
enum Mode {
    /// Keep whatever the target had. A file that did not exist gets the
    /// process default, which is what git itself would have produced.
    InheritTarget,
    /// Owner-only, whatever the target had. For key material, where inheriting
    /// a loose mode from a file that happened to be there is exactly wrong.
    OwnerOnly,
}

/// Writes `contents` to `path`, replacing it in one step.
///
/// The temporary file lives beside the target, because `rename` across
/// filesystems is not a rename at all and would fall back to a copy.
///
/// Three limits worth knowing rather than discovering.
///
/// A target that is a symlink is replaced by a regular file, where `fs::write`
/// would have followed the link — `.gitattributes` under a dotfile manager is
/// the case where that shows. A target that is one of several hard links to the
/// same inode loses the link for the same reason. And the temporary file is only
/// cleaned up on a returned error, so a process killed outright can leave one
/// behind.
///
/// That last one is not always harmless. `unlock` replaces working-tree files
/// through here, so on that path the leftover holds a **decrypted secret** under
/// a name no `.git-xcrypt` pattern was written for — `secrets/` still covers it,
/// `*.env` does not. It inherits the target's permissions, which for a file git
/// checked out means it is no more readable than the file it replaces, but a
/// later `git add -A` could store it in the clear. There is no portable way to
/// clean up after `SIGKILL`; the residue is recorded here rather than hidden.
/// Every such file is recognised by [`is_temporary_name`], which is what the
/// user documentation has to tell people to look for after a killed `unlock` —
/// and what `lock` sweeps before it encrypts, since a plaintext leftover would
/// otherwise survive the one command whose job is to leave none.
///
/// # Errors
///
/// [`Error::Io`] when the temporary file cannot be created, written, flushed or
/// renamed. On failure the target is left exactly as it was.
pub fn write(path: &Path, contents: &[u8]) -> Result<()> {
    replace(path, contents, Mode::InheritTarget)
}

/// Writes `contents` to `path` with owner-only permissions, in one step.
///
/// The same replacement as [`write`], with two differences that matter only for
/// key material: the file is created `0600` before a single byte reaches it, and
/// the target's permissions are **not** inherited — a key file that was somehow
/// left world readable must not stay that way.
///
/// **On Windows there is no mode to set, so nothing here narrows anything**: the
/// file inherits the ACL of the directory it is created in. For the repository's
/// own key that is the protection git gives `.git/config`, which is the same
/// protection as the rest of the checkout. For `export-key` the user picks the
/// directory, so the directory *is* the protection. Weaker than `0600` either
/// way, and recorded as a limitation in `README.md` §Known limitations and in
/// `context/foundation/zalozenia.md` — the founding document claimed owner-only
/// ACLs here until 2026-08-05, which was never true of any build.
///
/// # Errors
///
/// As [`write`].
pub fn write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    replace(path, contents, Mode::OwnerOnly)
}

fn replace(path: &Path, contents: &[u8], mode: Mode) -> Result<()> {
    let (temporary, mut file) = create_temporary(path, mode)?;

    let result = (|| -> std::io::Result<()> {
        // A fresh file gets 0666 minus the umask, so without this a deliberately
        // narrowed `.git/config` — the one that holds credential helpers and
        // remote URLs — would come back world readable. It happens before the
        // first write, so there is no window in which the content is on disk
        // under looser permissions than the file it replaces.
        if matches!(mode, Mode::InheritTarget)
            && let Ok(existing) = fs::metadata(path)
        {
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

/// Creates a fresh file next to `path`, and only ever a fresh one.
///
/// `create_new` is `O_EXCL`: it fails rather than opening anything that is
/// already there, symlink included, which is what keeps a pre-created link from
/// redirecting the write. The name is random rather than derived from the
/// process id, so it cannot be predicted and pre-created in the first place;
/// `O_EXCL` alone would then turn the attack into a denial of service, hence the
/// retries.
///
/// A key file is created at `0600` from the outset, so its content is never on
/// disk under a wider mode even for an instant.
fn create_temporary(path: &Path, mode: Mode) -> Result<(PathBuf, fs::File)> {
    let name = path.file_name().ok_or_else(|| {
        Error::Io(std::io::Error::other(format!(
            "{} does not name a file",
            path.display()
        )))
    })?;

    #[cfg(not(unix))]
    let _ = mode;

    const ATTEMPTS: usize = 8;
    for _ in 0..ATTEMPTS {
        let candidate = path.with_file_name(temporary_name(name)?);

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if matches!(mode, Mode::OwnerOnly) {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }

        match options.open(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(Error::Io(err)),
        }
    }

    // Eight random names taken in a row is not luck. Reporting the last
    // `AlreadyExists` would name a file the user never chose and read as "the
    // destination is in the way", which is the opposite of what happened.
    Err(Error::Io(std::io::Error::other(format!(
        "could not write {}: {ATTEMPTS} temporary names beside it were all taken",
        path.display()
    ))))
}

/// What every temporary name carries between the target's name and `.tmp`.
const MARKER: &[u8] = b".git-xcrypt-";

/// How many random bytes go into a temporary name.
const RANDOM_LEN: usize = 8;

/// The longest single name a filesystem will normally take, in bytes.
///
/// `NAME_MAX` is 255 on ext4, APFS, HFS+, XFS and NTFS alike. Nothing here reads
/// the real limit — there is no portable way to — so this is the floor every
/// target platform meets.
const MAX_NAME: usize = 255;

/// A sibling name no one can guess and therefore no one can pre-create.
///
/// The target's own name is **shortened when the suffix would not fit**. Git
/// puts no such ceiling on a path: a file whose name is 224 bytes or longer
/// commits and checks out perfectly, and before this the sibling name came to
/// 256 bytes and `create_temporary` failed with `ENAMETOOLONG`. Measured, on a
/// repository holding one such file: `lock` exited 1 saying "running lock again
/// finishes the job", which was false — it failed identically for ever, so the
/// repository could never be closed and the secret stayed in the clear.
///
/// The cost of shortening is that [`strip_temporary_suffix`] then reconstructs a
/// *truncated* target, so residue left by a killed run on such a file may not be
/// recognised as belonging to a declared path and may go unswept. That is the
/// same outcome residue under an undeclared path already has, and it replaces a
/// command that could not run at all.
fn temporary_name(name: &std::ffi::OsStr) -> Result<OsString> {
    let mut random = [0u8; RANDOM_LEN];
    getrandom::fill(&mut random).map_err(|err| Error::Entropy(err.to_string()))?;

    let suffix = format!(
        "{}{}.tmp",
        String::from_utf8_lossy(MARKER),
        crate::hex(&random)
    );

    let mut temporary = shorten(name, MAX_NAME.saturating_sub(suffix.len()));
    temporary.push(suffix);
    Ok(temporary)
}

/// `name`, cut down to at most `limit` bytes.
///
/// A file name is an arbitrary byte string on Unix, so the cut is by bytes and
/// may land inside a multi-byte character — which is fine for a name nothing
/// ever decodes. On other platforms the name goes through its lossy text form,
/// which is what every other path in this crate does with a Windows name.
fn shorten(name: &std::ffi::OsStr, limit: usize) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
        let bytes = name.as_bytes();
        if bytes.len() <= limit {
            return name.to_os_string();
        }
        OsString::from_vec(bytes[..limit].to_vec())
    }
    #[cfg(not(unix))]
    {
        let text = name.to_string_lossy();
        if text.len() <= limit {
            return name.to_os_string();
        }
        let mut cut = limit;
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        OsString::from(&text[..cut])
    }
}

/// The target a temporary file was named after, if `name` is one of ours.
///
/// A process killed outright cannot clean up after itself, and on the `unlock`
/// and `lock` paths the residue holds a **decrypted secret**. `lock` promises
/// that no plaintext of a selected path survives it, so it has to recognise
/// residue — and, because it deletes what it recognises, it has to recognise it
/// *narrowly*. Returning the target rather than a yes/no is what lets the caller
/// add the second condition that makes deletion safe: only sweep residue whose
/// target the declaration actually selects.
///
/// Deliberately exact. The marker must be followed by exactly [`RANDOM_LEN`]
/// bytes of **lowercase** hex — the only kind [`temporary_name`] emits — then
/// `.tmp`, and something must precede the marker, because these names are always
/// built from a target's own name. A file a user happens to have called
/// `notes.git-xcrypt-draft.tmp` is not matched, and neither is
/// `notes.git-xcrypt-DEADBEEFDEADBEEF.tmp`.
#[must_use]
pub fn strip_temporary_suffix(name: &[u8]) -> Option<&[u8]> {
    let rest = name.strip_suffix(b".tmp")?;
    let head = rest.get(..rest.len().checked_sub(RANDOM_LEN * 2)?)?;
    let hex = &rest[head.len()..];

    if !hex
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    let target = head.strip_suffix(MARKER)?;
    (!target.is_empty()).then_some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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

    #[cfg(unix)]
    #[test]
    fn an_owner_only_write_narrows_a_loose_target_instead_of_inheriting_it() {
        // The opposite rule from the one above, and deliberately so: a key file
        // that was left world readable must come back owner-only, never keep the
        // mode it happened to have.
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("default");
        fs::write(&path, b"world readable placeholder").expect("writing must succeed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

        write_owner_only(&path, b"key material").expect("writing must succeed");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "a key file kept loose permissions");
    }

    #[test]
    fn a_temporary_file_never_reuses_a_name_and_never_opens_an_existing_one() {
        // The name used to be `<target>.git-xcrypt-<pid>.tmp`: predictable, and
        // opened without `O_EXCL`, so anyone able to write the directory could
        // pre-create it as a symlink and have the master key written through it.
        let dir = TempDir::new().expect("temporary directory");
        let target = dir.path().join("repo.key");

        let (first, _held) = create_temporary(&target, Mode::OwnerOnly).expect("first");
        let (second, _also) = create_temporary(&target, Mode::OwnerOnly).expect("second");

        assert_ne!(first, second, "two runs picked the same temporary name");
        assert!(
            create_temporary(&first, Mode::OwnerOnly).is_ok(),
            "a name in use must simply be skipped"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_key_temporary_is_owner_only_before_any_content_reaches_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().expect("temporary directory");
        let (path, _held) =
            create_temporary(&dir.path().join("repo.key"), Mode::OwnerOnly).expect("creating");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the key would have been world readable while it was being written"
        );
    }
}
