//! Making git look at a file again after `unlock` rewrote it.
//!
//! Rewriting a working-tree file in place is not enough to leave `git status`
//! clean, and the reason is a shortcut inside git. The index caches the `stat`
//! of every file next to the object id of its **cleaned** content. When the
//! cached size differs from the size on disk, git concludes the content changed
//! and stops there — it never runs the clean filter to check. For an unfiltered
//! file that shortcut is sound: a different size is a different file. For a
//! filtered one it is not, and `unlock` hits it head on, because a clone checked
//! out without a key recorded the size of the *ciphertext*, and the file is now
//! its plaintext, 38 bytes shorter.
//!
//! Measured on git 2.55, in a clone unlocked with the right key:
//!
//! ```text
//! git hash-object --path secrets/db.env -- secrets/db.env  → b51d5ac…  (matches the index)
//! git update-index --refresh                               → "needs update"
//! git status --porcelain                                   → " M secrets/db.env"
//! ```
//!
//! The content is right, the blob is right, and git still reports a change —
//! permanently, since the refresh never succeeds and so never rewrites the entry.
//! Zeroing the cached size flips it: git's own comment in `read-cache.c` says
//! that a zero length means "we have never even read the `lstat` information
//! once", so it has to go to the filesystem and compare content. Measured, same
//! repository: after zeroing, refresh exits 0 and `git status` is clean.
//!
//! So this module edits four bytes per affected entry and nothing else. It does
//! not rebuild the index: writing it out through a library would silently drop
//! the extensions that library does not know how to write — the split-index
//! link above all, whose loss is not a slow `git status` but a destroyed index.
//! Patching in place preserves every byte we did not mean to change, and the
//! trailing checksum is verified before the edit and recomputed after it, so a
//! file that is not shaped the way we think is left alone rather than mangled.

use std::fs;
use std::path::Path;

use crate::{Error, Result};

/// `DIRC`, then the version and the entry count.
const HEADER_LEN: usize = 12;

/// What the index looked like, and what was done to it.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The cached size was cleared for this many entries.
    Cleared(usize),
    /// Nothing was written, and why. Never a failure: the working tree is
    /// already correct, so this costs a noisy `git status`, not data.
    Skipped(String),
}

/// Makes git re-read `paths` by forgetting the size it cached for them.
///
/// `paths` are repository-relative and spelled with forward slashes, the way
/// the index stores them.
///
/// # Errors
///
/// [`Error::Io`] when the index exists but cannot be read or replaced.
pub fn forget_stat(index_path: &Path, hash: gix_hash::Kind, paths: &[Vec<u8>]) -> Result<Outcome> {
    if paths.is_empty() {
        return Ok(Outcome::Cleared(0));
    }

    let mut data = match fs::read(index_path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Outcome::Skipped(format!(
                "{} does not exist, so there is no stat cache to refresh",
                index_path.display()
            )));
        }
        Err(err) => return Err(Error::Io(err)),
    };

    let hash_len = hash.len_in_bytes();
    if data.len() < HEADER_LEN + hash_len || !data.starts_with(b"DIRC") {
        return Ok(skipped(
            index_path,
            "it is not an index this build can read",
        ));
    }

    let body_len = data.len() - hash_len;
    let recorded = &data[body_len..];
    // `index.skipHash` writes zeroes here and tells git not to verify. Keeping
    // that promise means writing zeroes back rather than filling it in.
    let skip_hash = recorded.iter().all(|byte| *byte == 0);
    if !skip_hash {
        let Some(digest) = checksum(&data[..body_len], hash) else {
            return Ok(skipped(index_path, "its checksum could not be computed"));
        };
        if digest != recorded {
            return Ok(skipped(
                index_path,
                "its checksum does not match its contents",
            ));
        }
    }

    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if !(2..=4).contains(&version) {
        return Ok(skipped(
            index_path,
            &format!("it is version {version}, which this build does not know"),
        ));
    }

    let Some(fields) = size_fields(&data[..body_len], version, count, hash_len, paths) else {
        return Ok(skipped(index_path, "its entries did not parse"));
    };
    if fields.is_empty() {
        return Ok(Outcome::Cleared(0));
    }

    for offset in &fields {
        data[*offset..*offset + 4].fill(0);
    }
    if !skip_hash {
        let Some(digest) = checksum(&data[..body_len], hash) else {
            return Ok(skipped(index_path, "its checksum could not be computed"));
        };
        data[body_len..].copy_from_slice(&digest);
    }

    match replace_under_lock(index_path, &data) {
        Ok(()) => Ok(Outcome::Cleared(fields.len())),
        Err(Error::Config(message)) => Ok(Outcome::Skipped(message)),
        Err(other) => Err(other),
    }
}

/// The usual shape of a refusal, with an instruction the user can act on.
fn skipped(index_path: &Path, why: &str) -> Outcome {
    Outcome::Skipped(format!(
        "{} was left alone because {why}. The files are decrypted correctly; if \
         `git status` shows them as modified, `git add --renormalize .` settles it.",
        index_path.display()
    ))
}

/// The index checksum over `body`.
fn checksum(body: &[u8], hash: gix_hash::Kind) -> Option<Vec<u8>> {
    let mut hasher = gix_hash::hasher(hash);
    hasher.update(body);
    hasher
        .try_finalize()
        .ok()
        .map(|digest| digest.as_slice().to_vec())
}

/// Offsets of the `size` field of every entry naming one of `paths`.
///
/// Returns `None` for anything that does not parse exactly, which is what keeps
/// a misread from turning into a patched byte in the wrong place.
///
/// The layout, identical in every index version: `ctime` (8), `mtime` (8),
/// `dev`, `ino`, `mode`, `uid`, `gid`, `size` (4 each), the object id, then a
/// 16-bit flags word. Only the name differs — versions 2 and 3 store it
/// NUL-terminated and pad the entry to a multiple of eight, version 4 stores it
/// as "strip this many bytes off the previous name, then append this" with no
/// padding at all.
fn size_fields(
    body: &[u8],
    version: u32,
    count: usize,
    hash_len: usize,
    paths: &[Vec<u8>],
) -> Option<Vec<usize>> {
    /// Offset of the `size` field from the start of an entry.
    const SIZE_FIELD: usize = 36;
    // Everything before the name: the stat block, the object id, the flags.
    let fixed = 40 + hash_len + 2;

    let mut fields = Vec::new();
    let mut cursor = HEADER_LEN;
    let mut previous: Vec<u8> = Vec::new();

    for _ in 0..count {
        let start = cursor;
        let flags_at = start.checked_add(40 + hash_len)?;
        if body.len() < flags_at + 2 {
            return None;
        }
        let flags = u16::from_be_bytes([body[flags_at], body[flags_at + 1]]);
        let extended = flags & 0x4000 != 0;
        let declared = usize::from(flags & 0x0fff);

        let mut at = start + fixed;
        if version >= 3 && extended {
            at += 2;
        }
        if at > body.len() {
            return None;
        }

        let name = if version < 4 {
            // A declared length of 0xfff means "longer than this field can
            // say"; only then is the NUL the sole authority.
            let end = if declared < 0x0fff {
                let end = at.checked_add(declared)?;
                if body.len() <= end || body[end] != 0 {
                    return None;
                }
                end
            } else {
                at + body[at..].iter().position(|byte| *byte == 0)?
            };
            // Git pads each entry to a multiple of eight, always leaving at
            // least one NUL after the name.
            cursor = start + (((end - start) + 8) & !7);
            body[at..end].to_vec()
        } else {
            let (strip, used) = varint(body.get(at..)?)?;
            let suffix_at = at + used;
            let end = suffix_at + body.get(suffix_at..)?.iter().position(|byte| *byte == 0)?;
            if strip > previous.len() {
                return None;
            }
            cursor = end + 1;
            let mut name = previous[..previous.len() - strip].to_vec();
            name.extend_from_slice(&body[suffix_at..end]);
            name
        };

        if cursor > body.len() {
            return None;
        }
        if paths.iter().any(|path| path.as_slice() == name.as_slice()) {
            fields.push(start + SIZE_FIELD);
        }
        previous = name;
    }

    Some(fields)
}

/// Git's variable-width integer, as version 4 uses it for the prefix length.
///
/// Returns the value and how many bytes it took. A port of git's
/// `decode_varint`, which is not the usual LEB128: each continuation adds one
/// before shifting, so no value has two encodings.
fn varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut index = 1;
    let mut byte = *bytes.first()?;
    let mut value = usize::from(byte & 0x7f);

    while byte & 0x80 != 0 {
        // Ten bytes is already far past any plausible path length; the bound
        // is here so a corrupt index cannot spin.
        if index >= 10 {
            return None;
        }
        value = value.checked_add(1)?;
        byte = *bytes.get(index)?;
        index += 1;
        value = value
            .checked_mul(128)?
            .checked_add(usize::from(byte & 0x7f))?;
    }

    Some((value, index))
}

/// Replaces the index through `index.lock`, the way git itself does.
///
/// Using git's own lock name rather than a private temporary file is what makes
/// this safe next to a concurrent git: whoever creates the lock first wins, and
/// the other backs off.
///
/// # Errors
///
/// [`Error::Config`] when the lock is already held — a refusal, not a failure —
/// and [`Error::Io`] when the write itself fails.
fn replace_under_lock(index_path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let lock = index_path.with_extension("lock");
    let mut options = fs::OpenOptions::new();
    let mut file = match options.write(true).create_new(true).open(&lock) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::Config(format!(
                "{} is held by another git process, so the stat cache was left alone. \
                 The files are decrypted correctly; if `git status` shows them as \
                 modified, `git add --renormalize .` settles it.",
                lock.display()
            )));
        }
        Err(err) => return Err(Error::Io(err)),
    };

    let result = (|| -> std::io::Result<()> {
        if let Ok(existing) = fs::metadata(index_path) {
            file.set_permissions(existing.permissions())?;
        }
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);

    if let Err(err) = result {
        let _ = fs::remove_file(&lock);
        return Err(Error::Io(err));
    }
    if let Err(err) = fs::rename(&lock, index_path) {
        let _ = fs::remove_file(&lock);
        return Err(Error::Io(err));
    }
    Ok(())
}

/// The hash a repository's index is checksummed with.
///
/// SHA-1 unless the repository says otherwise, which is what git assumes too.
#[must_use]
pub fn object_hash(object_format: Option<&str>) -> gix_hash::Kind {
    match object_format {
        Some(format) if format.eq_ignore_ascii_case("sha256") => gix_hash::Kind::Sha256,
        _ => gix_hash::Kind::Sha1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// A repository with two committed files and an index of `version`.
    fn repo_with_index(version: u32) -> TempDir {
        let dir = TempDir::new().expect("temporary directory");
        let run = |args: &[&str]| {
            let ok = Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .status()
                .expect("git must be on PATH")
                .success();
            assert!(ok, "git {args:?} failed");
        };
        run(&["init", "-q"]);
        run(&["config", "user.name", "t"]);
        run(&["config", "user.email", "t@t.invalid"]);
        for name in [
            "a.txt",
            "deep/nested/b.txt",
            "deep/nested/c-with-a-long-name.txt",
        ] {
            let path = dir.path().join(name);
            fs::create_dir_all(path.parent().expect("a parent")).expect("directories");
            fs::write(&path, format!("content of {name}\n")).expect("writing");
        }
        run(&["add", "-A"]);
        run(&["commit", "-q", "-m", "files"]);
        run(&["update-index", &format!("--index-version={version}")]);
        dir
    }

    fn index_of(dir: &TempDir) -> std::path::PathBuf {
        dir.path().join(".git").join("index")
    }

    fn recorded_size(dir: &TempDir, path: &str) -> u64 {
        let output = Command::new("git")
            .args(["ls-files", "--debug", "--", path])
            .current_dir(dir.path())
            .output()
            .expect("git must be on PATH");
        let text = String::from_utf8(output.stdout).expect("git printed non-UTF-8");
        let line = text
            .lines()
            .find(|line| line.trim_start().starts_with("size:"))
            .expect("ls-files --debug always prints a size");
        line.trim_start()
            .trim_start_matches("size:")
            .split_whitespace()
            .next()
            .expect("a number")
            .parse()
            .expect("a number")
    }

    /// Whether git still accepts the index, and what it says about the tree.
    fn git_status(dir: &TempDir) -> String {
        let output = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(dir.path())
            .output()
            .expect("git must be on PATH");
        assert!(
            output.status.success(),
            "git rejected the patched index: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("git printed non-UTF-8")
    }

    #[test]
    fn every_index_version_survives_the_patch() {
        for version in [2u32, 3, 4] {
            let dir = repo_with_index(version);
            assert!(recorded_size(&dir, "deep/nested/b.txt") > 0);

            let outcome = forget_stat(
                &index_of(&dir),
                gix_hash::Kind::Sha1,
                &[b"deep/nested/b.txt".to_vec()],
            )
            .expect("patching must succeed");

            assert_eq!(
                outcome,
                Outcome::Cleared(1),
                "index version {version} was not patched"
            );
            assert_eq!(
                recorded_size(&dir, "deep/nested/b.txt"),
                0,
                "index version {version}: the size was not cleared"
            );
            assert!(
                recorded_size(&dir, "a.txt") > 0,
                "index version {version}: an untargeted entry was cleared too"
            );
            assert_eq!(
                git_status(&dir),
                "",
                "index version {version}: git saw a change that is not there"
            );
        }
    }

    #[test]
    fn a_path_that_is_not_in_the_index_changes_nothing() {
        let dir = repo_with_index(2);
        let before = fs::read(index_of(&dir)).expect("reading the index");

        let outcome = forget_stat(
            &index_of(&dir),
            gix_hash::Kind::Sha1,
            &[b"never-existed".to_vec()],
        )
        .expect("patching must succeed");

        assert_eq!(outcome, Outcome::Cleared(0));
        assert_eq!(before, fs::read(index_of(&dir)).expect("reading the index"));
    }

    #[test]
    fn a_damaged_index_is_left_exactly_as_it_was() {
        let dir = repo_with_index(2);
        let path = index_of(&dir);
        let mut data = fs::read(&path).expect("reading the index");
        // A byte in the middle of the entries: the checksum no longer matches,
        // which is the signal that this file is not what we think it is.
        let middle = data.len() / 2;
        data[middle] ^= 0xff;
        fs::write(&path, &data).expect("writing");

        let outcome = forget_stat(&path, gix_hash::Kind::Sha1, &[b"a.txt".to_vec()])
            .expect("a damaged index is not our failure");

        assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
        assert_eq!(data, fs::read(&path).expect("reading the index"));
    }

    #[test]
    fn a_held_lock_stops_the_patch_rather_than_racing_git() {
        let dir = repo_with_index(2);
        let path = index_of(&dir);
        fs::write(path.with_extension("lock"), b"").expect("taking the lock");
        let before = fs::read(&path).expect("reading the index");

        let outcome = forget_stat(&path, gix_hash::Kind::Sha1, &[b"a.txt".to_vec()])
            .expect("a held lock is not our failure");

        assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
        assert_eq!(before, fs::read(&path).expect("reading the index"));
    }

    #[test]
    fn there_is_nothing_to_do_without_an_index() {
        let dir = TempDir::new().expect("temporary directory");
        let outcome = forget_stat(
            &dir.path().join("index"),
            gix_hash::Kind::Sha1,
            &[b"a.txt".to_vec()],
        )
        .expect("an absent index is not our failure");
        assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
    }

    #[test]
    fn the_object_format_decides_the_hash() {
        assert_eq!(object_hash(None), gix_hash::Kind::Sha1);
        assert_eq!(object_hash(Some("sha1")), gix_hash::Kind::Sha1);
        assert_eq!(object_hash(Some("SHA256")), gix_hash::Kind::Sha256);
    }

    #[test]
    fn the_variable_width_integer_matches_gits_encoding() {
        // Values git itself produces: one byte below 128, and the two-byte form
        // that starts at 128 because the continuation adds one before shifting.
        assert_eq!(varint(&[0x00]), Some((0, 1)));
        assert_eq!(varint(&[0x7f]), Some((127, 1)));
        assert_eq!(varint(&[0x80, 0x00]), Some((128, 2)));
        assert_eq!(varint(&[0x80, 0x01]), Some((129, 2)));
        assert_eq!(varint(&[0x81, 0x00]), Some((256, 2)));
        assert_eq!(varint(&[]), None);
        assert_eq!(varint(&[0x80]), None, "a truncated integer must not parse");
    }
}
