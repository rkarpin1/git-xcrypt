//! Reading git's index, and making git look at a file again after it was
//! rewritten in place.
//!
//! Rewriting a working-tree file in place is not enough to leave `git status`
//! clean, and the reason is a shortcut inside git. The index caches the `stat`
//! of every file next to the object id of its **cleaned** content. When the
//! cached size differs from the size on disk, git concludes the content changed
//! and stops there — it never runs the clean filter to check. For an unfiltered
//! file that shortcut is sound: a different size is a different file. For a
//! filtered one it is not, and `unlock` hits it head on, because a clone checked
//! out without a key recorded the size of the *ciphertext*, and the file is now
//! its plaintext, 38 bytes shorter. `lock` hits the same wall going the other
//! way.
//!
//! The object ids the index stores are read here too, by [`staged_ids`]. That is
//! what lets `lock` answer "is this content already a blob in this repository"
//! without opening the object database: the index records the id of every
//! tracked path's *cleaned* content, and encryption is deterministic, so hashing
//! what the clean path would produce and comparing is exact.
//!
//! **Paths are matched as raw bytes, and callers supply them from `read_dir`.**
//! On a case-insensitive filesystem (`core.ignorecase`, the default on macOS and
//! Windows) and under `core.precomposeunicode`, the same file has two spellings:
//! git keeps the one it was added under, the directory keeps the one on disk.
//! Measured on git 2.55/APFS — a file added as `secret.env` and renamed to
//! `SECRET.env` reads as untracked here, and an NFD name on disk does not match
//! the NFC name in the index. The consequences are on the safe side for `lock`,
//! which then refuses rather than proceeds, and both callers now notice when a
//! name they know is tracked does not match. It is the same underlying gap as
//! the `core.ignorecase` question recorded against `S-02`, and closing it is a
//! decision about what a *pattern* means, not one this module can take.
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

    // The lock comes before the read, not between the read and the write. Git's
    // own protocol is lock-then-read for a reason: anything git writes to the
    // index in the meantime — a `git add` in another terminal, an IDE refreshing
    // in the background — would be silently reverted by our stale buffer, taking
    // the staged changes with it.
    let Some(lock) = Lock::acquire(index_path)? else {
        return Ok(Outcome::Skipped(format!(
            "{}.lock is held by another git process, so the stat cache was left \
             alone. The files are decrypted correctly; if `git status` shows them \
             as modified, `git add --renormalize .` settles it.",
            index_path.display()
        )));
    };

    let data = match fs::read(index_path) {
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
    let Index {
        mut data,
        body_len,
        version,
        count,
        skip_hash,
    } = match inspect(data, hash) {
        Ok(index) => index,
        Err(why) => return Ok(skipped(index_path, &why)),
    };

    let Some(scan) = scan(&data[..body_len], version, count, hash_len, paths) else {
        return Ok(skipped(index_path, "its entries did not parse"));
    };
    if scan.split_index {
        // The entries live in `.git/sharedindex.<oid>` and this file holds only
        // the differences, so there is nothing here to patch. Measured on git
        // 2.55 with `core.splitIndex=true`: without this branch the walk matched
        // nothing, reported success and left `git status` permanently dirty —
        // the exact failure this module exists to prevent, arriving silently.
        // `features.manyFiles=true` turns split index on wholesale.
        return Ok(skipped(
            index_path,
            "this repository uses a split index, whose entries live in a shared \
             file this build does not patch",
        ));
    }
    if scan.size_fields.is_empty() {
        // None of the rewritten files is tracked — an encrypted file a user
        // keeps in the working tree without committing it, for instance. There
        // is no cached stat to forget.
        return Ok(Outcome::Cleared(0));
    }

    for offset in &scan.size_fields {
        data[*offset..*offset + 4].fill(0);
    }
    if !skip_hash {
        let Some(digest) = checksum(&data[..body_len], hash) else {
            return Ok(skipped(index_path, "its checksum could not be computed"));
        };
        data[body_len..].copy_from_slice(&digest);
    }

    lock.commit(&data)?;
    Ok(Outcome::Cleared(scan.size_fields.len()))
}

/// What the index says about a set of paths.
#[derive(Debug, PartialEq, Eq)]
pub enum Staged {
    /// The object id the index records for each requested path, in the order
    /// they were asked for. `None` where the index has no stage-0 entry for it,
    /// which covers an untracked path and an unresolved conflict alike — both
    /// mean "this path's content is not simply stored here".
    Read(Vec<Option<Vec<u8>>>),
    /// The index could not be read, and why.
    ///
    /// A separate answer from "no entry", because the two must not be confused
    /// by a caller that refuses on the second: an unreadable index is not
    /// evidence that anything is unstored.
    Unavailable(String),
}

/// The object ids the index records for `paths`.
///
/// No lock is taken: git replaces the index by renaming a complete file over
/// it, so a reader sees one version or the other and never a half-written one.
/// [`forget_stat`] locks because it writes.
///
/// # Errors
///
/// [`Error::Io`] when the index exists but cannot be read. An index that does
/// not exist yet is not an error — nothing is tracked, so every answer is
/// `None`.
pub fn staged_ids(index_path: &Path, hash: gix_hash::Kind, paths: &[Vec<u8>]) -> Result<Staged> {
    let data = match fs::read(index_path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Staged::Read(vec![None; paths.len()]));
        }
        Err(err) => return Err(Error::Io(err)),
    };

    let index = match inspect(data, hash) {
        Ok(index) => index,
        Err(why) => return Ok(Staged::Unavailable(why)),
    };

    let mut found: Vec<Option<Vec<u8>>> = vec![None; paths.len()];
    let body = &index.data[..index.body_len];
    let walked = walk(
        body,
        index.version,
        index.count,
        hash.len_in_bytes(),
        &mut |entry| {
            // Stage 0 only. A path in the middle of a merge has entries at
            // stages 1 to 3 and no settled content at all, which has to read as
            // "not stored" rather than as whichever side happened to come last.
            if entry.stage != 0 {
                return;
            }
            // Every matching position, not the first: a caller is allowed to ask
            // about the same path twice, and answering only one of them would
            // leave the other reading as "not stored" — which for `lock` is the
            // difference between a file it keeps and a file it deletes.
            for (at, path) in paths.iter().enumerate() {
                if path.as_slice() == entry.name {
                    found[at] = Some(entry.id.to_vec());
                }
            }
        },
    );

    // `found` is published only on a complete walk. `visit` runs per entry, so a
    // walk that gives up half way has already filled part of it — and a partial
    // answer here would be a truthful-looking `Some(id)` beside a `None` that
    // only means "the parse stopped before reaching it", which is the value that
    // decides whether `lock` deletes a file.
    match walked {
        None => Ok(Staged::Unavailable("its entries did not parse".into())),
        Some(true) => Ok(Staged::Unavailable(
            "this repository uses a split index, whose entries live in a shared \
             file this build does not read"
                .into(),
        )),
        Some(false) => Ok(Staged::Read(found)),
    }
}

/// The object id git stores for `content` as a blob.
///
/// Git hashes `blob <length>\0` followed by the bytes. Deterministic encryption
/// is what makes this useful: hashing the ciphertext the clean path would
/// produce answers "is this working-tree file already stored" exactly, without
/// opening a single object.
#[must_use]
pub fn blob_id(hash: gix_hash::Kind, content: &[u8]) -> Option<Vec<u8>> {
    let mut hasher = gix_hash::hasher(hash);
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hasher
        .try_finalize()
        .ok()
        .map(|digest| digest.as_slice().to_vec())
}

/// An index this build is willing to act on.
struct Index {
    data: Vec<u8>,
    /// Everything before the trailing checksum.
    body_len: usize,
    version: u32,
    count: usize,
    /// The checksum was zeroed, as `index.skipHash` does, and must stay so.
    skip_hash: bool,
}

/// Validates the fixed parts of an index, or says why it cannot be used.
///
/// Shared by the reader and the writer so the two can never disagree about
/// which files they understand.
fn inspect(data: Vec<u8>, hash: gix_hash::Kind) -> std::result::Result<Index, String> {
    let hash_len = hash.len_in_bytes();
    if data.len() < HEADER_LEN + hash_len || !data.starts_with(b"DIRC") {
        return Err("it is not an index this build can read".into());
    }

    let body_len = data.len() - hash_len;
    let recorded = &data[body_len..];
    // `index.skipHash` writes zeroes here and tells git not to verify. Keeping
    // that promise means writing zeroes back rather than filling it in. A tail
    // zeroed by a bad write rather than by that setting is not covered by this
    // check, but is by the structural one in `walk`: the entry and extension
    // walk has to land exactly on the end of the data or nothing is written.
    let skip_hash = recorded.iter().all(|byte| *byte == 0);
    if !skip_hash {
        let Some(digest) = checksum(&data[..body_len], hash) else {
            return Err("its checksum could not be computed".into());
        };
        if digest != recorded {
            return Err("its checksum does not match its contents".into());
        }
    }

    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if !(2..=4).contains(&version) {
        return Err(format!(
            "it is version {version}, which this build does not know"
        ));
    }

    Ok(Index {
        data,
        body_len,
        version,
        count,
        skip_hash,
    })
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

/// What one pass over the index found.
#[derive(Debug)]
struct Scan {
    /// Offsets of the `size` field of every entry naming one of `paths`.
    size_fields: Vec<usize>,
    /// The index carries a `link` extension, so its entries are elsewhere.
    split_index: bool,
}

/// Offset of the `size` field from the start of an entry.
const SIZE_FIELD: usize = 36;

/// Offset of the object id from the start of an entry, after the stat block.
const ID_FIELD: usize = 40;

/// One index entry, as [`walk`] hands it over.
struct Entry<'a> {
    /// Offset of the entry from the start of the index.
    start: usize,
    /// The path, spelled exactly as the index spells it.
    name: &'a [u8],
    /// Object id of the entry's cleaned content.
    id: &'a [u8],
    /// Merge stage; anything but 0 is an unresolved conflict.
    stage: u8,
}

/// Finds the entries the caller asked about, if the whole index parses.
///
/// No stage filter, unlike [`staged_ids`], and the asymmetry is deliberate: this
/// one only zeroes a cached `stat`, and a conflicted entry carries a zeroed one
/// already, so clearing it changes nothing git will act on. Verified against git
/// 2.55 on a conflicted index in versions 2, 3 and 4 — the merge still resolved.
/// The only visible effect is that [`Outcome::Cleared`] counts the extra stages.
fn scan(
    body: &[u8],
    version: u32,
    count: usize,
    hash_len: usize,
    paths: &[Vec<u8>],
) -> Option<Scan> {
    let mut fields = Vec::new();
    let split_index = walk(body, version, count, hash_len, &mut |entry| {
        if paths.iter().any(|path| path.as_slice() == entry.name) {
            fields.push(entry.start + SIZE_FIELD);
        }
    })?;

    Some(Scan {
        size_fields: fields,
        split_index,
    })
}

/// Walks the entries and then the extensions, or gives up entirely.
///
/// Returns `None` for anything that does not parse exactly, which is what keeps
/// a misread from turning into a patched byte in the wrong place. The extension
/// walk is not only there to spot a split index: it has to consume the file to
/// its last byte, which is what proves the entry walk ended where it should
/// rather than somewhere plausible. `true` means the index carries a `link`
/// extension, so its entries live in a shared file this build does not open.
///
/// The entry layout is identical in every index version: `ctime` (8), `mtime`
/// (8), `dev`, `ino`, `mode`, `uid`, `gid`, `size` (4 each), the object id, then
/// a 16-bit flags word. Only the name differs — versions 2 and 3 store it
/// NUL-terminated and pad the entry to a multiple of eight, version 4 stores it
/// as "strip this many bytes off the previous name, then append this" with no
/// padding at all.
///
/// `visit` is called once per entry, in file order. It is a callback rather than
/// a returned list because two callers want different fields out of the same
/// walk, and a second copy of this parser is the last thing this module needs.
fn walk(
    body: &[u8],
    version: u32,
    count: usize,
    hash_len: usize,
    visit: &mut dyn FnMut(&Entry<'_>),
) -> Option<bool> {
    // Everything before the name: the stat block, the object id, the flags.
    let fixed = ID_FIELD + hash_len + 2;

    let mut cursor = HEADER_LEN;
    let mut previous: Vec<u8> = Vec::new();

    for _ in 0..count {
        let start = cursor;
        let flags_at = start.checked_add(ID_FIELD + hash_len)?;
        if body.len() < flags_at + 2 {
            return None;
        }
        let flags = u16::from_be_bytes([body[flags_at], body[flags_at + 1]]);
        let extended = flags & 0x4000 != 0;
        let stage = ((flags >> 12) & 0x3) as u8;
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
        visit(&Entry {
            start,
            name: &name,
            id: &body[start + ID_FIELD..flags_at],
            stage,
        });
        previous = name;
    }

    // The extension section: a four-byte signature and a length each, back to
    // back, until the data runs out. Walking it has to land exactly on the last
    // byte — anything else means the entry walk went wrong somewhere earlier and
    // the offsets above are not `size` fields at all.
    let mut split_index = false;
    while cursor < body.len() {
        let header_end = cursor.checked_add(8)?;
        if header_end > body.len() {
            return None;
        }
        if &body[cursor..cursor + 4] == b"link" {
            split_index = true;
        }
        let length = u32::from_be_bytes([
            body[cursor + 4],
            body[cursor + 5],
            body[cursor + 6],
            body[cursor + 7],
        ]) as usize;
        cursor = header_end.checked_add(length)?;
        if cursor > body.len() {
            return None;
        }
    }

    Some(split_index)
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

/// `index.lock`, held for the whole read-modify-write.
///
/// Using git's own lock name rather than a private temporary file is what makes
/// this safe next to a concurrent git: whoever creates the lock first wins, and
/// the other backs off. Dropping the guard without committing removes the lock,
/// so every early return in [`forget_stat`] releases it.
struct Lock {
    path: std::path::PathBuf,
    target: std::path::PathBuf,
    file: Option<fs::File>,
}

impl Lock {
    /// Takes the lock, or reports that someone else has it.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the lock file cannot be created for any other reason.
    fn acquire(index_path: &Path) -> Result<Option<Self>> {
        let path = index_path.with_extension("lock");
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => Ok(Some(Self {
                path,
                target: index_path.to_path_buf(),
                file: Some(file),
            })),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(err) => Err(Error::Io(err)),
        }
    }

    /// Writes `data` and renames the lock into place.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the write or the rename fails; the index is then left
    /// exactly as it was and the lock is released.
    fn commit(mut self, data: &[u8]) -> Result<()> {
        use std::io::Write as _;

        let mut file = self.file.take().ok_or_else(|| {
            Error::Io(std::io::Error::other("the index lock was already released"))
        })?;

        let result = (|| -> std::io::Result<()> {
            if let Ok(existing) = fs::metadata(&self.target) {
                file.set_permissions(existing.permissions())?;
            }
            file.write_all(data)?;
            file.sync_all()?;
            Ok(())
        })();
        drop(file);

        if let Err(err) = result.and_then(|()| fs::rename(&self.path, &self.target)) {
            let _ = fs::remove_file(&self.path);
            return Err(Error::Io(err));
        }

        // Same best-effort flush `atomic::write` does after its rename, for the
        // same reason and with a smaller consequence: a crash here costs a stale
        // stat cache, not a missing file.
        if let Some(parent) = self.target.parent()
            && let Ok(directory) = fs::File::open(parent)
        {
            let _ = directory.sync_all();
        }
        Ok(())
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            // Not committed: release the lock rather than leave a repository
            // that no git command can write to.
            let _ = fs::remove_file(&self.path);
        }
    }
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
    fn a_split_index_is_refused_out_loud_instead_of_quietly_doing_nothing() {
        // With `core.splitIndex` the entries live in `.git/sharedindex.<oid>`
        // and this file holds only the differences, so the walk matches nothing.
        // Reporting that as success left `git status` permanently dirty with no
        // message — measured on git 2.55, and the reason this branch exists.
        // `features.manyFiles=true` turns split index on wholesale.
        let dir = repo_with_index(2);
        let ok = Command::new("git")
            .args(["update-index", "--split-index"])
            .current_dir(dir.path())
            .status()
            .expect("git must be on PATH")
            .success();
        assert!(ok, "git could not split the index");

        let outcome = forget_stat(&index_of(&dir), gix_hash::Kind::Sha1, &[b"a.txt".to_vec()])
            .expect("a split index is not our failure");

        match outcome {
            Outcome::Skipped(message) => assert!(
                message.contains("split index"),
                "the user must be told which limitation they hit: {message}"
            ),
            other => panic!("a split index must not be reported as done: {other:?}"),
        }
        assert_eq!(git_status(&dir), "", "the index was left unusable");
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

    /// What git itself records for `path`, so the reader is checked against git.
    fn git_staged_id(dir: &TempDir, path: &str) -> String {
        let output = Command::new("git")
            .args(["rev-parse", &format!(":{path}")])
            .current_dir(dir.path())
            .output()
            .expect("git must be on PATH");
        String::from_utf8(output.stdout)
            .expect("git printed non-UTF-8")
            .trim()
            .to_string()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn the_object_ids_read_back_are_the_ones_git_recorded() {
        for version in [2u32, 3, 4] {
            let dir = repo_with_index(version);
            let paths = vec![
                b"a.txt".to_vec(),
                b"deep/nested/c-with-a-long-name.txt".to_vec(),
                b"never-existed".to_vec(),
            ];

            let staged = staged_ids(&index_of(&dir), gix_hash::Kind::Sha1, &paths)
                .expect("reading must succeed");

            let Staged::Read(ids) = staged else {
                panic!("index version {version}: the entries could not be read");
            };
            assert_eq!(
                ids[0].as_deref().map(hex),
                Some(git_staged_id(&dir, "a.txt")),
                "index version {version}"
            );
            assert_eq!(
                ids[1].as_deref().map(hex),
                Some(git_staged_id(&dir, "deep/nested/c-with-a-long-name.txt")),
                "index version {version}"
            );
            assert_eq!(ids[2], None, "index version {version}: an invented path");
        }
    }

    #[test]
    fn a_blob_id_matches_what_git_would_store() {
        let dir = repo_with_index(2);
        let content = b"content of a.txt\n";

        let ours = blob_id(gix_hash::Kind::Sha1, content).expect("hashing must succeed");

        assert_eq!(hex(&ours), git_staged_id(&dir, "a.txt"));
    }

    #[test]
    fn the_same_path_asked_about_twice_is_answered_twice() {
        // `lock` asks about its selection and its sweep candidates in one query,
        // and a file can legitimately be in both. Answering only the first
        // occurrence left the second reading as "not stored", which is the
        // difference between a tracked file kept and a tracked file deleted.
        let dir = repo_with_index(2);
        let paths = vec![b"a.txt".to_vec(), b"a.txt".to_vec()];

        let staged = staged_ids(&index_of(&dir), gix_hash::Kind::Sha1, &paths)
            .expect("reading must succeed");

        let Staged::Read(ids) = staged else {
            panic!("the entries could not be read");
        };
        assert_eq!(ids[0], ids[1]);
        assert!(ids[1].is_some(), "the repeated path was answered as absent");
    }

    #[test]
    fn an_index_with_no_file_behind_it_reports_nothing_stored() {
        let dir = TempDir::new().expect("temporary directory");
        let staged = staged_ids(
            &dir.path().join("index"),
            gix_hash::Kind::Sha1,
            &[b"a.txt".to_vec()],
        )
        .expect("an absent index is not our failure");
        assert_eq!(staged, Staged::Read(vec![None]));
    }

    #[test]
    fn a_damaged_index_is_unavailable_rather_than_read_as_empty() {
        // The distinction `lock` rests on: "no entry" means unsaved work and is
        // a refusal to lock, while "cannot read" must not be mistaken for it.
        let dir = repo_with_index(2);
        let path = index_of(&dir);
        let mut data = fs::read(&path).expect("reading the index");
        let middle = data.len() / 2;
        data[middle] ^= 0xff;
        fs::write(&path, &data).expect("writing");

        let staged = staged_ids(&path, gix_hash::Kind::Sha1, &[b"a.txt".to_vec()])
            .expect("a damaged index is not our failure");

        assert!(matches!(staged, Staged::Unavailable(_)), "{staged:?}");
    }

    #[test]
    fn a_split_index_is_unavailable_rather_than_read_as_empty() {
        let dir = repo_with_index(2);
        let ok = Command::new("git")
            .args(["update-index", "--split-index"])
            .current_dir(dir.path())
            .status()
            .expect("git must be on PATH")
            .success();
        assert!(ok, "git could not split the index");

        let staged = staged_ids(&index_of(&dir), gix_hash::Kind::Sha1, &[b"a.txt".to_vec()])
            .expect("a split index is not our failure");

        match staged {
            Staged::Unavailable(message) => assert!(message.contains("split index")),
            other => panic!("a split index must not read as an empty index: {other:?}"),
        }
    }

    #[test]
    fn an_unresolved_conflict_reads_as_nothing_stored() {
        // Stages 1 to 3 hold the two sides and their base, and none of them is
        // the file's settled content — so `lock` has to see "not stored".
        let dir = repo_with_index(2);
        let run = |args: &[&str]| {
            let output = Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .output()
                .expect("git must be on PATH");
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(&["checkout", "-q", "-b", "other"]);
        fs::write(dir.path().join("a.txt"), "theirs\n").expect("writing");
        run(&["commit", "-q", "-am", "theirs"]);
        run(&["checkout", "-q", "-"]);
        fs::write(dir.path().join("a.txt"), "mine\n").expect("writing");
        run(&["commit", "-q", "-am", "mine"]);
        let merged = Command::new("git")
            .args(["merge", "other"])
            .current_dir(dir.path())
            .output()
            .expect("git must be on PATH");
        assert!(!merged.status.success(), "the merge was meant to conflict");

        let staged = staged_ids(&index_of(&dir), gix_hash::Kind::Sha1, &[b"a.txt".to_vec()])
            .expect("reading must succeed");

        assert_eq!(staged, Staged::Read(vec![None]));
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
