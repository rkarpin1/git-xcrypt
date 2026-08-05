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
//! the NFC name in the index. Both callers notice when a name they know is
//! tracked does not match. **This gap survived open decision 13**, settled on
//! 2026-08-05: pattern matching now folds ASCII case, so a *declaration* reaches
//! every spelling of a name — but the question here is a different one, whether
//! an index entry and a directory entry are the same file, and neither the index
//! nor `read_dir` folds anything. What changed is which refusal fires first: the
//! walk below now recognises `Secrets/db.env` as declared, so `lock` stops on
//! "declared and not tracked under this name" rather than on "the index names a
//! path this walk never saw". Same state, same exit code, and the message now
//! names the spelling on disk, which is the one the user has to act on.
//!
//! **Correction, 2026-08-05: the consequences were not "on the safe side for
//! `lock`, which then refuses rather than proceeds", as this comment claimed
//! until now.** Measured on git 2.55 and APFS: after `mv secrets Secrets` the
//! index still said `secrets/db.env`, `git status` was clean, the working-tree
//! walk selected nothing, and `lock --yes` printed "no file here is declared for
//! encryption", exited 0 and deleted the key over a readable plaintext secret —
//! the interactive path did the same after a typed `yes`. `lock` now proves the
//! opposite by content rather than assuming it: see
//! `commands::lock::refuse_if_a_declared_file_is_still_open`, which reads this
//! module's listing and refuses while any declared tracked path still holds
//! plain text on disk.
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
//! So this module patches bytes rather than rebuilding the index: writing it out
//! through a library would silently drop the extensions that library does not
//! know how to write — the split-index link above all, whose loss is not a slow
//! `git status` but a destroyed index. Patching in place preserves every byte we
//! did not mean to change, and the trailing checksum is verified before the edit
//! and recomputed after it, so a file that is not shaped the way we think is
//! left alone rather than mangled.
//!
//! [`forget_stat`] touches four bytes per affected entry. [`restage`] also
//! replaces the object id, and therefore has to drop the `TREE` cache — see its
//! own comment for the measured reason, which is a commit that quietly stored
//! the plaintext again.

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

/// Points index entries at different blobs, and forgets their cached size.
///
/// This is what `status --fix` is: git's own `git add` on a path whose staged
/// content is plain text, done without spawning git. The blob has to exist in
/// the object database already — the caller writes it — and this puts the index
/// entry on it, so the next commit stores the ciphertext.
///
/// The stat cache is cleared in the same pass, and not as a nicety: with the
/// old size still recorded, git compares it against the working-tree file,
/// concludes the content changed and never runs the clean filter to find out
/// otherwise. See this module's opening comment.
///
/// Stage 0 only. A path in the middle of a merge has no settled content, and
/// rewriting one side of a conflict to point at a blob nobody asked for would be
/// the worst kind of help.
///
/// Reports the paths it actually repointed, not how many. A count cannot say
/// *which*, and the difference is not cosmetic: a path the index spells
/// differently than the directory does — case folding on macOS and Windows, NFD
/// against NFC — is silently not found, and a caller left to subtract counts
/// would name the wrong file as fixed while the real one vanished from the
/// "still in the clear" list.
///
/// # Errors
///
/// [`Error::Io`] when the index cannot be read or replaced. [`Error::Config`]
/// when an object id is not the length this repository's hash produces —
/// writing a short id into an entry would corrupt every entry after it.
pub fn restage(
    index_path: &Path,
    hash: gix_hash::Kind,
    updates: &[(Vec<u8>, Vec<u8>)],
) -> Result<Restaged> {
    let hash_len = hash.len_in_bytes();
    if updates.is_empty() {
        return Ok(Restaged::Done(Vec::new()));
    }
    for (path, id) in updates {
        if id.len() != hash_len {
            return Err(Error::Config(format!(
                "{}: the new object id is {} bytes, but this repository's index \
                 stores {hash_len}; the index was left alone",
                String::from_utf8_lossy(path),
                id.len()
            )));
        }
    }

    // Lock first, then read: the same order git uses, and for the same reason —
    // a `git add` in another terminal between our read and our write would be
    // silently reverted by a stale buffer, taking its staged changes with it.
    let Some(lock) = Lock::acquire(index_path)? else {
        return Ok(Restaged::Skipped(format!(
            "{}.lock is held by another git process, so nothing was re-staged. \
             Try again, or run `git add` on the reported paths yourself.",
            index_path.display()
        )));
    };

    let data = match fs::read(index_path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Restaged::Skipped(format!(
                "{} does not exist, so there is nothing staged to re-stage",
                index_path.display()
            )));
        }
        Err(err) => return Err(Error::Io(err)),
    };

    let Index {
        mut data,
        body_len,
        version,
        count,
        skip_hash,
    } = match inspect(data, hash) {
        Ok(index) => index,
        Err(why) => return Ok(Restaged::Skipped(why_skipped(index_path, &why))),
    };

    // The name comes back with the offset, so what was patched is known rather
    // than inferred from a count.
    let mut edits: Vec<(usize, &[u8], Vec<u8>)> = Vec::new();
    let walked = walk(&data[..body_len], version, count, hash_len, &mut |entry| {
        if entry.stage != 0 {
            return;
        }
        if let Some((path, id)) = updates.iter().find(|(path, _)| path == entry.name) {
            edits.push((entry.start, id.as_slice(), path.clone()));
        }
    });

    let layout = match walked {
        None => {
            return Ok(Restaged::Skipped(why_skipped(
                index_path,
                "its entries did not parse",
            )));
        }
        Some(walked) if walked.split_index => {
            return Ok(Restaged::Skipped(why_skipped(
                index_path,
                "this repository uses a split index, whose entries live in a shared \
                 file this build does not patch",
            )));
        }
        Some(walked) => walked,
    };
    if edits.is_empty() {
        return Ok(Restaged::Done(Vec::new()));
    }

    let mut patched = Vec::with_capacity(edits.len());
    for (start, id, path) in edits {
        data[start + ID_FIELD..start + ID_FIELD + hash_len].copy_from_slice(id);
        data[start + SIZE_FIELD..start + SIZE_FIELD + 4].fill(0);
        patched.push(path);
    }

    // **The cache tree has to go, and this is not housekeeping.** `TREE` caches
    // the tree object each directory would write to, and git trusts it: measured
    // on git 2.55, an index whose entry was repointed at a new blob while `TREE`
    // still named the old directory tree left `git diff-index --cached HEAD`
    // reporting *no change at all*, and the next `git commit` wrote the stale
    // tree — so the plaintext went back into the object database from a command
    // that had just reported it fixed. `git add` avoids this by invalidating the
    // path's ancestors; dropping the extension is the same thing with a wider
    // brush, and costs one rebuild on the next commit.
    //
    // `EOIE` goes with it because it carries a hash over the extension headers,
    // which removing one invalidates. Everything else is kept: `IEOT` indexes
    // the *entries*, whose lengths are unchanged, and `REUC`, `UNTR` and the
    // fsmonitor state describe things this edit did not touch.
    let mut rebuilt = data[..layout.extensions_at].to_vec();
    for extension in &layout.extensions {
        if matches!(&extension.signature, b"TREE" | b"EOIE") {
            continue;
        }
        rebuilt.extend_from_slice(&data[extension.start..extension.end]);
    }

    if skip_hash {
        rebuilt.extend_from_slice(&vec![0u8; hash_len]);
    } else {
        let Some(digest) = checksum(&rebuilt, hash) else {
            return Ok(Restaged::Skipped(why_skipped(
                index_path,
                "its checksum could not be computed",
            )));
        };
        rebuilt.extend_from_slice(&digest);
    }
    debug_assert!(body_len >= layout.extensions_at);

    lock.commit(&rebuilt)?;
    Ok(Restaged::Done(patched))
}

/// What [`restage`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Restaged {
    /// The paths whose entries were repointed, in the order the index stores
    /// them. A path the caller asked about and that is missing here was **not**
    /// re-staged, whatever the reason.
    Done(Vec<Vec<u8>>),
    /// Nothing was written, and why.
    Skipped(String),
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
        Some(walked) if walked.split_index => Ok(Staged::Unavailable(
            "this repository uses a split index, whose entries live in a shared \
             file this build does not read"
                .into(),
        )),
        Some(_) => Ok(Staged::Read(found)),
    }
}

/// Every stage-0 entry in the index, or why it could not be read.
///
/// The same distinction [`Staged`] draws, and for the same reason: an index this
/// build cannot parse is not evidence that nothing is tracked.
#[derive(Debug, PartialEq, Eq)]
pub enum Listed {
    /// Every stage-0 entry, in the order the index stores them.
    Read(Vec<Tracked>),
    /// The index could not be read, and why.
    Unavailable(String),
}

/// One tracked path, as the index records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracked {
    /// The path, spelled exactly as the index spells it.
    pub path: Vec<u8>,
    /// Object id of its cleaned content.
    pub id: Vec<u8>,
    /// The entry mode: `0o100644`, `0o100755`, `0o120000` for a symbolic link,
    /// `0o160000` for a submodule.
    ///
    /// Carried rather than dropped, and the reason is not tidiness. Measured on
    /// the build before it was: `status --fix` read a tracked **symlink** as
    /// ordinary content — a symlink's blob is its target string, which carries
    /// no magic — followed it with `fs::read`, encrypted whatever it pointed at
    /// and repointed the entry, leaving the mode at `0o120000`. The next clone
    /// got a symlink whose target was the first NUL of a ciphertext, and the
    /// plaintext of a file no pattern declared was now a blob in the object
    /// database. The history scan had the check all along and the two disagreed.
    pub mode: u32,
    /// Whether this is a `git add -N` placeholder rather than staged content.
    ///
    /// Such an entry carries mode `100644` and the empty blob, so it reads as
    /// "stored in the clear" and `--fix` used to repoint it — announcing a
    /// repair that the next `git commit` did not make, because git still treats
    /// the path as unstaged.
    pub intent_to_add: bool,
}

impl Tracked {
    /// Whether this entry is a regular file, the only kind git filters.
    ///
    /// A symbolic link and a submodule gitlink both hold something that is not
    /// file content, so no declaration could ever have applied to them.
    #[must_use]
    pub fn is_regular_file(&self) -> bool {
        self.mode & 0o170_000 == 0o100_000
    }

    /// Whether this entry holds content the next commit would actually store.
    #[must_use]
    pub fn holds_content(&self) -> bool {
        self.is_regular_file() && !self.intent_to_add
    }
}

/// Lists what the index records, without being told the paths in advance.
///
/// [`staged_ids`] answers about paths a caller already knows; `status` needs the
/// other direction — "which declared paths would the next commit store, and as
/// what" — and can only get there by enumerating. Both go through the one parser
/// in this module, so there is never a second reading of the same bytes.
///
/// # Errors
///
/// [`Error::Io`] when the index exists but cannot be read. An index that does
/// not exist yet is not an error: nothing is tracked, so the list is empty.
pub fn list(index_path: &Path, hash: gix_hash::Kind) -> Result<Listed> {
    let data = match fs::read(index_path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Listed::Read(Vec::new()));
        }
        Err(err) => return Err(Error::Io(err)),
    };

    let index = match inspect(data, hash) {
        Ok(index) => index,
        Err(why) => return Ok(Listed::Unavailable(why)),
    };

    let mut entries = Vec::with_capacity(index.count);
    let walked = walk(
        &index.data[..index.body_len],
        index.version,
        index.count,
        hash.len_in_bytes(),
        &mut |entry| {
            // Stage 0 only, as in `staged_ids`: a path mid-merge has no settled
            // content, and reporting whichever side came last as "what this
            // repository stores" would be a guess presented as a fact.
            if entry.stage == 0 {
                entries.push(Tracked {
                    path: entry.name.to_vec(),
                    id: entry.id.to_vec(),
                    mode: entry.mode,
                    intent_to_add: entry.intent_to_add,
                });
            }
        },
    );

    // Published only on a complete walk, exactly as `staged_ids` does: a partial
    // list reads as "these are the tracked paths" while quietly omitting the
    // rest, and here the omission would be a declared path reported as safe.
    match walked {
        None => Ok(Listed::Unavailable("its entries did not parse".into())),
        Some(walked) if walked.split_index => Ok(Listed::Unavailable(
            "this repository uses a split index, whose entries live in a shared \
             file this build does not read"
                .into(),
        )),
        Some(_) => Ok(Listed::Read(entries)),
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

/// The same refusal for [`restage`], whose caller has a different repair.
///
/// `git add --renormalize` is the wrong advice here: nothing was rewritten in
/// the working tree, so what the user needs is to stage the paths themselves.
fn why_skipped(index_path: &Path, why: &str) -> String {
    format!(
        "{} was left alone because {why}, so nothing was re-staged. \
         `git add` on the reported paths does the same job.",
        index_path.display()
    )
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
    /// The entry mode, which says whether this is a file at all.
    mode: u32,
    /// `git add -N`: the path is announced but its content is not staged.
    intent_to_add: bool,
}

/// Offset of the `mode` field from the start of an entry.
///
/// After `ctime` (8), `mtime` (8), `dev` (4) and `ino` (4).
const MODE_FIELD: usize = 24;

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
    let walked = walk(body, version, count, hash_len, &mut |entry| {
        if paths.iter().any(|path| path.as_slice() == entry.name) {
            fields.push(entry.start + SIZE_FIELD);
        }
    })?;

    Some(Scan {
        size_fields: fields,
        split_index: walked.split_index,
    })
}

/// Walks the entries and then the extensions, or gives up entirely.
///
/// Returns `None` for anything that does not parse exactly, which is what keeps
/// a misread from turning into a patched byte in the wrong place. The extension
/// walk is not only there to spot a split index: it has to consume the file to
/// its last byte, which is what proves the entry walk ended where it should
/// rather than somewhere plausible. The extensions are located but not decoded,
/// which is enough for the two questions callers have: whether a `link`
/// extension makes this a split index, and which bytes an edit has to leave out
/// when a cache it invalidates has to go.
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
) -> Option<Walked> {
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
        // The on-disk extended word carries git's bits 16..31, so its `0x2000`
        // is `CE_INTENT_TO_ADD (1 << 29)`.
        let intent_to_add = version >= 3
            && extended
            && body.len() >= flags_at + 4
            && u16::from_be_bytes([body[flags_at + 2], body[flags_at + 3]]) & 0x2000 != 0;
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
            mode: u32::from_be_bytes([
                body[start + MODE_FIELD],
                body[start + MODE_FIELD + 1],
                body[start + MODE_FIELD + 2],
                body[start + MODE_FIELD + 3],
            ]),
            intent_to_add,
        });
        previous = name;
    }

    // The extension section: a four-byte signature and a length each, back to
    // back, until the data runs out. Walking it has to land exactly on the last
    // byte — anything else means the entry walk went wrong somewhere earlier and
    // the offsets above are not `size` fields at all.
    let mut walked = Walked {
        split_index: false,
        extensions_at: cursor,
        extensions: Vec::new(),
    };
    while cursor < body.len() {
        let header_end = cursor.checked_add(8)?;
        if header_end > body.len() {
            return None;
        }
        let mut signature = [0u8; 4];
        signature.copy_from_slice(&body[cursor..cursor + 4]);
        if &signature == b"link" {
            walked.split_index = true;
        }
        let length = u32::from_be_bytes([
            body[cursor + 4],
            body[cursor + 5],
            body[cursor + 6],
            body[cursor + 7],
        ]) as usize;
        let start = cursor;
        cursor = header_end.checked_add(length)?;
        if cursor > body.len() {
            return None;
        }
        walked.extensions.push(Extension {
            signature,
            start,
            end: cursor,
        });
    }

    Some(walked)
}

/// What one pass over the whole index learned about its layout.
struct Walked {
    /// The index carries a `link` extension, so its entries are elsewhere.
    split_index: bool,
    /// Where the entries stop and the extensions begin.
    extensions_at: usize,
    /// Every extension, in file order.
    extensions: Vec<Extension>,
}

/// One extension, located rather than decoded.
struct Extension {
    signature: [u8; 4],
    start: usize,
    end: usize,
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
