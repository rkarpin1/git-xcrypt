//! Walking every reachable commit, looking for declared paths stored in the clear.
//!
//! This is the answer to the product's largest real risk: a secret committed
//! **before** the pattern that covers it existed. Nothing in the working tree
//! shows it, `HEAD` need not show it either — deleting the file does not delete
//! the blob — and it is still sitting at the hosting provider. A shallow check
//! would report such a repository as clean, which is worse than no check at all.
//!
//! Three properties shape the implementation.
//!
//! **No decryption, and no key.** The verdict per blob is the eleven bytes of
//! magic at its start, so `status` works in a locked repository and in a clone
//! that was never unlocked — which is exactly where a user most needs to ask.
//!
//! **Every object is looked at once.** A tree shared by a thousand commits is
//! walked once, a blob appearing under a thousand commits is read once. Without
//! that the cost would be quadratic in the history rather than linear in the
//! object count, and the founding document's premise — "the cost depends on the
//! number of objects, not their size" — would not hold. The premise holds only
//! *approximately*, and the gap is worth naming: reading a blob through the
//! object database decompresses all of it, not the first eleven bytes, because
//! neither a loose object nor a packed delta can be truncated part way. The
//! deduplication is what keeps that bounded.
//!
//! **Nothing here fails the scan over one bad object.** A repository with a
//! missing object is broken in a way this command did not cause and cannot fix,
//! and refusing outright would withhold the findings from every object that
//! *did* read. Such objects are counted and reported, so "nothing found" and
//! "nothing found in what I could read" never look the same. A **reference**
//! that will not resolve is counted separately and weighs more, because it is a
//! whole branch unvisited rather than one file unjudged.
//!
//! Known limits, recorded rather than hidden:
//!
//! * **The walk state is unbounded.** `seen_trees` holds one entry per
//!   `(tree, path)` pair over all reachable history, with the path cloned. It is
//!   comfortable for ordinary repositories and there is no cap, no progress
//!   output and no way to interrupt it part way. If that ever bites, interning
//!   the path prefixes and keying on `(ObjectId, usize)` cuts the dominant term.
//! * **A path mid-merge is invisible to the index half** of `status`, which
//!   reads stage 0 only. The history scan still sees the conflicting blobs,
//!   because they come from commits; what is missing is a statement about what
//!   the *next* commit would store, which is genuinely undecided until the merge
//!   is resolved.
//! * **[`HeadLookup`] resolves `HEAD` once per filter process.** A long-running
//!   filter outlives a `git rebase` that moves it, so the warning can be judged
//!   against the tree `HEAD` had at startup. It is advisory either way.
//! * **The reflog and the other pseudo-references are out of scope.** Every
//!   worktree's `HEAD` and `refs/` are walked, but not `ORIG_HEAD`,
//!   `MERGE_HEAD`, `FETCH_HEAD` or `logs/`. So the canonical "oops": commit a
//!   secret, `git reset --hard HEAD~1`, then declare the pattern — the blob
//!   stays in the object database until `gc.reflogExpire` (90 days by default)
//!   and this scan reports nothing. The boundary is deliberate: those objects
//!   are local and no push carries them, so they are lost work rather than
//!   published exposure. `git reflog expire --expire=now --all` followed by
//!   `git gc --prune=now` clears them. The scan also says nothing about what a
//!   *remote* already holds, which no local command can.
//! * **A declared blob is decompressed whole to be judged.** Only 11 bytes are
//!   needed, but the object database hands over the whole object, so one
//!   multi-gigabyte declared blob in history is a whole-file allocation.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use gix_hash::ObjectId;
use gix_object::{Find as _, FindExt as _, FindHeader as _};
use gix_ref::file::ReferenceExt as _;

use crate::config::Config;
use crate::format;
use crate::{Error, Result};

/// One declared path that reachable history holds in the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    /// Repository-relative path, exactly as the tree spells it.
    pub path: Vec<u8>,
    /// Distinct plaintext blobs stored under it, with a commit holding each.
    pub sightings: Vec<Sighting>,
}

/// One plaintext blob, and a commit that contains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    /// The blob itself.
    pub blob: ObjectId,
    /// A commit whose tree contains it.
    ///
    /// *A* commit, not the list of them: trees are deduplicated across the walk,
    /// so the first commit to reach a given tree is the one recorded. Naming one
    /// is what makes the finding checkable; the remedy is per path anyway, since
    /// history rewriting takes paths and not commits.
    pub commit: ObjectId,
}

/// What one scan found.
#[derive(Debug, Default)]
pub struct Scan {
    /// Declared paths held in the clear, sorted by path.
    pub exposed: Vec<Exposure>,
    /// How many commits were visited.
    pub commits: usize,
    /// How many distinct blobs under a declared path were inspected.
    pub blobs: usize,
    /// Objects that could not be read, so could not be judged.
    ///
    /// Separate from [`Scan::warnings`] because the count changes what the
    /// report means: a scan that skipped something has not proved anything about
    /// it, and must not be summarised as though it had.
    pub unreadable: usize,
    /// References the walk could not start from.
    ///
    /// Counted apart from the objects for the same reason and a sharper one: a
    /// reference store that cannot be read at all yields **no tips**, so the
    /// scan visits nothing and finds nothing. Measured on the build before this
    /// existed — `chmod 000 .git/packed-refs` and a removed loose branch left
    /// `status` reporting a repository with a plaintext blob in its history as
    /// clean, exit code 0. A warning on `stderr` is not enough: a CI gate reads
    /// the code.
    pub unresolved_refs: usize,
    /// Names of the references the walk could not start from, capped.
    ///
    /// The count alone reaches `stdout` as "1 reference(s) could not be
    /// resolved", which tells an operator reading a CI log nothing they can act
    /// on. The names are what turn it into an instruction.
    pub unresolved_names: Vec<String>,
    /// The reference store could not be enumerated at all, so nothing here
    /// covers anything.
    pub refs_unavailable: bool,
    /// This repository fetches objects lazily, so some were never downloaded.
    ///
    /// The twin of [`Scan::shallow`], and it was making the same mistake: a
    /// promisor object is absent by design, and reporting it as unreadable sent
    /// the user to `git fsck`, which exits 0 on a partial clone and reports
    /// nothing at all.
    pub partial: bool,
    /// This is a shallow clone, so history stops at the graft points.
    ///
    /// Reported rather than treated as corruption. A shallow clone is an
    /// ordinary, healthy state — and before this was honoured, the walk queued
    /// the parents git deliberately did not fetch, failed to read them, and told
    /// the user that objects were missing and to run `git fsck`, which is happy
    /// with a shallow clone and would have reported nothing. The finding still
    /// stands, because a history that was never fetched genuinely cannot be
    /// vouched for; only the explanation was wrong.
    pub shallow: bool,
    /// Things worth stating that are not findings — a reference deliberately
    /// not walked, a file under `refs/` that git ignores too.
    pub notes: Vec<String>,
    /// Anything worth saying once, carried out so the binary owns the messages.
    pub warnings: Vec<String>,
}

/// The most detail any single message carries about unreadable objects.
///
/// One line per missing object in a repository whose pack is gone would be the
/// whole terminal; the count in [`Scan::unreadable`] carries the rest.
const MAX_UNREADABLE_WARNINGS: usize = 5;

/// Scans everything reachable in the repository at `git_dir` / `common_dir`.
///
/// `config` decides which paths are worth reading a blob for; everything else is
/// skipped without touching the object database.
///
/// # Errors
///
/// [`Error::Config`] when the object database or the reference store cannot be
/// opened at all — "cannot tell" must never be reported as "nothing is wrong" by
/// the one command whose whole job is to tell.
pub fn scan(
    objects: &gix_odb::Handle,
    git_dir: &Path,
    common_dir: &Path,
    hash: gix_hash::Kind,
    config: &Config,
    partial: bool,
) -> Result<Scan> {
    let mut scan = Scan::default();
    let tips = tips(git_dir, common_dir, hash, objects, &mut scan);
    let grafts = grafts(git_dir, common_dir);
    scan.shallow = !grafts.is_empty();
    scan.partial = partial;

    let mut queue: Vec<ObjectId> = tips;
    let mut seen_commits: HashSet<ObjectId> = HashSet::new();
    // Keyed by (tree, path it sits at): the same tree object can appear at two
    // different paths — two directories with identical contents is ordinary —
    // and the path is half of what the patterns match on.
    let mut seen_trees: HashSet<(ObjectId, Vec<u8>)> = HashSet::new();
    let mut verdicts: HashMap<ObjectId, bool> = HashMap::new();
    let mut found: HashMap<Vec<u8>, Vec<Sighting>> = HashMap::new();

    let mut buffer = Vec::new();
    while let Some(commit) = queue.pop() {
        if !seen_commits.insert(commit) {
            continue;
        }

        let mut iter = match objects.find_commit_iter(&commit, &mut buffer) {
            Ok(iter) => iter,
            Err(err) => {
                note_unreadable(&mut scan, &commit, &err.to_string());
                continue;
            }
        };
        let Ok(tree) = iter.tree_id() else {
            note_unreadable(&mut scan, &commit, "its tree could not be read");
            continue;
        };
        // Collected before the tree walk, which reuses the buffer this iterator
        // borrows.
        let parents: Vec<ObjectId> = iter.parent_ids().collect();

        scan.commits += 1;
        walk_tree(
            objects,
            config,
            tree,
            commit,
            &mut seen_trees,
            &mut verdicts,
            &mut found,
            &mut scan,
        );
        // A graft point is where a shallow clone stops. Its parents were never
        // fetched, so queuing them would be asking the object database for
        // objects git knows are absent — which read as corruption.
        if !grafts.contains(&commit) {
            queue.extend(parents);
        }
    }

    scan.blobs = verdicts.len();
    scan.exposed = collect(found);
    Ok(scan)
}

/// The commits a shallow clone was cut off at, if it is one.
///
/// `$GIT_COMMON_DIR/shallow` holds one object id per line. Anything unparsable
/// is skipped rather than reported: this file only ever makes the walk stop
/// earlier, so misreading it costs coverage that is already absent, never a
/// false clean bill of health.
fn grafts(git_dir: &Path, common_dir: &Path) -> HashSet<ObjectId> {
    let mut found = HashSet::new();
    for directory in [common_dir, git_dir] {
        let Ok(text) = std::fs::read_to_string(directory.join("shallow")) else {
            continue;
        };
        for line in text.lines() {
            if let Ok(id) = ObjectId::from_hex(line.trim().as_bytes()) {
                found.insert(id);
            }
        }
    }
    found
}

/// Opens the repository's object database.
///
/// Shared rather than opened per question: `status` asks about the index and
/// about history in one run, and two handles would mean two sets of open packs
/// for the same objects.
///
/// **`hash` is not optional and `gix_odb::at` is not usable.** That convenience
/// wrapper takes the default hash, which is SHA-1, and the store *asserts* the
/// hash of every id handed to it. Measured on git 2.55 in a repository created
/// with `--object-format=sha256`: `git-xcrypt status` panicked inside
/// `gix-odb`, and so did the filter on the check-in path — which with
/// `required = true` aborts every git operation in the repository. A tool this
/// build already reads SHA-256 indexes for must not fall over on the object
/// database.
///
/// # Errors
///
/// [`Error::Config`] when the database cannot be opened at all.
pub fn objects(common_dir: &Path, hash: gix_hash::Kind) -> Result<gix_odb::Handle> {
    let path = common_dir.join("objects");
    gix_odb::at_opts(
        &path,
        Vec::new(),
        gix_odb::store::init::Options {
            object_hash: hash,
            ..gix_odb::store::init::Options::default()
        },
    )
    .map_err(|err| {
        Error::Config(format!(
            "the object database at {} could not be opened ({err}), so this \
             repository cannot be inspected",
            path.display()
        ))
    })
}

/// Whether the blob `id` is stored without our magic.
///
/// `None` when the object is not there to be judged, which a caller has to
/// report rather than read as "fine": the whole point of this command is that
/// silence and safety are different things.
#[must_use]
pub fn stored_in_the_clear(objects: &gix_odb::Handle, id: &gix_hash::oid) -> Option<bool> {
    let mut buffer = Vec::new();
    match objects.try_find(id, &mut buffer) {
        Ok(Some(data)) => Some(!format::looks_encrypted(data.data)),
        Ok(None) | Err(_) => None,
    }
}

/// One cheap question, asked on the check-in path: is this path already in
/// `HEAD` in the clear?
///
/// The founding document gives the filter this job because the filter is the one
/// mechanism that runs whatever client is driving git. A `pre-commit` hook is
/// bypassed by `--no-verify`, switched off by a checkbox in an IDE, and does not
/// survive a clone; the attribute mechanism git enforces itself.
///
/// The constraint that shapes it is that this runs while `git add` waits. A full
/// history scan here would stall every commit, so the question is deliberately
/// the narrow one — one path, one tree chain, one blob — and the answer is only
/// ever a message. **It must never make the filter exit non-zero.** With
/// `required = true` a non-zero exit aborts the whole operation, and this is a
/// warning about the past, not a reason to refuse the present.
///
/// Everything is resolved lazily and cached, so a repository where nothing is
/// declared never opens the object database at all, and one where a hundred
/// secrets live in the same directory reads that directory's tree once.
pub struct HeadLookup {
    objects: gix_odb::Handle,
    /// The tree `HEAD` points at, resolved on the first question.
    root: Option<ObjectId>,
    /// Directory path to the tree it names, `None` where there is no such
    /// directory in `HEAD`.
    directories: HashMap<Vec<u8>, Option<ObjectId>>,
}

impl HeadLookup {
    /// Prepares the lookup, or gives up quietly.
    ///
    /// `None` when there is nothing to look in — an unborn branch, an
    /// unreadable object database. Quiet is right: this whole facility is an
    /// extra, and a repository that cannot answer the question is not a
    /// repository that should stop accepting commits over it.
    #[must_use]
    pub fn open(git_dir: &Path, common_dir: &Path, hash: gix_hash::Kind) -> Option<Self> {
        let objects = objects(common_dir, hash).ok()?;
        let options = gix_ref::store::init::Options {
            object_hash: hash,
            ..gix_ref::store::init::Options::default()
        };
        let store = if git_dir == common_dir {
            gix_ref::file::Store::at(git_dir.to_path_buf(), options)
        } else {
            gix_ref::file::Store::for_linked_worktree(
                git_dir.to_path_buf(),
                common_dir.to_path_buf(),
                options,
            )
        };

        let mut head = store.try_find("HEAD").ok().flatten()?;
        let commit = head.peel_to_id(&store, &objects).ok()?;

        let mut buffer = Vec::new();
        let root = objects
            .find_commit_iter(&commit, &mut buffer)
            .ok()
            .and_then(|mut iter| iter.tree_id().ok());

        Some(Self {
            objects,
            root,
            directories: HashMap::new(),
        })
    }

    /// Whether `HEAD` holds `path` as content without our magic.
    ///
    /// False for anything it cannot answer, deliberately: a false negative here
    /// costs a message, a false positive costs the user's trust in every message
    /// this tool prints.
    pub fn holds_in_the_clear(&mut self, path: &[u8]) -> bool {
        let Some(root) = self.root else {
            return false;
        };

        let (directory, filename) = match path.iter().rposition(|byte| *byte == b'/') {
            Some(at) => (&path[..at], &path[at + 1..]),
            None => (&path[..0], path),
        };
        let Some(tree) = self.directory(root, directory) else {
            return false;
        };

        let mut buffer = Vec::new();
        let Ok(entries) = self.objects.find_tree_iter(&tree, &mut buffer) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else { return false };
            if entry.filename != filename {
                continue;
            }
            if !entry.mode.is_blob() {
                return false;
            }
            return stored_in_the_clear(&self.objects, entry.oid).unwrap_or(false);
        }
        false
    }

    /// The tree `directory` names under `root`, walking one component at a time.
    fn directory(&mut self, root: ObjectId, directory: &[u8]) -> Option<ObjectId> {
        if directory.is_empty() {
            return Some(root);
        }
        if let Some(cached) = self.directories.get(directory) {
            return *cached;
        }

        let mut current = root;
        for component in directory.split(|byte| *byte == b'/') {
            let mut buffer = Vec::new();
            let Ok(entries) = self.objects.find_tree_iter(&current, &mut buffer) else {
                self.directories.insert(directory.to_vec(), None);
                return None;
            };
            let mut next = None;
            for entry in entries.flatten() {
                if entry.filename == component && entry.mode.is_tree() {
                    next = Some(entry.oid.to_owned());
                    break;
                }
            }
            match next {
                Some(id) => current = id,
                None => {
                    self.directories.insert(directory.to_vec(), None);
                    return None;
                }
            }
        }

        self.directories.insert(directory.to_vec(), Some(current));
        Some(current)
    }
}

/// Turns the gathered sightings into a stable, sorted report.
fn collect(found: HashMap<Vec<u8>, Vec<Sighting>>) -> Vec<Exposure> {
    let mut exposed: Vec<Exposure> = found
        .into_iter()
        .map(|(path, mut sightings)| {
            sightings.sort_by_key(|sighting| sighting.blob);
            Exposure { path, sightings }
        })
        .collect();
    exposed.sort_by(|left, right| left.path.cmp(&right.path));
    exposed
}

/// Every commit reachable from a reference, `HEAD` included.
///
/// Failures are per reference: a repository with one broken tag still has a
/// history worth scanning, and refusing the whole command over it would hide
/// every finding in the rest.
///
/// **Every worktree's references, not only this one's.** A linked worktree has a
/// `HEAD` and a private `refs/` of its own under `.git/worktrees/<name>/`, and
/// git counts both as reachability: measured on git 2.55, a commit named only by
/// a detached `worktrees/wt/HEAD` survived `git gc --prune=now`. Scanning only
/// the store this command was run from reported `VERDICT: no findings` and exit
/// `0` for a repository whose object database still held a declared path in the
/// clear — naming the same commit with an ordinary branch flipped it to `5`.
fn tips(
    git_dir: &Path,
    common_dir: &Path,
    hash: gix_hash::Kind,
    objects: &gix_odb::Handle,
    scan: &mut Scan,
) -> Vec<ObjectId> {
    let options = || gix_ref::store::init::Options {
        object_hash: hash,
        ..gix_ref::store::init::Options::default()
    };
    // A linked worktree keeps its own `HEAD` beside the shared `refs/`, so the
    // store has to be told about both. Opening it at the git directory alone
    // would leave every branch invisible and report a repository with plenty of
    // history as having none.
    let store = if git_dir == common_dir {
        gix_ref::file::Store::at(git_dir.to_path_buf(), options())
    } else {
        gix_ref::file::Store::for_linked_worktree(
            git_dir.to_path_buf(),
            common_dir.to_path_buf(),
            options(),
        )
    };

    let mut tips = Vec::new();
    collect_tips(&store, objects, scan, &mut tips);

    // The main checkout, when this scan runs in a linked one. `worktrees/`
    // below only ever holds *linked* registrations, so nothing else visits the
    // main checkout's `HEAD` — and its worktree-private references live
    // directly in the common directory, which is the store this arm opens.
    // Measured on git 2.55, 2026-08-05: with the main checkout detached at a
    // commit holding a plain-text secret no branch names, `status` from a
    // linked worktree said `VERDICT: no findings` and exited 0, while the same
    // command from the main checkout exited 5. The shared references are
    // collected twice on this path; the sort at the bottom deduplicates them,
    // exactly as it does for the registrations underneath.
    if git_dir != common_dir {
        let main = gix_ref::file::Store::at(common_dir.to_path_buf(), options());
        collect_tips(&main, objects, scan, &mut tips);
    }

    // The other checkouts. Their shared references are already in `tips`, so
    // what this adds is each one's own `HEAD` and its worktree-private
    // categories — `refs/bisect/*` above all, which is where a bisect in
    // progress parks the commits it is testing.
    //
    // A registration directory that cannot be listed is a store that cannot be
    // enumerated, not an empty one: every other checkout's `HEAD` would go
    // unvisited, and this scan's silence would read as a clean bill of health.
    // Measured on git 2.55, 2026-08-05: `chmod 000 .git/worktrees` over a
    // repository whose only path to a plain-text secret was a linked worktree's
    // detached `HEAD` turned exit 5 into `VERDICT: no findings`, exit 0. The
    // same rule `packed-refs` already follows, one directory over. Only the
    // directory being absent means there are no linked worktrees.
    match std::fs::read_dir(common_dir.join("worktrees")) {
        Ok(entries) => {
            for entry in entries {
                let registration = match entry {
                    Ok(entry) => entry.path(),
                    Err(err) => {
                        scan.refs_unavailable = true;
                        scan.warnings.push(format!(
                            "a worktree registration could not be read ({err}), so that \
                             checkout's references were not scanned"
                        ));
                        continue;
                    }
                };
                if registration == git_dir || !registration.join("HEAD").is_file() {
                    continue;
                }
                let other = gix_ref::file::Store::for_linked_worktree(
                    registration,
                    common_dir.to_path_buf(),
                    options(),
                );
                collect_tips(&other, objects, scan, &mut tips);
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            scan.refs_unavailable = true;
            scan.warnings.push(format!(
                "the worktree registrations could not be listed ({err}), so no other \
                 checkout's references were scanned"
            ));
        }
    }

    tips.sort();
    tips.dedup();
    tips
}

/// Adds every commit one reference store names to `tips`.
///
/// Split out so the same reading applies to this checkout's store and to every
/// other worktree's, rather than the second being a second implementation.
fn collect_tips(
    store: &gix_ref::file::Store,
    objects: &gix_odb::Handle,
    scan: &mut Scan,
    tips: &mut Vec<ObjectId>,
) {
    let mut push = |mut reference: gix_ref::Reference, scan: &mut Scan| {
        let name = reference.name.as_bstr().to_string();
        // A symbolic reference whose target does not exist yet is an unborn
        // branch — the state of every repository between `git init` and its
        // first commit, and of `git checkout --orphan`. It is not a failure and
        // must not be reported as one: a fresh repository greeting the user with
        // "HEAD could not be resolved" is a bug report waiting to be filed.
        if let Some(target) = reference.target.try_name()
            && matches!(store.try_find(target), Ok(None))
        {
            return;
        }
        match reference.peel_to_id(store, objects) {
            // A tag on a blob or a tree is a real thing — git.git carries
            // `junio-gpg-pub` — and it names no history at all. Queuing it would
            // make the commit walk fail to read a "commit" that was never one,
            // which counted as an unreadable object and turned a healthy
            // repository into a permanently red gate advising `git fsck`, which
            // would then report nothing wrong.
            Ok(id) => match objects.try_header(&id) {
                Ok(Some(header)) if header.kind == gix_object::Kind::Commit => tips.push(id),
                // A tag on a tree or a blob names no history, so there is
                // nothing here to scan — but silence would make "nothing found"
                // and "nothing looked at" identical, which is the one thing this
                // module refuses to do.
                Ok(Some(header)) => scan.notes.push(format!(
                    "{name} points at a {} and was not walked",
                    header.kind
                )),
                Ok(None) | Err(_) => {
                    note_unresolved(scan, &name, &format!("{id} could not be read"));
                }
            },
            Err(err) => {
                note_unresolved(scan, &name, &format!("it could not be resolved ({err})"));
            }
        }
    };

    match store.iter() {
        Ok(platform) => match platform.all() {
            Ok(references) => {
                for reference in references {
                    match reference {
                        Ok(reference) => push(reference, scan),
                        // Git prints `warning: ignoring broken ref` and carries
                        // on for a file under `refs/` that is not a reference —
                        // crash residue, a stray `notes.txt`. Such a file names
                        // no history, so nothing goes unscanned because of it,
                        // and failing the gate over one was a false alarm on a
                        // state git itself shrugs at. A reference that *is* one
                        // and will not resolve is caught when it is peeled.
                        //
                        // **Only that one variant, though.** The other three mean
                        // a reference exists and was *not* walked: a ref file
                        // that could not be read, a directory traversal that
                        // failed, a `packed-refs` line that would not parse.
                        // Measured before this split, with `chmod 000
                        // .git/refs/heads/leak` over a branch holding a
                        // plain-text `secrets/db.env`: `VERDICT: no findings.`
                        // and exit 0, under a note claiming the file "is not a
                        // reference" when gix had said it "could not be read in
                        // full". That is the packed-refs failure this module was
                        // already fixed for, one file over.
                        Err(gix_ref::file::iter::loose_then_packed::Error::ReferenceCreation {
                            source,
                            relative_path,
                        }) => scan.notes.push(format!(
                            "a file under refs/ is not a reference \
                             ({relative_path:?}: {source})"
                        )),
                        Err(err) => note_unresolved(
                            scan,
                            "a reference under refs/",
                            &format!("it could not be read ({err})"),
                        ),
                    }
                }
            }
            Err(err) => {
                scan.refs_unavailable = true;
                scan.warnings
                    .push(format!("the references could not be listed ({err})"));
            }
        },
        Err(err) => {
            scan.refs_unavailable = true;
            scan.warnings
                .push(format!("packed-refs could not be read ({err})"));
        }
    }

    // `HEAD` is a pseudo-reference and is not part of `all()`. On a detached
    // checkout it is the only thing naming the current commit, so leaving it out
    // would make exactly the state a bisect leaves you in unscannable.
    match store.try_find("HEAD") {
        Ok(Some(head)) => push(head, scan),
        // An unborn branch: a fresh repository with no commit yet.
        Ok(None) => {}
        // One reference, not the store: everything under `refs/` was still
        // enumerated, so claiming "no history was scanned at all" would
        // contradict the commit count printed three lines later.
        Err(err) => note_unresolved(scan, "HEAD", &format!("it could not be read ({err})")),
    }
}

/// Walks one tree, descending into subtrees and judging declared blobs.
///
/// Iterative rather than recursive: a repository is free to contain a path
/// thousands of directories deep, and a stack overflow in a diagnostic command
/// would be a crash where a report belongs.
#[expect(
    clippy::too_many_arguments,
    reason = "one walk with one set of caches; splitting the state would mean \
              threading a struct that exists only to satisfy the count"
)]
fn walk_tree(
    objects: &gix_odb::Handle,
    config: &Config,
    root: ObjectId,
    commit: ObjectId,
    seen_trees: &mut HashSet<(ObjectId, Vec<u8>)>,
    verdicts: &mut HashMap<ObjectId, bool>,
    found: &mut HashMap<Vec<u8>, Vec<Sighting>>,
    scan: &mut Scan,
) {
    let mut pending = vec![(root, Vec::new())];

    while let Some((tree, prefix)) = pending.pop() {
        if !seen_trees.insert((tree, prefix.clone())) {
            continue;
        }

        let mut buffer = Vec::new();
        let entries = match objects.find_tree_iter(&tree, &mut buffer) {
            Ok(entries) => entries,
            Err(err) => {
                note_unreadable(scan, &tree, &err.to_string());
                continue;
            }
        };

        for entry in entries {
            let Ok(entry) = entry else {
                note_unreadable(scan, &tree, "one of its entries did not parse");
                break;
            };

            let mut path = prefix.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(entry.filename);

            if entry.mode.is_tree() {
                pending.push((entry.oid.to_owned(), path));
                continue;
            }
            // Symlinks and submodule gitlinks are never filtered by git, so
            // there is nothing about them a declaration could have enforced.
            if !entry.mode.is_blob() {
                continue;
            }
            if !config.decide(&path).encrypt {
                continue;
            }

            let id = entry.oid.to_owned();
            let clear = match verdicts.get(&id) {
                Some(clear) => *clear,
                None => {
                    let Some(clear) = is_clear(objects, &id, scan) else {
                        continue;
                    };
                    verdicts.insert(id, clear);
                    clear
                }
            };

            if clear {
                let sightings = found.entry(path).or_default();
                if !sightings.iter().any(|sighting| sighting.blob == id) {
                    sightings.push(Sighting { blob: id, commit });
                }
            }
        }
    }
}

/// Whether a blob is stored without our magic, or `None` if it could not be read.
fn is_clear(objects: &gix_odb::Handle, id: &ObjectId, scan: &mut Scan) -> Option<bool> {
    let mut buffer = Vec::new();
    match objects.try_find(id, &mut buffer) {
        Ok(Some(data)) => Some(!format::looks_encrypted(data.data)),
        Ok(None) => {
            note_unreadable(scan, id, "it is not in this repository's object database");
            None
        }
        Err(err) => {
            note_unreadable(scan, id, &err.to_string());
            None
        }
    }
}

/// Records a reference the walk could not start from.
///
/// Budgeted like the objects, and separately from them: a repository with a
/// thousand broken references would otherwise flood `stderr`, and before the
/// budgets were split the references consumed the objects' allowance.
fn note_unresolved(scan: &mut Scan, name: &str, why: &str) {
    scan.unresolved_refs += 1;
    if scan.unresolved_refs <= MAX_UNREADABLE_WARNINGS {
        scan.unresolved_names.push(name.to_string());
        scan.warnings.push(format!("{name}: not scanned, {why}"));
    }
}

/// Records an object the scan could not judge.
///
/// The budget counts the messages this function has produced, not the whole
/// warning list: sharing it with the per-reference messages meant five bad refs
/// left every unreadable object unnamed, counted but never identified.
fn note_unreadable(scan: &mut Scan, id: &ObjectId, why: &str) {
    scan.unreadable += 1;
    if scan.unreadable <= MAX_UNREADABLE_WARNINGS {
        scan.warnings.push(format!("{id}: not scanned, {why}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    /// Drives a real repository: only git's own objects prove any of this.
    struct Fixture {
        dir: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = TempDir::new().expect("temporary directory");
            let fixture = Self { dir };
            fixture.git(&["init", "-q", "-b", "main"]);
            fixture.git(&["config", "user.name", "t"]);
            fixture.git(&["config", "user.email", "t@t.invalid"]);
            fixture
        }

        fn git(&self, args: &[&str]) -> std::process::Output {
            let output = Command::new("git")
                .args(args)
                .current_dir(self.dir.path())
                .output()
                .expect("git must be on PATH");
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output
        }

        fn write(&self, relative: &str, content: &[u8]) {
            let path = self.dir.path().join(relative);
            fs::create_dir_all(path.parent().expect("a parent")).expect("directories");
            fs::write(path, content).expect("writing");
        }

        fn commit(&self, message: &str) {
            self.git(&["add", "-A"]);
            self.git(&["commit", "-q", "-m", message]);
        }

        fn scan(&self, declarations: &str) -> Scan {
            let config = Config::parse(declarations).expect("the declarations must parse");
            let git_dir = self.dir.path().join(".git");
            let objects = super::objects(&git_dir, gix_hash::Kind::Sha1)
                .expect("the object database must open");
            super::scan(
                &objects,
                &git_dir,
                &git_dir,
                gix_hash::Kind::Sha1,
                &config,
                false,
            )
            .expect("the scan must succeed")
        }
    }

    fn paths(scan: &Scan) -> Vec<String> {
        scan.exposed
            .iter()
            .map(|exposure| String::from_utf8_lossy(&exposure.path).into_owned())
            .collect()
    }

    #[test]
    fn a_secret_named_only_by_another_worktrees_head_is_found() {
        // A linked worktree's `HEAD` is reachability to git — measured on 2.55,
        // a commit named only by `worktrees/wt/HEAD` survives
        // `git gc --prune=now`. Before this, the scan opened only the store of
        // the checkout it was run from, so the same repository reported
        // `VERDICT: no findings` and exit 0 with the plaintext still in the
        // object database.
        let fixture = Fixture::new();
        fixture.write("README.md", b"start\n");
        fixture.commit("start");
        fixture.git(&["checkout", "-q", "-b", "side"]);
        fixture.write("secrets/parked.env", b"hunter2\n");
        fixture.commit("on the side");
        let head = fixture.git(&["rev-parse", "HEAD"]);
        let head = String::from_utf8(head.stdout).expect("a hash");
        let head = head.trim().to_string();
        fixture.git(&["checkout", "-q", "main"]);

        let elsewhere = tempfile::TempDir::new().expect("temporary directory");
        let checkout = elsewhere.path().join("wt");
        fixture.git(&[
            "worktree",
            "add",
            "-q",
            "--detach",
            checkout.to_str().expect("a path"),
            &head,
        ]);
        // The branch goes, so nothing under `refs/` names the commit any more.
        fixture.git(&["branch", "-D", "side"]);

        let scan = fixture.scan("secrets/\n");

        assert_eq!(paths(&scan), ["secrets/parked.env"]);
    }

    #[test]
    fn a_secret_named_only_by_the_main_checkouts_head_is_found_from_a_linked_worktree() {
        // The mirror of the test above, and the direction it did not cover.
        // `worktrees/` only registers *linked* checkouts, so a scan run from
        // one of them never visited the main checkout's `HEAD`. Measured on
        // git 2.55: this exact shape answered `VERDICT: no findings`, exit 0,
        // from the linked worktree, and exit 5 from the main checkout.
        let fixture = Fixture::new();
        fixture.write("README.md", b"start\n");
        fixture.commit("start");
        fixture.git(&["checkout", "-q", "-b", "side"]);
        fixture.write("secrets/parked.env", b"hunter2\n");
        fixture.commit("on the side");

        // The main checkout detaches at the secret, the branch goes, and a
        // linked worktree parks at the clean commit — so the main `HEAD` is
        // the only thing left naming the plaintext.
        fixture.git(&["checkout", "-q", "--detach", "side"]);
        fixture.git(&["branch", "-D", "side"]);
        let elsewhere = tempfile::TempDir::new().expect("temporary directory");
        let checkout = elsewhere.path().join("wt");
        fixture.git(&[
            "worktree",
            "add",
            "-q",
            "--detach",
            checkout.to_str().expect("a path"),
            "main",
        ]);

        let common = fixture.dir.path().join(".git");
        let linked = common.join("worktrees").join("wt");
        let config = Config::parse("secrets/\n").expect("the declarations must parse");
        let objects =
            super::objects(&common, gix_hash::Kind::Sha1).expect("the object database must open");
        let scan = super::scan(
            &objects,
            &linked,
            &common,
            gix_hash::Kind::Sha1,
            &config,
            false,
        )
        .expect("the scan must succeed");

        assert_eq!(paths(&scan), ["secrets/parked.env"]);
    }

    #[test]
    fn an_unlistable_worktree_registration_directory_is_not_an_empty_one() {
        // The listing is what covers every other checkout's `HEAD`, so a
        // failure to take it must land in `undetermined` rather than read as
        // "no other checkouts". Provoked with a *file* where the directory
        // belongs rather than a permission bit, so the branch runs on all
        // three platforms — the same trick `tests/lock_unlock.rs` uses, and
        // for the same reason: what is checked is the branch, not the errno.
        let fixture = Fixture::new();
        fixture.write("README.md", b"start\n");
        fixture.commit("start");
        fs::write(
            fixture.dir.path().join(".git/worktrees"),
            b"not a directory\n",
        )
        .expect("writing over the registrations");

        let scan = fixture.scan("secrets/\n");

        assert!(
            scan.refs_unavailable,
            "an unlistable worktrees directory was read as an empty one"
        );
    }

    #[test]
    fn a_secret_reachable_only_through_a_tag_is_found() {
        // An annotated tag is an object of its own; without peeling it, the
        // commit behind it would never enter the walk.
        let fixture = Fixture::new();
        fixture.write("README.md", b"start\n");
        fixture.commit("start");
        fixture.write("secrets/tagged.env", b"hunter2\n");
        fixture.commit("tagged");
        fixture.git(&["tag", "-a", "v1", "-m", "release"]);
        fixture.git(&["reset", "-q", "--hard", "HEAD~1"]);

        let scan = fixture.scan("secrets/\n");

        assert_eq!(paths(&scan), ["secrets/tagged.env"]);
    }
}
