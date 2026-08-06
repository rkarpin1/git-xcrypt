//! `git-xcrypt status` — whether the declarations are actually enforced.
//!
//! The boundary is worth stating before anything else, because it is easy to
//! read this command as more than it is: it answers **"are my declarations
//! enforced"**, not **"are there secrets in this repository"**. A file that never
//! matched a pattern is invisible here, by construction.
//!
//! Within that boundary it has two jobs, and the first is the one nothing else
//! covers. A clone inherits `.gitattributes` through history but not
//! `.git/config`, so it carries the catch-all line with no driver behind it —
//! and git reads an undefined filter exactly as it reads no filter, which means
//! the next `git add` on a secret exits 0 and stores the plaintext. Nothing in
//! that sequence produces a signal. Asking for one is what this command is for.
//!
//! The second job is `--fix`, and there is a measured reason it has to exist.
//! The founding document says a pattern added to `.git-xcrypt` "works
//! immediately, with no synchronising command", and that is true of the filter:
//! it re-reads the declaration on every call. It is **not** true of git. Git
//! decides from its cached `stat` whether to call the filter at all, so a file
//! that was already committed and is not then edited is skipped — measured on
//! git 2.55, past the racy-clean window:
//!
//! ```text
//! git add -A && git commit            # before the pattern existed
//! printf 'secrets/\n' > .git-xcrypt
//! git add -A && git commit            # exit 0, no warning
//! git cat-file blob HEAD:secrets/db.env  → hunter2
//! ```
//!
//! Nothing in that sequence is wrong from git's point of view, and nothing in
//! it tells the user. So this command reports the state and `--fix` repairs it,
//! which is the whole reason the fix operates on the index rather than merely
//! printing advice.
//!
//! The exit code is part of the contract: `5` on a finding, so the command works
//! as a CI gate and so "the repository has a problem" is distinguishable from
//! "the tool broke". Since 2026-08-04 there is a third answer, `6`, for the runs
//! that could not tell — a shallow or partial clone, an index that will not
//! parse. Collapsing that into `5` failed the gate on a healthy `git clone
//! --depth 1`, which is what `actions/checkout` produces unless it is given
//! `fetch-depth: 0`.
//!
//! Since 2026-08-05 there is a fourth, and it outranks the other two: `2`, the
//! frozen table's "configuration or a state conflict", for a repository where
//! git is not set up to enforce anything — an unregistered filter, a missing
//! catch-all line, a missing declaration. **Configuration comes before data**,
//! because without a configuration that enforces anything the data here is worth
//! nothing, and `5` used to tell a repository that had never run `init` that an
//! exposure had been found. It hides nothing: every section is printed under
//! every verdict, so a misconfigured repository that also leaked still names the
//! leak and still prints the rotate-first procedure. See [`Verdict`].

use std::fmt;

use crate::config::Config;
use crate::repo::{DRIVER, Repo, git_spelling};
use gix_object::Write as _;

use crate::{Result, gitattributes, gitconfig, gitindex, history};

/// One reason git would not be filtering this repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupGap {
    /// A `filter.git-xcrypt.*` key is not set anywhere git reads.
    MissingKey(String),
    /// The key is set, but not to anything git reads as true.
    NotTrue {
        /// The dotted key.
        key: String,
        /// What it is set to.
        value: String,
    },
    /// `.gitattributes` carries no `* filter=git-xcrypt` line.
    CatchAllMissing,
    /// Git resolves `filter` to something other than this tool for declared paths.
    ///
    /// The catch-all is one line among many and git takes the **last** match, so
    /// an attribute line below the managed section, a `.gitattributes` in a
    /// subdirectory, or `$GIT_DIR/info/attributes` — which is not versioned and
    /// outranks everything — turns this tool off for paths it believes it
    /// protects. Measured on git 2.55: `git check-attr filter` then answers
    /// `unset`, the next `git add` stores the plaintext, and every other check in
    /// this command passes.
    ///
    /// Until 2026-08-04 this was a **note**: the report named the files and the
    /// lines and left the reader to run `git check-attr`. That was the last route
    /// to a green report on a repository that does not encrypt, because a note
    /// does not fail a CI gate.
    FilterUnresolved {
        /// The declared paths git would not filter, capped for the message.
        paths: Vec<String>,
        /// How many there are altogether.
        total: usize,
        /// What git resolves instead, spelled as `git check-attr` spells it.
        resolved: String,
    },
    /// Git converts the line endings of declared paths itself.
    ///
    /// The twin of [`SetupGap::FilterUnresolved`], on the second attribute the
    /// managed section sets, and it costs more rather than less. The section
    /// writes `-text` on every encrypted path precisely so that git's own CRLF
    /// conversion never touches the ciphertext; an attribute line that outranks
    /// it puts the conversion back.
    ///
    /// Measured on git 2.55, with `sync` freshly run so nothing else in this
    /// command had anything to say: a 2 MB file under `secrets/** text` lost 34
    /// `CR` bytes out of its **ciphertext**, `git add` exited 0, `git commit`
    /// exited 0, and the checkout failed the authentication tag and left no file
    /// at all. Nobody can decrypt what was committed — not the author, not with
    /// the key, not ever. `status` printed `VERDICT: no findings.` and exited 0.
    ///
    /// A gap rather than a note for the reason the unresolved filter is one:
    /// both mean the declaration is not enforced, and a note does not fail a CI
    /// gate.
    CiphertextConverted {
        /// The declared paths git would convert, capped for the message.
        paths: Vec<String>,
        /// How many there are altogether.
        total: usize,
        /// The attribute line that decides it, with the file and line it sits in.
        culprit: String,
    },
    /// `.git-xcrypt` is not there, so nothing declares what to encrypt.
    ///
    /// Filed as a gap rather than only as a question since 2026-08-05. It is not
    /// an exposure — the check-in path refuses on this state, so no `git add`
    /// stores anything in the clear over it — but it is precisely a
    /// configuration that enforces nothing, and the remedy is a file, not a
    /// rotated secret. It still puts the rest of the run in `undetermined`,
    /// because without the declaration neither the index nor history can be
    /// judged at all.
    DeclarationMissing,
    /// A file the whole mechanism bootstraps from is not tracked.
    ///
    /// `.gitattributes` is what makes git call the filter and `.git-xcrypt` is
    /// what the filter reads. Neither is any use to a clone unless it is
    /// committed, and `init` creates them without committing them — so a
    /// repository can look perfectly configured locally and publish nothing that
    /// enforces anything. The clone finds out; the machine that pushed does not.
    Untracked(String),
}

impl fmt::Display for SetupGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey(key) => write!(
                f,
                "{key} is not set, so git has no filter to run for this repository"
            ),
            Self::NotTrue { key, value } => write!(
                f,
                "{key} is `{value}`, not true — without it a failing filter is \
                 ignored and git stores the unfiltered content with exit code 0"
            ),
            Self::CatchAllMissing => write!(
                f,
                "{} carries no `{}` line, so git never calls the filter",
                crate::repo::ATTRIBUTES_FILE,
                gitattributes::CATCH_ALL
            ),
            Self::FilterUnresolved {
                paths,
                total,
                resolved,
            } => {
                write!(
                    f,
                    "git resolves `filter` to `{resolved}` for {total} declared path(s), \
                     not `{DRIVER}` — so committing them stores the plain text, whatever \
                     the `{catch_all}` line says. Some attribute line outranks it; \
                     `git check-attr filter -- <path>` shows which, and the notes below \
                     name every file carrying a `filter` line. Deleting or narrowing that \
                     line is the fix — `git-xcrypt init` will not remove it. Reached: {}",
                    paths.join(", "),
                    catch_all = gitattributes::CATCH_ALL
                )?;
                if *total > paths.len() {
                    write!(f, ", … and {} more", total - paths.len())?;
                }
                Ok(())
            }
            Self::CiphertextConverted {
                paths,
                total,
                culprit,
            } => {
                write!(
                    f,
                    "git converts the line endings of {total} declared path(s) itself, \
                     because this line outranks the managed `-text`:\n      {culprit}\n    \
                     That conversion runs over the **ciphertext**: `git add` and \
                     `git commit` both exit 0, the damaged blob is committed, and the \
                     next checkout fails the authentication tag and leaves no file at \
                     all — measured on git 2.55, 34 `CR` bytes eaten out of a 2 MB blob. \
                     What is committed cannot be decrypted again by anyone, with any \
                     key. Delete or narrow that line so the managed `-text` wins, then \
                     run `git-xcrypt sync`; anything already committed under it has to \
                     be re-added from a copy of the plain text. Reached: {}",
                    paths.join(", ")
                )?;
                if *total > paths.len() {
                    write!(f, ", … and {} more", total - paths.len())?;
                }
                Ok(())
            }
            Self::DeclarationMissing => write!(
                f,
                "{config} is missing, so nothing here declares what to encrypt. \
                 Nothing is stored in the clear over this — every `git add` in \
                 this repository refuses until it is back — and nothing is \
                 enforced either. `git-xcrypt init` creates one; a clone gets it \
                 from the commit that carries it",
                config = crate::repo::CONFIG_FILE
            ),
            Self::Untracked(path) => write!(
                f,
                "{path} is not committed, so no clone of this repository gets it \
                 — and without it a clone filters nothing. `git add {path}` and \
                 commit it"
            ),
        }
    }
}

/// What `status` found.
///
/// Four sections, deliberately separate, because the remedies are four different
/// things and a single list would hide which one applies.
#[derive(Debug, Default)]
pub struct Report {
    /// Reasons git is not filtering here. Any of these means the guarantee is off.
    pub setup: Vec<SetupGap>,
    /// Whether a repository key is present at all.
    pub has_key: bool,
    /// Declared paths the index already stores as ciphertext. The good case.
    pub encrypted: Vec<Vec<u8>>,
    /// Declared paths the index stores **in the clear** — what a commit made now
    /// would push. This is the set `--fix` repairs.
    pub in_the_clear: Vec<Vec<u8>>,
    /// Declared paths that reachable history holds in the clear.
    ///
    /// Nothing local repairs this. The report says so in as many words.
    pub leaked: Vec<crate::history::Exposure>,
    /// Paths a negation deliberately keeps in the clear.
    ///
    /// Listed rather than left out: a hole a user wrote on purpose must not be
    /// invisible, or the declaration reads as covering more than it does.
    pub by_choice: Vec<Vec<u8>>,
    /// Paths `--fix` re-staged through the filter.
    ///
    /// Named separately from [`Report::encrypted`] so the sentence that follows
    /// them — that this changes the next commit and nothing about the past — has
    /// something to attach to.
    pub fixed: Vec<Vec<u8>>,
    /// Things this build could not determine, and why.
    ///
    /// These fail the gate. "I could not tell" reported as a pass is the one
    /// answer a command like this must never give.
    pub undetermined: Vec<String>,
    /// How much history was walked, for the closing line.
    pub scanned: Scanned,
    /// Whether the history scan ran at all.
    ///
    /// Without it the closing line printed "scanned 0 commit(s)" for a run that
    /// returned before the scan, which reads as "I looked and there was nothing"
    /// in a repository with five hundred commits.
    pub scan_ran: bool,
    /// Whether `--fix` was asked for.
    ///
    /// The advice under "in the clear" tells a user to run `--fix`; printing
    /// that in the output of `--fix` itself points at the command that has just
    /// declined, and says nothing about the attempt.
    pub fix_requested: bool,
    /// Notes that describe a lesser problem and never change the exit code.
    pub notes: Vec<String>,
    /// Anything worth saying once, carried out so the binary owns the messages.
    pub warnings: Vec<String>,
}

/// How much of the repository the scan covered.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Scanned {
    /// Commits visited.
    pub commits: usize,
    /// Distinct blobs under a declared path that were read.
    pub blobs: usize,
}

/// What a run concluded, as the exit code reports it.
///
/// Four values, and each one asks the operator for something different: fix the
/// configuration, rotate a secret, fix the checkout, or nothing at all. That is
/// the only reason they are separate — a gate is read as a number, and a number
/// that carries two questions gets the wrong answer to one of them. Both splits
/// were made after measuring a case where the shared code sent a reader the
/// wrong way: `6` because a healthy `git clone --depth 1` failed the gate like a
/// leaking repository, and `2` because a repository that had never run `init`
/// was told an exposure had been found. See [`crate::exit::UNDETERMINED`] and
/// [`crate::exit::CONFIG`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Everything was checked and nothing was found.
    Clean,
    /// Nothing was found, but part of the question could not be answered.
    Undetermined,
    /// Something was found.
    Exposed,
    /// Git is not set up to enforce the declarations here.
    ///
    /// The highest of the four since 2026-08-05, and the only one that reversed
    /// a precedence — see [`Report::verdict`].
    Misconfigured,
}

impl Report {
    /// What this run concluded.
    ///
    /// **Configuration, then a finding, then a question.** The owner's reason for
    /// putting configuration first, 2026-08-05: *without a working configuration
    /// the data in the repository is worth nothing* — a checkout where git is not
    /// running the filter cannot be judged clean, cannot be trusted about what it
    /// stores next, and above all cannot be repaired by acting on anything this
    /// report says about its data. So the operator is sent to the one repair that
    /// makes the rest meaningful, and asks again afterwards.
    ///
    /// It is a reversal in exactly one place. Until 2026-08-05 a setup gap was
    /// [`Verdict::Exposed`], which handed `5` — "an exposure was found, rotate
    /// the secret" — to a repository that had never run `init` and had nothing in
    /// it to rotate, while the one thing genuinely wrong with it read as a
    /// detail. `2` is the frozen table's "configuration or a state conflict",
    /// used here exactly as `init` and `lock` already use it.
    ///
    /// Everything else stands: a finding still outranks an unanswered question,
    /// so a run that hit an unreadable index *and* found a leak has found a leak.
    /// And no verdict withholds a section — a misconfigured repository that also
    /// leaked prints the leak, the paths and the rotate-first procedure exactly
    /// as it did before, because the code changes the order of the work and not
    /// what the reader is told.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        if !self.setup.is_empty() {
            Verdict::Misconfigured
        } else if !self.in_the_clear.is_empty() || !self.leaked.is_empty() {
            Verdict::Exposed
        } else if self.undetermined.is_empty() {
            Verdict::Clean
        } else {
            Verdict::Undetermined
        }
    }

    /// Whether this run found plain text where ciphertext was expected.
    ///
    /// Read off the findings rather than off [`Report::verdict`], and that is
    /// deliberate: since 2026-08-05 a setup gap outranks a finding, so a
    /// repository that both leaked and is misconfigured answers
    /// [`Verdict::Misconfigured`] while its leak is every bit as real. Deriving
    /// this from the verdict would make it say no.
    #[must_use]
    pub fn exposed(&self) -> bool {
        !self.in_the_clear.is_empty() || !self.leaked.is_empty()
    }

    /// Whether any setup gap means git stores declared content unfiltered
    /// **on this machine**.
    ///
    /// Three of them do not, and they are different failures rather than milder
    /// ones. [`SetupGap::CiphertextConverted`]: git runs the filter and then
    /// damages what it produced, so what is lost is the file, not the secret.
    /// [`SetupGap::DeclarationMissing`]: the check-in path refuses outright, so
    /// nothing is stored at all. [`SetupGap::Untracked`]: git enforces the
    /// declarations *here* — the attributes and the declaration are read from
    /// the working tree — and publishes nothing that enforces them anywhere
    /// else; the exposure is a clone's, not this checkout's. Same exit code,
    /// four different remedies — and only the first calls for rotating
    /// anything. Telling a user whose repository filters correctly that
    /// "committing a declared file stores it in the clear" sends them to
    /// rotate secrets that were never exposed, which is the failure mode the
    /// 2026-08-05 precedence change was made to remove.
    fn stores_in_the_clear(&self) -> bool {
        self.setup.iter().any(|gap| {
            !matches!(
                gap,
                SetupGap::CiphertextConverted { .. }
                    | SetupGap::DeclarationMissing
                    | SetupGap::Untracked(_)
            )
        })
    }

    /// Whether the only thing wrong is that nothing declares what to encrypt.
    fn only_the_declaration_is_missing(&self) -> bool {
        self.setup
            .iter()
            .all(|gap| matches!(gap, SetupGap::DeclarationMissing))
    }

    /// Whether the only thing wrong is that the bootstrap files are uncommitted.
    fn only_the_bootstrap_is_untracked(&self) -> bool {
        self.setup
            .iter()
            .all(|gap| matches!(gap, SetupGap::Untracked(_)))
    }
}

/// A repository-relative path as a message shows it.
///
/// Lossy on purpose and only here: a path is arbitrary bytes on Unix, so the
/// decision paths — matching, hashing, index lookup — keep the bytes, and only
/// the moment of printing gives up on them.
/// How many paths the good-news section prints before summarising.
const MAX_LISTED: usize = 10;

/// How many plaintext blobs are shown per exposed path.
const MAX_SIGHTINGS: usize = 3;

fn show(path: &[u8]) -> String {
    bstr::BStr::new(path).to_string()
}

/// A path as a shell argument, for the command the report tells a user to run.
///
/// Single quotes stop the shell expanding anything; a literal quote is closed,
/// escaped and reopened — the same escape `init` uses for the binary path it
/// registers. Without it a file called `it's.env` would produce a command that
/// either fails to parse or, worse, parses as something else. The report is
/// printed and never executed by this tool, which makes correctness here a
/// matter of not handing a user a broken instruction, not of injection.
fn shell_quoted(path: &[u8]) -> String {
    format!("'{}'", show(path).replace('\'', r"'\''"))
}

/// Renders the whole report, sections and remedies included.
///
/// A `Display` rather than a pile of `eprintln!` in the binary: the wording here
/// *is* part of the safeguard — a user must never read "fixed" as "the secret is
/// safe" — so it has to be assertable from a test.
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_verdict(f)?;
        if self.setup.is_empty() {
            writeln!(
                f,
                "setup: git is configured to run the filter in this repository."
            )?;
        } else {
            // Three different sentences, because the gaps have three different
            // outcomes and one wording cannot be true of all of them. A
            // registration gap stores the plain text; a conversion gap destroys
            // the ciphertext instead; a missing declaration stores nothing at
            // all because the check-in path refuses. Telling a user their
            // secrets are in the clear when they are not sends them to rotate
            // credentials that were never exposed, while telling them to run
            // `init` fixes nothing.
            if self.stores_in_the_clear() {
                writeln!(
                    f,
                    "setup: git is NOT filtering this repository. Until this is fixed, \
                     committing a declared file stores it in the clear, with exit code 0 \
                     and no warning."
                )?;
            } else if self.only_the_declaration_is_missing() {
                writeln!(
                    f,
                    "setup: git calls the filter here, but the filter has nothing to \
                     read. Nothing is stored in the clear over this — every `git add` \
                     in this repository refuses until the declaration is back — and \
                     nothing below was checked, because there is no way to tell which \
                     paths should have been."
                )?;
            } else if self.only_the_bootstrap_is_untracked() {
                writeln!(
                    f,
                    "setup: git enforces the declarations on this machine — the files \
                     below are read from the working tree — but they are not \
                     committed, so no clone gets them and nothing published enforces \
                     anything. Commits made *here* store ciphertext; commits made \
                     from a clone would not."
                )?;
            } else {
                writeln!(
                    f,
                    "setup: git runs the filter here, but does not leave its output \
                     alone. Nothing is stored in the clear over this; what it costs is \
                     the ciphertext, and with it the file."
                )?;
            }
            for gap in &self.setup {
                writeln!(f, "  - {gap}")?;
            }
            // Only where it is the remedy. Neither command touches
            // `.gitattributes` lines a user wrote, so offering them against a
            // conversion gap would send a reader round a loop that changes
            // nothing; that gap carries its own instruction instead.
            if self.stores_in_the_clear() {
                writeln!(f, "\n  Fix it with one of:")?;
                if self.has_key {
                    writeln!(f, "    git-xcrypt init      # the key here is kept")?;
                } else {
                    writeln!(f, "    git-xcrypt unlock <key-file>")?;
                    writeln!(f, "    git-xcrypt import-key <key-file>")?;
                }
            } else if self.only_the_bootstrap_is_untracked() {
                // Neither `init` nor `unlock` commits anything, so offering
                // them here would send a reader round a loop that changes
                // nothing — the same rule the comment above states for the
                // conversion gap. The remedy is a commit.
                writeln!(f, "\n  Fix it by committing the files:")?;
                writeln!(
                    f,
                    "    git add {} {} && git commit",
                    crate::repo::ATTRIBUTES_FILE,
                    crate::repo::CONFIG_FILE
                )?;
            }
        }

        self.write_undetermined(f)?;
        self.write_fixed(f)?;
        self.write_encrypted(f)?;
        self.write_in_the_clear(f)?;
        self.write_leaked(f)?;
        self.write_by_choice(f)?;

        for note in &self.notes {
            writeln!(f, "\nnote: {note}")?;
        }

        if self.scan_ran {
            writeln!(
                f,
                "\nscanned {} commit(s) and {} distinct blob(s) under a declared \
                 path. `status` answers whether your declarations are enforced, not \
                 whether this repository holds secrets: a path no pattern ever \
                 matched is invisible to it.",
                self.scanned.commits, self.scanned.blobs
            )
        } else {
            // "scanned 0 commit(s)" reads as "I looked and there was nothing",
            // which in a five-hundred-commit repository is the opposite of true.
            writeln!(
                f,
                "\nhistory was NOT scanned — see `undetermined` above. `status` \
                 answers whether your declarations are enforced, not whether this \
                 repository holds secrets: a path no pattern ever matched is \
                 invisible to it."
            )
        }
    }
}

impl Report {
    /// One line, first, saying whether anything was found.
    ///
    /// Not decoration. `write_encrypted` lists every declared path, and a
    /// repository with three hundred secrets and one leak put the leak — and the
    /// instruction to rotate it — three hundred lines below the fold, under a
    /// solid wall of good news. The founding document is explicit that the
    /// wording here *is* the safeguard; a safeguard nobody scrolls to is not one.
    fn write_verdict(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.verdict() {
            Verdict::Clean => return writeln!(f, "VERDICT: no findings.\n"),
            // Deliberately not phrased as a finding. An operator reading this in
            // a CI log has to act on the checkout, not on the repository, and
            // the sentence has to be readable as such without the exit code.
            Verdict::Undetermined => {
                return writeln!(
                    f,
                    "VERDICT: undetermined — {} thing(s) could not be checked. \
                     NOTHING WAS FOUND, and nothing is ruled out either.\n",
                    self.undetermined.len()
                );
            }
            Verdict::Exposed | Verdict::Misconfigured => {}
        }

        let mut parts: Vec<String> = Vec::new();
        if !self.leaked.is_empty() {
            parts.push(format!("{} path(s) leaked in history", self.leaked.len()));
        }
        if !self.in_the_clear.is_empty() {
            parts.push(format!(
                "{} path(s) stored in the clear now",
                self.in_the_clear.len()
            ));
        }
        if !self.undetermined.is_empty() {
            parts.push(format!("{} thing(s) undetermined", self.undetermined.len()));
        }

        // The configuration verdict leads with the repair that makes every other
        // line here mean something, and then says what else is on the page. It
        // must never read as "and nothing else was found": a leak reported under
        // code `2` is the same leak it would be under `5`, and an operator who
        // stops reading at the first line has to know there is more below.
        if self.verdict() == Verdict::Misconfigured {
            write!(
                f,
                "VERDICT: {} setup gap(s) — git is not enforcing the declarations \
                 in this repository. Fix the setup first and ask again; until then \
                 nothing here can be called clean.",
                self.setup.len()
            )?;
            if parts.is_empty() {
                return writeln!(f, "\n");
            }
            return writeln!(
                f,
                " Also found, and NOT cancelled by the above — see the sections \
                 below: {}.\n",
                parts.join(", ")
            );
        }

        writeln!(f, "VERDICT: {}.\n", parts.join(", "))
    }

    /// What could not be determined, and therefore what nothing here proves.
    fn write_undetermined(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.undetermined.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nundetermined: this run could not answer the following, so nothing \
             below is a clean bill of health."
        )?;
        for reason in &self.undetermined {
            writeln!(f, "  - {reason}")?;
        }
        // Said only when it is the whole story. Beside a real finding the
        // sentence would soften the finding, which is the opposite of what this
        // section is for.
        if self.verdict() == Verdict::Undetermined {
            writeln!(
                f,
                "\n  This is exit code {undetermined}, not {exposed}: settle the reasons above \
                 and ask again. Nothing here was found — it was not looked at.",
                undetermined = crate::exit::UNDETERMINED,
                exposed = crate::exit::EXPOSED
            )?;
        }
        Ok(())
    }

    /// What `--fix` did, and — at least as important — what it did not.
    ///
    /// The closing sentence is the safeguard, not decoration. `--fix` repairs the
    /// future and nothing else, and a user who reads "fixed" as "the secret is
    /// safe now" has been actively misled by this command.
    fn write_fixed(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.fixed.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nfixed: {} path(s) were re-staged through the filter, so the NEXT \
             commit stores them encrypted.",
            self.fixed.len()
        )?;
        for path in &self.fixed {
            writeln!(f, "  {}", show(path))?;
        }
        writeln!(
            f,
            "\n  What is staged for each of them is its **working-tree** content, \
             the same as `git add` would stage — so any edit you had not staged \
             yet is staged now. Check `git diff --cached` before committing.\n\
             \n  \
             No file was rewritten and NO HISTORY WAS REWRITTEN. Nothing was \
             un-leaked: every plain-text version already committed is still in \
             this repository and in every clone of it. If any of these files held \
             a secret that has been pushed, rotate the secret — that is the only \
             step that revokes it."
        )
    }

    /// The good case: declared and already stored as ciphertext.
    fn write_encrypted(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.encrypted.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nencrypted: {} declared path(s) are stored as ciphertext.",
            self.encrypted.len()
        )?;
        // Capped, unlike every other section. This is the one list that grows
        // with the size of a healthy repository, and it is the only one a reader
        // does not need in full — while the sections below it are the ones they
        // came for.
        for path in self.encrypted.iter().take(MAX_LISTED) {
            writeln!(f, "  {}", show(path))?;
        }
        if self.encrypted.len() > MAX_LISTED {
            writeln!(f, "  … and {} more", self.encrypted.len() - MAX_LISTED)?;
        }
        Ok(())
    }

    /// Declared, and stored in the clear right now.
    fn write_in_the_clear(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.in_the_clear.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nin the clear: {} declared path(s) are stored unencrypted right now, \
             so a commit made from here would push the plain text.",
            self.in_the_clear.len()
        )?;
        for path in &self.in_the_clear {
            writeln!(f, "  {}", show(path))?;
        }
        if self.fix_requested {
            // --fix already ran and left these behind; the reason is in the
            // warnings on stderr. Repeating "run --fix" here would point at the
            // command whose output the reader is holding.
            return writeln!(
                f,
                "\n  `--fix` was asked for and did not re-stage these — the reason for \
                 each is on stderr. `git add` on them by hand does the same job."
            );
        }
        writeln!(
            f,
            "\n  `git add` on each of them re-stages the content through the filter, \
             and `git-xcrypt status --fix` does exactly that for all of them at once. \
             It changes what the NEXT commit stores. It does not touch history, and \
             any plain text already committed stays where it is."
        )
    }

    /// Declared, and somewhere in reachable history in the clear.
    ///
    /// The wording is load-bearing. Rewriting history does not undo a leak — the
    /// plaintext is in every clone, fork, cache and CI log that ever saw it — so
    /// the procedure has to open with rotation and say why. A user who reads
    /// "cleaned up" here has been told the wrong thing.
    fn write_leaked(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.leaked.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nleaked in history: {} declared path(s) sat in this repository in the \
             clear at some point, and the blobs are still here.",
            self.leaked.len()
        )?;
        // Every path is listed — they are the actionable unit and the thing a
        // rewrite takes. The per-blob detail is capped: it is evidence, not
        // instruction, and a path with forty revisions would bury the procedure
        // below it under forty lines nobody reads.
        for exposure in &self.leaked {
            writeln!(
                f,
                "  {} — {} plaintext blob(s)",
                show(&exposure.path),
                exposure.sightings.len()
            )?;
            for sighting in exposure.sightings.iter().take(MAX_SIGHTINGS) {
                writeln!(
                    f,
                    "      blob {} in commit {}",
                    sighting.blob, sighting.commit
                )?;
            }
            if exposure.sightings.len() > MAX_SIGHTINGS {
                writeln!(
                    f,
                    "      … and {} more",
                    exposure.sightings.len() - MAX_SIGHTINGS
                )?;
            }
        }

        writeln!(
            f,
            "\n  Rewriting history does NOT undo this. If the repository was ever \
             pushed, the plain text is in every clone, fork, cache and CI log that \
             saw it. In order:"
        )?;
        writeln!(
            f,
            "\n  1. ROTATE THE SECRET. This is the only step that actually revokes \
             the exposure, and it is worth doing even if you do nothing else."
        )?;
        if self.fix_requested && self.in_the_clear.is_empty() {
            writeln!(
                f,
                "  2. Already done: the current content is re-staged, so future \
                 commits are encrypted."
            )?;
        } else {
            writeln!(
                f,
                "  2. Re-stage the current content so future commits are encrypted:\n\
                 \x20      git-xcrypt status --fix"
            )?;
        }
        writeln!(
            f,
            "  3. Only then, and only if you also want the old blobs gone, rewrite \
             history with the external git-filter-repo. git-xcrypt does not rewrite \
             history and will not pretend to:"
        )?;
        // One `--path` each is fine for a handful and unusable for hundreds, so
        // past a point the command switches to the form git-filter-repo provides
        // for exactly this.
        if self.leaked.len() > MAX_LISTED {
            writeln!(
                f,
                "\x20      # {} paths — put them in a file, one per line, then:\n\
                 \x20      git filter-repo --invert-paths --paths-from-file leaked.txt",
                self.leaked.len()
            )?;
        } else {
            write!(f, "\x20      git filter-repo --invert-paths")?;
            for exposure in &self.leaked {
                write!(f, " --path {}", shell_quoted(&exposure.path))?;
            }
            writeln!(f)?;
        }
        writeln!(
            f,
            "     That deletes the file from every commit. To keep the file and drop \
             only its history, remove it, rewrite, then add it back through the \
             filter. Either way everyone with a clone has to re-clone."
        )?;
        // Everything above this command is decided on bytes; the command itself
        // is text, and there the two part company. On Linux any byte string
        // without `/` or NUL is a file name, so a path can reach here that no
        // string can spell — and the rendering turns the stray bytes into U+FFFD,
        // which git-filter-repo then matches against nothing while exiting 0. The
        // finding is still right and the name above still identifies the file to
        // a human; it is the instruction that has quietly stopped being one.
        if self
            .leaked
            .iter()
            .any(|exposure| std::str::from_utf8(&exposure.path).is_err())
        {
            writeln!(
                f,
                "\n     One or more of these paths is not valid UTF-8, so the names \
                 above are shown with replacement characters and the command WILL \
                 NOT match them — it would rewrite history and remove nothing, \
                 reporting success. Take the exact bytes from `git log --all \
                 --name-only -z` (or `git ls-tree -z -r <commit>`) and pass them \
                 through `--paths-from-file`."
            )?;
        }
        Ok(())
    }

    /// Paths a negation keeps in the clear on purpose.
    fn write_by_choice(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.by_choice.is_empty() {
            return Ok(());
        }
        writeln!(
            f,
            "\nin the clear by choice: {} path(s) a `!` line in {} takes back out, \
             so they are stored unencrypted on purpose.",
            self.by_choice.len(),
            crate::repo::CONFIG_FILE
        )?;
        for path in &self.by_choice {
            writeln!(f, "  {}", show(path))?;
        }
        Ok(())
    }
}

/// Inspects `repo` and reports what it found.
///
/// # Errors
///
/// [`Error::Config`] when git's configuration or `.gitattributes` cannot be
/// read — "cannot tell" must never be reported as "nothing is wrong" by the one
/// command whose whole job is to tell.
///
/// [`Error::Config`]: crate::Error::Config
pub fn run(repo: &Repo, fix: bool) -> Result<Report> {
    let mut report = Report {
        has_key: repo.has_key(),
        fix_requested: fix,
        ..Report::default()
    };

    // The full cascade, not `.git/config` alone: git resolves a driver through
    // system, global and local files alike, so a registration in `~/.gitconfig`
    // is a working registration and reporting it as missing would be wrong.
    // The common directory, because a linked worktree has a `config` file git
    // ignores — the same resolution `init` had to be taught.
    let config = gitconfig::open_full(repo.git_dir(), repo.common_dir())?;

    for key in gitattributes::driver_keys() {
        match gitconfig::get(&config, &key) {
            None => report.setup.push(SetupGap::MissingKey(key)),
            Some(value) if key.ends_with(".required") && !gitconfig::is_true(&value) => {
                report.setup.push(SetupGap::NotTrue { key, value });
            }
            Some(value) if value.trim().is_empty() && key.ends_with(".process") => {
                // An empty command is not a command. Git would try to run it and
                // fail, which with `required` set aborts everything — but the
                // honest report is that nothing is registered.
                report.setup.push(SetupGap::MissingKey(key));
            }
            Some(_) => {}
        }
    }

    // The `?` would surface an unreadable `.gitattributes` as `Error::Io`, which
    // the frozen table gives code 1 — the same code a typo produces, and not
    // what this function's own contract promises. It is a state conflict.
    let catch_all = gitattributes::catch_all_present(&repo.attributes_path()).map_err(|err| {
        crate::Error::Config(format!(
            "{} could not be read ({err}), so whether git filters this repository \
             at all cannot be determined",
            repo.attributes_path().display()
        ))
    })?;
    if !catch_all {
        report.setup.push(SetupGap::CatchAllMissing);
    }

    report.notes.extend(diff_driver_note(repo, &config));
    if !report.has_key {
        // Otherwise a locked repository and a healthy one render identically,
        // and "no findings" reads as "everything is fine here" to someone who
        // has just lost the ability to read any of it.
        report.notes.push(
            "there is no key in this repository, so nothing here can be decrypted. \
             That is the expected state after `lock` and in a fresh clone; \
             `git-xcrypt unlock <key-file>` opens it."
                .into(),
        );
    }

    // The same wrap as `.gitattributes` above, for the same reason: `?` alone
    // surfaces an unreadable `.git-xcrypt` as `Error::Io`, code 1 — a bare
    // "could not be read" with no verdict, no sections and no code a gate can
    // act on, indistinguishable from a typo. Measured with `chmod 000
    // .git-xcrypt`. It is a state conflict: a declaration nobody can read
    // enforces nothing this command can prove, exactly like a missing one —
    // and like there, nothing is stored in the clear over it, because the
    // check-in path refuses on the same state.
    let declarations = Config::load(&repo.xcrypt_config_path()).map_err(|err| match err {
        crate::Error::Io(err) => crate::Error::Config(format!(
            "{err}; status cannot tell which paths were meant to be encrypted, so \
             nothing was checked. The check-in path refuses over the same state, \
             so nothing is being stored in the clear; make {} readable and ask \
             again",
            crate::repo::CONFIG_FILE
        )),
        other => other,
    })?;
    if declarations.missing {
        // Both, and they are two different statements. The gap is the state:
        // nothing here declares what to encrypt, so the configuration enforces
        // nothing — a `2`, not a `5`, because the check-in path refuses on this
        // state and no secret has been stored in the clear over it. The
        // undetermined entry is the consequence: the run stops here, so every
        // section below is empty for want of a question rather than for want of
        // a finding, and saying so is the difference between "I checked" and "I
        // could not". Silence there would be worse than either code.
        report.setup.push(SetupGap::DeclarationMissing);
        report.undetermined.push(format!(
            "nothing below was checked: without {} there is no way to tell which \
             paths should be encrypted, so neither the index nor the history was \
             scanned. This says nothing about what is in this repository.",
            crate::repo::CONFIG_FILE
        ));
        return Ok(report);
    }
    report.warnings.extend(declarations.pointless_eol.clone());
    report.notes.extend(stale_section_note(repo, &declarations));

    let hash = gitindex::object_hash(gitconfig::get(&config, "extensions.objectformat").as_deref());
    let objects = history::objects(repo.common_dir(), hash)?;

    // Git's own attribute stack, not a search for suspicious lines: the question
    // is what `git check-attr filter` answers for each declared path, and only a
    // resolution answers it. Built once for the whole run — it reads every
    // `.gitattributes` in the working tree, and doing that per path would turn a
    // diagnostic into a walk of the tree squared.
    //
    // `core.ignorecase` belongs here and **only** here. This resolver reproduces
    // what git does, so it has to obey the setting git obeys; selection folds
    // ASCII case unconditionally and reads no configuration at all (see
    // `config::MATCHING`). Confusing the two axes would break the very thing this
    // resolver exists to detect.
    let ignore_case =
        gitconfig::get(&config, "core.ignorecase").is_some_and(|value| gitconfig::is_true(&value));
    let mut filters = gitattributes::AttributeResolver::new(
        repo.work_tree(),
        // The common directory: `info/` is shared by every checkout, so a linked
        // worktree resolves the *main* `info/attributes` — see the resolver.
        repo.common_dir(),
        // Resolved, not read verbatim: `~/` and the XDG default are sources git
        // honours, and a `text` line in one of them converts the ciphertext.
        gitconfig::global_attributes_file(&config).as_deref(),
        ignore_case,
        // The index copies git falls back to for a deleted `.gitattributes`:
        // check-in reads them, so the verdict has to as well.
        gitattributes::staged_fallbacks(
            repo.work_tree(),
            &repo.git_dir().join("index"),
            repo.common_dir(),
            hash,
            ignore_case,
        ),
    );

    inspect_index(
        repo,
        &declarations,
        &objects,
        hash,
        &mut filters,
        &mut report,
    )?;
    report.notes.extend(foreign_source_note(
        repo,
        &filters,
        report
            .setup
            .iter()
            .any(|gap| matches!(gap, SetupGap::FilterUnresolved { .. })),
    ));
    if fix {
        restage(repo, &declarations, hash, &mut report)?;
    }

    let scan = history::scan(
        &objects,
        repo.git_dir(),
        repo.common_dir(),
        hash,
        &declarations,
        is_partial_clone(&config),
    )?;
    report.scan_ran = true;
    report.scanned = Scanned {
        commits: scan.commits,
        blobs: scan.blobs,
    };
    report.warnings.extend(scan.warnings);
    if scan.partial {
        // The twin of the shallow case, and it was making the same mistake:
        // a promisor object is absent by design, so reporting it as unreadable
        // sent the user to `git fsck`, which exits 0 here and finds nothing.
        report.undetermined.push(
            "this is a partial clone, so some objects were never downloaded and \
             could not be judged. `git fetch --refetch --filter=blob:none` or a \
             full clone brings them down; `git fsck` will not report them missing."
                .into(),
        );
    }
    if scan.shallow {
        // Named before the object count, and separately: a shallow clone is not
        // a damaged one, and telling a user to run `git fsck` over a graft point
        // sends them after a problem that is not there.
        report.undetermined.push(
            "this is a shallow clone, so the history before its graft point was \
             never fetched and could not be scanned. `git fetch --unshallow` \
             brings the rest down; until then nothing here covers it."
                .into(),
        );
    }
    if scan.unreadable > 0 {
        report.undetermined.push(format!(
            "{} object(s) in this repository could not be read, so they were not \
             judged. A history scan that skipped something has proved nothing \
             about it; `git fsck` says what is missing.",
            scan.unreadable
        ));
    }
    // A reference the walk could not start from is not one skipped object — it
    // is a whole branch's history unvisited, and if the store as a whole cannot
    // be enumerated the scan visited nothing at all and found nothing for that
    // reason alone. Measured before this: `chmod 000 .git/packed-refs` left a
    // repository with a plaintext blob in its history reporting clean, exit 0.
    if scan.refs_unavailable {
        report.undetermined.push(
            "this repository's references could not be listed, so no history was \
             scanned at all. Nothing above says anything about what is in it."
                .into(),
        );
    } else if scan.unresolved_refs > 0 {
        // Named, not counted. "1 reference(s) could not be resolved" in a CI log
        // gives an operator nothing to act on.
        let mut named = scan.unresolved_names.join(", ");
        if scan.unresolved_refs > scan.unresolved_names.len() {
            named.push_str(", …");
        }
        report.undetermined.push(format!(
            "{} reference(s) could not be resolved, so whatever is reachable only \
             through them was not scanned: {named}",
            scan.unresolved_refs
        ));
    }
    report.notes.extend(scan.notes);
    report.leaked = scan.exposed;

    Ok(report)
}

/// Whether this repository fetches objects lazily.
///
/// Git marks a partial clone with `remote.<name>.promisor` and
/// `extensions.partialclone`; either is enough to know an absent object is a
/// design decision rather than damage.
fn is_partial_clone(config: &gix_config::File) -> bool {
    if gitconfig::get(config, "extensions.partialclone").is_some() {
        return true;
    }
    config
        .sections_by_name("remote")
        .into_iter()
        .flatten()
        .any(|section| {
            section
                .value("promisor")
                .is_some_and(|value| gitconfig::is_true(&value.to_string()))
        })
}

/// Reads what the index would have the next commit store.
///
/// The index rather than `HEAD`, because that is the question with a remedy: a
/// declared path whose staged blob is plain text is what a commit made now would
/// push, and `git add` fixes exactly that. `HEAD` is covered by the history scan,
/// which reaches it along with everything else.
fn inspect_index(
    repo: &Repo,
    declarations: &Config,
    objects: &gix_odb::Handle,
    hash: gix_hash::Kind,
    filters: &mut gitattributes::AttributeResolver,
    report: &mut Report,
) -> Result<()> {
    let index_path = repo.git_dir().join("index");
    // An I/O failure reading the index is the same *answer* as an index that
    // will not parse — "nothing is known about what the next commit would
    // store" — and used to be a different outcome: the `?` propagated out of
    // `run`, so `status` printed no verdict at all and exited 1, "usage error or
    // unclassified". Measured with `chmod 000 .git/index` on a repository that
    // was genuinely exposed: no verdict, no leaked section, exit 1, and the
    // message did not even name the file. A `.git` written by `sudo git` or a
    // read-only mount reaches it.
    let listed = gitindex::list(&index_path, hash).unwrap_or_else(|err| {
        gitindex::Listed::Unavailable(format!("it could not be read ({err})"))
    });
    let entries = match listed {
        gitindex::Listed::Read(entries) => entries,
        gitindex::Listed::Unavailable(why) => {
            // Refusing outright would withhold the history scan, which needs no
            // index at all and carries the finding that matters most. Failing
            // the gate over it keeps "could not tell" from reading as "fine".
            report.undetermined.push(format!(
                "{} could not be used because {why}, so nothing is known about what \
                 the next commit would store. For a split index, \
                 `git update-index --no-split-index` converts it back.",
                index_path.display()
            ));
            return Ok(());
        }
    };

    // `init` creates these two and does not commit them. A repository where
    // they were never staged looks perfectly configured from inside and
    // publishes nothing that enforces anything — the clone finds out, the
    // machine that pushed does not. Both are checked against the index rather
    // than the disk, because being on disk is exactly what is not in question.
    //
    // Only once something else is tracked, though. Between `git init` and the
    // first `git add` everything is untracked, and complaining then is a
    // complaint about a repository that has not published anything yet.
    if !entries.is_empty() {
        let mut tracked_bootstrap = [false, false];
        for entry in &entries {
            if entry.path == crate::repo::ATTRIBUTES_FILE.as_bytes() {
                tracked_bootstrap[0] = true;
            } else if entry.path == crate::repo::CONFIG_FILE.as_bytes() {
                tracked_bootstrap[1] = true;
            }
        }
        for (present, name) in tracked_bootstrap
            .iter()
            .zip([crate::repo::ATTRIBUTES_FILE, crate::repo::CONFIG_FILE])
        {
            if !present {
                report.setup.push(SetupGap::Untracked(name.to_string()));
            }
        }
    }

    // Declared paths git resolves to something other than our driver, with what
    // it resolves instead. Collected rather than reported one by one: a
    // subdirectory `.gitattributes` reaches every file under it, and three
    // hundred identical gaps would bury every other finding.
    let mut unfiltered: Vec<(String, String)> = Vec::new();
    // Declared paths whose stored bytes git converts itself, with the line that
    // decides it. Grouped the same way and for the same reason.
    let mut converted: Vec<(String, String)> = Vec::new();

    for entry in entries {
        // A symbolic link and a submodule gitlink are not file content, so git
        // never filters them and no declaration could have applied. Measured on
        // the build that skipped this check: a tracked symlink read as "in the
        // clear", `--fix` followed it, encrypted the file it pointed at — one
        // no pattern selected — and left a symlink whose target was the first
        // NUL of a ciphertext. `history::walk_tree` had the check all along.
        // A `git add -N` placeholder is the third case: mode 100644 and the
        // empty blob, so it reads as content in the clear — and repointing it
        // announced a repair the next commit did not make, because git still
        // treats the path as unstaged.
        if !entry.holds_content() {
            continue;
        }
        let gitindex::Tracked { path: name, id, .. } = entry;

        if declarations.negated(&name) {
            report.by_choice.push(name);
            continue;
        }
        if !declarations.decide(&name).encrypt {
            // No entry here about a name that differs only in case. Until
            // 2026-08-05 there was one, reported as *undetermined*, because
            // selection matched bytes while git folded case — so the managed
            // section reached paths the filter did not, and which spelling won
            // was an open decision nothing was allowed to guess. Selection now
            // folds ASCII case unconditionally (`config::MATCHING`), so the two
            // answers cannot differ and the note could only ever have been
            // false. What folding still does not reach is spelled out in
            // `README.md` §Known limitations rather than reported per path: it
            // is a property of the declaration, identical on every machine and
            // in every repository, so a scan has nothing to add to it.
            continue;
        }

        // What git would actually do with this path, asked of git's own rules.
        // A declared path git does not resolve to our driver is stored in the
        // clear on the next `git add`, with exit code 0 and no warning — and
        // every other check in this command passes while it happens.
        let resolved = filters.resolve(&name);
        if !resolved.filter.is_ours() {
            unfiltered.push((show(&name), resolved.filter.to_string()));
        }
        // The second question of the same stack. A path git filters correctly
        // and then converts is not half-protected: the ciphertext is destroyed,
        // which costs more than storing the plain text would have.
        if let gitattributes::EolConversion::On(culprit) = resolved.conversion {
            converted.push((show(&name), display_culprit(repo, &culprit)));
        }

        let Ok(id) = gix_hash::oid::try_from_bytes(&id) else {
            report.undetermined.push(format!(
                "{}: the index records an object id this build cannot read",
                show(&name)
            ));
            continue;
        };
        match history::stored_in_the_clear(objects, id) {
            Some(true) => report.in_the_clear.push(name),
            Some(false) => report.encrypted.push(name),
            None => report.undetermined.push(format!(
                "{}: the index names object {id}, which is not in this repository's \
                 object database, so what it holds is unknown",
                show(&name)
            )),
        }
    }

    report.encrypted.sort();
    report.in_the_clear.sort();
    report.by_choice.sort();

    if !unfiltered.is_empty() {
        unfiltered.sort();
        let resolved = unfiltered
            .first()
            .map(|(_, resolved)| resolved.clone())
            .unwrap_or_default();
        report.setup.push(SetupGap::FilterUnresolved {
            paths: unfiltered
                .iter()
                .take(MAX_LISTED)
                .map(|(path, _)| path.clone())
                .collect(),
            total: unfiltered.len(),
            resolved,
        });
    }

    if !converted.is_empty() {
        converted.sort();
        let culprit = converted
            .first()
            .map(|(_, culprit)| culprit.clone())
            .unwrap_or_default();
        report.setup.push(SetupGap::CiphertextConverted {
            paths: converted
                .iter()
                .take(MAX_LISTED)
                .map(|(path, _)| path.clone())
                .collect(),
            total: converted.len(),
            culprit,
        });
    }

    Ok(())
}

/// The attribute line behind a verdict, with its path made repository-relative.
///
/// An absolute path out of a temporary directory tells a reader nothing they can
/// act on, and `$GIT_DIR/info/attributes` has to keep enough of its path to be
/// recognisable as the unversioned source it is.
fn display_culprit(repo: &Repo, culprit: &gitattributes::Culprit) -> String {
    let Some(source) = &culprit.source else {
        return culprit.to_string();
    };
    let shown = repo.relative(source).unwrap_or(source);
    gitattributes::Culprit {
        source: Some(shown.to_path_buf()),
        ..culprit.clone()
    }
    .to_string()
}

/// Names the attribute files carrying `filter` lines, once resolution has run.
///
/// Kept as a **note** and emitted only when there is something to attach it to,
/// which is the change 2026-08-04 brought. Before it, the mere presence of a
/// foreign `filter` line produced this note on every run — and `*.psd
/// filter=lfs` in a subdirectory is entirely ordinary, so the note fired in
/// repositories where nothing was wrong and taught a reader to skip it.
///
/// It still says what the resolution cannot: these lines exist, and a path they
/// reach which the index does not yet hold would not be filtered either. That is
/// the honest boundary of a check that resolves only the paths git is tracking.
fn foreign_source_note(
    repo: &Repo,
    filters: &gitattributes::AttributeResolver,
    reached_a_declared_path: bool,
) -> Vec<String> {
    let mut notes = Vec::new();
    for source in filters.sources() {
        let Ok(lines) = gitattributes::foreign_filter_lines(source) else {
            continue;
        };
        if lines.is_empty() {
            continue;
        }
        let shown = git_spelling(repo.relative(source).unwrap_or(source));
        let verdict = if reached_a_declared_path {
            "and git takes the LAST match. Some of them reach a declared path — \
             see the setup gap above, which is the finding."
        } else {
            "and git takes the LAST match. Checked against every declared path the \
             index holds: git still resolves `filter=git-xcrypt` for all of them, \
             so nothing tracked is unprotected by these. A path they reach which \
             the index does not yet hold would be."
        };
        notes.push(format!(
            "{shown} carries {} line(s) of its own that set or unset `filter`, \
             {verdict} Check with `git check-attr filter -- <path>`:\n    {}",
            lines.len(),
            lines.join("\n    ")
        ));
    }
    notes
}

/// Re-stages every declared path the index holds in the clear.
///
/// This is `git add` on those paths, done without spawning git: the working-tree
/// content goes through [`decide::clean`] — the very function git calls on the
/// check-in path, so the bytes are the bytes a real `git add` would store — the
/// resulting blob is written to the object database, and the index entry is
/// pointed at it.
///
/// **The working tree is not touched.** Encrypting the files in place is what
/// `lock` does, and doing it here would take a user's own secrets away from them
/// in the name of a repair. What changes is what the *next commit* stores.
///
/// A path whose working-tree file is gone is left alone: there is nothing to
/// clean, and inventing content for it would be worse than saying so.
///
/// The blob is written before the index is locked, so a run that then finds the
/// lock held — or an index it will not patch — leaves an unreferenced ciphertext
/// object behind. Harmless, and `git gc` collects it; worth knowing only because
/// "nothing was re-staged" does not mean "nothing was written".
fn restage(
    repo: &Repo,
    declarations: &Config,
    hash: gix_hash::Kind,
    report: &mut Report,
) -> Result<()> {
    if report.in_the_clear.is_empty() {
        return Ok(());
    }

    // A missing key stops the repair, not the report. `--fix` is the one part of
    // this command that needs a key, and propagating the error here would throw
    // away the setup findings and the whole history scan — leaving a user who
    // typed one flag too many with less information than if they had not.
    // Every failure here, not only a missing key: an unreadable or corrupt key
    // file used to propagate and throw away the setup findings and the whole
    // history scan, which is the same loss the missing-key case was fixed for.
    let key = match repo.load_key() {
        Ok(key) => key,
        Err(err) => {
            let what = match err {
                crate::Error::NoKey => "there is none here".to_string(),
                other => format!("it could not be read ({other})"),
            };
            report.undetermined.push(format!(
                "--fix needs the repository key in order to re-encrypt, and {what}, \
                 so nothing was re-staged. `git-xcrypt unlock <key-file>` puts one \
                 in place. The {} path(s) reported below are still in the clear.",
                report.in_the_clear.len()
            ));
            return Ok(());
        }
    };
    let loose = gix_odb::loose::Store::at(
        repo.common_dir().join("objects"),
        gix_odb::loose::Options {
            object_hash: hash,
            ..gix_odb::loose::Options::default()
        },
    );

    let mut updates: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut kept: Vec<Vec<u8>> = Vec::new();

    for name in std::mem::take(&mut report.in_the_clear) {
        let path = repo.work_tree().join(crate::repo::working_tree_path(&name));
        // The working-tree twin of `holds_content`. The index entry says
        // regular file, but the disk decides what `fs::read` returns, and a
        // path replaced by a symlink since it was staged would be read through
        // — encrypting a file no pattern declared and repointing the entry at
        // it, while `git add` would stage the typechange instead. `lock`,
        // `unlock` and the history walk all decline symlinks; this is the one
        // other working-tree read. A missing file falls through to the read
        // below, whose message already covers it.
        if let Ok(metadata) = std::fs::symlink_metadata(&path)
            && !metadata.is_file()
        {
            report.warnings.push(format!(
                "{}: not re-staged, it is no longer a regular file on disk, so \
                 reading it would take content from somewhere else. The index \
                 still holds it in the clear; `git add` records what is really \
                 there.",
                show(&name)
            ));
            kept.push(name);
            continue;
        }
        let content = match std::fs::read(&path) {
            Ok(content) => zeroize::Zeroizing::new(content),
            Err(err) => {
                report.warnings.push(format!(
                    "{}: not re-staged, its working-tree file could not be read \
                     ({err}). The index still holds it in the clear.",
                    show(&name)
                ));
                kept.push(name);
                continue;
            }
        };

        // One file this build cannot clean — ciphertext under a key this
        // repository does not hold, a truncated header — must not take the
        // report with it. Propagating here printed nothing at all and exited 4
        // over a run that had already established two secrets sitting in
        // history in the clear, so the gate read "the tool broke" and lost every
        // finding. The two failures either side of this one were already handled
        // this way; this one was the odd case out.
        let outcome = match crate::decide::clean(Some(&key), declarations, &name, &content) {
            Ok(outcome) => outcome,
            Err(err) => {
                report.warnings.push(format!(
                    "{}: not re-staged ({}). The index still holds it in the clear.",
                    show(&name),
                    named(&name, err)
                ));
                kept.push(name);
                continue;
            }
        };
        if let Some(warning) = outcome.warning {
            // The filter prints this; the second implementation of the check-in
            // path must not be the one that swallows it.
            report.warnings.push(warning);
        }
        match loose.write_buf(gix_object::Kind::Blob, &outcome.content) {
            Ok(id) => updates.push((name, id.as_slice().to_vec())),
            Err(err) => {
                report.warnings.push(format!(
                    "{}: not re-staged, its encrypted form could not be written to \
                     the object database ({err})",
                    show(&name)
                ));
                kept.push(name);
            }
        }
    }

    // Same reasoning as the read above: a lock that cannot be taken, or an index
    // that cannot be replaced, means `--fix` did nothing — which is a warning
    // beside a report that still has a history scan to deliver, not a reason to
    // print nothing and exit 1. Measured with `chmod a-w .git`: the whole report
    // vanished, exposures included.
    let restaged = gitindex::restage(&repo.git_dir().join("index"), hash, &updates)
        .unwrap_or_else(|err| gitindex::Restaged::Skipped(err.to_string()));
    match restaged {
        gitindex::Restaged::Done(patched) => {
            // Which, not how many. A path the index spells differently than the
            // directory does — case folding on macOS and Windows, NFD against
            // NFC — is simply not found, and subtracting counts would name the
            // wrong file as fixed while the real one disappeared from both
            // lists. Everything that was asked for and did not come back stays
            // in `in_the_clear`, where it belongs.
            let missed: Vec<Vec<u8>> = updates
                .into_iter()
                .map(|(name, _)| name)
                .filter(|name| !patched.contains(name))
                .collect();
            if !missed.is_empty() {
                report.warnings.push(format!(
                    "{} path(s) were not found in the index under the name they \
                     have on disk, so they were left as they were: {}. `git add` \
                     on them by hand settles it.",
                    missed.len(),
                    missed
                        .iter()
                        .map(|name| show(name))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                kept.extend(missed);
            }
            report.fixed = patched;
        }
        gitindex::Restaged::Skipped(why) => {
            report.warnings.push(why);
            kept.extend(updates.into_iter().map(|(name, _)| name));
        }
    }

    report.in_the_clear = kept;
    report.in_the_clear.sort();
    report.fixed.sort();
    Ok(())
}

/// Puts a path in front of an error that only knew about content.
fn named(name: &[u8], err: crate::Error) -> crate::Error {
    use crate::Error;
    let at = show(name);
    match err {
        Error::Format(message) => Error::Format(format!("{at}: {message}")),
        Error::Crypto(message) => Error::Crypto(format!("{at}: {message}")),
        Error::Config(message) => Error::Config(format!("{at}: {message}")),
        Error::Io(err) => Error::Io(std::io::Error::other(format!("{at}: {err}"))),
        mismatch @ Error::KeyMismatch { .. } => Error::Format(format!("{at}: {mismatch}")),
        other => other,
    }
}

/// Mentions a `.gitattributes` section that no longer matches `.git-xcrypt`.
///
/// A note, never a gap: nothing here stores a secret in the clear, and code `5`
/// means an exposure. But the note used to call the consequence a dirty `git
/// status` after a clone's `unlock`, and that understates it badly enough to be
/// its own defect — the wording is part of the safeguard, not decoration.
///
/// Measured on git 2.55. A declared path whose managed `-text` line is missing
/// still gets encrypted (the filter reads `.git-xcrypt`, not `.gitattributes`),
/// but git then applies **its own** CRLF conversion to the ciphertext whenever
/// any other attribute source declares that path `text`. On a 2 MB file that ate
/// 34 `CR` bytes: `git add` exited 0, the commit succeeded, and the later
/// checkout failed the authentication tag and left no file at all. The blob in
/// history cannot be decrypted by anyone, ever.
///
/// It takes a foreign `text` attribute to fire — our own magic starts with NUL,
/// so `text=auto` and `core.autocrlf` alone see binary and leave it be — which
/// is why this stays a note rather than a gap. It is not, however, cosmetic.
fn stale_section_note(repo: &Repo, declarations: &Config) -> Option<String> {
    let lines = gitattributes::render_lines(declarations);
    let (existing, desired) = gitattributes::desired(&repo.attributes_path(), &lines).ok()?;
    (existing != desired).then(|| {
        format!(
            "{} no longer matches {} — the per-pattern lines are out of date. \
             Nothing is stored in the clear over this, but the missing `-text` \
             lets git apply its own CRLF conversion to the ciphertext of any \
             path some other attribute declares `text`, which corrupts the blob \
             silently and costs the file at checkout. A clone's `unlock` will \
             also rewrite the section and leave `git status` dirty. \
             `git-xcrypt sync` settles both.",
            crate::repo::ATTRIBUTES_FILE,
            crate::repo::CONFIG_FILE
        )
    })
}

/// Mentions an absent diff driver, without letting it fail the gate.
///
/// Deliberately outside [`gitattributes::driver_keys`] and outside the exit
/// code. A missing `diff.git-xcrypt.textconv` costs a readable `git diff` and
/// nothing else — no secret reaches the object database over it — and `lock`
/// removes it **on purpose**, because with no key the driver drags a failing
/// smudge filter into every `git log -p`. Counting it as a finding would make
/// every correctly locked repository report itself broken, which is the fastest
/// way to teach a user to ignore this command.
///
/// So it is said only where it is actionable: a repository that holds a key, and
/// therefore could be showing plaintext diffs, and is not.
fn diff_driver_note(repo: &Repo, config: &gix_config::File) -> Option<String> {
    if !repo.has_key() {
        return None;
    }
    if gitconfig::get(config, &format!("diff.{DRIVER}.textconv")).is_some() {
        return None;
    }
    Some(format!(
        "diff.{DRIVER}.textconv is not registered, so `git diff` on an encrypted \
         file reports `Binary files differ` instead of comparing the plain text. \
         `git-xcrypt init` registers it. Nothing is stored in the clear over this."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One leak, spelled the way the history scan spells one.
    fn a_leak() -> crate::history::Exposure {
        crate::history::Exposure {
            path: b"secrets/db.env".to_vec(),
            sightings: Vec::new(),
        }
    }

    #[test]
    fn a_question_left_unanswered_is_its_own_verdict_and_never_masks_a_finding() {
        // The two codes are the whole point of the split: `6` says fix the
        // checkout, `5` says rotate a secret. A run that hit both has found a
        // secret, so the stronger answer has to win — measured here rather than
        // trusted, because the direction of that precedence is the one thing
        // that would quietly weaken the gate.
        let clean = Report::default();
        assert_eq!(clean.verdict(), Verdict::Clean);

        let undetermined = Report {
            undetermined: vec!["a shallow clone".into()],
            ..Report::default()
        };
        assert_eq!(undetermined.verdict(), Verdict::Undetermined);
        assert!(
            undetermined.to_string().contains("NOTHING WAS FOUND"),
            "the verdict line must not read as a finding: {undetermined}"
        );

        let both = Report {
            undetermined: vec!["a shallow clone".into()],
            in_the_clear: vec![b"secrets/db.env".to_vec()],
            ..Report::default()
        };
        assert_eq!(both.verdict(), Verdict::Exposed);
        assert!(
            !both.to_string().contains("NOTHING WAS FOUND"),
            "an exposure must not be softened by what could not be checked: {both}"
        );
    }

    #[test]
    fn configuration_outranks_both_other_answers_and_conceals_neither() {
        // The precedence added 2026-08-05, in the four combinations that decide
        // it. A setup gap wins over a finding and over a question alike, because
        // a repository git is not filtering cannot be repaired by acting on what
        // this report says about its data — the configuration is what makes the
        // rest mean anything.
        let gap = || {
            vec![SetupGap::MissingKey(
                "filter.git-xcrypt.process".to_string(),
            )]
        };

        let misconfigured = Report {
            setup: gap(),
            ..Report::default()
        };
        assert_eq!(misconfigured.verdict(), Verdict::Misconfigured);

        let over_a_question = Report {
            setup: gap(),
            undetermined: vec!["a shallow clone".into()],
            ..Report::default()
        };
        assert_eq!(over_a_question.verdict(), Verdict::Misconfigured);

        // The one that matters most. A leak reported under code `2` is the same
        // leak it would be under `5`, so the verdict may reorder the work and
        // must not take a section off the page — an operator who fixes the setup
        // and never learns there was a leak has been failed by the gate that
        // told them the truth about their configuration.
        let over_a_finding = Report {
            setup: gap(),
            leaked: vec![a_leak()],
            in_the_clear: vec![b"secrets/late.env".to_vec()],
            ..Report::default()
        };
        assert_eq!(over_a_finding.verdict(), Verdict::Misconfigured);
        let text = over_a_finding.to_string();
        for expected in [
            "leaked in history",
            "secrets/db.env",
            "ROTATE THE SECRET",
            "in the clear:",
            "secrets/late.env",
            // And the verdict line itself has to point at them, or the first
            // line of the report contradicts the rest of it.
            "Also found",
        ] {
            assert!(
                text.contains(expected),
                "the configuration verdict swallowed `{expected}`:\n{text}"
            );
        }
        assert!(
            over_a_finding.exposed(),
            "a leak under a configuration verdict is still a leak:\n{text}"
        );

        // And with the configuration settled, the very same findings answer `5`.
        let settled = Report {
            leaked: vec![a_leak()],
            in_the_clear: vec![b"secrets/late.env".to_vec()],
            ..Report::default()
        };
        assert_eq!(settled.verdict(), Verdict::Exposed);
    }

    #[test]
    fn a_missing_declaration_is_a_configuration_gap_that_still_admits_it_checked_nothing() {
        // It is not an exposure — the check-in path refuses on this state, so
        // nothing was ever stored in the clear over it — and it is not merely an
        // unanswered question either: a repository that declares nothing
        // enforces nothing. Both halves have to reach the reader, and the second
        // is the one silence would cost most.
        let report = Report {
            setup: vec![SetupGap::DeclarationMissing],
            undetermined: vec!["nothing below was checked".into()],
            ..Report::default()
        };
        assert_eq!(report.verdict(), Verdict::Misconfigured);
        let text = report.to_string();
        assert!(
            text.contains("history was NOT scanned"),
            "a run that stopped before the scan must say so: {text}"
        );
        assert!(
            !text.contains("stores it in the clear"),
            "nothing is stored in the clear over a refused `git add`, and saying \
             otherwise sends a user to rotate a secret that was never exposed: {text}"
        );
    }
}
