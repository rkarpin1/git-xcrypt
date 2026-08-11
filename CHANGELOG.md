# Changelog

Notable changes to `git-xcrypt`, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

One thing this project treats as part of the public interface, beyond the usual:
**the bytes it writes**. A change to the encrypted file format, the key file
format, or the text/binary rule rewrites the ciphertext of files that already
exist in someone's history — so those are listed under their own heading, and a
release that changed any of them without a new `suite` byte would be a bug, not
a minor version.

## [0.1.2] - 2026-08-11

One behaviour change and the installation documentation. **Nothing about the
bytes moved**: the encrypted file format, the key file format and the
text/binary rule are exactly those frozen with 0.1.0. A repository encrypted
with any earlier version needs nothing done to it.

### Changed

- **`export-key --stdout` prints to a terminal instead of refusing one.** It
  used to exit `2` and write nothing when standard output was a terminal. The
  flag is the consent, so the key is written and the cost is named instead:
  `stderr` says that the key now lives in the scrollback, in the multiplexer's
  buffer and in any session log, none of which the command can reach afterwards,
  and that the way out is to clear all three or rotate the key. Piping is
  untouched — the warning goes to `stderr`, so `export-key --stdout | gh secret
  set …` still carries the key and nothing else. What no process can police is
  unchanged and still documented: a shell redirect escapes every check that
  keeps a key out of the working tree.

### Documentation

- **The README says how to install.** A section of its own before Quick start,
  with the three routes separated: a ready-made binary from the releases page,
  `cargo install git-xcrypt --locked`, and `cargo binstall git-xcrypt`. The last
  carries the caveat it needs — `cargo binstall` is a separate tool, not part of
  cargo, so it has to be installed first; measured with cargo-binstall 1.21.1,
  it resolves this crate's release archive with no configuration on either side,
  and falls back to building when no archive matches the target.

### Internal

- A `/publish-cargo-version` command for agents working in this repository,
  under `.claude/`, and excluded from the published package along with
  `/context`, `/.idea` and `/.github`.

## [0.1.1] - 2026-08-11

Bug fixes and one dependency change. **Nothing about the bytes moved**: the
encrypted file format, the key file format and the text/binary rule are exactly
those frozen with 0.1.0, and the frozen vectors reproduce byte for byte under
the new cipher crate. A repository encrypted with 0.1.0 needs nothing done to
it.

### Fixed

- **A declared path no longer has its line endings changed when nothing asked
  for a conversion.** With `core.autocrlf` false or unset and `core.eol` unset -
  git's own default, and the one configuration in which git converts nothing - a
  checkout now writes the stored bytes back unchanged instead of the platform's
  own ending. Before this, declaring a file secret changed it, in opposite
  directions on the two platforms: measured on git 2.55, a CRLF file came back
  LF on Linux and an LF file came back CRLF on Windows, while the identical
  undeclared file beside it was untouched, and `git status` stayed clean
  throughout. An explicit `core.eol=native`, or `eol=native` on the pattern,
  still selects the platform. The check-in half is unchanged and remains a
  documented limit: a file brought in with CRLF still comes back LF, because
  `clean` normalises before the header can record which ending was there.
- **`git -c core.autocrlf=...` reaches the filter.** Git passes command-line
  overrides to child processes through `GIT_CONFIG_PARAMETERS`, which was not
  being read, so one command could give two answers - measured, with the file
  saying false and the command saying true, `git checkout` expanded the paths
  git owns to CRLF and left declared ones at LF, in adjacent directories.
  Anything unparsable is ignored rather than guessed at, leaving the
  configuration files as authoritative as before.
- **`lock` refuses over a leftover file it cannot identify, instead of deleting
  the key.** A temporary name is `<target>.git-xcrypt-<hex>.tmp`, and above a
  223-byte target the name is cut to fit the filesystem's 255-byte limit, so it
  no longer identifies what it was named after. Measured: with `*.env` declared
  and a 230-byte file name, `lock` announced success, deleted the key and exited
  0 over a decrypted secret still in the working tree - untracked, and no longer
  matching the pattern that would have encrypted it. It now exits 2, keeps the
  key, changes nothing, and says what to look at. An ordinary temp-shaped file
  whose target is undeclared still only gets a note.
- **A configuration key that cannot be parsed is answered, not fatal.** Reading
  one aborted the process, and on the filter path with `required = true` that
  aborts every git operation in the repository rather than failing one command.

### Added

- **A warning when a declared `eol=` cannot reach a file.** `eol=` applies only
  to content the filter normalises, so under the default `text=auto` a file the
  content rule reads as binary is stored verbatim and the declaration silently
  does nothing for it - one pattern honouring `eol=crlf` for one file and not
  for the next beside it. The filter now names any file this happens to, and
  only that file.

### Changed

- **The cipher crate is `aes-siv` 0.8.0-rc.3, and `.cargo/config.toml` is gone.**
  It pulls `aes` 0.9, which compiles the aarch64 backend unconditionally and
  picks between hardware and software at runtime, so hardware AES now works by
  every install route rather than only for builds run from a clone - the gap
  that flag could not close. A pre-release deliberately: it is the only one in
  the dependency graph, everything under it resolves to stable at MSRV 1.85, and
  the requirement lifts itself to 0.8.0 when that lands.

## [0.1.0] — 2026-08-07

First release. Everything below is new; there is no earlier version to have
changed anything from.

### Added

- **Transparent encryption through git's filter.** `.gitattributes` carries one
  static `* filter=git-xcrypt` line, so the filter sees every file in the
  repository and decides for itself, reading `.git-xcrypt`. Adding a pattern
  takes effect on the next `git add` with no synchronising command. Registered
  as `filter.git-xcrypt.process` — the long-running protocol, because a process
  per file measured 22× slower.
- **A managed `.gitattributes` section that works before `sync` has ever run.**
  `init` writes two lines covering the whole repository, neither naming a
  pattern, so a fresh repository is correct immediately and nothing can go
  stale. `sync` replaces them with a line per declared pattern —
  `*.key filter=git-xcrypt -text diff=git-xcrypt` — which confines the diff
  driver to declared paths; git spawns it per blob, and a 1000-file diff was
  measured at 8461 ms against 23 ms. `sync --global` goes back, `--ignorecase`
  spells each ASCII letter as a class, and `--check` reports a stale section
  through exit code 2 instead of writing — the same code `status` gives on the
  same state, so a CI job gets one answer rather than whichever command it ran.
  `sync` also counts the lines outside its section that set `filter`, `text`,
  `eol` or `crlf` and points at `status`: git takes the last match, so one of
  them may outrank what it just wrote.
- **`.git-xcrypt`**, a versioned declaration in `.gitignore` syntax, as the one
  source of truth for what is encrypted. Negations, directory patterns and
  anchoring behave as they do in `.gitignore`; after a pattern you may write the
  line-ending attributes `text`, `-text`, `binary`, `text=auto` and
  `eol=lf|crlf|native`, with the meanings they have in `.gitattributes`. Names
  containing whitespace are closed with quotes, as in `.gitattributes`.
- **Commands** `init`, `sync`, `status`, `export-key`, `unlock`, `lock`, plus
  `diff` and `process`, which `init` registers for git to call.
  See the table in `README.md`.
- **`export-key` will not write the key anywhere git can pick it up.** A
  destination inside the working tree is refused, and so is one inside any other
  checkout of the same repository or inside the git directory; an existing file
  is refused unless `--force` says the replacement is meant, because that file
  is somebody's only way back into a different repository. On Unix the export is
  written with mode `0600`; on Windows nothing narrows it, so there the
  directory you pick *is* the protection.
- **A key can reach CI without touching the disk.** `export-key --stdout` pipes
  it into a secret store and refuses a terminal, where it would survive in the
  scrollback; `unlock --key <text>` takes the same text back. Both carry the
  format a key file holds, so the header keeps verifying the material behind it.
  The costs are named on `stderr` at every use and in `README.md`: `--key` is
  visible to `ps` while the command runs and is recorded by an interactive
  shell, and a redirect out of `--stdout` escapes the checks that keep a key out
  of the working tree.
- **`unlock --key-only`** installs the key and repairs the filter registration
  without decrypting anything, for a checkout that should stay as it is. The
  evidence check still runs, so a key the working tree's own headers contradict
  is refused before it reaches disk.
- **`lock` refuses over everything it cannot account for**, because it deletes
  the only copy of the key and `unlock` will not undo that. It asks for a typed
  `yes` (`--yes` skips the question, never the warning), names the key by
  fingerprint and never by material, and refuses outright when a declared file
  holds uncommitted changes, when another checkout of the same repository reads
  the same key, or when either appears while it is running — the working tree
  and the other checkouts are both re-examined after the answer and again after
  the encryption pass.
- **`status` as a CI gate.** It scans the whole reachable history for
  declared paths stored in the clear, resolves git's own `filter` and
  `text`/`eol` attributes for every declared path the way `git check-attr` does,
  and repairs what it safely can with `--fix`. Anything it could not cover is
  named out loud rather than folded into a clean bill of health.
- **Line-ending conversion owned by the tool, not by git.** Encrypted paths
  carry `-text`, so git never converts ciphertext. Normalisation to LF before
  encryption is identical on every machine; the choice of LF or CRLF on the way
  out reads git's configuration, which is the only place a difference between
  machines is wanted.
- **Four automatic checks on the `git add` path**, and only one of them stops
  anything. A warning when a file is encrypted for the first time and the same
  path already sits in `HEAD` in the clear. A warning when the managed
  `.gitattributes` section no longer matches the declaration, said once per git
  operation rather than once per file. A warning when normalising a file would
  throw away its own line endings, so the working tree cannot come back — git
  covers that with `core.safecrlf`, and this one is narrower on purpose: it asks
  whether the original is recoverable, not whether the bytes change, so an
  ordinary LF-only file stays silent where git's would warn on every checkout
  with `core.autocrlf=true`. And a refusal — not a warning — when git's
  attribute stack would convert the ciphertext about to be written, which is
  otherwise unrecoverable at checkout. The three warnings never return a
  non-zero code: with `filter.git-xcrypt.required = true` that would abort every
  git operation in the repository, which none of those states deserves.
- **Ready-made binaries** for Linux (musl, x86_64 and aarch64), macOS (x86_64
  and aarch64) and Windows (MSVC, x86_64), each with a SHA-256 sum and a
  [build provenance attestation](https://github.com/rkarpin1/git-xcrypt#verifying-a-downloaded-release)
  naming the commit and workflow run it came from.

### Frozen with this release

These are frozen because changing them rewrites data that already exists. A
future change goes in a new `suite` byte, not in a new version of these:

- **Encrypted file format** — 11-byte magic `\0GITXCRYPT\0`, `format_version`
  `0x01`, `suite` `0x01` (AES-256-SIV, RFC 5297), a flags byte whose bit 0
  records whether the plaintext was normalised, an 8-byte `key_id`, and a
  16-byte synthetic IV: 38 bytes of overhead, exactly. Bytes `0..22` are
  authenticated as associated data. Bytes `0..22` are frozen forever; everything
  from offset 22 is defined by `suite`.
- **Key file format** — its own versioned header over a 32-byte master key, with
  the cipher's key derived per suite through HKDF-SHA-256, so a future suite
  needs no change to the file sitting in users' backups.
- **The text/binary rule** (`text=auto`, which is the default) — a port of git's
  `gather_stats`, including the correction that forgives a single trailing `SUB`
  (`0x1A`). It decides whether a file is normalised, so it decides the
  ciphertext of most files.
- **ASCII case folding in pattern matching** — `secrets/` reaches
  `Secrets/db.env`, unconditionally and without reading `core.ignorecase`, so
  the same repository encrypts the same set of files on every machine. Folding
  stops at ASCII, exactly where git's does. The generated `.gitattributes`
  lines spell the pattern as written unless `sync --ignorecase` asks for the
  folded form; the two halves then differ for a path spelled in another case,
  which costs that path its `diff` driver and its `-text` but stores nothing in
  the clear.
- **Exit codes** — `0` success, `1` usage or unclassified failure, `2`
  configuration or state conflict, `3` no key, `4` bad format, `5` `status`
  found an exposure, `6` `status` could not tell. A stale managed section is a
  `2` from both `sync --check` and `status`: it used to be a `1` from one and a
  clean `0` from the other, which meant the verdict depended on which command a
  job happened to run.

### Deliberately not in this release

Recorded so their absence reads as a decision rather than an oversight; the file
format is ready for the first four without changing:

- Recipients and team use — no `add-user` / `list-users`, no key envelopes. The
  model is one person, and the key travels as a file.
- Key rotation, and more than one key per repository.
- Support for `gpg` or an OpenPGP keyring.
- Migration from repositories encrypted with the original `git-crypt`.
- Purging plaintext from history. `status` reports the exposure and prints the
  procedure, which begins with rotating the secret — rewriting history cleans
  the repository but does not undo the leak.
- Hiding metadata. File names, paths, sizes and the fact that a file changed
  stay in the clear, and size leaks exactly: a blob is 38 bytes plus the
  content.
- `working-tree-encoding` (character encoding conversion, e.g. UTF-16).

The rest of what this tool does not protect you from is in
[§What it does and does not protect](https://github.com/rkarpin1/git-xcrypt#what-it-does-and-does-not-protect)
and [§Known limitations](https://github.com/rkarpin1/git-xcrypt#known-limitations).
Two are worth carrying away without reading further: the key file in `.git/` is
the **only** copy and backing it up is yours to do, and a clone where `init` or
`unlock` has not run is not safe to commit from.

### Requirements

- Rust 1.88 or newer to build from source; the published binaries need nothing
  installed.
- A real `git`. Clients that reimplement the protocol — JGit, anything on
  libgit2 — are outside the guarantee, because they may not speak the
  long-running filter protocol and would then let plaintext through.

[0.1.2]: https://github.com/rkarpin1/git-xcrypt/releases/tag/v0.1.2
[0.1.1]: https://github.com/rkarpin1/git-xcrypt/releases/tag/v0.1.1
[0.1.0]: https://github.com/rkarpin1/git-xcrypt/releases/tag/v0.1.0
