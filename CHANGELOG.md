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

## [Unreleased]

A breaking change to one flag. **Nothing about the bytes moved**: a key exported
by any earlier version still imports. This is a minor version, not a patch.

### Changed

- **`unlock --key` now reads the key instead of taking it as an argument.** At a
  terminal it prompts and you paste, ending the entry with a blank line; behind a
  pipe it reads without prompting. The key never reaches the process list or the
  shell history.
- **The old form is now `unlock --key-value <text>`**, otherwise unchanged,
  warning included. A script still passing `--key "$KEY"` stops with a usage
  error and exit code `1` instead of installing anything.
- **The cipher crate is `aes-siv` 0.8.0**, no longer a release candidate. Nothing
  else about the dependency changed.

## [0.1.2] - 2026-08-11

One behaviour change and the installation documentation. **Nothing about the
bytes moved**: a repository encrypted with any earlier version needs nothing done
to it.

### Changed

- **`export-key --stdout` prints to a terminal instead of refusing one.** It used
  to exit `2` and write nothing. The key is written and the cost named instead:
  it now lives in the scrollback, in the multiplexer's buffer and in any session
  log, so clear all three or rotate it. Piping is unaffected.

### Documentation

- **The README says how to install** — a ready-made binary from the releases
  page, `cargo install git-xcrypt --locked`, or `cargo binstall git-xcrypt`.

## [0.1.1] - 2026-08-11

Bug fixes and one dependency change. **Nothing about the bytes moved**: a
repository encrypted with 0.1.0 needs nothing done to it.

### Fixed

- **A declared path no longer has its line endings changed when nothing asked for
  a conversion.** With `core.autocrlf` false or unset and `core.eol` unset, a
  checkout now writes the stored bytes back unchanged instead of the platform's
  own ending. Declaring a file secret used to change it, in opposite directions
  on Linux and Windows, with `git status` clean throughout. An explicit
  `core.eol=native`, or `eol=native` on the pattern, still selects the platform.
  A file brought in with CRLF still comes back LF; that limit is unchanged.
- **`git -c core.autocrlf=...` reaches the filter.** Overrides given on the
  command line were ignored, so one command could convert the paths git owns and
  leave declared ones alone.
- **`lock` refuses over a leftover file it cannot identify, instead of deleting
  the key.** Above a 223-byte name, a temporary file no longer identifies what it
  was named after, and `lock` used to report success, delete the key and leave a
  decrypted secret in the working tree. It now exits `2`, keeps the key, changes
  nothing, and says what to look at.
- **A configuration file that cannot be parsed no longer aborts every git
  operation** in the repository.

### Added

- **A warning when a declared `eol=` cannot reach a file.** Under the default
  `text=auto`, a file read as binary is stored verbatim and the declaration does
  nothing for it — one pattern honouring `eol=crlf` for one file and not for the
  next beside it. The filter now names any file this happens to.

### Changed

- **The cipher crate is `aes-siv` 0.8.0-rc.3.** Hardware AES on aarch64 now works
  by every install route, rather than only for builds run from a clone.

## [0.1.0] — 2026-08-07

First release. Everything below is new; there is no earlier version to have
changed anything from.

### Added

- **Transparent encryption through git's filter.** `.gitattributes` carries one
  static `* filter=git-xcrypt` line, so the filter sees every file in the
  repository and decides for itself, reading `.git-xcrypt`. Adding a pattern
  takes effect on the next `git add`, with no synchronising command.
- **A managed `.gitattributes` section that works before `sync` has ever run.**
  `init` writes two lines covering the whole repository, so a fresh repository is
  correct immediately and nothing can go stale. `sync` replaces them with a line
  per declared pattern, which confines the diff driver to declared paths;
  `--global` goes back, `--ignorecase` spells each ASCII letter as a class, and
  `--check` reports a stale section through exit code `2` instead of writing —
  the same code `status` gives on the same state. `sync` also points at `status`
  when lines outside its section set `filter`, `text`, `eol` or `crlf`, since git
  takes the last match.
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
  destination inside the working tree, inside another checkout of the same
  repository or inside the git directory is refused, and so is an existing file
  unless `--force` says the replacement is meant. On Unix the export is written
  with mode `0600`; on Windows nothing narrows it, so there the directory you
  pick *is* the protection.
- **A key can reach CI without touching the disk.** `export-key --stdout` pipes
  it into a secret store and refuses a terminal; `unlock --key <text>` takes the
  same text back, and the header keeps verifying the material behind it. The
  costs are named on `stderr` at every use: `--key` is visible to `ps` while the
  command runs and is recorded by an interactive shell, and a redirect out of
  `--stdout` escapes the checks that keep a key out of the working tree.
- **`unlock --key-only`** installs the key and repairs the filter registration
  without decrypting anything. A key the working tree's own headers contradict is
  still refused before it reaches disk.
- **`lock` refuses over everything it cannot account for**, because it deletes
  the only copy of the key and `unlock` will not undo that. It asks for a typed
  `yes` (`--yes` skips the question, never the warning), names the key by
  fingerprint and never by material, and refuses when a declared file holds
  uncommitted changes or another checkout of the same repository reads the same
  key — including when either appears while it is running.
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
- **Four automatic checks on the `git add` path**, of which only one stops
  anything. Warnings when a file is encrypted for the first time and the same
  path already sits in `HEAD` in the clear, when the managed `.gitattributes`
  section no longer matches the declaration, and when normalising a file would
  throw away its own line endings. A refusal — not a warning — when git's
  attribute stack would convert the ciphertext about to be written, which is
  otherwise unrecoverable at checkout. The warnings never return a non-zero code:
  with `filter.git-xcrypt.required = true` that would abort every git operation
  in the repository.
- **Ready-made binaries** for Linux (musl, x86_64 and aarch64), macOS (x86_64
  and aarch64) and Windows (MSVC, x86_64), each with a SHA-256 sum and a
  [build provenance attestation](https://github.com/rkarpin1/git-xcrypt#verifying-a-downloaded-release)
  naming the commit and workflow run it came from.

### Frozen with this release

These are frozen because changing them rewrites data that already exists. A
future change goes in a new `suite` byte, not in a new version of these:

- **Encrypted file format** — 11-byte magic `\0GITXCRYPT\0`, `format_version`
  `0x01`, `suite` `0x01` (AES-256-SIV, RFC 5297), a flags byte whose bit 0
  records whether the plaintext was normalised, an 8-byte `key_id` and a 16-byte
  synthetic IV: 38 bytes of overhead, exactly. Bytes `0..22` are frozen forever;
  everything from offset 22 is defined by `suite`.
- **Key file format** — its own versioned header over a 32-byte master key, with
  the cipher's key derived per suite, so a future suite needs no change to the
  file sitting in users' backups.
- **The text/binary rule** (`text=auto`, the default), which matches git's own,
  including the single trailing `SUB` (`0x1A`) it forgives. It decides whether a
  file is normalised, so it decides the ciphertext of most files.
- **ASCII case folding in pattern matching** — `secrets/` reaches
  `Secrets/db.env`, unconditionally and without reading `core.ignorecase`, so the
  same repository encrypts the same set of files on every machine. Folding stops
  at ASCII, exactly where git's does. The generated `.gitattributes` lines spell
  the pattern as written unless `sync --ignorecase` asks for the folded form; a
  path spelled in another case then loses its `diff` driver and its `-text`, but
  nothing is stored in the clear.
- **Exit codes** — `0` success, `1` usage or unclassified failure, `2`
  configuration or state conflict, `3` no key, `4` bad format, `5` `status` found
  an exposure, `6` `status` could not tell.

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
