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

## [0.1.0] — unreleased

First release. Everything below is new; there is no earlier version to have
changed anything from.

### Added

- **Transparent encryption through git's filter.** `.gitattributes` carries one
  static `* filter=git-xcrypt` line, so the filter sees every file in the
  repository and decides for itself, reading `.git-xcrypt`. Adding a pattern
  takes effect on the next `git add` with no synchronising command. Registered
  as `filter.git-xcrypt.process` — the long-running protocol, because a process
  per file measured 22× slower.
- **`.git-xcrypt`**, a versioned declaration in `.gitignore` syntax, as the one
  source of truth for what is encrypted. Negations, directory patterns and
  anchoring behave as they do in `.gitignore`; after a pattern you may write the
  line-ending attributes `text`, `-text`, `binary`, `text=auto` and
  `eol=lf|crlf|native`, with the meanings they have in `.gitattributes`. Names
  containing whitespace are closed with quotes, as in `.gitattributes`.
- **Commands** `init`, `sync`, `status`, `export-key`, `unlock`, `lock`, plus
  `diff` and `process`, which `init` registers for git to call.
  See the table in `README.md`.
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
- **Two automatic checks on the `git add` path.** A warning when a file is
  encrypted for the first time and the same path already sits in `HEAD` in the
  clear, and a refusal — not a warning — when git's attribute stack would
  convert the ciphertext about to be written, which is otherwise unrecoverable
  at checkout.
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
  stops at ASCII, exactly where git's does.
- **Exit codes** — `0` success, `1` usage or unclassified failure, `2`
  configuration or state conflict, `3` no key, `4` bad format, `5` `status`
  found an exposure, `6` `status` could not tell.

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

[0.1.0]: https://github.com/rkarpin1/git-xcrypt/releases/tag/v0.1.0
