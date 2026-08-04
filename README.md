# git-xcrypt

Transparent encryption of selected files in a git repository: plaintext in your
working tree, ciphertext in the remote. A self-contained Rust binary — no
system `gpg`, no helper scripts, no external processes on the filter path.

**Status: v0.1 in development, not yet released.** Every command listed below
works and is covered by tests that drive a real git. There is no published
release or package yet, so today the only way in is `cargo install --path .`.

## Quick start

```sh
git init my-project && cd my-project
git-xcrypt init                 # generates a key, registers the filter
```

Declare what is secret in `.git-xcrypt`, which uses `.gitignore` syntax and is
versioned with the project:

```gitignore
secrets/
*.env
!secrets/README.md              # an exception, stored in the clear
secrets/deploy.ps1  text eol=crlf
secrets/key.p12     binary
```

Then run `git-xcrypt sync` and commit as usual:

```sh
git-xcrypt sync                 # refresh the managed .gitattributes section
git add -A && git commit -m "add secrets"
```

Your working tree still shows plaintext. The repository stores ciphertext.

**Run `sync` after every change to `.git-xcrypt`.** Which paths get encrypted
takes effect immediately — the filter reads `.git-xcrypt` on every `git add` —
but the per-pattern lines `sync` writes carry `-text`, and that is what keeps
git's own CRLF conversion away from the ciphertext. Without it, any other
attribute declaring such a path `text` makes git rewrite the encrypted bytes:
measured on a 2 MB file, `git add` exits 0, the damaged blob is committed, and
the file is unrecoverable at checkout. `git-xcrypt sync --check` exits 1 on a
stale section, which makes it usable as a CI gate, and `git-xcrypt status`
mentions it too.

### On a second machine

```sh
git-xcrypt export-key ~/git-xcrypt-my-project.key   # on the first machine
# carry the file across by whatever channel you trust

git clone <url> && cd my-project                    # on the second
git-xcrypt unlock ~/git-xcrypt-my-project.key
```

`git status` is clean immediately afterwards. That is the point of the
deterministic cipher: unchanged files never look modified.

## Commands

| Command | What it does |
| --- | --- |
| `init` | Generate the repository key, register the filter and the diff driver, create `.git-xcrypt`, write the managed `.gitattributes` section. |
| `sync` | Regenerate the per-pattern `.gitattributes` lines. `--check` reports staleness through exit code 1 instead of writing. |
| `status` | Report whether your declarations are actually enforced, scanning the whole reachable history. `--fix` re-stages declared files the index holds in the clear. Exits `5` on a finding. |
| `export-key` | Write the repository key to a file outside the working tree. |
| `import-key` | Put a key carried from another machine into this repository. |
| `unlock` | Decrypt the working tree and register the filter, importing a key file first if one is given. |
| `lock` | Encrypt the working tree and delete the key. Interactive by default; `--yes` skips the question but not the refusal on uncommitted changes. |
| `diff`, `process` | Registered by `init` for git to call. Not meant to be run by hand. |

Exit codes: `0` success, `1` usage or unclassified failure, `2` configuration or
state conflict, `3` no key, `4` bad format, `5` `status` found an exposure.

## What it does and does not protect

**Encrypted:** the contents of every file a pattern selects, with AES-256-SIV
(RFC 5297) and a 32-byte master key that never leaves `.git/`.

**Not hidden:** file names, paths, sizes and the fact that a file changed. The
size leaks exactly — an encrypted blob is 38 bytes plus the content. Because
encryption is deterministic, two files with identical contents are visibly
identical, and a file reverting to an earlier version is visible as such. These
are accepted trade-offs of the construction, not defects.

**Not protected against:** a compromised machine. After `unlock`, secrets sit in
the clear on disk.

### The one risk worth reading twice

A secret committed **before** its pattern reached `.git-xcrypt` stays in history
in the clear, forever, and pushing sends it to the host. `git-xcrypt status`
scans the whole reachable history for exactly this and exits `5` when it finds
something. If it does: **rotate the secret first.** Rewriting history cleans the
repository but does not undo the leak — the secret is already in forks, caches,
CI logs and every clone that exists.

`status` answers "are my declarations enforced", not "does this repository hold
secrets". A file no pattern ever matched is invisible to it.

## Known limitations

- **A failing filter blocks every git operation in the repository.** `init` sets
  `filter.git-xcrypt.required = true` on purpose: without it git ignores a
  filter failure and stores the plaintext with exit code 0. The cost is that a
  missing or unrunnable `git-xcrypt` binary stops `git add`, `git checkout` and
  `git status` with `fatal: … filter 'git-xcrypt' failed`. To get moving again,
  put the binary back, or unregister the driver by hand:
  `git config --unset filter.git-xcrypt.process` and
  `git config --unset filter.git-xcrypt.required`. Anything committed while it
  is unregistered is stored in the clear.
- **A clone that has not been unlocked is not safe to write to.** `.git/config`
  is not versioned, so a fresh clone carries the catch-all `.gitattributes` line
  with no driver behind it, and git treats an undefined filter as no filter.
  `git-xcrypt status` detects this and exits `5`.
- **Real git only.** The filter is registered under the long-running protocol
  (`filter.<driver>.process`). Clients that reimplement git rather than calling
  it — JGit, and tools built on libgit2 — may not speak it and may treat the
  file as unfiltered. IDEs and GUIs that shell out to `git` are fine.
- `git archive` exports ciphertext: git does not apply filters to it.
- Submodules have their own configuration and need their own `init`.
- `working-tree-encoding` (character-set conversion, e.g. UTF-16) is not
  supported.
- A file with mixed line endings does not survive the round trip: normalisation
  is lossy, so such a file comes back changed. Git warns about the same thing
  through `core.safecrlf`; whether to reproduce that warning is still open.
- A repository encrypted with the original `git-crypt` is **not** supported and
  there is no migration path.

## Building

```sh
cargo install --path .
```

Requires Rust 1.88 or newer (the crate declares this as its MSRV and CI holds it
there). The binary is self-contained: no external libraries and no child
processes, `gpg` included.

Being named `git-xcrypt` and on `PATH` also makes `git xcrypt <command>` work.

## Attribution

`git-xcrypt` is *inspired by* [AGWA/git-crypt](https://github.com/AGWA/git-crypt)
(GPL-3.0) and [AprilNEA/git-crypt-rs](https://github.com/AprilNEA/git-crypt-rs)
(MIT OR Apache-2.0). It is **not a port of either**.

No code is taken from either project. Command naming, the clean/smudge working
model and the general UX are kept compatible; the encrypted file format, the key
format and recipient management are our own. A repository encrypted with the
original `git-crypt` is **not** supported and there is no migration path.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
