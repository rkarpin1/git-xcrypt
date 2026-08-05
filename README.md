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

## The key file is the only copy — back it up yourself

**Read this before you commit anything you cannot afford to lose.**

`git-xcrypt init` writes one 32-byte master key to
`.git/git-xcrypt/keys/default`. `.git/` is not versioned, is not pushed, and is
not part of any clone. Nothing in this tool copies that key anywhere, and
**v0.1 has no backup mechanism at all** — that is a deliberate scope decision,
not an oversight.

So:

- If the key file is lost, **every secret in the repository's entire history
  becomes unreadable, permanently.** Not just the current files: every version
  of every encrypted file in every commit, in every clone, forever. There is no
  recovery procedure and there is no one to ask.
- Losing it is easy. `rm -rf` on a working copy takes it. A reinstalled laptop
  takes it. `git clone` of your own repository does **not** bring it back.
  `git-xcrypt lock` deletes it on purpose, and `unlock` does not undo that.

Make a copy the moment you run `init`:

```sh
git-xcrypt export-key ~/backup/git-xcrypt-my-project.key
```

On Unix the file is written with mode `0600`. **On Windows nothing narrows it**
— it inherits whatever its directory hands down, so there the directory you pick
*is* the protection; see Known limitations. Where it should **not** go:

- **not inside the repository or any other checkout of it** — `export-key`
  refuses those outright, because one `git add -A` would commit the key;
- **not into the git directory** — also refused;
- **not into a CI log, a terminal scrollback or a shell redirect.** The key is
  never printed to `stdout`; keep it that way.

Where it should go is somewhere that survives losing the machine and that you
trust with a plaintext secret: a password manager, an encrypted backup volume,
or an offline device. Treat it exactly as you would treat the secrets it opens —
because anyone holding it can read all of them, in every commit.

`git-xcrypt lock` asks for a typed `yes` and prints the `key_id` before deleting
the key, and refuses outright when declared files have uncommitted changes.
Those are speed bumps in front of the cliff. They are not a backup.

## Commands

| Command | What it does |
| --- | --- |
| `init` | Generate the repository key, register the filter and the diff driver, create `.git-xcrypt`, write the managed `.gitattributes` section. |
| `sync` | Regenerate the per-pattern `.gitattributes` lines. `--check` reports staleness through exit code 1 instead of writing. |
| `status` | Report whether your declarations are actually enforced, scanning the whole reachable history. `--fix` re-stages declared files the index holds in the clear. Exits `5` on a finding, `6` when it could not tell. |
| `export-key` | Write the repository key to a file outside the working tree. This is also how you make the backup nothing else makes — see above. |
| `import-key` | Put a key carried from another machine into this repository. |
| `unlock` | Decrypt the working tree and register the filter, importing a key file first if one is given. |
| `lock` | Encrypt the working tree and delete the key. Interactive by default; `--yes` skips the question but not the refusal on uncommitted changes. |
| `diff`, `process` | Registered by `init` for git to call. Not meant to be run by hand. |

Exit codes: `0` success, `1` usage or unclassified failure, `2` configuration or
state conflict, `3` no key, `4` bad format, `5` `status` found an exposure, `6`
`status` could not tell.

### Using `status` as a CI gate

```yaml
- uses: actions/checkout@v5
  with:
    fetch-depth: 0        # required: see below
- run: git-xcrypt status
```

What the exit code means to the job:

| Code | Meaning | What to do |
| --- | --- | --- |
| `0` | Everything was checked and nothing was found. | Nothing. |
| `5` | Something was found: a setup gap, a declared file staged in the clear, a plaintext version in history, a declared path git does not resolve `filter=git-xcrypt` for, or one whose ciphertext git converts because some attribute line outranks the managed `-text`. | Read the report. If a secret leaked, **rotate it first**. |
| `6` | The run could not answer. A shallow or partial clone, an index that will not parse, a reference store that will not enumerate, a missing `.git-xcrypt`. | Fix the checkout and run it again. Nothing was found, and nothing is ruled out. |
| `1`–`4` | The tool itself failed — bad arguments, not a repository, no key, bad format. | Fix the invocation or the environment. |

**`fetch-depth: 0` is not optional for a full answer.** `actions/checkout` clones
with `--depth 1` by default, and history that was never fetched cannot be
scanned — so the default setup exits `6`, honestly, rather than passing on a
history it never saw. The same applies to `--filter=blob:none` partial clones.

A finding always outranks an unanswered question: a run that both hit an
unreadable index and found a leak exits `5`.

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
something — and `6` when it could not look at all, which is not the same answer.
If it exits `5`: **rotate the secret first.** Rewriting history cleans the
repository but does not undo the leak — the secret is already in forks, caches,
CI logs and every clone that exists.

`status` answers "are my declarations enforced", not "does this repository hold
secrets". A file no pattern ever matched is invisible to it.

### Attributes that turn the filter off, or turn conversion back on

The managed section is a few attribute lines among many, and git takes the
**last** match. A line below the section, a `.gitattributes` in a subdirectory,
or `.git/info/attributes` — which is not versioned, so nobody reviewing a pull
request can see it — outranks it. There are two ways that hurts, and they hurt
differently:

- **`-filter` on a declared path.** Git runs no filter, `git add` stores the
  plain text with exit code 0, and the secret is in the repository.
- **`text`, or a bare `eol=`, on a declared path.** Git *does* run the filter and
  then converts the line endings of what it produced — the **ciphertext**.
  Measured on git 2.55: 34 `CR` bytes eaten out of a 2 MB blob, `git add` and
  `git commit` both exit 0, and the next checkout fails the authentication tag
  and leaves no file at all. Nothing is exposed; the file is simply gone, and no
  key will ever bring it back. This is what the managed `-text` prevents, and
  why `sync` belongs in your workflow rather than being cosmetic.

`git-xcrypt status` resolves both attributes for every declared path the index
holds, using git's own precedence rules, macros included, and fails with exit `5`
either way — the report names the winning line and the file and line number it
sits in. It resolves rather than guesses, so none of these trigger it: an
ordinary `*.psd filter=lfs`, `text=auto`, `binary`, `-text` with any `eol=`, or
`core.autocrlf` at any value. Our magic starts with a NUL byte, so every code
path in git that consults binary detection leaves the ciphertext alone.
`git check-attr filter text eol -- <path>` gives the same answers by hand.

A foreign `diff=` line on a declared path is measured harmless: it costs you a
readable `git diff` and touches no stored byte. `status` does not fail over it.

The boundary: only paths the index already tracks are resolved. A line that
would disable the filter for a file nobody has committed yet is reported as a
note, not a finding.

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
  `git-xcrypt status` detects this and exits `5`. A shallow clone of the same
  repository exits `6` instead once it is unlocked: nothing is wrong with it,
  but the history it never fetched cannot be vouched for.
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
- **Key files are only given permissions on Unix.** `init` and `export-key`
  create them with mode `0600` there, before a single byte of key material
  reaches the file. On Windows nothing sets permissions at all: the file
  inherits the ACL of the directory it is created in, and narrowing it would
  need `unsafe` platform bindings, which this crate forbids outright. The
  repository's own key lives in `.git/` and is therefore as protected as the
  rest of your checkout — but an exported key is exactly as protected as the
  directory you chose for it, so on Windows choose one only your account can
  read.
- **There is no key backup mechanism.** Keeping a copy of the key file is
  entirely your job, and losing it costs the whole history of secrets. See "The
  key file is the only copy" above; this is a decided scope boundary for v0.1,
  not a gap waiting to be filled before release.
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
