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
| `status` | Report whether your declarations are actually enforced, scanning the whole reachable history. `--fix` re-stages declared files the index holds in the clear. Exits `5` on a finding, `6` when it could not tell. |
| `export-key` | Write the repository key to a file outside the working tree. |
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
| `5` | Something was found: a setup gap, a declared file staged in the clear, a plaintext version in history, or a declared path git does not resolve `filter=git-xcrypt` for. | Read the report. If a secret leaked, **rotate it first**. |
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

### Attributes that turn the filter off

The `* filter=git-xcrypt` line is one attribute line among many, and git takes
the **last** match. A line below the managed section, a `.gitattributes` in a
subdirectory, or `.git/info/attributes` — which is not versioned, so nobody
reviewing a pull request can see it — can set `-filter` on a declared path.
`git add` then stores the plain text with exit code 0.

`git-xcrypt status` resolves the `filter` attribute for every declared path the
index holds, using git's own precedence rules, macros included, and fails with
exit `5` when git would not run this tool. It resolves rather than guesses, so
an ordinary `*.psd filter=lfs` line does not trigger it. `git check-attr filter
-- <path>` gives the same answer by hand.

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
