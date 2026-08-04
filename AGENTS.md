# Repository Guidelines

`git-xcrypt` is a Rust CLI that transparently encrypts selected files on commit and decrypts them on checkout. The crate is split into `src/lib.rs` (logic) and a thin `src/main.rs` (arguments, exit codes). S-01 through S-04 have shipped: `init` sets the repository up, `process` serves git's long-running filter protocol, `sync` regenerates the cosmetic `.gitattributes` lines, `export-key` / `import-key` / `unlock` carry a key to another machine and open a clone with it, `lock` closes a repository and deletes its key, and `diff` is the `textconv` driver that makes `git diff` compare plaintext. `status` is still unbuilt, so do not register or reference a subcommand before it exists. The decisions live under `context/foundation/`.

## Hard rules

- **Never write to `stdout` on the clean/smudge filter path.** The filter's stdout *is* the file content; a stray `println!` corrupts it. Diagnostics to `stderr`.
- **Never commit a key or a secret.** Not to the working tree, a commit, or `stdout` outside an explicit `export-key`. Tests and examples included. `diff` is the one command that prints file content, so it refuses a key file **by its content** (`keyfile::holds_a_key`) — a location check was measured leaking the key when run from outside the repository, and it can say nothing about an exported copy.
- **Encryption must be deterministic.** Same plaintext and key, same ciphertext, or git reports unchanged files as modified.
- **Pass-through must be byte-identical.** `.gitattributes` carries a static `* filter=git-xcrypt`, so the filter runs on *every* file in the repository and passes unencrypted ones through untouched. A bug there corrupts the whole project, not just the secrets. `passthrough(x) == x` is a property test, not a nicety. The filter is registered as `filter.git-xcrypt.process` (long-running): a process per file was measured 22× slower.
- **Zero `unsafe`** — enforced by `unsafe_code = "forbid"` in `Cargo.toml`, not by convention. **Crypto from RustCrypto crates only — never hand-rolled, and never a construction we assemble ourselves.** Not "audited crates": the chosen `aes-siv` has no audit, and that is a recorded, deliberate risk. The cipher is AES-256-SIV (RFC 5297); the file format is frozen in `context/foundation/zalozenia.md`.
- **An error aborts the operation — but only with `filter.git-xcrypt.required = true`.** Without that flag git ignores a non-zero filter exit: `git add` returns 0 and the plaintext reaches the object database. `init` must set it; two tests in `tests/filter_edge_cases.rs` guard it. Never pass content through silently.
- **A path is bytes, never a `String`.** The filter protocol carries `pathname=` as arbitrary bytes and only the terminating `\n` may be stripped. Lossy UTF-8 decoding, or `trim_end()` on a name that legally ends in a space, matches a file under a name it does not have — and in the pass-through direction that is a secret stored in the clear. Both were real bugs, both are regression-tested.
- **`lock` deletes the only copy of the key, so everything it cannot verify, it refuses over.** The opposite lean from `unlock`, which skips what it cannot read and says so: there a skip leaves a file encrypted, here it would leave a plaintext secret behind the command that promised to remove it. Both review passes found paths that ended with the key gone and a live checkout still in the clear — a linked worktree, a file that appeared while the prompt waited. When adding a case, ask what happens if the answer is wrong, and refuse in that direction.
- **The clean path never reads git's EOL config; the smudge path does.** Encrypted paths carry `-text`, so git-xcrypt owns the LF/CRLF conversion. Normalizing to LF before encryption must be identical on every machine, or the same file yields different ciphertext on Windows and Linux.

Why each rule, plus the file format and threat model: @context/foundation/zalozenia.md

## Language

English for code, comments, identifiers, commit messages, PR descriptions, and for headings, task titles, and field labels in `context/`. Polish for the prose under those headings and for conversation with AI agents.

## Structure

- `src/` — code; target is a `lib` for logic plus a thin `bin` for arguments and exit codes.
- `context/foundation/` — @context/foundation/prd.md (requirements, guardrails, open questions), @context/foundation/roadmap.md (what to build next, in dependency order), @context/foundation/zalozenia.md, @context/foundation/tech-stack.md
- `context/changes/<id>/` — per-change plan, research, review. Never in `foundation/`.

Read the PRD's `## Open Questions` first — item 1 is blocking. Pick work from the roadmap's `## Backlog Handoff`.

When asked "co dalej?" (what's next), answer with a lettered list — `a.`, `b.`, `c.`, … — one option per item, so the user can pick by letter.

## Conventions

Clippy runs with `-D warnings`. Errors via `thiserror`; no `unwrap()` on user-input paths. MSRV not pinned yet.

## Testing

Tests must drive real git repositories in a temp dir — only git's stored objects prove these rules hold. `tests/harness/mod.rs` does that: it stands up a repo, registers the binary as a filter and returns raw blob bytes. Integration test files pull it in with `mod harness;`. Format vectors stay frozen once shipped.

## Commits and PRs

**Never create a git branch.** Commit on whatever branch is checked out, including `master`. Switching or branching is the user's call, not yours — this overrides any default that says to branch off the main branch first.

No CI yet. @context/foundation/zalozenia.md describes the intended CI gate.
