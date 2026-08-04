# Repository Guidelines

`git-xcrypt` is a Rust CLI that transparently encrypts selected files on commit and decrypts them on checkout. The crate is split into `src/lib.rs` (logic) and a thin `src/main.rs` (arguments, exit codes). S-01 through S-06 have shipped: `init` sets the repository up, `process` serves git's long-running filter protocol, `sync` regenerates the per-pattern `.gitattributes` lines, `export-key` / `import-key` / `unlock` carry a key to another machine and open a clone with it, `lock` closes a repository and deletes its key, `diff` is the `textconv` driver that makes `git diff` compare plaintext, and `status` reports whether the declarations are actually enforced — scanning all reachable history, repairing what it can with `--fix`, and exiting `5` on a finding so it works as a CI gate. That completes the v0.1 command set. The decisions live under `context/foundation/`.

## Hard rules

- **Never write to `stdout` on the clean/smudge filter path.** The filter's stdout *is* the file content; a stray `println!` corrupts it. Diagnostics to `stderr`.
- **Never commit a key or a secret.** Not to the working tree, a commit, or `stdout` outside an explicit `export-key`. Tests and examples included. `diff` is the one command that prints file content, so it refuses a key file **by its content** (`keyfile::holds_a_key`) — a location check was measured leaking the key when run from outside the repository, and it can say nothing about an exported copy.
- **Encryption must be deterministic.** Same plaintext and key, same ciphertext, or git reports unchanged files as modified.
- **Pass-through must be byte-identical.** `.gitattributes` carries a static `* filter=git-xcrypt`, so the filter runs on *every* file in the repository and passes unencrypted ones through untouched. A bug there corrupts the whole project, not just the secrets. `passthrough(x) == x` is a property test, not a nicety. The filter is registered as `filter.git-xcrypt.process` (long-running): a process per file was measured 22× slower.
- **Zero `unsafe`** — enforced by `unsafe_code = "forbid"` in `Cargo.toml`, not by convention. **Crypto from RustCrypto crates only — never hand-rolled, and never a construction we assemble ourselves.** Not "audited crates": the chosen `aes-siv` has no audit, and that is a recorded, deliberate risk. The cipher is AES-256-SIV (RFC 5297); the file format is frozen in `context/foundation/zalozenia.md`.
- **An error aborts the operation — but only with `filter.git-xcrypt.required = true`.** Without that flag git ignores a non-zero filter exit: `git add` returns 0 and the plaintext reaches the object database. `init` must set it; two tests in `tests/filter_edge_cases.rs` guard it. Never pass content through silently.
- **A path is bytes, never a `String`.** The filter protocol carries `pathname=` as arbitrary bytes and only the terminating `\n` may be stripped. Lossy UTF-8 decoding, or `trim_end()` on a name that legally ends in a space, matches a file under a name it does not have — and in the pass-through direction that is a secret stored in the clear. Both were real bugs, both are regression-tested.
- **`lock` deletes the only copy of the key, so everything it cannot verify, it refuses over.** The opposite lean from `unlock`, which skips what it cannot read and says so: there a skip leaves a file encrypted, here it would leave a plaintext secret behind the command that promised to remove it. Both review passes found paths that ended with the key gone and a live checkout still in the clear — a linked worktree, a file that appeared while the prompt waited. When adding a case, ask what happens if the answer is wrong, and refuse in that direction.
- **"I could not tell" must never be reported as "nothing is wrong."** `status` is read as a clean bill of health, and both of its review passes found states where it gave one it had not earned: an unreadable `packed-refs` yielded no tips, so the walk visited nothing, found nothing and exited `0` over a plaintext blob in history. Anything the scan could not cover — unresolvable references, unreadable objects, an unparsable index, a shallow clone's graft point — belongs in `undetermined`, which fails the gate. Exit `5` means "this repository has a problem"; a tool that broke has its own codes.
- **Git decides whether to call the filter at all.** Adding a pattern to `.git-xcrypt` reaches the filter immediately, and does **not** reach a file git considers unchanged: the cached `stat` makes `git add -A` skip it, so an already-committed secret is committed again in the clear, exit `0`, no warning. Measured on git 2.55 past the racy-clean window. That gap is the reason `status --fix` patches the index rather than printing advice, and why `status` cannot be replaced by anything that only looks at the working tree.
- **The clean path never reads git's EOL config; the smudge path does.** Encrypted paths carry `-text`, so git-xcrypt owns the LF/CRLF conversion. Normalizing to LF before encryption must be identical on every machine, or the same file yields different ciphertext on Windows and Linux.
- **The rendered `.gitattributes` lines must cover exactly the paths the filter encrypts — neither narrower nor broader.** They are called cosmetic because letting them go stale never stores a secret in the clear, and that is *all* the word means here. `-text` is what keeps git's own CRLF conversion off the ciphertext. Measured on git 2.55: an encrypted path without it, with any other attribute source declaring it `text`, had 34 `CR` bytes eaten out of a 2 MB blob — `git add` exited 0, the commit succeeded, and the file was unrecoverable at checkout. Narrower corrupts ciphertext; broader puts `-text` on files stored in the clear. The two files spell patterns differently (`secrets/` becomes `**/secrets/**`, `*.env` needs a second line), so the rendering is the risky part, not the parsing.

Why each rule, plus the file format and threat model: @context/foundation/zalozenia.md

## Language

English for code, comments, identifiers, commit messages, PR descriptions, and for headings, task titles, and field labels in `context/`. Polish for the prose under those headings and for conversation with AI agents.

## Structure

- `src/` — code; target is a `lib` for logic plus a thin `bin` for arguments and exit codes.
- `context/foundation/` — @context/foundation/prd.md (requirements, guardrails, open questions), @context/foundation/roadmap.md (what to build next, in dependency order), @context/foundation/zalozenia.md, @context/foundation/tech-stack.md
- `context/changes/<id>/` — per-change plan, research, review. Never in `foundation/`.

Read the PRD's `## Open Questions` first; none of them blocks today. Pick work from the roadmap's `## Backlog Handoff`. What is left of v0.1, in this order: **`S-08` first** — the binary-detection parity fix (a trailing `SUB`, 0x1A) has to land *before* anything ships, because `looks_binary` is frozen with the format and changing it afterwards rewrites the ciphertext of existing files — then `S-07`, the release itself.

When asked "co dalej?" (what's next), answer with a lettered list — `a.`, `b.`, `c.`, … — one option per item, so the user can pick by letter.

## Conventions

Clippy runs with `-D warnings`. Errors via `thiserror`; no `unwrap()` on user-input paths. MSRV is **1.88**, declared in `Cargo.toml` and held by the `msrv` job in CI — measured, not assumed: edition 2024 alone would allow 1.85, but `let` chains in `if` conditions do not compile there.

## Testing

Tests must drive real git repositories in a temp dir — only git's stored objects prove these rules hold. `tests/harness/mod.rs` does that: it stands up a repo, registers the binary as a filter and returns raw blob bytes; `BareRemote` in the same file stands up a bare repository to push to, because "the blobs in the remote are encrypted" is a claim about a remote. Integration test files pull it in with `mod harness;`. Format vectors stay frozen once shipped.

`tests/acceptance.rs` holds the founding document's six-step scenario as one test. It is the one place where a regression in any part of the promise shows up as a single red line; keep it that way rather than splitting it up.

The three properties `zalozenia.md` asks for — `passthrough(x) == x`, `decrypt(encrypt(x)) == x`, `encrypt(x) == encrypt(x)` — are `proptest` properties in `src/decide.rs` and `src/crypto.rs`, with the hand-written sample lists kept beside them: a generator that happens not to draw the empty file or a lone `CR` would quietly stop covering the shapes that once broke.

**When adding a guard, try to break it.** Several rules above were once "guarded" by tests that passed with the rule removed — `required = true` by tests that set the flag themselves, the 128:1 binary ratio by nothing at all, the long-running protocol by a test that only counted encrypted files. Mutate the line, watch the suite go red, then put it back.

## Commits and PRs

**Never create a git branch.** Commit on whatever branch is checked out, including `master`. Switching or branching is the user's call, not yours — this overrides any default that says to branch off the main branch first.

CI lives in `.github/workflows/ci.yml`: `cargo test --all-targets` on Linux, macOS and Windows, plus `fmt --check`, `clippy --all-targets -- -D warnings`, `cargo audit`, `cargo deny check` (policy in `deny.toml`) and an MSRV build. `release.yml` builds five targets on a `v*` tag.

The three-platform matrix is not ceremony. Whole branches have never run on the development machine: `EolMode::Native`'s CRLF arm is `cfg!(windows)`, every key-permission test is `#[cfg(unix)]`, and APFS refuses the non-UTF-8 path names `decide` and the index are written to handle. Before adding a `#[cfg(unix)]` test, ask whether the other platform is now uncovered.
