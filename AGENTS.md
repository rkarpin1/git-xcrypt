# Repository Guidelines

`git-crypt` is a Rust CLI that transparently encrypts selected files on commit and decrypts them on checkout. `src/main.rs` is still hello world; the decisions live under `context/foundation/`.

## Hard rules

- **Never write to `stdout` on the clean/smudge filter path.** The filter's stdout *is* the file content; a stray `println!` corrupts it. Diagnostics to `stderr`.
- **Never commit a key or a secret.** Not to the working tree, a commit, or `stdout` outside an explicit `export-key`. Tests and examples included.
- **Encryption must be deterministic.** Same plaintext and key, same ciphertext, or git reports unchanged files as modified.
- **Zero `unsafe`; crypto from audited crates only.**
- **An error aborts the operation.** Never pass content through silently.

Why each rule, plus the file format and threat model: @context/foundation/zalozenia.md

## Language

English for code, comments, identifiers, commit messages, PR descriptions, and for headings, task titles, and field labels in `context/`. Polish for the prose under those headings and for conversation with AI agents.

## Structure

- `src/` — code; target is a `lib` for logic plus a thin `bin` for arguments and exit codes.
- `context/foundation/` — @context/foundation/prd.md (requirements, guardrails, open questions), @context/foundation/roadmap.md (what to build next, in dependency order), @context/foundation/zalozenia.md, @context/foundation/tech-stack.md
- `context/changes/<id>/` — per-change plan, research, review. Never in `foundation/`.

Read the PRD's `## Open Questions` first — item 1 is blocking. Pick work from the roadmap's `## Backlog Handoff`.

## Conventions

Clippy runs with `-D warnings`. Errors via `thiserror`; no `unwrap()` on user-input paths. MSRV not pinned yet.

## Testing

`tests/` does not exist yet. Tests must drive real git repositories in a temp dir — only git's stored objects prove these rules hold. Format vectors stay frozen once shipped.

## Commits and PRs

No commits yet, no CI yet. @context/foundation/zalozenia.md describes the intended CI gate.
