---
description: Set or bump the crate version, run the gates, commit, tag v<version>, push, and publish to crates.io.
argument-hint: "[0.3.1 | patch | minor | major]   (default: patch)"
allowed-tools: Bash(cargo:*), Bash(git:*), Bash(gh:*), Bash(date:*), Read, Edit, Grep, Glob
---

Release `git-xcrypt` at the version given in `$ARGUMENTS`.

Two of the steps below cannot be undone: a pushed tag starts the release
workflow, and a crates.io publish can only be yanked, never replaced. So the run
splits in two — everything local and reversible first, then **one** confirmation,
then the outward-facing half. Do not ask for confirmation at every step; ask
once, at the checkpoint.

## 1. Decide the version, and refuse early

`$ARGUMENTS` is either an explicit version (`0.3.1`) or a bump level (`patch`,
`minor`, `major`). Empty means `patch`.

Read the current version from `Cargo.toml` (`^version = "..."`, the package one —
not a dependency's). Then refuse, **without changing a single file**, if:

- the target is not greater than the current version;
- the tag `v<target>` already exists (`git tag -l "v<target>"`);
- the working tree is dirty. A release commit here holds the version bump and
  nothing else — see `8a51a5f`, which touched exactly `Cargo.toml`,
  `Cargo.lock`, `CHANGELOG.md` and `README.md`. If there are unrelated changes,
  say so and stop; committing them is the user's call, not this command's;
- **the branch is not in sync with `origin`.** Run `git fetch origin`, then
  `git rev-list --left-right --count origin/<branch>...HEAD`. Behind by anything
  means stop. The failure this prevents is quiet: the tag is created locally, the
  push is rejected as non-fast-forward, the user rebases to fix it — and the
  annotated tag is left pointing at a commit that no longer exists on any branch.

State the current version, the target, and why you picked that level, before
touching a file.

## 2. Edit the four files

Take today's date from the machine (`date -I`) — not from what you believe the
date to be.

- **`Cargo.toml`** — the package `version`. Leave `rust-version` alone; MSRV is
  a decision, not a side effect.
- **`Cargo.lock`** — do not hand-edit. Run `cargo check`; cargo rewrites the
  crate's own entry (verified: bumping `Cargo.toml` to `0.1.2` and running
  `cargo check` put `version = "0.1.2"` in the lock file).
- **`CHANGELOG.md`** — **two** edits, and forgetting the second leaves a dangling
  reference that renders as bare text in brackets:
  1. a new `## [<version>] - <date>` section at the top of the list, in the Keep
     a Changelog shape the file already uses;
  2. a matching link definition at the **bottom** of the file, beside the ones
     already there:
     `[<version>]: https://github.com/rkarpin1/git-xcrypt/releases/tag/v<version>`

  Write the section from the commits since the last tag — find it with
  `git describe --tags --abbrev=0`, then read
  `git log --oneline <that-tag>..HEAD`. Not from memory. This project treats
  **the bytes it writes** as public interface, so if the encrypted file format,
  the key file format or the text/binary rule moved, that belongs under its own
  heading and the release is not a patch.
- **`README.md`** — the `**Status: vX.Y.Z.**` line.

## 3. Run the gates

All of them, and stop at the first failure — a red gate ends the run, it does
not become a caveat in the report:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

If the change being released touched `src/commands/filter.rs`, `src/rules/`,
`src/crypto/` or `src/git/attributes.rs`, also run the performance budgets,
which are `#[ignore]`d on purpose:

```sh
cargo test --release --test performance -- --ignored --nocapture
```

Compare that run against the previous run on **this** machine, not against the
absolute numbers: the 2 ns/B figure is calibrated on `aarch64-apple-darwin`.

`cargo publish --dry-run` is **not** here. It refuses a dirty working tree, and
at this point the tree is dirty by construction — measured: `error: 4 files in
the working directory contain changes that were not yet committed into git`. It
runs after the commit instead, where it also checks the exact bytes that will be
published rather than a tree nobody will ship.

## 4. Commit and tag

Commit on the branch that is checked out. **Never create a branch** — switching
or branching is the user's call.

```sh
git commit -m "release: <version>"          # plus the body, see below
git tag -a "v<version>" -m "git-xcrypt <version>"
```

The commit message follows `8a51a5f`: a subject `release: <version>`, then a
paragraph saying what kind of release it is and **whether anything about the
bytes moved**, then the bullet list of changes, then a line stating the suite
result. End with:

```
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
```

The tag is **annotated**, named `v<version>`, with the subject
`git-xcrypt <version>` — that is the shape `v0.1.0` and `v0.1.1` already have.
The name is not cosmetic: `.github/workflows/release.yml` triggers on `v*` and
its `verify-version` job fails the whole release if the tag does not match
`Cargo.toml`.

Now that the tree is clean, run the last gate:

```sh
cargo publish --dry-run
```

## 5. Checkpoint — ask here, once

Show the user: the version, the tag, the files changed, the gate results, and
the two things about to happen that cannot be undone. Then ask whether to push
and publish. Nothing after this line runs without an answer.

## 6. Push, then publish

```sh
git push origin <current-branch>
git push origin "v<version>"
cargo publish
```

Push the commit before the tag, or the release workflow builds a tag whose
commit the remote does not have yet. `cargo publish` needs a crates.io token
(`cargo login`) and a verified email on the account — the first attempt at
`0.1.1` came back `400: a verified email address is required`, with nothing
landing in the registry.

**If the tag is pushed and `cargo publish` then fails**, the release is half
done: the workflow is already building artefacts for a version the registry does
not have. Fix whatever `cargo publish` complained about and **run it again**.
Do not delete the tag, do not move it, do not force-push — the tag and the
artefacts are correct; only the registry is behind. Re-tagging would invalidate
a release that already built and was attested.

## 7. Verify as an outsider, then report

Do not report success from the fact that the commands exited `0`:

```sh
gh run list --workflow=release.yml --limit 1
gh release view "v<version>" --repo rkarpin1/git-xcrypt --json assets --jq '.assets[].name'
```

Expect ten assets: five archives and five `.sha256` files. Then say what was
released, what the gates measured, and anything you could not check.
