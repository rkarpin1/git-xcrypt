# git-xcrypt

Transparent encryption of selected files in a git repository: plaintext in your
working tree, ciphertext in the remote. A self-contained Rust binary — no
system `gpg`, no helper scripts, no external processes on the filter path.

**Status: early development.** No user-facing command exists yet. The design
decisions live under [`context/foundation/`](context/foundation/).

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
