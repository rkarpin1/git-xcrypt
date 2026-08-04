//! Frozen vectors for the on-disk format.
//!
//! These are the contract with every repository ever encrypted by this tool.
//! Once shipped they do not change: a different byte here means existing
//! repositories stop decrypting. If a change to the cipher, the header or the
//! line-ending rule alters these bytes, that change needs a new `suite` — not
//! an edited vector.
//!
//! The RFC 5297 vector lives in `src/crypto.rs`, because it needs the cipher
//! crate directly; it pins `aes-siv` against the specification, while these
//! pin our own wrapping of it.

use git_xcrypt::config::Config;
use git_xcrypt::crypto::{decrypt, encrypt};
use git_xcrypt::decide;
use git_xcrypt::eol::looks_binary;
use git_xcrypt::format::{FLAG_LF_NORMALIZED, OVERHEAD, looks_encrypted};
use git_xcrypt::key::{MASTER_KEY_LEN, MasterKey};

/// The key every vector below was produced with.
fn vector_key() -> MasterKey {
    MasterKey::from_bytes([0x2au8; MASTER_KEY_LEN])
}

/// Decodes a hex string from a vector.
fn from_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex needs an even length");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("vectors must be hex"))
        .collect()
}

/// Renders bytes the way the vectors are written, for readable failures.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One frozen case: plaintext, the flags recorded in the header, the blob.
struct Vector {
    name: &'static str,
    plaintext: Vec<u8>,
    flags: u8,
    blob_hex: &'static str,
}

fn vectors() -> Vec<Vector> {
    vec![
        Vector {
            name: "empty file",
            plaintext: Vec::new(),
            flags: 0,
            blob_hex: "0047495458435259505400010100fd2f0a5c2d19a55b\
                       1b81b276215472586686614d8f2dfc9b",
        },
        Vector {
            name: "one byte",
            plaintext: b"x".to_vec(),
            flags: 0,
            blob_hex: "0047495458435259505400010100fd2f0a5c2d19a55b\
                       59d0204b92720f46d481b8f527677869b8",
        },
        Vector {
            name: "text recorded as LF-normalised",
            plaintext: b"api_key = do-not-commit-me\n".to_vec(),
            flags: FLAG_LF_NORMALIZED,
            blob_hex: "0047495458435259505400010101fd2f0a5c2d19a55b\
                       1b464b8975b40b190398812f9a672edd57ed3b1bae61c4e7b7e7e1f8308\
                       dead4d6acfadbe14bacd29714f0",
        },
        Vector {
            name: "every byte value",
            plaintext: (0u8..=255).collect(),
            flags: 0,
            blob_hex: "0047495458435259505400010100fd2f0a5c2d19a55b\
                       519b5180823840926c3ab54dcc20e9722c924e36f8c33de8bf7a363513e\
                       177081315344c67e8fdc1277aa0e9c0ad8147e9e63f2ed3882b336e9ce3\
                       153143c2d2b9105d433fabec75e131bb0eef27f1fd126a888e06d5bf9fd\
                       56e780c5b7f2a900a672304e0fe11d3dbbfece5181d401c661b787b5d8e\
                       57ec929bf860d0a8664b0cc3e1027da251f25ff098fc9558155871cbffb\
                       d6329b876fda1ec18f9a67ccf14709f2e42e2479a5b245de1ab76327317\
                       d4d77f7065148b5866382c48afb1aeb31005b9aae44ab58e61ddc7d3325\
                       201d69bdd21523adc19dbee85413f2ce1909ab5c9ce5d7de816868dfad2\
                       033355ffd6de8ca057334f3b3aba7384d34140c5ff1cf026bd1297eb768\
                       ebfe5a7a09669",
        },
    ]
}

/// Vector hex is wrapped across lines for readability; strip the padding.
fn normalise(hex: &str) -> String {
    hex.chars().filter(|c| !c.is_whitespace()).collect()
}

#[test]
fn encryption_still_produces_the_frozen_bytes() {
    for vector in vectors() {
        let produced = encrypt(&vector_key(), vector.flags, &vector.plaintext)
            .expect("a frozen vector must encrypt");
        assert_eq!(
            to_hex(&produced),
            normalise(vector.blob_hex),
            "the on-disk format changed for `{}` — existing repositories would stop \
             decrypting. A deliberate change needs a new suite, not an edited vector.",
            vector.name
        );
    }
}

#[test]
fn the_frozen_bytes_still_decrypt() {
    for vector in vectors() {
        let blob = from_hex(&normalise(vector.blob_hex));
        let (flags, plaintext) =
            decrypt(&vector_key(), &blob).expect("a frozen vector must decrypt");
        assert_eq!(flags, vector.flags, "flags changed for `{}`", vector.name);
        assert_eq!(
            plaintext, vector.plaintext,
            "plaintext changed for `{}`",
            vector.name
        );
    }
}

/// Frozen verdicts for the `text=auto` rule.
///
/// `zalozenia.md` requires these alongside the format vectors, and the reason is
/// concrete: the vectors above call `crypto::encrypt` with explicit flags, so
/// they are blind to `looks_binary`. Without this table the text/binary boundary
/// can move — re-ciphering every file that crosses it — with the suite green.
///
/// Each case is `(content, is_binary)` and mirrors a measurement against git's
/// own `gather_stats`/`convert_is_binary`.
fn binary_verdicts() -> Vec<(&'static str, Vec<u8>, bool)> {
    vec![
        ("empty", Vec::new(), false),
        (
            "plain ASCII",
            b"api_key = do-not-commit-me\n".to_vec(),
            false,
        ),
        ("CRLF text", b"one\r\ntwo\r\n".to_vec(), false),
        (
            "forgiven controls",
            b"bs\x08tab\tff\x0cesc\x1b\n".to_vec(),
            false,
        ),
        ("a NUL anywhere", b"text then \0 a nul".to_vec(), true),
        (
            "a NUL far in",
            {
                let mut v = vec![b'A'; 100_000];
                v.push(0);
                v
            },
            true,
        ),
        ("lone CR at the end", b"trailing\r".to_vec(), true),
        ("lone CR inside", b"old\rmac\r".to_vec(), true),
        ("CR CR LF", b"a\r\r\nb\r\n".to_vec(), true),
        ("LF then CR", b"\n\r".to_vec(), true),
        // Bytes >= 0x80 are printable, which is what keeps UTF-8 text as text.
        (
            "high bytes",
            (0x80u8..=0xff).cycle().take(2560).collect(),
            false,
        ),
        (
            "many controls",
            (1u8..=8).cycle().take(2400).collect(),
            true,
        ),
        // DEL is above 0x20 but git counts it against the content. Padding with
        // LF must not rescue it: line endings count towards neither bucket.
        (
            "DEL padded with LF",
            {
                let mut v = vec![0x7f; 200];
                v.extend_from_slice(b"x\r\n");
                v
            },
            true,
        ),
        (
            "LF padded controls",
            {
                let mut v = vec![b'\n'; 200];
                v.extend_from_slice(b"\x01\r\n");
                v
            },
            true,
        ),
        // One DEL among plenty of printable bytes stays text: 256 >> 7 == 2.
        (
            "one DEL in prose",
            {
                let mut v = vec![b'a'; 256];
                v.push(0x7f);
                v
            },
            false,
        ),
    ]
}

#[test]
fn the_text_auto_rule_still_gives_the_frozen_verdicts() {
    for (name, content, expected) in binary_verdicts() {
        assert_eq!(
            looks_binary(&content),
            expected,
            "the text/binary boundary moved for `{name}` — every file that crosses \
             it gets different ciphertext, so this needs a new suite, not an edited \
             vector"
        );
    }
}

#[test]
fn the_recorded_normalisation_flag_follows_the_frozen_verdict() {
    // Goes through `decide::clean`, not `crypto::encrypt`, so it pins the whole
    // chain: pattern match, text/binary verdict, flag bit, ciphertext.
    let config = Config::parse("*.env\n").expect("test config");

    for (name, content, is_binary) in binary_verdicts() {
        let blob = decide::clean(Some(&vector_key()), &config, b"a.env", &content)
            .expect("a selected path must encrypt")
            .content;
        assert!(looks_encrypted(&blob), "`{name}` was not encrypted at all");

        let (flags, plaintext) = decrypt(&vector_key(), &blob).expect("our own blob");
        let normalised = flags & FLAG_LF_NORMALIZED != 0;
        assert_eq!(
            normalised, !is_binary,
            "`{name}`: the recorded normalisation flag disagrees with the frozen verdict"
        );
        if is_binary {
            assert_eq!(
                plaintext, content,
                "`{name}` was converted despite being binary"
            );
        }
    }
}

#[test]
fn every_vector_costs_exactly_the_overhead() {
    for vector in vectors() {
        let blob = from_hex(&normalise(vector.blob_hex));
        assert_eq!(
            blob.len(),
            vector.plaintext.len() + OVERHEAD,
            "`{}` does not match the documented 38-byte overhead",
            vector.name
        );
    }
}
