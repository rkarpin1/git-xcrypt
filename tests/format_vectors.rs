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
//!
//! **Three formats are frozen here, not one.** `zalozenia.md` §Zarządzanie
//! kluczami says the key file is frozen "as hard as the data format, because it
//! sits in users' backups", and until these vectors existed nothing held it to
//! that. Measured against the whole suite: bumping `KEY_FILE_VERSION` from 1 to
//! 2 — which makes every key file already on disk unreadable — and swapping the
//! export's base64 alphabet for the URL-safe one — which makes every key in a
//! password manager fail to import — both left all 392 tests green.

use git_xcrypt::config::Config;
use git_xcrypt::crypto::{decrypt, encrypt};
use git_xcrypt::decide;
use git_xcrypt::eol::looks_binary;
use git_xcrypt::format::{FLAG_LF_NORMALIZED, OVERHEAD, looks_encrypted};
use git_xcrypt::key::{MASTER_KEY_LEN, MasterKey};
use git_xcrypt::keyfile;

/// The key every vector below was produced with.
///
/// A published constant, not a secret: it is spelled out in this file, the
/// ciphertext vectors below are its output, and the same value already sits in
/// `src/crypto.rs`. "Never commit a key" is about keys that open something.
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
        // A trailing SUB — the DOS end-of-file marker — is the one control byte
        // git forgives after the fact: `gather_stats` ends with
        // `if (size >= 1 && buf[size-1] == '\032') stats->nonprintable--;`.
        // Measured on git 2.55 with `* text=auto`: `a\r\n\x1a` is stored as
        // `61 0a 1a`, so git normalised the CRLF and called the file text.
        ("a trailing SUB", b"a\r\n\x1a".to_vec(), false),
        // Only the last byte, and only one of them. Measured: `a\r\n\x1a\x1a`
        // keeps its CR in the blob, so git calls it binary.
        ("two trailing SUBs", b"a\r\n\x1a\x1a".to_vec(), true),
        // In the middle it counts like any other control byte. Measured:
        // `a\x1ab\r\n` keeps its CR.
        ("a SUB in the middle", b"a\x1ab\r\n".to_vec(), true),
        // The forgiveness is worth exactly one byte, no more. Measured:
        // `a\x01\r\n\x1a` keeps its CR — the SUB cancels itself, not the 0x01.
        (
            "a trailing SUB and one control",
            b"a\x01\r\n\x1a".to_vec(),
            true,
        ),
        // The ratio boundary with the correction applied, both sides of it.
        // Measured: 128 printable with `\x01` and a trailing SUB is text,
        // 127 printable is binary.
        (
            "128 printable, one control, trailing SUB",
            {
                let mut v = vec![b'A'; 128];
                v.extend_from_slice(b"\x01\r\n\x1a");
                v
            },
            false,
        ),
        (
            "127 printable, one control, trailing SUB",
            {
                let mut v = vec![b'A'; 127];
                v.extend_from_slice(b"\x01\r\n\x1a");
                v
            },
            true,
        ),
        // Nothing but a SUB: the correction takes the only non-printable away
        // and must not go below zero. Measured through a checkout with
        // `core.autocrlf=true`: `\n\x1a` comes back as `\r\n\x1a`, so text.
        ("LF then SUB", b"\n\x1a".to_vec(), false),
        ("a control, LF, then SUB", b"\x01\n\x1a".to_vec(), true),
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

/// The key file in `.git/git-xcrypt/keys/`, byte for byte.
///
/// `MAGIC || version || 32-byte master key`. Frozen because it is what a user's
/// existing repository holds: change any of it and `unlock` on a machine that
/// never upgraded stops working, or — worse — a key file written by a newer
/// build reads as "not a git-xcrypt key file" and `init` offers to make a
/// second key.
const KEY_FILE_HEX: &str = "004749545843525950544b455900 01 \
                            2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\
                            2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";

/// The portable form `export-key` writes.
///
/// Frozen for a reason the binary form does not have: this file leaves the
/// machine. It lives in password managers, in backups and in email bodies, and
/// the build that reads it back may be years older or newer than the one that
/// wrote it. The base64 alphabet is part of the contract, not an implementation
/// detail — the URL-safe one produces a file no shipped build can import.
const EXPORT_TEXT: &str = "git-xcrypt-key-v1 fd2f0a5c2d19a55b\n\
                           KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=\n";

/// A second export, whose base64 uses the two characters the alphabets disagree
/// about.
///
/// [`vector_key`] is every byte `0x2a`, and its base64 happens to contain
/// neither `+` nor `/` — so the vector above is blind to the alphabet, and
/// swapping in the URL-safe engine left it green. This key exercises both, which
/// is the only part of the export a careless dependency bump can change without
/// touching a line of our own code.
const ALPHABET_KEY: [u8; MASTER_KEY_LEN] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

/// What [`ALPHABET_KEY`] must always export as.
const ALPHABET_EXPORT: &str = "git-xcrypt-key-v1 4964bf31d42512be\n\
                               4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8=\n";

#[test]
fn the_key_file_still_holds_the_frozen_bytes() {
    let dir = tempfile::TempDir::new().expect("temporary directory");
    let path = dir.path().join("default");
    keyfile::write(&path, &vector_key()).expect("writing the key must succeed");

    assert_eq!(
        to_hex(&std::fs::read(&path).expect("reading the key")),
        normalise(KEY_FILE_HEX),
        "the key file format changed — every key file already on disk, and every \
         backup of one, stops being readable by this build"
    );
}

#[test]
fn the_frozen_key_file_still_reads_back() {
    // The direction that matters to a user who upgrades: a key file written by
    // an older build has to keep opening.
    let dir = tempfile::TempDir::new().expect("temporary directory");
    let path = dir.path().join("default");
    std::fs::write(&path, from_hex(&normalise(KEY_FILE_HEX))).expect("writing");

    let key = keyfile::read(&path).expect("a frozen key file must still read");
    assert_eq!(key.expose_bytes(), vector_key().expose_bytes());
    assert_eq!(key.key_id(), vector_key().key_id());
}

#[test]
fn the_portable_export_still_holds_the_frozen_text() {
    assert_eq!(
        *keyfile::encode_portable(&vector_key()),
        EXPORT_TEXT,
        "the portable key format changed — every key a user carried to another \
         machine, or filed in a password manager, stops importing"
    );
}

#[test]
fn the_frozen_portable_export_still_imports() {
    let key = keyfile::decode_portable(EXPORT_TEXT).expect("a frozen export must still import");
    assert_eq!(key.expose_bytes(), vector_key().expose_bytes());
}

#[test]
fn the_export_still_uses_the_frozen_base64_alphabet() {
    let key = MasterKey::from_bytes(ALPHABET_KEY);
    assert_eq!(
        *keyfile::encode_portable(&key),
        ALPHABET_EXPORT,
        "the export's base64 alphabet changed — every key already in a password \
         manager stops importing, and nothing else in this suite notices"
    );
    let back =
        keyfile::decode_portable(ALPHABET_EXPORT).expect("a frozen export must still import");
    assert_eq!(back.expose_bytes(), &ALPHABET_KEY);
}

#[test]
fn the_key_id_in_a_file_header_is_the_one_the_key_file_names() {
    // The two formats meet here: `export-key` prints this fingerprint for a
    // human to match against, and every encrypted file carries it at offset 14.
    // A change to either derivation that left both self-consistent would still
    // be caught by the vectors, but this says out loud that they are one value.
    let blob = from_hex(&normalise(vectors()[0].blob_hex));
    assert_eq!(&blob[14..22], &vector_key().key_id());
    assert!(EXPORT_TEXT.contains(&git_xcrypt::format_key_id(&vector_key().key_id())));
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
