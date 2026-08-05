//! Reading and writing the repository key on disk.
//!
//! Two shapes, both holding the same 32-byte **master key** — never a cipher
//! key, so a future suite cannot strand either of them:
//!
//! * the binary file in `.git/git-xcrypt/keys/`, which the tool reads on every
//!   filter run and no human ever looks at;
//! * the portable text file [`encode_portable`] produces, which is what
//!   `export-key` writes and `import-key` and `unlock` read. It is text so it
//!   survives a password manager, an email body and a copy-paste, and it names
//!   its `key_id` in the clear so a user can tell two exports apart without
//!   decrypting anything.
//!
//! Both carry their own magic and version, independent of the data format's,
//! because the three evolve for different reasons.

use std::fs;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::{Zeroize as _, Zeroizing};

use crate::format::KEY_ID_LEN;
use crate::key::{MASTER_KEY_LEN, MasterKey};
use crate::{Error, Result};

/// Identifies a key file and keeps it from being mistaken for anything else.
const KEY_FILE_MAGIC: &[u8] = b"\0GITXCRYPTKEY\0";

/// The only key file version written today.
const KEY_FILE_VERSION: u8 = 1;

/// Total length of a key file: magic, version byte, master key.
const KEY_FILE_LEN: usize = KEY_FILE_MAGIC.len() + 1 + MASTER_KEY_LEN;

/// Whether `content` is one of this tool's key files, in either shape.
///
/// For the diff driver, which git hands arbitrary paths and which prints what it
/// reads. A key file carries neither the data magic nor anything else that would
/// stop it going straight to `stdout`, and `git-xcrypt diff <key> > k` would put
/// it in the working tree, one `git add -A` from a commit. Deciding on the
/// content rather than on the location is what makes the refusal hold for an
/// exported copy, for a hard link and whatever the current directory is.
///
/// **It has to recognise exactly what [`decode_portable`] accepts**, which is
/// why both go through [`significant_lines`] rather than each having their own
/// idea of where the file starts. Measured before that: one `# my laptop` line
/// above the header — the annotation a key picks up in a password manager, and
/// a shape this module has a test for — made the header stop being the first
/// byte, so the check missed it and `git-xcrypt diff` printed the repository's
/// master key in base64 with exit code 0. A leading blank line and leading
/// spaces did the same. All three still imported as a working key.
///
/// Content that is not UTF-8 cannot be a portable key at all: [`read_portable`]
/// reads the file as text, so such a file would never be accepted as one.
#[must_use]
pub fn holds_a_key(content: &[u8]) -> bool {
    if content.starts_with(KEY_FILE_MAGIC) {
        return true;
    }
    std::str::from_utf8(content).is_ok_and(|text| {
        significant_lines(text)
            .next()
            .is_some_and(|line| line.starts_with(EXPORT_PREFIX))
    })
}

/// The lines of a portable key file that carry anything.
///
/// Blank lines and `#` comments are skipped and surrounding whitespace comes
/// off, because a key travelling through a password manager or an email body
/// picks all three up. Shared with [`holds_a_key`] deliberately: the parser and
/// the refusal disagreeing about where the file begins is a hole through which
/// the key reaches `stdout`.
fn significant_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Serialises a key into the bytes stored on disk.
///
/// The buffer holds the master key, so it is wrapped in [`Zeroizing`]: without
/// that, `MasterKey`'s own `ZeroizeOnDrop` would protect one copy of the key and
/// leave this one behind on the heap.
fn encode(key: &MasterKey) -> Zeroizing<Vec<u8>> {
    let mut bytes = Vec::with_capacity(KEY_FILE_LEN);
    bytes.extend_from_slice(KEY_FILE_MAGIC);
    bytes.push(KEY_FILE_VERSION);
    bytes.extend_from_slice(key.expose_bytes());
    Zeroizing::new(bytes)
}

/// Parses the bytes of a key file.
fn decode(bytes: &[u8]) -> Result<MasterKey> {
    if bytes.len() != KEY_FILE_LEN || !bytes.starts_with(KEY_FILE_MAGIC) {
        return Err(Error::Format("this is not a git-xcrypt key file".into()));
    }
    let version = bytes[KEY_FILE_MAGIC.len()];
    if version != KEY_FILE_VERSION {
        return Err(Error::Format(format!(
            "key file version {version} needs a newer git-xcrypt"
        )));
    }

    let mut material = [0u8; MASTER_KEY_LEN];
    material.copy_from_slice(&bytes[KEY_FILE_MAGIC.len() + 1..]);
    let key = MasterKey::from_bytes(material);
    material.zeroize();
    Ok(key)
}

/// Writes `key` to `path`, creating parent directories.
///
/// The file is owner-only before any key material reaches it: on Unix the
/// replacement is created with mode `0600` and renamed into place, so neither a
/// fresh file nor one that already existed with looser permissions has a moment
/// in which the key is world readable.
///
/// # Errors
///
/// [`Error::Io`] when the directory or the file cannot be created.
pub fn write(path: &Path, key: &MasterKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_owner_only(path, &encode(key))
}

/// Reads the key stored at `path`.
///
/// # Errors
///
/// [`Error::NoKey`] when the file is absent, [`Error::Format`] when it is not a
/// key file this build understands.
pub fn read(path: &Path) -> Result<MasterKey> {
    // Zeroizing, because this buffer is a full copy of the master key.
    let bytes = match fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Err(Error::NoKey),
        Err(err) => return Err(Error::Io(err)),
    };
    decode(&bytes)
}

/// Creates `path` with owner-only permissions and writes `contents`.
///
/// Shared with `export-key`, which has the same requirement. The replacement is
/// atomic: a key file caught half-written is a repository nobody can ever
/// decrypt again, so there must be no moment in which one exists.
///
/// # Errors
///
/// [`Error::Io`] when the file cannot be created or written.
pub fn write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    crate::atomic::write_owner_only(path, contents)
}

/// Name and version of the portable export format, as its first line begins.
///
/// Its own version, deliberately: this file lives in users' password managers
/// and backups, so it is frozen for reasons that have nothing to do with the
/// data format or with which cipher suite is current.
const EXPORT_PREFIX: &str = "git-xcrypt-key-v";

/// The only portable version written today.
const EXPORT_VERSION: u32 = 1;

/// Renders `key` in the portable text form `export-key` writes.
///
/// Two significant lines: a header naming the format, its version and the
/// `key_id` in hex, then the master key in base64. The buffer is a full copy of
/// the key, hence [`Zeroizing`].
#[must_use]
pub fn encode_portable(key: &MasterKey) -> Zeroizing<String> {
    // Sized from the constants rather than guessed: the `Zeroizing` below only
    // protects this buffer if it is never reallocated, and a reallocation would
    // leave the half-built text — key included — behind on the heap.
    let capacity = EXPORT_PREFIX.len() + 4 + KEY_ID_LEN * 2 + MASTER_KEY_LEN.div_ceil(3) * 4 + 3;
    let mut text = String::with_capacity(capacity);
    text.push_str(EXPORT_PREFIX);
    text.push_str(&EXPORT_VERSION.to_string());
    text.push(' ');
    text.push_str(&crate::format_key_id(&key.key_id()));
    text.push('\n');
    // `encode` allocates a buffer of its own holding the whole key; wrapping the
    // outer string and leaving that one on the heap would protect one copy of
    // two.
    let encoded = Zeroizing::new(BASE64.encode(key.expose_bytes()));
    text.push_str(&encoded);
    text.push('\n');
    debug_assert!(
        text.len() <= capacity,
        "the export buffer grew, so a copy of the key was left on the heap"
    );
    Zeroizing::new(text)
}

/// Parses the portable text form.
///
/// Blank lines and `#` comments are skipped, because a key travelling through a
/// password manager or an email body picks them up. Everything else fails
/// closed: an unknown version, a key of the wrong length, trailing content, or a
/// `key_id` that does not match the material below it — the last of which is how
/// a truncated or hand-edited copy announces itself before it is imported.
///
/// # Errors
///
/// [`Error::Format`] for anything this build cannot read as a key.
pub fn decode_portable(text: &str) -> Result<MasterKey> {
    let mut lines = significant_lines(text);

    let header = lines
        .next()
        .ok_or_else(|| Error::Format("this is not a git-xcrypt key file".into()))?;
    let declared = parse_export_header(header)?;

    let encoded = lines
        .next()
        .ok_or_else(|| Error::Format("the key file has a header but no key".into()))?;
    if lines.next().is_some() {
        return Err(Error::Format(
            "the key file carries more than one key; refusing to guess which one is meant".into(),
        ));
    }

    // Zeroizing: this is the master key in the clear, one decode away.
    let material = Zeroizing::new(BASE64.decode(encoded).map_err(|err| {
        Error::Format(format!(
            "the key in this file is not readable base64: {err}"
        ))
    })?);
    if material.len() != MASTER_KEY_LEN {
        return Err(Error::Format(format!(
            "a repository key is {MASTER_KEY_LEN} bytes; this file holds {}",
            material.len()
        )));
    }

    let mut bytes = [0u8; MASTER_KEY_LEN];
    bytes.copy_from_slice(&material);
    let key = MasterKey::from_bytes(bytes);
    bytes.zeroize();

    if key.key_id() != declared {
        return Err(Error::Format(format!(
            "this key file says it holds key {}, but its key material is {} — \
             it was truncated or edited in transit",
            crate::format_key_id(&declared),
            crate::format_key_id(&key.key_id())
        )));
    }

    Ok(key)
}

/// Reads the `git-xcrypt-key-v<n> <key_id>` line.
fn parse_export_header(header: &str) -> Result<[u8; KEY_ID_LEN]> {
    let rest = header
        .strip_prefix(EXPORT_PREFIX)
        .ok_or_else(|| Error::Format("this is not a git-xcrypt key file".into()))?;
    let (version, key_id) = rest
        .split_once(' ')
        .ok_or_else(|| Error::Format("the key file header names no key".into()))?;

    if version.parse::<u32>().ok() != Some(EXPORT_VERSION) {
        return Err(Error::Format(format!(
            "key file version {version} needs a newer git-xcrypt"
        )));
    }

    parse_key_id(key_id.trim())
}

/// Parses a `key_id` written as sixteen hex digits.
fn parse_key_id(text: &str) -> Result<[u8; KEY_ID_LEN]> {
    if text.len() != KEY_ID_LEN * 2 {
        return Err(Error::Format(format!(
            "`{text}` is not a key fingerprint; expected {} hex digits",
            KEY_ID_LEN * 2
        )));
    }

    let mut key_id = [0u8; KEY_ID_LEN];
    for (index, byte) in key_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::Format(format!("`{text}` is not a key fingerprint")))?;
    }
    Ok(key_id)
}

/// Writes `key` to `path` in the portable form, owner-only.
///
/// # Errors
///
/// [`Error::Io`] when the file cannot be created or written.
pub fn write_portable(path: &Path, key: &MasterKey) -> Result<()> {
    write_owner_only(path, encode_portable(key).as_bytes())
}

/// Reads a key from a portable file.
///
/// # Errors
///
/// [`Error::Usage`] when the file the user named is not there, [`Error::Io`]
/// when it cannot be read, [`Error::Format`] when it is not a key file this
/// build understands.
pub fn read_portable(path: &Path) -> Result<MasterKey> {
    // Zeroizing: the text holds the key, base64 or not.
    let text = match fs::read_to_string(path) {
        Ok(text) => Zeroizing::new(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Usage(format!(
                "{}: no such key file",
                path.display()
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
            return Err(Error::Format(format!(
                "{}: not a git-xcrypt key file — it is not even text",
                path.display()
            )));
        }
        Err(err) => return Err(Error::Io(err)),
    };

    decode_portable(&text).map_err(|err| match err {
        Error::Format(message) => Error::Format(format!("{}: {message}", path.display())),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn a_pre_existing_loose_file_is_narrowed_before_the_key_lands_in_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("default");
        fs::write(&path, b"world readable placeholder").expect("writing must succeed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod must succeed");

        write(&path, &MasterKey::from_bytes([4u8; MASTER_KEY_LEN])).expect("writing must succeed");

        let mode = fs::metadata(&path)
            .expect("the key file")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "an existing key file kept its loose permissions"
        );
    }

    #[test]
    fn every_shape_decode_portable_accepts_is_recognised_as_a_key() {
        // The refusal in the diff driver is content-based, so it has to cover
        // exactly what the parser accepts. It did not: one `#` line above the
        // header moved the header off byte zero, `holds_a_key` said no and
        // `git-xcrypt diff` printed the master key in base64 with exit code 0.
        // Measured, on all three paddings below, each of which still imported.
        let key = MasterKey::from_bytes([41u8; MASTER_KEY_LEN]);
        let exported = encode_portable(&key);
        let mut lines = exported.lines();
        let (header, material) = (lines.next().expect("header"), lines.next().expect("key"));

        for (name, text) in [
            ("as written", exported.to_string()),
            (
                "annotated in a password manager",
                format!("# my laptop, 2026-08-04\n{header}\n{material}\n"),
            ),
            ("a leading blank line", format!("\n{header}\n{material}\n")),
            ("indented by a paste", format!("  {header}\n  {material}\n")),
            (
                "CRLF from an email body",
                format!("{header}\r\n{material}\r\n"),
            ),
        ] {
            assert!(
                decode_portable(&text).is_ok(),
                "`{name}` stopped being a key file, so this test proves nothing"
            );
            assert!(
                holds_a_key(text.as_bytes()),
                "`{name}` is a usable key file that the diff driver would have printed"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_portable_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("exported.key");
        write_portable(&path, &MasterKey::from_bytes([28u8; MASTER_KEY_LEN]))
            .expect("writing must succeed");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "an exported key must not be readable by others"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("default");
        write(&path, &MasterKey::from_bytes([3u8; MASTER_KEY_LEN])).expect("writing must succeed");

        let mode = fs::metadata(&path)
            .expect("the key file must exist")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the key file must not be readable by others"
        );
    }
}
