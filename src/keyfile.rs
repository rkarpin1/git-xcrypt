//! Reading and writing the repository key on disk.
//!
//! The file carries its own magic and version, independent of the data format's,
//! because the two evolve for different reasons. It holds the 32-byte master
//! key — never a cipher key — so a future suite cannot strand it.

use std::fs;
use std::path::Path;

use zeroize::{Zeroize as _, Zeroizing};

use crate::key::{MASTER_KEY_LEN, MasterKey};
use crate::{Error, Result};

/// Identifies a key file and keeps it from being mistaken for anything else.
const KEY_FILE_MAGIC: &[u8] = b"\0GITXCRYPTKEY\0";

/// The only key file version written today.
const KEY_FILE_VERSION: u8 = 1;

/// Total length of a key file: magic, version byte, master key.
const KEY_FILE_LEN: usize = KEY_FILE_MAGIC.len() + 1 + MASTER_KEY_LEN;

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
/// The file is owner-only before any key material reaches it: on Unix it is
/// created with mode `0600`, and an already existing file — where the creation
/// mode would be ignored — is narrowed straight after opening and before the
/// first write. Either way there is no window in which the key is world
/// readable.
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
/// Shared with `export-key`, which has the same requirement.
///
/// # Errors
///
/// [`Error::Io`] when the file cannot be created or written.
pub fn write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;

    // `mode` above applies only when the file is created. A key file that
    // already existed keeps whatever permissions it had, so it is narrowed
    // here — before a single byte of key material is written into it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(contents)?;
    file.sync_all()?;

    // On Windows the mode above does not exist. Inheriting the directory ACL is
    // the same protection git itself gives `.git/config`, and `.git/` is where
    // this file lives — but it is weaker than `0600` and is recorded as such in
    // `context/foundation/zalozenia.md`.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn a_key_survives_a_round_trip() {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("keys").join("default");
        let key = MasterKey::from_bytes([9u8; MASTER_KEY_LEN]);

        write(&path, &key).expect("writing the key must succeed");
        let read_back = read(&path).expect("reading the key must succeed");

        assert_eq!(read_back.expose_bytes(), key.expose_bytes());
        assert_eq!(read_back.key_id(), key.key_id());
    }

    #[test]
    fn a_missing_key_is_reported_as_missing_not_as_io() {
        let dir = TempDir::new().expect("temporary directory");
        match read(&dir.path().join("absent")) {
            Err(Error::NoKey) => {}
            Err(other) => panic!("expected NoKey, got {other:?}"),
            Ok(_) => panic!("reading an absent key must not succeed"),
        }
    }

    #[test]
    fn a_foreign_file_is_refused() {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("not-a-key");
        fs::write(&path, b"just some bytes").expect("writing must succeed");
        assert!(read(&path).is_err());
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let dir = TempDir::new().expect("temporary directory");
        let path = dir.path().join("future");
        let mut bytes = encode(&MasterKey::from_bytes([1u8; MASTER_KEY_LEN]));
        bytes[KEY_FILE_MAGIC.len()] = KEY_FILE_VERSION + 1;
        fs::write(&path, &bytes).expect("writing must succeed");
        assert!(read(&path).is_err());
    }

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
