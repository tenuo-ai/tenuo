//! Persistent holder identity. Path and environment are caller-owned.

use crate::crypto::{PublicKey, SigningKey};
use std::fmt;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

/// Ed25519 holder key loaded from, or created at, a caller-supplied path.
///
/// The file is hex-encoded secret-key bytes plus a trailing newline.
/// This type does not choose a default path and does not read environment
/// variables.
#[derive(Clone)]
pub struct PersistentIdentity {
    key: SigningKey,
    path: PathBuf,
}

impl PersistentIdentity {
    /// Load an existing key, or generate and persist one if the file is absent.
    ///
    /// Parent directories are created as needed. The write is `*.tmp` then
    /// rename. On Unix the file is `0600`. A corrupt existing file is an error;
    /// it is never overwritten.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref().to_path_buf();
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let key = parse_key(&path, &contents)?;
                tighten_permissions(&path)?;
                Ok(Self { key, path })
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let key = SigningKey::generate();
                persist_key(&path, &key)?;
                Ok(Self { key, path })
            }
            Err(error) => Err(IdentityError::Io {
                path,
                operation: "read",
                source: error,
            }),
        }
    }

    /// In-process key that is not written to disk. For tests and one-shot tools.
    pub fn ephemeral(key: SigningKey) -> Self {
        Self {
            key,
            path: PathBuf::new(),
        }
    }

    /// The holder signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// Corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// Path this identity was loaded from or written to. Empty for [`Self::ephemeral`].
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for PersistentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentIdentity")
            .field("path", &self.path)
            .field("public_key", &self.public_key())
            .finish()
    }
}

fn parse_key(path: &Path, contents: &str) -> Result<SigningKey, IdentityError> {
    let trimmed = contents.trim();
    let bytes = hex::decode(trimmed).map_err(|_| IdentityError::InvalidEncoding {
        path: path.to_path_buf(),
    })?;
    let secret: [u8; 32] =
        bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| IdentityError::InvalidLength {
                path: path.to_path_buf(),
                got: bytes.len(),
            })?;
    Ok(SigningKey::from_bytes(&secret))
}

fn persist_key(path: &Path, key: &SigningKey) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| IdentityError::Io {
                path: parent.to_path_buf(),
                operation: "create directory",
                source,
            })?;
        }
    }

    let tmp = tmp_path(path);
    fs::write(&tmp, format!("{}\n", hex::encode(key.secret_key_bytes()))).map_err(|source| {
        IdentityError::Io {
            path: tmp.clone(),
            operation: "write",
            source,
        }
    })?;
    set_owner_only(&tmp)?;
    fs::rename(&tmp, path).map_err(|source| IdentityError::Io {
        path: path.to_path_buf(),
        operation: "rename",
        source,
    })?;
    set_owner_only(path)?;
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

fn tighten_permissions(path: &Path) -> Result<(), IdentityError> {
    set_owner_only(path)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        IdentityError::Io {
            path: path.to_path_buf(),
            operation: "chmod 0600",
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

/// Failure loading or persisting a holder identity.
#[derive(Debug)]
pub enum IdentityError {
    /// Filesystem operation failed. Includes the path and what was attempted.
    Io {
        /// Path the operation targeted.
        path: PathBuf,
        /// Read, write, rename, chmod, or directory creation.
        operation: &'static str,
        /// Underlying OS error.
        source: io::Error,
    },
    /// The file was not hex.
    InvalidEncoding {
        /// Path of the unreadable file.
        path: PathBuf,
    },
    /// The decoded secret was not 32 bytes.
    InvalidLength {
        /// Path of the unreadable file.
        path: PathBuf,
        /// Decoded length in bytes.
        got: usize,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                path,
                operation,
                source,
            } => write!(
                f,
                "holder identity {operation} failed at {}: {source}",
                path.display()
            ),
            Self::InvalidEncoding { path } => {
                write!(
                    f,
                    "holder identity at {} is not hex-encoded",
                    path.display()
                )
            }
            Self::InvalidLength { path, got } => write!(
                f,
                "holder identity at {} must be 32 bytes, got {got}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidEncoding { .. } | Self::InvalidLength { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_then_reuses_the_same_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("holder.key");
        let first = PersistentIdentity::load_or_generate(&path).unwrap();
        let second = PersistentIdentity::load_or_generate(&path).unwrap();
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(first.path(), path.as_path());
        assert!(path.exists());
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("agent").join("holder.key");
        let identity = PersistentIdentity::load_or_generate(&path).unwrap();
        assert!(path.exists());
        assert_eq!(identity.path(), path.as_path());
    }

    #[test]
    fn rejects_corrupt_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("holder.key");
        fs::write(&path, "not-hex\n").unwrap();
        let err = PersistentIdentity::load_or_generate(&path).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidEncoding { .. }));
        assert!(err.to_string().contains("holder.key"));
    }

    #[test]
    fn rejects_wrong_length() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("holder.key");
        fs::write(&path, "aa\n").unwrap();
        let err = PersistentIdentity::load_or_generate(&path).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidLength { got: 1, .. }));
    }

    #[cfg(unix)]
    #[test]
    fn persisted_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("holder.key");
        PersistentIdentity::load_or_generate(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
