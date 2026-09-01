//! Enforcement-point revocation tracker: verify, freshness, and persistent floor.

use crate::crypto::PublicKey;
use crate::revocation::SignedRevocationList;
use crate::verification::RevocationSnapshot;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Untrusted material from a provider. Not usable until [`RevocationTracker::accept`].
#[derive(Clone, Debug)]
pub struct RevocationUpdate {
    pub srl: SignedRevocationList,
    pub fetched_at: DateTime<Utc>,
}

/// Persistent monotonic floor: rollback and equivocation survive restart.
pub trait RevocationFloorStore: Send + Sync {
    fn compare_and_set(
        &self,
        issuer: &PublicKey,
        version: u64,
        content_hash: [u8; 32],
    ) -> Result<(), RevocationError>;
}

/// Per-issuer monotonic floor: issuer key bytes to `(version, content_hash)`.
type FloorMap = HashMap<[u8; 32], (u64, [u8; 32])>;

/// In-memory floor. Development and tests only — not a production default.
pub struct InMemoryFloorStore {
    floors: Mutex<FloorMap>,
}

impl InMemoryFloorStore {
    pub fn for_development() -> Self {
        Self {
            floors: Mutex::new(HashMap::new()),
        }
    }
}

impl RevocationFloorStore for InMemoryFloorStore {
    fn compare_and_set(
        &self,
        issuer: &PublicKey,
        version: u64,
        content_hash: [u8; 32],
    ) -> Result<(), RevocationError> {
        let mut floors = self
            .floors
            .lock()
            .map_err(|_| RevocationError::Unavailable)?;
        apply_floor(&mut floors, issuer, version, content_hash)
    }
}

/// JSON file of per-issuer `(version, content_hash)`. Survives process restart.
pub struct FileFloorStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileFloorStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RevocationError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| RevocationError::Unavailable)?;
        }
        if !path.exists() {
            write_floors(&path, &HashMap::new())?;
        }
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }
}

impl RevocationFloorStore for FileFloorStore {
    fn compare_and_set(
        &self,
        issuer: &PublicKey,
        version: u64,
        content_hash: [u8; 32],
    ) -> Result<(), RevocationError> {
        let _guard = self.lock.lock().map_err(|_| RevocationError::Unavailable)?;
        let mut floors = read_floors(&self.path)?;
        apply_floor(&mut floors, issuer, version, content_hash)?;
        write_floors(&self.path, &floors)
    }
}

fn apply_floor(
    floors: &mut HashMap<[u8; 32], (u64, [u8; 32])>,
    issuer: &PublicKey,
    version: u64,
    content_hash: [u8; 32],
) -> Result<(), RevocationError> {
    let key = issuer.to_bytes();
    match floors.get(&key) {
        None => {
            floors.insert(key, (version, content_hash));
            Ok(())
        }
        Some(&(current, current_hash)) => {
            if version < current {
                return Err(RevocationError::Rollback {
                    current,
                    attempted: version,
                });
            }
            if version == current && current_hash != content_hash {
                return Err(RevocationError::Equivocation { version });
            }
            floors.insert(key, (version, content_hash));
            Ok(())
        }
    }
}

fn read_floors(path: &Path) -> Result<FloorMap, RevocationError> {
    let raw = fs::read_to_string(path).map_err(|_| RevocationError::Unavailable)?;
    let encoded: HashMap<String, (u64, String)> =
        serde_json::from_str(&raw).map_err(|_| RevocationError::Unavailable)?;
    let mut out = HashMap::new();
    for (issuer_hex, (version, hash_hex)) in encoded {
        let issuer = decode_hex32(&issuer_hex)?;
        let hash = decode_hex32(&hash_hex)?;
        out.insert(issuer, (version, hash));
    }
    Ok(out)
}

fn write_floors(
    path: &Path,
    floors: &HashMap<[u8; 32], (u64, [u8; 32])>,
) -> Result<(), RevocationError> {
    let encoded: HashMap<String, (u64, String)> = floors
        .iter()
        .map(|(issuer, (version, hash))| (hex::encode(issuer), (*version, hex::encode(hash))))
        .collect();
    let json = serde_json::to_string(&encoded).map_err(|_| RevocationError::Unavailable)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json).map_err(|_| RevocationError::Unavailable)?;
    fs::rename(&tmp, path).map_err(|_| RevocationError::Unavailable)
}

fn decode_hex32(value: &str) -> Result<[u8; 32], RevocationError> {
    let bytes = hex::decode(value).map_err(|_| RevocationError::Unavailable)?;
    bytes.try_into().map_err(|_| RevocationError::Unavailable)
}

/// Per-issuer monotonic revocation state. Core-owned; providers cannot mint snapshots.
pub struct RevocationTracker {
    trusted_issuers: Vec<PublicKey>,
    max_age: Duration,
    clock_tolerance: Duration,
    floors: Arc<dyn RevocationFloorStore>,
    latest: Mutex<Option<Arc<RevocationSnapshot>>>,
}

impl RevocationTracker {
    pub fn new(
        trusted_issuers: Vec<PublicKey>,
        max_age: Duration,
        clock_tolerance: Duration,
        floors: Arc<dyn RevocationFloorStore>,
    ) -> Result<Self, RevocationError> {
        if trusted_issuers.is_empty() {
            return Err(RevocationError::EmptyTrust);
        }
        if max_age.is_zero() {
            return Err(RevocationError::InvalidMaxAge);
        }
        Ok(Self {
            trusted_issuers,
            max_age,
            clock_tolerance,
            floors,
            latest: Mutex::new(None),
        })
    }

    /// Explicitly named development constructor. Not the production default.
    pub fn with_in_memory_floors(
        trusted_issuers: Vec<PublicKey>,
        max_age: Duration,
        clock_tolerance: Duration,
    ) -> Result<Self, RevocationError> {
        Self::new(
            trusted_issuers,
            max_age,
            clock_tolerance,
            Arc::new(InMemoryFloorStore::for_development()),
        )
    }

    pub fn accept(
        &self,
        update: RevocationUpdate,
        as_of: DateTime<Utc>,
    ) -> Result<Arc<RevocationSnapshot>, RevocationError> {
        let issuer = update.srl.issuer().clone();
        if !self.trusted_issuers.iter().any(|key| key == &issuer) {
            return Err(RevocationError::UntrustedIssuer);
        }
        update
            .srl
            .verify(&issuer)
            .map_err(|_| RevocationError::SignatureInvalid)?;

        let skew = chrono::Duration::from_std(self.clock_tolerance)
            .unwrap_or_else(|_| chrono::Duration::seconds(0));
        if update.fetched_at > as_of + skew {
            return Err(RevocationError::FetchedInFuture);
        }

        let fresh_until = update.fetched_at
            + chrono::Duration::from_std(self.max_age)
                .unwrap_or_else(|_| chrono::Duration::seconds(0));
        if as_of > fresh_until {
            return Err(RevocationError::Stale);
        }

        let content_hash = content_hash(&update.srl);
        self.floors
            .compare_and_set(&issuer, update.srl.version(), content_hash)?;

        let snapshot = Arc::new(RevocationSnapshot::from_tracker(
            update.srl,
            update.fetched_at,
            fresh_until,
        ));
        *self
            .latest
            .lock()
            .map_err(|_| RevocationError::Unavailable)? = Some(snapshot.clone());
        Ok(snapshot)
    }

    /// Last accepted snapshot, denied if missing or stale at `as_of`.
    pub fn latest(&self, as_of: DateTime<Utc>) -> Result<Arc<RevocationSnapshot>, RevocationError> {
        let guard = self
            .latest
            .lock()
            .map_err(|_| RevocationError::Unavailable)?;
        let snapshot = guard.as_ref().ok_or(RevocationError::Unavailable)?;
        if !snapshot.is_fresh_at(as_of) {
            return Err(RevocationError::Stale);
        }
        Ok(snapshot.clone())
    }
}

fn content_hash(srl: &SignedRevocationList) -> [u8; 32] {
    let mut ids: Vec<&str> = srl.revoked_ids().iter().map(String::as_str).collect();
    ids.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(srl.version().to_be_bytes());
    for id in ids {
        hasher.update(id.as_bytes());
        hasher.update([0]);
    }
    hasher.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationError {
    EmptyTrust,
    InvalidMaxAge,
    UntrustedIssuer,
    SignatureInvalid,
    FetchedInFuture,
    Stale,
    Rollback { current: u64, attempted: u64 },
    Equivocation { version: u64 },
    Unavailable,
}

impl std::fmt::Display for RevocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTrust => write!(f, "revocation tracker has no trusted issuers"),
            Self::InvalidMaxAge => write!(f, "revocation max_age must be greater than zero"),
            Self::UntrustedIssuer => write!(f, "revocation issuer is not trusted"),
            Self::SignatureInvalid => write!(f, "revocation list signature is invalid"),
            Self::FetchedInFuture => write!(f, "revocation fetch time is in the future"),
            Self::Stale => write!(f, "revocation snapshot is stale"),
            Self::Rollback { current, attempted } => {
                write!(f, "revocation version {attempted} rolls back {current}")
            }
            Self::Equivocation { version } => {
                write!(f, "revocation version {version} changed content")
            }
            Self::Unavailable => write!(f, "revocation state is unavailable"),
        }
    }
}

impl std::error::Error for RevocationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use std::time::Duration;

    fn srl(issuer: &SigningKey, version: u64, ids: &[&str]) -> SignedRevocationList {
        let mut builder = SignedRevocationList::builder().version(version);
        for id in ids {
            builder = builder.revoke(*id);
        }
        builder.build(issuer).unwrap()
    }

    #[test]
    fn accept_then_rollback_and_equivocation() {
        let issuer = SigningKey::generate();
        let tracker = RevocationTracker::with_in_memory_floors(
            vec![issuer.public_key()],
            Duration::from_secs(60),
            Duration::from_secs(5),
        )
        .unwrap();
        let now = Utc::now();
        tracker
            .accept(
                RevocationUpdate {
                    srl: srl(&issuer, 2, &["a"]),
                    fetched_at: now,
                },
                now,
            )
            .unwrap();

        let rollback = tracker.accept(
            RevocationUpdate {
                srl: srl(&issuer, 1, &["a"]),
                fetched_at: now,
            },
            now,
        );
        assert!(matches!(
            rollback,
            Err(RevocationError::Rollback {
                current: 2,
                attempted: 1
            })
        ));

        let equiv = tracker.accept(
            RevocationUpdate {
                srl: srl(&issuer, 2, &["b"]),
                fetched_at: now,
            },
            now,
        );
        assert!(matches!(
            equiv,
            Err(RevocationError::Equivocation { version: 2 })
        ));
    }

    #[test]
    fn file_floor_survives_restart() {
        let dir = std::env::temp_dir().join(format!("tenuo-floor-{}", uuid::Uuid::new_v4()));
        let path = dir.join("floors.json");
        let issuer = SigningKey::generate();
        let now = Utc::now();

        let first = RevocationTracker::new(
            vec![issuer.public_key()],
            Duration::from_secs(60),
            Duration::from_secs(5),
            Arc::new(FileFloorStore::open(&path).unwrap()),
        )
        .unwrap();
        first
            .accept(
                RevocationUpdate {
                    srl: srl(&issuer, 3, &["x"]),
                    fetched_at: now,
                },
                now,
            )
            .unwrap();
        drop(first);

        let second = RevocationTracker::new(
            vec![issuer.public_key()],
            Duration::from_secs(60),
            Duration::from_secs(5),
            Arc::new(FileFloorStore::open(&path).unwrap()),
        )
        .unwrap();
        let rollback = second.accept(
            RevocationUpdate {
                srl: srl(&issuer, 2, &["x"]),
                fetched_at: now,
            },
            now,
        );
        assert!(matches!(rollback, Err(RevocationError::Rollback { .. })));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn untrusted_and_future_fetch_denied() {
        let issuer = SigningKey::generate();
        let other = SigningKey::generate();
        let tracker = RevocationTracker::with_in_memory_floors(
            vec![issuer.public_key()],
            Duration::from_secs(30),
            Duration::from_secs(0),
        )
        .unwrap();
        let now = Utc::now();
        assert_eq!(
            tracker
                .accept(
                    RevocationUpdate {
                        srl: srl(&other, 1, &[]),
                        fetched_at: now,
                    },
                    now,
                )
                .err()
                .unwrap(),
            RevocationError::UntrustedIssuer
        );
        assert_eq!(
            tracker
                .accept(
                    RevocationUpdate {
                        srl: srl(&issuer, 1, &[]),
                        fetched_at: now + chrono::Duration::seconds(30),
                    },
                    now,
                )
                .err()
                .unwrap(),
            RevocationError::FetchedInFuture
        );
    }
}
