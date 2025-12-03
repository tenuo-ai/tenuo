use std::collections::HashSet;
use crate::error::{Error, Result};

/// A list of revoked warrant IDs.
///
/// This structure is used by the Data Plane and Authorizer to reject
/// warrants that have been explicitly revoked before their expiration.
#[derive(Debug, Clone, Default)]
pub struct RevocationList {
    revoked_ids: HashSet<String>,
}

impl RevocationList {
    /// Create a new, empty revocation list.
    pub fn new() -> Self {
        Self {
            revoked_ids: HashSet::new(),
        }
    }

    /// Add a warrant ID to the revocation list.
    pub fn revoke(&mut self, warrant_id: impl Into<String>) {
        self.revoked_ids.insert(warrant_id.into());
    }

    /// Check if a warrant ID is revoked.
    pub fn is_revoked(&self, warrant_id: &str) -> bool {
        self.revoked_ids.contains(warrant_id)
    }

    /// Import a list of revoked IDs.
    pub fn import(&mut self, ids: Vec<String>) {
        for id in ids {
            self.revoked_ids.insert(id);
        }
    }
}
