use crate::constraints::ConstraintSet;
use crate::crypto::PublicKey;
use crate::warrant::{TrustLevel, WarrantId, WarrantType};
use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

/// The payload of a warrant (unsigned).
///
/// Refactored to separate file to avoid macro scope issues.
#[derive(Debug, Clone)]
pub struct WarrantPayload {
    /// Schema version for this warrant.
    pub version: u8,
    /// Type of warrant: ISSUER or EXECUTION.
    pub warrant_type: WarrantType,
    /// Unique identifier for this warrant.
    pub id: WarrantId,
    /// Tools: Map of tool_name -> constraint_set.
    ///
    /// This replaces the separate `tools` and `constraints` fields, allowing
    /// for granular, per-tool constraints.
    pub tools: BTreeMap<String, ConstraintSet>,
    /// Authorized holder's public key.
    pub holder: PublicKey,
    /// Issuer's public key.
    pub issuer: PublicKey,
    /// Unix timestamp (seconds) when issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when expires.
    pub expires_at: u64,
    /// Maximum delegation depth (policy limit, decreases on attenuation).
    pub max_depth: u8,
    /// Current delegation depth (0 for root, increments on attenuation).
    pub depth: u32,
    /// Hash of the parent warrant's payload (for tracking/auditing).
    /// Content-addressed linkage to parent.
    pub parent_hash: Option<[u8; 32]>,
    /// Extension data (arbitrary bytes).
    pub extensions: BTreeMap<String, Vec<u8>>,

    // Issuer Warrant Fields
    pub issuable_tools: Option<Vec<String>>,
    pub trust_ceiling: Option<TrustLevel>,
    pub max_issue_depth: Option<u32>,
    pub constraint_bounds: Option<ConstraintSet>,

    // Common Fields
    pub trust_level: Option<TrustLevel>,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
    pub required_approvers: Option<Vec<PublicKey>>,
    pub min_approvals: Option<u32>,
}

// Integer key mapping (wire format):
// 0: version
// 1: id
// 2: warrant_type
// 3: tools
// 4: holder
// 5: issuer
// 6: issued_at
// 7: expires_at
// 8: max_depth
// 9: parent_hash
// 10: extensions
// 11: issuable_tools
// 12: trust_ceiling
// 13: max_issue_depth
// 14: constraint_bounds
// 15: required_approvers
// 16: min_approvals
// 17: trust_level
// 18: depth
// Metadata fields not in authz-critical path (session_id, agent_id)
// are serialized into extensions with reserved keys:
const EXT_KEY_SESSION_ID: &str = "tenuo.session_id";
const EXT_KEY_AGENT_ID: &str = "tenuo.agent_id";

impl Serialize for WarrantPayload {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Prepare extensions with metadata folded in
        let mut extensions = self.extensions.clone();
        if let Some(session) = &self.session_id {
            extensions.insert(EXT_KEY_SESSION_ID.to_string(), session.as_bytes().to_vec());
        }
        if let Some(agent) = &self.agent_id {
            extensions.insert(EXT_KEY_AGENT_ID.to_string(), agent.as_bytes().to_vec());
        }

        // Count fields to serialize
        let mut entries = 12; // required fields 0-10 + depth at 18
        if self.parent_hash.is_none() {
            entries -= 1;
        }
        if extensions.is_empty() {
            entries -= 1;
        }
        if self.issuable_tools.is_some() {
            entries += 1;
        }
        if self.trust_ceiling.is_some() {
            entries += 1;
        }
        if self.max_issue_depth.is_some() {
            entries += 1;
        }
        if self.constraint_bounds.is_some() {
            entries += 1;
        }
        if self.required_approvers.is_some() {
            entries += 1;
        }
        if self.min_approvals.is_some() {
            entries += 1;
        }
        if self.trust_level.is_some() {
            entries += 1;
        }

        let mut map = serializer.serialize_map(Some(entries))?;
        map.serialize_entry(&0u8, &self.version)?;
        map.serialize_entry(&1u8, &self.id)?;
        map.serialize_entry(&2u8, &self.warrant_type)?;
        map.serialize_entry(&3u8, &self.tools)?;
        map.serialize_entry(&4u8, &self.holder)?;
        map.serialize_entry(&5u8, &self.issuer)?;
        map.serialize_entry(&6u8, &self.issued_at)?;
        map.serialize_entry(&7u8, &self.expires_at)?;
        map.serialize_entry(&8u8, &self.max_depth)?;
        if let Some(parent_hash) = &self.parent_hash {
            map.serialize_entry(&9u8, parent_hash)?;
        }
        if !extensions.is_empty() {
            map.serialize_entry(&10u8, &extensions)?;
        }
        if let Some(issuable) = &self.issuable_tools {
            map.serialize_entry(&11u8, issuable)?;
        }
        if let Some(ceiling) = &self.trust_ceiling {
            map.serialize_entry(&12u8, ceiling)?;
        }
        if let Some(max_issue) = &self.max_issue_depth {
            map.serialize_entry(&13u8, max_issue)?;
        }
        if let Some(bounds) = &self.constraint_bounds {
            map.serialize_entry(&14u8, bounds)?;
        }
        if let Some(req) = &self.required_approvers {
            map.serialize_entry(&15u8, req)?;
        }
        if let Some(min) = &self.min_approvals {
            map.serialize_entry(&16u8, min)?;
        }
        if let Some(tl) = &self.trust_level {
            map.serialize_entry(&17u8, tl)?;
        }
        map.serialize_entry(&18u8, &self.depth)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for WarrantPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WPVisitor;

        impl<'de> Visitor<'de> for WPVisitor {
            type Value = WarrantPayload;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("CBOR map of warrant payload with integer keys")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = HashSet::new();

                let mut version = None;
                let mut id = None;
                let mut warrant_type = None;
                let mut tools = None;
                let mut holder = None;
                let mut issuer = None;
                let mut issued_at = None;
                let mut expires_at = None;
                let mut max_depth = None;
                let mut parent_hash = None;
                let mut extensions: BTreeMap<String, Vec<u8>> = BTreeMap::new();
                let mut issuable_tools = None;
                let mut trust_ceiling = None;
                let mut max_issue_depth = None;
                let mut constraint_bounds = None;
                let mut required_approvers = None;
                let mut min_approvals = None;
                let mut trust_level = None;
                let mut depth: Option<u32> = None;

                while let Some(key) = map.next_key::<u8>()? {
                    if !seen.insert(key) {
                        return Err(A::Error::custom(format!("duplicate key {}", key)));
                    }
                    match key {
                        0 => version = Some(map.next_value()?),
                        1 => id = Some(map.next_value()?),
                        2 => warrant_type = Some(map.next_value()?),
                        3 => tools = Some(map.next_value()?),
                        4 => holder = Some(map.next_value()?),
                        5 => issuer = Some(map.next_value()?),
                        6 => issued_at = Some(map.next_value()?),
                        7 => expires_at = Some(map.next_value()?),
                        8 => max_depth = Some(map.next_value()?),
                        9 => parent_hash = map.next_value()?,
                        10 => extensions = map.next_value()?,
                        11 => issuable_tools = map.next_value()?,
                        12 => trust_ceiling = map.next_value()?,
                        13 => max_issue_depth = map.next_value()?,
                        14 => constraint_bounds = map.next_value()?,
                        15 => required_approvers = map.next_value()?,
                        16 => min_approvals = map.next_value()?,
                        17 => trust_level = map.next_value()?,
                        18 => depth = Some(map.next_value()?),
                        _ => {
                            // Spec requires FAIL CLOSED on unknown keys
                            return Err(A::Error::custom(format!(
                                "unknown payload field key {}",
                                key
                            )));
                        }
                    }
                }

                let version = version.ok_or_else(|| A::Error::custom("missing version"))?;
                let id = id.ok_or_else(|| A::Error::custom("missing id"))?;
                let warrant_type =
                    warrant_type.ok_or_else(|| A::Error::custom("missing warrant_type"))?;
                let tools = tools.ok_or_else(|| A::Error::custom("missing tools"))?;
                let holder = holder.ok_or_else(|| A::Error::custom("missing holder"))?;
                let issuer = issuer.ok_or_else(|| A::Error::custom("missing issuer"))?;
                let issued_at = issued_at.ok_or_else(|| A::Error::custom("missing issued_at"))?;
                let expires_at =
                    expires_at.ok_or_else(|| A::Error::custom("missing expires_at"))?;
                let max_depth = max_depth.ok_or_else(|| A::Error::custom("missing max_depth"))?;

                // Extract metadata from extensions
                let mut session_id = None;
                let mut agent_id = None;
                if let Some(bytes) = extensions.remove(EXT_KEY_SESSION_ID) {
                    session_id = String::from_utf8(bytes)
                        .map(Some)
                        .map_err(|e| A::Error::custom(format!("invalid session_id utf8: {}", e)))?;
                }
                if let Some(bytes) = extensions.remove(EXT_KEY_AGENT_ID) {
                    agent_id = String::from_utf8(bytes)
                        .map(Some)
                        .map_err(|e| A::Error::custom(format!("invalid agent_id utf8: {}", e)))?;
                }

                Ok(WarrantPayload {
                    version,
                    warrant_type,
                    id,
                    tools,
                    holder,
                    issuer,
                    issued_at,
                    expires_at,
                    max_depth,
                    depth: depth.unwrap_or(0), // 0 for root warrants
                    parent_hash,
                    extensions,
                    issuable_tools,
                    trust_ceiling,
                    max_issue_depth,
                    constraint_bounds,
                    trust_level,
                    session_id,
                    agent_id,
                    required_approvers,
                    min_approvals,
                })
            }
        }

        deserializer.deserialize_map(WPVisitor)
    }
}
