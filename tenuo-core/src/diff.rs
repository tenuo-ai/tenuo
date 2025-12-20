//! Delegation diff computation for audit and preview.
//!
//! This module provides types and functions for computing the differences
//! between a parent warrant and a proposed child warrant during attenuation.
//! This is useful for:
//! - Previewing changes before delegation
//! - Audit trails showing exactly what changed
//! - SIEM integration for security monitoring

use crate::constraints::Constraint;
use crate::warrant::{TrustLevel, Warrant};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of change between parent and child values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    /// No change.
    Unchanged,
    /// Value was added (not present in parent).
    Added,
    /// Value was removed (present in parent, not in child).
    Removed,
    /// Constraint was narrowed (more restrictive).
    Narrowed,
    /// TTL was reduced.
    Reduced,
    /// TTL was increased (should not happen in valid attenuation).
    Increased,
    /// Trust level was demoted (lower trust).
    Demoted,
    /// Trust level was promoted (should not happen in valid attenuation).
    Promoted,
    /// Tools were dropped.
    Dropped,
}

impl ChangeType {
    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeType::Unchanged => "unchanged",
            ChangeType::Added => "added",
            ChangeType::Removed => "removed",
            ChangeType::Narrowed => "narrowed",
            ChangeType::Reduced => "reduced",
            ChangeType::Increased => "increased",
            ChangeType::Demoted => "demoted",
            ChangeType::Promoted => "promoted",
            ChangeType::Dropped => "dropped",
        }
    }
}

/// Diff for tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsDiff {
    /// Tools in parent warrant.
    pub parent_tools: Vec<String>,
    /// Tools in child warrant.
    pub child_tools: Vec<String>,
    /// Tools kept in child.
    pub kept: Vec<String>,
    /// Tools dropped from parent.
    pub dropped: Vec<String>,
}

impl ToolsDiff {
    /// Create a new tools diff.
    pub fn new(parent_tools: Vec<String>, child_tools: Vec<String>) -> Self {
        let kept: Vec<String> = child_tools
            .iter()
            .filter(|t| parent_tools.contains(t))
            .cloned()
            .collect();
        let dropped: Vec<String> = parent_tools
            .iter()
            .filter(|t| !child_tools.contains(t))
            .cloned()
            .collect();

        Self {
            parent_tools,
            child_tools,
            kept,
            dropped,
        }
    }

    /// Check if any tools were dropped.
    pub fn has_changes(&self) -> bool {
        !self.dropped.is_empty()
    }
}

/// Diff for a single constraint field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintDiff {
    /// Field name.
    pub field: String,
    /// Parent constraint (if any).
    pub parent_constraint: Option<Constraint>,
    /// Child constraint (if any).
    pub child_constraint: Option<Constraint>,
    /// Type of change.
    pub change: ChangeType,
}

impl ConstraintDiff {
    /// Create a new constraint diff.
    pub fn new(
        field: String,
        parent_constraint: Option<Constraint>,
        child_constraint: Option<Constraint>,
    ) -> Self {
        let change = match (&parent_constraint, &child_constraint) {
            (None, Some(_)) => ChangeType::Added,
            (Some(_), None) => ChangeType::Removed,
            (Some(p), Some(c)) if p != c => ChangeType::Narrowed,
            _ => ChangeType::Unchanged,
        };

        Self {
            field,
            parent_constraint,
            child_constraint,
            change,
        }
    }
}

/// Diff for TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlDiff {
    /// Parent TTL in seconds (remaining).
    pub parent_ttl_seconds: Option<i64>,
    /// Child TTL in seconds.
    pub child_ttl_seconds: Option<i64>,
    /// Type of change.
    pub change: ChangeType,
}

impl TtlDiff {
    /// Create a new TTL diff.
    pub fn new(parent_ttl_seconds: Option<i64>, child_ttl_seconds: Option<i64>) -> Self {
        let change = match (parent_ttl_seconds, child_ttl_seconds) {
            (Some(p), Some(c)) if c < p => ChangeType::Reduced,
            (Some(p), Some(c)) if c > p => ChangeType::Increased,
            _ => ChangeType::Unchanged,
        };

        Self {
            parent_ttl_seconds,
            child_ttl_seconds,
            change,
        }
    }
}

/// Diff for trust level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDiff {
    /// Parent trust level.
    pub parent_trust: Option<TrustLevel>,
    /// Child trust level.
    pub child_trust: Option<TrustLevel>,
    /// Type of change.
    pub change: ChangeType,
}

impl TrustDiff {
    /// Create a new trust diff.
    pub fn new(parent_trust: Option<TrustLevel>, child_trust: Option<TrustLevel>) -> Self {
        let change = match (parent_trust, child_trust) {
            (Some(p), Some(c)) if c < p => ChangeType::Demoted,
            (Some(p), Some(c)) if c > p => ChangeType::Promoted,
            _ => ChangeType::Unchanged,
        };

        Self {
            parent_trust,
            child_trust,
            change,
        }
    }
}

/// Diff for delegation depth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepthDiff {
    /// Parent depth.
    pub parent_depth: u32,
    /// Child depth.
    pub child_depth: u32,
    /// Whether child is terminal (depth 0 remaining or at max).
    pub is_terminal: bool,
}

impl DepthDiff {
    /// Create a new depth diff.
    pub fn new(parent_depth: u32, child_depth: u32, max_depth: Option<u32>) -> Self {
        let is_terminal = max_depth.map(|m| child_depth >= m).unwrap_or(false);
        Self {
            parent_depth,
            child_depth,
            is_terminal,
        }
    }
}

/// Complete diff between parent and child warrant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationDiff {
    /// Parent warrant ID.
    pub parent_warrant_id: String,
    /// Child warrant ID (None if not yet delegated).
    pub child_warrant_id: Option<String>,
    /// Timestamp of diff computation.
    pub timestamp: DateTime<Utc>,
    /// Tools diff.
    pub tools: ToolsDiff,
    /// Capability diffs by tool.
    pub capabilities: HashMap<String, HashMap<String, ConstraintDiff>>,
    /// TTL diff.
    pub ttl: TtlDiff,
    /// Trust diff.
    pub trust: TrustDiff,
    /// Depth diff.
    pub depth: DepthDiff,
    /// Intent/purpose for this delegation.
    pub intent: Option<String>,
}

impl DelegationDiff {
    /// Convert to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Generate human-readable diff output.
    pub fn to_human(&self) -> String {
        let mut lines = Vec::new();
        let width = 68;

        // Header
        lines.push(format!("╔{}╗", "═".repeat(width)));
        lines.push(format!(
            "║  DELEGATION DIFF{:width$}║",
            "",
            width = width - 17
        ));

        let child_id = self.child_warrant_id.as_deref().unwrap_or("(pending)");
        let header = format!(
            "  Parent: {} → Child: {}",
            &self.parent_warrant_id, child_id
        );
        let padding = width.saturating_sub(header.len());
        lines.push(format!("║{}{:padding$}║", header, "", padding = padding));

        lines.push(format!("╠{}╣", "═".repeat(width)));
        lines.push(format!("║{:width$}║", "", width = width));

        // Tools section
        lines.push(format!("║  TOOLS{:width$}║", "", width = width - 7));
        for tool in &self.tools.child_tools {
            let line = format!("    ✓ {}", tool);
            let padding = width.saturating_sub(line.len());
            lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
        }
        for tool in &self.tools.dropped {
            let line = format!("    ✗ {}      DROPPED", tool);
            let padding = width.saturating_sub(line.len());
            lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
        }
        lines.push(format!("║{:width$}║", "", width = width));

        // Capabilities section
        if !self.capabilities.is_empty() {
            lines.push(format!("║  CAPABILITIES{:width$}║", "", width = width - 14));
            for (tool, tool_constraints) in &self.capabilities {
                let line = format!("    TOOL: {}", tool);
                let padding = width.saturating_sub(line.len());
                lines.push(format!("║{}{:padding$}║", line, "", padding = padding));

                for (field, diff) in tool_constraints {
                    let line = format!("      {}", field);
                    let padding = width.saturating_sub(line.len());
                    lines.push(format!("║{}{:padding$}║", line, "", padding = padding));

                    if let Some(ref pc) = diff.parent_constraint {
                        let line = format!("        parent: {:?}", pc);
                        let padding = width.saturating_sub(line.len());
                        lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
                    }
                    if let Some(ref cc) = diff.child_constraint {
                        let line = format!("        child:  {:?}", cc);
                        let padding = width.saturating_sub(line.len());
                        lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
                    }
                    let line = format!("        change: {}", diff.change.as_str().to_uppercase());
                    let padding = width.saturating_sub(line.len());
                    lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
                }
            }
            lines.push(format!("║{:width$}║", "", width = width));
        }

        // TTL section
        lines.push(format!("║  TTL{:width$}║", "", width = width - 5));
        if let Some(parent_ttl) = self.ttl.parent_ttl_seconds {
            let line = format!("    parent: {}s remaining", parent_ttl);
            let padding = width.saturating_sub(line.len());
            lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
        }
        if let Some(child_ttl) = self.ttl.child_ttl_seconds {
            let line = format!("    child:  {}s", child_ttl);
            let padding = width.saturating_sub(line.len());
            lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
        }
        if self.ttl.change != ChangeType::Unchanged {
            let line = format!("    change: {}", self.ttl.change.as_str().to_uppercase());
            let padding = width.saturating_sub(line.len());
            lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
        }
        lines.push(format!("║{:width$}║", "", width = width));

        // Trust section
        lines.push(format!("║  TRUST{:width$}║", "", width = width - 7));
        if let Some(ref pt) = self.trust.parent_trust {
            let line = format!("    parent: {:?}", pt);
            let padding = width.saturating_sub(line.len());
            lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
        }
        if let Some(ref ct) = self.trust.child_trust {
            let line = format!("    child:  {:?}", ct);
            let padding = width.saturating_sub(line.len());
            lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
        }
        if self.trust.change != ChangeType::Unchanged {
            let line = format!("    change: {}", self.trust.change.as_str().to_uppercase());
            let padding = width.saturating_sub(line.len());
            lines.push(format!("║{}{:padding$}║", line, "", padding = padding));
        }
        lines.push(format!("║{:width$}║", "", width = width));

        // Depth section
        lines.push(format!("║  DEPTH{:width$}║", "", width = width - 7));
        let line = format!("    parent: {}", self.depth.parent_depth);
        let padding = width.saturating_sub(line.len());
        lines.push(format!("║{}{:padding$}║", line, "", padding = padding));

        let terminal_str = if self.depth.is_terminal {
            "(terminal)"
        } else {
            "(non-terminal)"
        };
        let line = format!("    child:  {} {}", self.depth.child_depth, terminal_str);
        let padding = width.saturating_sub(line.len());
        lines.push(format!("║{}{:padding$}║", line, "", padding = padding));

        // Footer
        lines.push(format!("╚{}╝", "═".repeat(width)));

        lines.join("\n")
    }

    /// Generate SIEM-compatible JSON output.
    pub fn to_siem_json(&self) -> Result<String, serde_json::Error> {
        let mut deltas = Vec::new();

        // Tools dropped
        if !self.tools.dropped.is_empty() {
            deltas.push(serde_json::json!({
                "field": "tools",
                "change": "dropped",
                "value": self.tools.dropped
            }));
        }

        // Capability changes
        for (tool, tool_constraints) in &self.capabilities {
            for (field, diff) in tool_constraints {
                if diff.change != ChangeType::Unchanged {
                    let mut delta = serde_json::json!({
                        "field": format!("capabilities.{}.{}", tool, field),
                        "change": diff.change.as_str()
                    });
                    if let Some(ref pc) = diff.parent_constraint {
                        delta["from"] = serde_json::json!(format!("{:?}", pc));
                    }
                    if let Some(ref cc) = diff.child_constraint {
                        delta["to"] = serde_json::json!(format!("{:?}", cc));
                    }
                    deltas.push(delta);
                }
            }
        }

        // TTL change
        if self.ttl.change != ChangeType::Unchanged {
            let mut delta = serde_json::json!({
                "field": "ttl",
                "change": self.ttl.change.as_str()
            });
            if let Some(pt) = self.ttl.parent_ttl_seconds {
                delta["from"] = serde_json::json!(pt);
            }
            if let Some(ct) = self.ttl.child_ttl_seconds {
                delta["to"] = serde_json::json!(ct);
            }
            deltas.push(delta);
        }

        // Trust change
        if self.trust.change != ChangeType::Unchanged {
            let mut delta = serde_json::json!({
                "field": "trust",
                "change": self.trust.change.as_str()
            });
            if let Some(ref pt) = self.trust.parent_trust {
                delta["from"] = serde_json::json!(format!("{:?}", pt));
            }
            if let Some(ref ct) = self.trust.child_trust {
                delta["to"] = serde_json::json!(format!("{:?}", ct));
            }
            deltas.push(delta);
        }

        let output = serde_json::json!({
            "event_type": "tenuo.delegation",
            "parent_warrant_id": self.parent_warrant_id,
            "child_warrant_id": self.child_warrant_id,
            "warrant_type": "EXECUTION",
            "intent": self.intent,
            "deltas": deltas,
            "summary": {
                "tools_dropped": self.tools.dropped,
                "tools_kept": self.tools.kept,
                "capabilities_changed": self.capabilities.keys().count(),
                "ttl_reduced": self.ttl.change == ChangeType::Reduced,
                "trust_demoted": self.trust.change == ChangeType::Demoted,
                "is_terminal": self.depth.is_terminal
            }
        });

        serde_json::to_string_pretty(&output)
    }
}

/// Delegation receipt - a diff after delegation completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationReceipt {
    /// Parent warrant ID.
    pub parent_warrant_id: String,
    /// Child warrant ID (always set after delegation).
    pub child_warrant_id: String,
    /// Timestamp of delegation.
    pub timestamp: DateTime<Utc>,
    /// Tools diff.
    pub tools: ToolsDiff,
    /// Capability diffs.
    pub capabilities: HashMap<String, HashMap<String, ConstraintDiff>>,
    /// TTL diff.
    pub ttl: TtlDiff,
    /// Trust diff.
    pub trust: TrustDiff,
    /// Depth diff.
    pub depth: DepthDiff,
    /// Delegator's key fingerprint.
    pub delegator_fingerprint: String,
    /// Delegatee's key fingerprint.
    pub delegatee_fingerprint: String,
    /// Intent for this delegation.
    pub intent: Option<String>,
    /// Whether pass-through was used.
    pub used_pass_through: bool,
    /// Reason for pass-through (if used).
    pub pass_through_reason: Option<String>,
}

impl DelegationReceipt {
    /// Create a receipt from a diff after delegation.
    pub fn from_diff(
        diff: DelegationDiff,
        child_warrant_id: String,
        delegator_fingerprint: String,
        delegatee_fingerprint: String,
    ) -> Self {
        Self {
            parent_warrant_id: diff.parent_warrant_id,
            child_warrant_id,
            timestamp: diff.timestamp,
            tools: diff.tools,
            capabilities: diff.capabilities,
            ttl: diff.ttl,
            trust: diff.trust,
            depth: diff.depth,
            delegator_fingerprint,
            delegatee_fingerprint,
            intent: diff.intent,
            used_pass_through: false,
            pass_through_reason: None,
        }
    }

    /// Convert to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Generate SIEM-compatible JSON output.
    pub fn to_siem_json(&self) -> Result<String, serde_json::Error> {
        // Similar to DelegationDiff::to_siem_json but with receipt-specific fields
        let mut deltas = Vec::new();

        if !self.tools.dropped.is_empty() {
            deltas.push(serde_json::json!({
                "field": "tools",
                "change": "dropped",
                "value": self.tools.dropped
            }));
        }

        for (tool, tool_constraints) in &self.capabilities {
            for (field, diff) in tool_constraints {
                if diff.change != ChangeType::Unchanged {
                    let mut delta = serde_json::json!({
                        "field": format!("capabilities.{}.{}", tool, field),
                        "change": diff.change.as_str()
                    });
                    if let Some(ref pc) = diff.parent_constraint {
                        delta["from"] = serde_json::json!(format!("{:?}", pc));
                    }
                    if let Some(ref cc) = diff.child_constraint {
                        delta["to"] = serde_json::json!(format!("{:?}", cc));
                    }
                    deltas.push(delta);
                }
            }
        }

        if self.ttl.change != ChangeType::Unchanged {
            let mut delta = serde_json::json!({
                "field": "ttl",
                "change": self.ttl.change.as_str()
            });
            if let Some(pt) = self.ttl.parent_ttl_seconds {
                delta["from"] = serde_json::json!(pt);
            }
            if let Some(ct) = self.ttl.child_ttl_seconds {
                delta["to"] = serde_json::json!(ct);
            }
            deltas.push(delta);
        }

        if self.trust.change != ChangeType::Unchanged {
            let mut delta = serde_json::json!({
                "field": "trust",
                "change": self.trust.change.as_str()
            });
            if let Some(ref pt) = self.trust.parent_trust {
                delta["from"] = serde_json::json!(format!("{:?}", pt));
            }
            if let Some(ref ct) = self.trust.child_trust {
                delta["to"] = serde_json::json!(format!("{:?}", ct));
            }
            deltas.push(delta);
        }

        let output = serde_json::json!({
            "event_type": "tenuo.delegation.complete",
            "parent_warrant_id": self.parent_warrant_id,
            "child_warrant_id": self.child_warrant_id,
            "warrant_type": "EXECUTION",
            "intent": self.intent,
            "delegator_fingerprint": self.delegator_fingerprint,
            "delegatee_fingerprint": self.delegatee_fingerprint,
            "deltas": deltas,
            "summary": {
                "tools_dropped": self.tools.dropped,
                "tools_kept": self.tools.kept,
                "capabilities_changed": self.capabilities.keys().count(),
                "ttl_reduced": self.ttl.change == ChangeType::Reduced,
                "trust_demoted": self.trust.change == ChangeType::Demoted,
                "is_terminal": self.depth.is_terminal,
                "used_pass_through": self.used_pass_through
            }
        });

        serde_json::to_string_pretty(&output)
    }
}

/// Compute diff between two warrants.
pub fn compute_diff(parent: &Warrant, child: &Warrant) -> DelegationDiff {
    // Tools
    let parent_tools = parent.tools();
    let child_tools = child.tools();
    let tools = ToolsDiff::new(parent_tools, child_tools);

    // Capabilities
    let mut capabilities: HashMap<String, HashMap<String, ConstraintDiff>> = HashMap::new();

    // Get all tools from both
    let mut all_tools: Vec<String> = Vec::new();
    if let Some(p_caps) = parent.capabilities() {
        for tool in p_caps.keys() {
            all_tools.push(tool.clone());
        }
    }
    if let Some(c_caps) = child.capabilities() {
        for tool in c_caps.keys() {
            if !all_tools.contains(tool) {
                all_tools.push(tool.clone());
            }
        }
    }

    for tool in all_tools {
        let parent_constraints = parent
            .capabilities()
            .and_then(|c| c.get(&tool))
            .cloned()
            .unwrap_or_default();
        let child_constraints = child
            .capabilities()
            .and_then(|c| c.get(&tool))
            .cloned()
            .unwrap_or_default();

        let mut tool_diffs = HashMap::new();

        let mut all_fields: Vec<String> = Vec::new();
        for (field, _) in parent_constraints.iter() {
            all_fields.push(field.clone());
        }
        for (field, _) in child_constraints.iter() {
            if !all_fields.contains(field) {
                all_fields.push(field.clone());
            }
        }

        for field in all_fields {
            let pc = parent_constraints.get(&field).cloned();
            let cc = child_constraints.get(&field).cloned();
            tool_diffs.insert(field.clone(), ConstraintDiff::new(field, pc, cc));
        }

        if !tool_diffs.is_empty() {
            capabilities.insert(tool, tool_diffs);
        }
    }

    // TTL - compute remaining seconds
    let now = Utc::now();
    let parent_ttl = (parent.expires_at() - now).num_seconds();
    let child_ttl = (child.expires_at() - now).num_seconds();
    let ttl = TtlDiff::new(Some(parent_ttl.max(0)), Some(child_ttl.max(0)));

    // Trust
    let trust = TrustDiff::new(parent.trust_level(), child.trust_level());

    // Depth
    let depth = DepthDiff::new(parent.depth(), child.depth(), parent.max_depth());

    DelegationDiff {
        parent_warrant_id: parent.id().to_string(),
        child_warrant_id: Some(child.id().to_string()),
        timestamp: Utc::now(),
        tools,
        capabilities,
        ttl,
        trust,
        depth,
        intent: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_type_as_str() {
        assert_eq!(ChangeType::Unchanged.as_str(), "unchanged");
        assert_eq!(ChangeType::Narrowed.as_str(), "narrowed");
        assert_eq!(ChangeType::Reduced.as_str(), "reduced");
        assert_eq!(ChangeType::Demoted.as_str(), "demoted");
    }

    #[test]
    fn test_tools_diff() {
        let parent = vec![
            "read".to_string(),
            "write".to_string(),
            "delete".to_string(),
        ];
        let child = vec!["read".to_string(), "write".to_string()];

        let diff = ToolsDiff::new(parent, child);

        assert_eq!(diff.kept, vec!["read", "write"]);
        assert_eq!(diff.dropped, vec!["delete"]);
        assert!(diff.has_changes());
    }

    #[test]
    fn test_ttl_diff() {
        let diff = TtlDiff::new(Some(3600), Some(60));
        assert_eq!(diff.change, ChangeType::Reduced);

        let diff = TtlDiff::new(Some(60), Some(3600));
        assert_eq!(diff.change, ChangeType::Increased);

        let diff = TtlDiff::new(Some(60), Some(60));
        assert_eq!(diff.change, ChangeType::Unchanged);
    }

    #[test]
    fn test_trust_diff() {
        let diff = TrustDiff::new(Some(TrustLevel::System), Some(TrustLevel::External));
        assert_eq!(diff.change, ChangeType::Demoted);

        let diff = TrustDiff::new(Some(TrustLevel::External), Some(TrustLevel::System));
        assert_eq!(diff.change, ChangeType::Promoted);
    }
}
