"""
Delegation diff and receipt types for Tenuo.

Provides structured diff computation and human-readable output for warrant delegations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
import json

from tenuo_core import TrustLevel  # type: ignore[import-untyped]


class ChangeType(str, Enum):
    """Type of change in a diff."""
    ADDED = "added"
    REMOVED = "removed"
    NARROWED = "narrowed"
    WIDENED = "widened"  # Should not occur in valid delegations
    REDUCED = "reduced"
    INCREASED = "increased"  # Should not occur in valid delegations
    DEMOTED = "demoted"
    PROMOTED = "promoted"  # Should not occur in valid delegations
    UNCHANGED = "unchanged"


@dataclass
class ToolsDiff:
    """Diff for tools (execution warrants) or issuable_tools (issuer warrants)."""
    parent_tools: List[str]
    child_tools: List[str]
    kept: List[str] = field(default_factory=list)
    dropped: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Compute kept and dropped tools."""
        parent_set = set(self.parent_tools)
        child_set = set(self.child_tools)
        self.kept = sorted(list(child_set & parent_set))
        self.dropped = sorted(list(parent_set - child_set))


@dataclass
class ConstraintDiff:
    """Diff for a single constraint field."""
    field: str
    parent_constraint: Optional[Any]  # Constraint object
    child_constraint: Optional[Any]   # Constraint object
    change: ChangeType
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {
            "field": self.field,
            "change": self.change.value,
        }
        
        if self.parent_constraint is not None:
            result["from"] = self._constraint_to_str(self.parent_constraint)
        if self.child_constraint is not None:
            result["to"] = self._constraint_to_str(self.child_constraint)
            
        return result
    
    @staticmethod
    def _constraint_to_str(constraint: Any) -> str:
        """Convert constraint to human-readable string."""
        # Handle various constraint types
        if hasattr(constraint, '__str__'):
            return str(constraint)
        return repr(constraint)


@dataclass
class TtlDiff:
    """Diff for TTL."""
    parent_ttl_seconds: Optional[int]
    child_ttl_seconds: Optional[int]
    parent_remaining_seconds: Optional[int] = None
    change: ChangeType = ChangeType.UNCHANGED
    
    def __post_init__(self):
        """Compute change type."""
        if self.parent_ttl_seconds is not None and self.child_ttl_seconds is not None:
            if self.child_ttl_seconds < self.parent_ttl_seconds:
                self.change = ChangeType.REDUCED
            elif self.child_ttl_seconds > self.parent_ttl_seconds:
                self.change = ChangeType.INCREASED
            else:
                self.change = ChangeType.UNCHANGED
        else:
            self.change = ChangeType.UNCHANGED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result: Dict[str, Any] = {
            "change": self.change.value,
        }
        if self.parent_ttl_seconds is not None:
            result["from"] = self.parent_ttl_seconds  # type: ignore[assignment]
        if self.child_ttl_seconds is not None:
            result["to"] = self.child_ttl_seconds  # type: ignore[assignment]
        return result


@dataclass
class TrustDiff:
    """Diff for trust level."""
    parent_trust: Optional[TrustLevel]
    child_trust: Optional[TrustLevel]
    change: ChangeType = ChangeType.UNCHANGED
    
    def __post_init__(self):
        """Compute change type."""
        if self.parent_trust is None or self.child_trust is None:
            self.change = ChangeType.UNCHANGED
        else:
            # TrustLevel is an enum, compare by converting to int
            # TrustLevel values: Untrusted=0, External=10, Partner=20, Internal=30, Privileged=40, System=50
            try:
                parent_val = int(self.parent_trust) if isinstance(self.parent_trust, int) else getattr(self.parent_trust, 'value', 0)
                child_val = int(self.child_trust) if isinstance(self.child_trust, int) else getattr(self.child_trust, 'value', 0)
            except (ValueError, TypeError):
                # Fallback: compare as strings
                parent_str = str(self.parent_trust)
                child_str = str(self.child_trust)
                if parent_str == child_str:
                    self.change = ChangeType.UNCHANGED
                else:
                    # Assume demoted if different (monotonicity)
                    self.change = ChangeType.DEMOTED
                return
            
            if child_val < parent_val:
                self.change = ChangeType.DEMOTED
            elif child_val > parent_val:
                self.change = ChangeType.PROMOTED
            else:
                self.change = ChangeType.UNCHANGED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result: Dict[str, Any] = {
            "change": self.change.value,
        }
        if self.parent_trust is not None:
            result["from"] = str(self.parent_trust)
        if self.child_trust is not None:
            result["to"] = str(self.child_trust)
        return result


@dataclass
class DepthDiff:
    """Diff for delegation depth."""
    parent_depth: int
    child_depth: int
    is_terminal: bool = False
    
    def __post_init__(self):
        """Compute if terminal (depth 0 or max_depth reached)."""
        # Terminal if child has max_depth of 0 or depth reached max
        # This is a simplified check - actual implementation would need max_depth info
        self.is_terminal = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "parent": self.parent_depth,
            "child": self.child_depth,
            "is_terminal": self.is_terminal,
        }


@dataclass
class DelegationDiff:
    """Diff between parent and child warrant (before delegation completes)."""
    parent_warrant_id: str
    child_warrant_id: Optional[str]  # None before delegation
    timestamp: datetime
    tools: ToolsDiff
    constraints: Dict[str, ConstraintDiff]
    ttl: TtlDiff
    trust: TrustDiff
    depth: DepthDiff
    intent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "parent_warrant_id": self.parent_warrant_id,
            "child_warrant_id": self.child_warrant_id,
            "timestamp": self.timestamp.isoformat(),
            "tools": {
                "parent": self.tools.parent_tools,
                "child": self.tools.child_tools,
                "kept": self.tools.kept,
                "dropped": self.tools.dropped,
            },
            "constraints": {
                field: diff.to_dict() for field, diff in self.constraints.items()
            },
            "ttl": self.ttl.to_dict(),
            "trust": self.trust.to_dict(),
            "depth": self.depth.to_dict(),
            "intent": self.intent,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_human(self) -> str:
        """Convert to human-readable string."""
        lines = []
        lines.append("╔══════════════════════════════════════════════════════════════════╗")
        lines.append("║  DELEGATION DIFF                                                 ║")
        child_id = self.child_warrant_id or "(pending)"
        lines.append(f"║  Parent: {self.parent_warrant_id} → Child: {child_id:<30}║")
        lines.append("╠══════════════════════════════════════════════════════════════════╣")
        lines.append("║                                                                  ║")
        
        # Tools section
        lines.append("║  TOOLS                                                           ║")
        for tool in self.tools.kept:
            lines.append(f"║    ✓ {tool:<60}║")
        for tool in self.tools.dropped:
            lines.append(f"║    ✗ {tool:<60} DROPPED                                   ║")
        
        lines.append("║                                                                  ║")
        
        # Constraints section
        if self.constraints:
            lines.append("║  CONSTRAINTS                                                     ║")
            for field, diff in sorted(self.constraints.items()):
                lines.append(f"║    {field:<60}║")
                if diff.parent_constraint:
                    lines.append(f"║      parent: {str(diff.parent_constraint):<50}║")
                if diff.child_constraint:
                    lines.append(f"║      child:  {str(diff.child_constraint):<50}║")
                if diff.change != ChangeType.UNCHANGED:
                    lines.append(f"║      change: {diff.change.value.upper():<50}║")
        
        lines.append("║                                                                  ║")
        
        # TTL section
        lines.append("║  TTL                                                             ║")
        if self.ttl.parent_remaining_seconds is not None:
            lines.append(f"║    parent: {self.ttl.parent_remaining_seconds}s remaining{'':<40}║")
        elif self.ttl.parent_ttl_seconds is not None:
            lines.append(f"║    parent: {self.ttl.parent_ttl_seconds}s{'':<50}║")
        if self.ttl.child_ttl_seconds is not None:
            lines.append(f"║    child:  {self.ttl.child_ttl_seconds}s{'':<50}║")
        if self.ttl.change != ChangeType.UNCHANGED:
            lines.append(f"║    change: {self.ttl.change.value.upper():<50}║")
        
        lines.append("║                                                                  ║")
        
        # Trust section
        lines.append("║  TRUST                                                           ║")
        if self.trust.parent_trust:
            lines.append(f"║    parent: {str(self.trust.parent_trust):<50}║")
        if self.trust.child_trust:
            lines.append(f"║    child:  {str(self.trust.child_trust):<50}║")
        if self.trust.change != ChangeType.UNCHANGED:
            lines.append(f"║    change: {self.trust.change.value.upper()} (by context){'':<30}║")
        
        lines.append("║                                                                  ║")
        
        # Depth section
        lines.append("║  DEPTH                                                           ║")
        lines.append(f"║    parent: {self.depth.parent_depth}{'':<50}║")
        lines.append(f"║    child:  {self.depth.child_depth} ({'terminal' if self.depth.is_terminal else 'non-terminal'}){'':<30}║")
        
        lines.append("╚══════════════════════════════════════════════════════════════════╝")
        
        return "\n".join(lines)
    
    def to_siem_json(self) -> Dict[str, Any]:
        """Convert to SIEM-compatible JSON format."""
        deltas: List[Dict[str, Any]] = []
        
        # Tools deltas
        if self.tools.dropped:
            deltas.append({
                "field": "tools",
                "change": "dropped",
                "value": self.tools.dropped,
            })
        
        # Constraint deltas
        for field_name, diff in self.constraints.items():
            if diff.change == ChangeType.NARROWED:
                delta_item: Dict[str, Any] = {
                    "field": f"constraints.{field_name}",
                    "change": "narrowed",
                }
                if diff.parent_constraint is not None:
                    delta_item["from"] = str(diff.parent_constraint)
                if diff.child_constraint is not None:
                    delta_item["to"] = str(diff.child_constraint)
                deltas.append(delta_item)
        
        # TTL delta
        if self.ttl.change == ChangeType.REDUCED:
            ttl_delta: Dict[str, Any] = {
                "field": "ttl",
                "change": "reduced",
            }
            if self.ttl.parent_ttl_seconds is not None:
                ttl_delta["from"] = self.ttl.parent_ttl_seconds
            if self.ttl.child_ttl_seconds is not None:
                ttl_delta["to"] = self.ttl.child_ttl_seconds
            deltas.append(ttl_delta)
        
        # Trust delta
        if self.trust.change == ChangeType.DEMOTED:
            trust_delta: Dict[str, Any] = {
                "field": "trust",
                "change": "demoted",
            }
            if self.trust.parent_trust is not None:
                trust_delta["from"] = str(self.trust.parent_trust)
            if self.trust.child_trust is not None:
                trust_delta["to"] = str(self.trust.child_trust)
            deltas.append(trust_delta)
        
        summary = {
            "tools_dropped": self.tools.dropped,
            "tools_kept": self.tools.kept,
            "constraints_narrowed": [
                field for field, diff in self.constraints.items()
                if diff.change == ChangeType.NARROWED
            ],
            "ttl_reduced": self.ttl.change == ChangeType.REDUCED,
            "trust_demoted": self.trust.change == ChangeType.DEMOTED,
            "is_terminal": self.depth.is_terminal,
            "used_pass_through": False,  # Will be set in DelegationReceipt
        }
        
        return {
            "event_type": "tenuo.delegation",
            "parent_warrant_id": self.parent_warrant_id,
            "child_warrant_id": self.child_warrant_id,
            "warrant_type": "EXECUTION",  # Would need to get from warrant
            "intent": self.intent,
            "deltas": deltas,
            "summary": summary,
        }


@dataclass
class DelegationReceipt:
    """After delegation completes, diff becomes receipt."""
    parent_warrant_id: str
    child_warrant_id: str
    timestamp: datetime
    tools: ToolsDiff
    constraints: Dict[str, ConstraintDiff]
    ttl: TtlDiff
    trust: TrustDiff
    depth: DepthDiff
    delegator_fingerprint: str
    delegatee_fingerprint: str
    intent: Optional[str] = None
    used_pass_through: bool = False
    pass_through_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, including receipt-specific fields."""
        return {
            "parent_warrant_id": self.parent_warrant_id,
            "child_warrant_id": self.child_warrant_id,
            "timestamp": self.timestamp.isoformat(),
            "tools": {
                "parent": self.tools.parent_tools,
                "child": self.tools.child_tools,
                "kept": self.tools.kept,
                "dropped": self.tools.dropped,
            },
            "constraints": {
                field: diff.to_dict() for field, diff in self.constraints.items()
            },
            "ttl": self.ttl.to_dict(),
            "trust": self.trust.to_dict(),
            "depth": self.depth.to_dict(),
            "intent": self.intent,
            "delegator_fingerprint": self.delegator_fingerprint,
            "delegatee_fingerprint": self.delegatee_fingerprint,
            "used_pass_through": self.used_pass_through,
            "pass_through_reason": self.pass_through_reason,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_siem_json(self) -> Dict[str, Any]:
        """Convert to SIEM format with receipt fields."""
        deltas: List[Dict[str, Any]] = []
        
        # Tools deltas
        if self.tools.dropped:
            deltas.append({
                "field": "tools",
                "change": "dropped",
                "value": self.tools.dropped,
            })
        
        # Constraint deltas
        for field_name, diff in self.constraints.items():
            if diff.change == ChangeType.NARROWED:
                delta_item: Dict[str, Any] = {
                    "field": f"constraints.{field_name}",
                    "change": "narrowed",
                }
                if diff.parent_constraint is not None:
                    delta_item["from"] = str(diff.parent_constraint)
                if diff.child_constraint is not None:
                    delta_item["to"] = str(diff.child_constraint)
                deltas.append(delta_item)
        
        # TTL delta
        if self.ttl.change == ChangeType.REDUCED:
            ttl_delta: Dict[str, Any] = {
                "field": "ttl",
                "change": "reduced",
            }
            if self.ttl.parent_ttl_seconds is not None:
                ttl_delta["from"] = self.ttl.parent_ttl_seconds
            if self.ttl.child_ttl_seconds is not None:
                ttl_delta["to"] = self.ttl.child_ttl_seconds
            deltas.append(ttl_delta)
        
        # Trust delta
        if self.trust.change == ChangeType.DEMOTED:
            trust_delta: Dict[str, Any] = {
                "field": "trust",
                "change": "demoted",
            }
            if self.trust.parent_trust is not None:
                trust_delta["from"] = str(self.trust.parent_trust)
            if self.trust.child_trust is not None:
                trust_delta["to"] = str(self.trust.child_trust)
            deltas.append(trust_delta)
        
        summary = {
            "tools_dropped": self.tools.dropped,
            "tools_kept": self.tools.kept,
            "constraints_narrowed": [
                field for field, diff in self.constraints.items()
                if diff.change == ChangeType.NARROWED
            ],
            "ttl_reduced": self.ttl.change == ChangeType.REDUCED,
            "trust_demoted": self.trust.change == ChangeType.DEMOTED,
            "is_terminal": self.depth.is_terminal,
            "used_pass_through": self.used_pass_through,
        }
        
        if self.pass_through_reason:
            summary["pass_through_reason"] = self.pass_through_reason
        
        return {
            "event_type": "tenuo.delegation",
            "parent_warrant_id": self.parent_warrant_id,
            "child_warrant_id": self.child_warrant_id,
            "warrant_type": "EXECUTION",  # Would need to get from warrant
            "intent": self.intent,
            "deltas": deltas,
            "summary": summary,
        }
