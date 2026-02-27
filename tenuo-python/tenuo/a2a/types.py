"""
A2A Adapter - Type definitions.

Types for inter-agent delegation over the A2A protocol.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from tenuo_core import Warrant as _WarrantType
else:
    _WarrantType = Any  # Runtime: Any, since Warrant is lazily imported

__all__ = [
    # Context
    "current_task_warrant",
    # Core types
    "Grant",
    "AgentCard",
    "SkillInfo",
    "TenuoExtension",
    "Message",
    "TaskResult",
    "TaskUpdate",
    "TaskUpdateType",
    # Audit
    "AuditEvent",
    "AuditEventType",
    # Re-export (lazily imported via __getattr__)
    "Warrant",  # noqa: F822
]


# =============================================================================
# Context Variable for Current Task Warrant
# =============================================================================

current_task_warrant: ContextVar[Optional[_WarrantType]] = ContextVar("current_task_warrant", default=None)


# =============================================================================
# Grant - Skill-level capability (A2A wire format)
# =============================================================================


@dataclass
class Grant:
    """
    A skill-level capability grant with constraints.

    NOTE: This is the A2A wire format representation, distinct from
    tenuo_core.Capability which is the internal warrant representation.
    Grant is used for A2A protocol communication (JSON-RPC), while
    Capability is used for CBOR-encoded warrants.

    Example:
        Grant(
            skill="search_papers",
            constraints={"sources": UrlSafe(allow_domains=["arxiv.org"])}
        )
    """

    skill: str
    constraints: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for wire format."""
        return {"skill": self.skill, "constraints": {k: _serialize_constraint(v) for k, v in self.constraints.items()}}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Grant":
        """Deserialize from wire format."""
        return cls(skill=data["skill"], constraints=data.get("constraints", {}))


def _serialize_constraint(constraint: Any) -> Dict[str, Any]:
    """
    Serialize a constraint to wire format.

    Prefers constraint.to_dict() if available (canonical method).
    Falls back to type-specific extraction for known constraints.
    """
    # Prefer to_dict() if the constraint defines it
    if hasattr(constraint, "to_dict") and callable(constraint.to_dict):
        return constraint.to_dict()

    # Pass through dicts as-is
    if isinstance(constraint, dict):
        return constraint

    # Fallback: type-specific extraction for known Rust constraints
    if hasattr(constraint, "__class__"):
        type_name = constraint.__class__.__name__
        if type_name in ("UrlSafe", "PyUrlSafe"):
            return {
                "type": "UrlSafe",
                "allow_domains": getattr(constraint, "allow_domains", None),
            }
        elif type_name in ("Subpath", "PySubpath"):
            return {
                "type": "Subpath",
                "root": getattr(constraint, "root", None),
            }
        elif type_name == "Shlex":
            return {
                "type": "Shlex",
                "allow": getattr(constraint, "allowed_bins", None),
            }

    # Last resort: wrap in generic format
    return {"type": str(type(constraint).__name__), "value": str(constraint)}


# =============================================================================
# AgentCard - Agent metadata from discovery
# =============================================================================


@dataclass
class AgentCard:
    """
    Agent metadata returned by discover().

    Contains the agent's public key, skills, and Tenuo extension info.
    """

    name: str
    url: str
    skills: List[SkillInfo]
    tenuo_extension: Optional[TenuoExtension] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def requires_warrant(self) -> bool:
        """Check if this agent requires warrants."""
        return self.tenuo_extension is not None and self.tenuo_extension.required

    @property
    def public_key(self) -> Optional[str]:
        """Get agent's public key if available."""
        return self.tenuo_extension.public_key if self.tenuo_extension else None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentCard":
        """Parse from JSON response."""
        skills = [SkillInfo.from_dict(s) for s in data.get("skills", [])]
        tenuo_ext = None
        if "x-tenuo" in data:
            tenuo_ext = TenuoExtension.from_dict(data["x-tenuo"])
        return cls(
            name=data.get("name", ""),
            url=data.get("url", ""),
            skills=skills,
            tenuo_extension=tenuo_ext,
            raw=data,
        )


@dataclass
class SkillInfo:
    """Information about a skill offered by an agent."""

    id: str
    name: str
    constraints: Dict[str, ConstraintInfo] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SkillInfo":
        """Parse skill info from JSON."""
        constraints = {}
        if "x-tenuo-constraints" in data:
            for key, info in data["x-tenuo-constraints"].items():
                constraints[key] = ConstraintInfo.from_dict(info)
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            constraints=constraints,
        )


@dataclass
class ConstraintInfo:
    """Constraint requirement info from skill discovery."""

    type: str
    required: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConstraintInfo":
        return cls(
            type=data.get("type", "unknown"),
            required=data.get("required", True),
        )


@dataclass
class TenuoExtension:
    """Tenuo-specific extension in AgentCard."""

    version: str
    required: bool
    public_key: str
    previous_keys: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TenuoExtension":
        return cls(
            version=data.get("version", "0.1.0"),
            required=data.get("required", True),
            public_key=data.get("public_key", ""),
            previous_keys=data.get("previous_keys", []),
        )


# =============================================================================
# Task Types
# =============================================================================


@dataclass
class Message:
    """A message in a task conversation."""

    role: str  # "user", "assistant"
    content: str

    def to_dict(self) -> Dict[str, Any]:
        return {"role": self.role, "content": self.content}


@dataclass
class TaskResult:
    """Result from a completed task."""

    task_id: str
    status: str  # "complete", "error", "cancelled"
    output: Optional[str] = None
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskResult":
        return cls(
            task_id=data.get("task_id", ""),
            status=data.get("status", "unknown"),
            output=data.get("output"),
            artifacts=data.get("artifacts", []),
            error=data.get("error"),
        )


class TaskUpdateType(str, Enum):
    """Types of task updates in streaming."""

    STATUS = "status"
    ARTIFACT = "artifact"
    MESSAGE = "message"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class TaskUpdate:
    """Update during streaming task execution."""

    type: TaskUpdateType
    task_id: str
    data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskUpdate":
        return cls(
            type=TaskUpdateType(data.get("type", "status")),
            task_id=data.get("task_id", ""),
            data=data,
        )


# =============================================================================
# Audit Events
# =============================================================================


class AuditEventType(str, Enum):
    """Types of audit events."""

    WARRANT_RECEIVED = "warrant_received"
    WARRANT_VALIDATED = "warrant_validated"
    WARRANT_REJECTED = "warrant_rejected"
    SKILL_INVOKED = "skill_invoked"
    SKILL_DENIED = "skill_denied"
    WARRANT_EXPIRED = "warrant_expired"


@dataclass
class AuditEvent:
    """Structured audit event for compliance logging."""

    timestamp: datetime
    event: AuditEventType
    task_id: str
    skill: Optional[str] = None
    warrant_jti: Optional[str] = None
    warrant_iss: Optional[str] = None
    warrant_sub: Optional[str] = None
    outcome: str = ""
    constraints_checked: Dict[str, Any] = field(default_factory=dict)
    latency_ms: int = 0
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON audit log."""
        return {
            "timestamp": self.timestamp.isoformat() + "Z",
            "event": self.event.value,
            "task_id": self.task_id,
            "skill": self.skill,
            "warrant": {
                "jti": self.warrant_jti,
                "iss": self.warrant_iss,
                "sub": self.warrant_sub,
            }
            if self.warrant_jti
            else None,
            "outcome": self.outcome,
            "constraints_checked": self.constraints_checked,
            "latency_ms": self.latency_ms,
            "reason": self.reason,
        }


# =============================================================================
# Lazy Import for Warrant
# =============================================================================

# Warrant is lazily imported to avoid forcing tenuo_core on users who only
# need basic types like Grant or AgentCard.

_warrant_class = None


def __getattr__(name: str) -> Any:
    """Lazy import for Warrant to avoid module-level tenuo_core dependency."""
    global _warrant_class
    if name == "Warrant":
        if _warrant_class is None:
            try:
                from tenuo_core import Warrant as _Warrant

                _warrant_class = _Warrant
            except ImportError as e:
                raise ImportError("tenuo_core is required for Warrant. Install with: uv pip install tenuo[a2a]") from e
        return _warrant_class
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
