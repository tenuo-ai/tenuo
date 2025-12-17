"""
Structured Audit Logging for Tenuo Python SDK.

Provides SIEM-compatible JSON logging for security-critical events.
Designed to integrate with log aggregators (Fluentd, Datadog, Splunk, etc.)
and security information and event management (SIEM) systems.

Example output:
    {
        "id": "evt_01234567890abcdef",
        "event_type": "authorization_success",
        "severity": "info",
        "@timestamp": "2024-01-15T10:30:00.000Z",
        "service": "tenuo-python",
        "trace_id": "sess_abc123",
        "warrant_id": "wrt_xyz789",
        "tool": "read_file",
        "action": "authorized",
        "constraints": {"path": "/tmp/test.txt"},
        "actor": "my-agent",
        "details": "Authorization successful"
    }

Usage:
    from tenuo.audit import audit_logger, AuditEvent, AuditEventType

    # Configure logging (call once at startup)
    audit_logger.configure(service_name="my-service")

    # Log an event
    audit_logger.log(AuditEvent(
        event_type=AuditEventType.AUTHORIZATION_SUCCESS,
        warrant_id="wrt_123",
        tool="read_file",
        action="authorized"
    ))
"""

import json
import uuid
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, Callable
import logging


class AuditEventType(str, Enum):
    """Types of auditable security events."""
    
    # Authorization events
    AUTHORIZATION_SUCCESS = "authorization_success"
    AUTHORIZATION_FAILURE = "authorization_failure"
    
    # Warrant events
    WARRANT_CREATED = "warrant_created"
    WARRANT_ATTENUATED = "warrant_attenuated"
    WARRANT_VERIFIED = "warrant_verified"
    WARRANT_EXPIRED = "warrant_expired"
    
    # Context events
    CONTEXT_SET = "context_set"
    CONTEXT_CLEARED = "context_cleared"
    
    # PoP events
    POP_VERIFIED = "pop_verified"
    POP_FAILED = "pop_failed"
    
    # Enrollment events
    ENROLLMENT_SUCCESS = "enrollment_success"
    ENROLLMENT_FAILURE = "enrollment_failure"


class AuditSeverity(str, Enum):
    """Severity levels for audit events (SIEM compatible)."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """
    A structured audit event for SIEM integration.
    
    All security-critical operations should emit an AuditEvent.
    Events are serialized as JSON with consistent field names.
    """
    
    event_type: AuditEventType
    
    # Unique event ID (auto-generated)
    id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:16]}")
    
    # Severity (auto-inferred from event_type if not provided)
    severity: Optional[AuditSeverity] = None
    
    # Timestamp (ISO8601, auto-generated)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    # Service name
    service: str = "tenuo-python"
    
    # Correlation/trace ID (session_id, request_id)
    trace_id: Optional[str] = None
    
    # Warrant context
    warrant_id: Optional[str] = None
    tool: Optional[str] = None
    action: Optional[str] = None
    
    # Constraints that were checked
    constraints: Optional[Dict[str, Any]] = None
    
    # Actor information
    actor: Optional[str] = None
    client_ip: Optional[str] = None
    
    # Additional context
    details: Optional[str] = None
    error_code: Optional[str] = None
    related_ids: Optional[list] = None
    
    # Structured metadata (callsite, function name, etc.)
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Auto-infer severity from event type if not provided."""
        if self.severity is None:
            if self.event_type in (
                AuditEventType.AUTHORIZATION_SUCCESS,
                AuditEventType.WARRANT_CREATED,
                AuditEventType.WARRANT_ATTENUATED,
                AuditEventType.WARRANT_VERIFIED,
                AuditEventType.POP_VERIFIED,
                AuditEventType.ENROLLMENT_SUCCESS,
                AuditEventType.CONTEXT_SET,
            ):
                self.severity = AuditSeverity.INFO
            elif self.event_type in (
                AuditEventType.AUTHORIZATION_FAILURE,
                AuditEventType.POP_FAILED,
                AuditEventType.ENROLLMENT_FAILURE,
            ):
                self.severity = AuditSeverity.ERROR
            elif self.event_type == AuditEventType.WARRANT_EXPIRED:
                self.severity = AuditSeverity.WARNING
            else:
                self.severity = AuditSeverity.INFO
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "id": self.id,
            "event_type": self.event_type.value,
            "severity": self.severity.value if self.severity else "info",
            "@timestamp": self.timestamp,
            "service": self.service,
        }
        
        # Add optional fields (skip None values)
        optional_fields = [
            "trace_id", "warrant_id", "tool", "action", "constraints",
            "actor", "client_ip", "details", "error_code", "related_ids"
        ]
        for field_name in optional_fields:
            value = getattr(self, field_name)
            if value is not None:
                result[field_name] = value
        
        return result
    
    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """
    Global audit logger for Tenuo security events.
    
    Outputs JSON to stdout by default (suitable for K8s/container environments).
    Can be configured with custom handlers for other destinations.
    """
    
    def __init__(self):
        self._enabled = True
        self._service_name = "tenuo-python"
        self._handler: Callable[[AuditEvent], None] = self._default_handler
        self._python_logger: Optional[logging.Logger] = None
    
    def configure(
        self,
        enabled: bool = True,
        service_name: str = "tenuo-python",
        handler: Optional[Callable[[AuditEvent], None]] = None,
        use_python_logging: bool = False,
        logger_name: str = "tenuo.audit",
    ):
        """
        Configure the audit logger.
        
        Args:
            enabled: Whether to emit audit logs
            service_name: Service name to include in events
            handler: Custom handler function for events
            use_python_logging: Use Python's logging module instead of stdout
            logger_name: Logger name if using Python logging
        """
        self._enabled = enabled
        self._service_name = service_name
        
        if handler:
            self._handler = handler
        elif use_python_logging:
            self._python_logger = logging.getLogger(logger_name)
            self._handler = self._python_logging_handler
        else:
            self._handler = self._default_handler
    
    def _default_handler(self, event: AuditEvent):
        """Default handler: JSON to stdout."""
        print(event.to_json(), file=sys.stdout, flush=True)
    
    def _python_logging_handler(self, event: AuditEvent):
        """Handler that uses Python's logging module."""
        if self._python_logger:
            level = {
                AuditSeverity.INFO: logging.INFO,
                AuditSeverity.WARNING: logging.WARNING,
                AuditSeverity.ERROR: logging.ERROR,
                AuditSeverity.CRITICAL: logging.CRITICAL,
            }.get(event.severity or AuditSeverity.INFO, logging.INFO)
            self._python_logger.log(level, event.to_json())
    
    def log(self, event: AuditEvent):
        """Log an audit event."""
        if not self._enabled:
            return
        
        # Ensure service name is set
        event.service = self._service_name
        
        try:
            self._handler(event)
        except Exception:
            # Never fail on audit logging
            pass
    
    def authorization_success(
        self,
        warrant_id: str,
        tool: str,
        constraints: Dict[str, Any],
        actor: Optional[str] = None,
        trace_id: Optional[str] = None,
    ):
        """Log a successful authorization."""
        self.log(AuditEvent(
            event_type=AuditEventType.AUTHORIZATION_SUCCESS,
            warrant_id=warrant_id,
            tool=tool,
            action="authorized",
            constraints=constraints,
            actor=actor,
            trace_id=trace_id,
            details=f"Authorization successful for {tool}",
        ))
    
    def authorization_failure(
        self,
        warrant_id: Optional[str],
        tool: str,
        constraints: Dict[str, Any],
        reason: str,
        actor: Optional[str] = None,
        trace_id: Optional[str] = None,
    ):
        """Log a failed authorization."""
        self.log(AuditEvent(
            event_type=AuditEventType.AUTHORIZATION_FAILURE,
            warrant_id=warrant_id,
            tool=tool,
            action="denied",
            constraints=constraints,
            actor=actor,
            trace_id=trace_id,
            error_code="authorization_failed",
            details=f"Authorization denied: {reason}",
        ))


# Global audit logger instance
audit_logger = AuditLogger()


# Convenience functions
def log_authorization_success(
    warrant_id: str,
    tool: str,
    constraints: Dict[str, Any],
    **kwargs
):
    """Log a successful authorization event."""
    audit_logger.authorization_success(warrant_id, tool, constraints, **kwargs)


def log_authorization_failure(
    warrant_id: Optional[str],
    tool: str,
    constraints: Dict[str, Any],
    reason: str,
    **kwargs
):
    """Log a failed authorization event."""
    audit_logger.authorization_failure(warrant_id, tool, constraints, reason, **kwargs)
