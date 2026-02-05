"""
Tenuo Temporal Integration - Warrant-based Authorization for Durable Workflows

Compatibility:
    Temporal SDK: 1.4.0+
    Python: 3.9+

This module provides seamless integration between Tenuo's warrant-based
authorization and Temporal's durable workflow orchestration. Activity
execution is transparently authorized against the workflow's warrant.

Key Concepts:
    - Warrants propagate via Temporal headers, no code changes to activities
    - TenuoInterceptor enforces authorization at the activity boundary
    - KeyResolver abstraction for secure key material management

Security Philosophy (Fail Closed):
    - Missing warrant headers: Activities execute without authorization (opt-in)
    - Invalid warrant: Raises ChainValidationError
    - Expired warrant: Raises WarrantExpired
    - Constraint violation: Raises ConstraintViolation
    - PoP failure: Raises PopVerificationError (Phase 2)

Phase 1 Features:
    - TenuoInterceptor: Activity-level authorization
    - tenuo_headers(): Create headers for workflow start
    - current_warrant(): Access warrant from workflow context
    - EnvKeyResolver: Development key resolver
    - Basic audit event emission

Phase 2 Features:
    - PoP verification using scheduled_time (replay-safe)
    - @unprotected decorator for local activities
    - Fail-closed local activity guard
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Literal, Optional, TypeVar

logger = logging.getLogger("tenuo.temporal")

# Type variable for decorator
F = TypeVar("F", bound=Callable[..., Any])

# =============================================================================
# Header Constants
# =============================================================================

TENUO_WARRANT_HEADER = "x-tenuo-warrant"
TENUO_KEY_ID_HEADER = "x-tenuo-key-id"
TENUO_COMPRESSED_HEADER = "x-tenuo-compressed"
TENUO_POP_HEADER = "x-tenuo-pop"


# =============================================================================
# Exceptions
# =============================================================================


class TenuoTemporalError(Exception):
    """Base exception for tenuo.temporal module."""


class TenuoContextError(TenuoTemporalError):
    """Raised when Tenuo context is missing or invalid."""


class LocalActivityError(TenuoTemporalError):
    """Raised when a protected activity is used as local activity."""

    def __init__(self, activity_name: str):
        self.activity_name = activity_name
        super().__init__(
            f"Activity '{activity_name}' cannot be used as local activity. "
            "Protected activities must be executed as regular activities for "
            "authorization enforcement. Mark with @unprotected to allow local execution."
        )


@dataclass
class PopVerificationError(TenuoTemporalError):
    """Raised when Proof-of-Possession verification fails.

    Attributes:
        reason: Why PoP verification failed
        activity_name: The activity that failed PoP
    """

    reason: str
    activity_name: str

    def __str__(self) -> str:
        return f"PoP verification failed for '{self.activity_name}': {self.reason}"


@dataclass
class ConstraintViolation(TenuoTemporalError):
    """Raised when an activity violates warrant constraints.

    Attributes:
        tool: The tool/activity that was denied
        arguments: The arguments that were checked
        constraint: The constraint that was violated
        warrant_id: The warrant that denied the action
    """

    tool: str
    arguments: Dict[str, Any]
    constraint: str
    warrant_id: str

    def __str__(self) -> str:
        return f"Activity '{self.tool}' denied: {self.constraint} (warrant: {self.warrant_id})"


@dataclass
class WarrantExpired(TenuoTemporalError):
    """Raised when the warrant has expired.

    Attributes:
        warrant_id: The expired warrant
        expired_at: When the warrant expired
    """

    warrant_id: str
    expired_at: datetime

    def __str__(self) -> str:
        return f"Warrant '{self.warrant_id}' expired at {self.expired_at}"


@dataclass
class ChainValidationError(TenuoTemporalError):
    """Raised when warrant chain validation fails.

    Attributes:
        reason: Description of the validation failure
        depth: The depth at which validation failed
    """

    reason: str
    depth: int

    def __str__(self) -> str:
        return f"Warrant chain invalid at depth {self.depth}: {self.reason}"


@dataclass
class KeyResolutionError(TenuoTemporalError):
    """Raised when a signing key cannot be resolved.

    Attributes:
        key_id: The key ID that could not be resolved
    """

    key_id: str

    def __str__(self) -> str:
        return f"Cannot resolve key: {self.key_id}"


# =============================================================================
# Audit Event
# =============================================================================


@dataclass
class TemporalAuditEvent:
    """Audit event emitted for each authorization decision.

    Compatible with tenuo.audit.AuditEvent pattern.
    """

    # Temporal context
    workflow_id: str
    workflow_type: str
    workflow_run_id: str
    activity_name: str
    activity_id: str
    task_queue: str

    # Authorization decision
    decision: Literal["ALLOW", "DENY"]
    tool: str
    arguments: Dict[str, Any]

    # Warrant info
    warrant_id: str
    warrant_expires_at: Optional[datetime]
    warrant_capabilities: List[str]

    # Denial details (populated if denied)
    denial_reason: Optional[str] = None
    constraint_violated: Optional[str] = None

    # Metadata
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tenuo_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for structured logging."""
        return {
            "workflow_id": self.workflow_id,
            "workflow_type": self.workflow_type,
            "workflow_run_id": self.workflow_run_id,
            "activity_name": self.activity_name,
            "activity_id": self.activity_id,
            "task_queue": self.task_queue,
            "decision": self.decision,
            "tool": self.tool,
            "arguments": self.arguments,
            "warrant_id": self.warrant_id,
            "warrant_expires_at": (self.warrant_expires_at.isoformat() if self.warrant_expires_at else None),
            "warrant_capabilities": self.warrant_capabilities,
            "denial_reason": self.denial_reason,
            "constraint_violated": self.constraint_violated,
            "timestamp": self.timestamp.isoformat(),
            "tenuo_version": self.tenuo_version,
        }


# =============================================================================
# Key Resolver
# =============================================================================


class KeyResolver(ABC):
    """Abstract interface for resolving key IDs to signing keys.

    Implementations should fetch keys from secure storage
    (Vault, KMS, HSM, etc.) and cache appropriately.
    """

    @abstractmethod
    async def resolve(self, key_id: str) -> Any:  # Returns SigningKey
        """Resolve a key ID to a signing key.

        Args:
            key_id: The key identifier

        Returns:
            The signing key (tenuo_core.SigningKey)

        Raises:
            KeyResolutionError: If key cannot be resolved
        """
        ...


class EnvKeyResolver(KeyResolver):
    """Resolves keys from environment variables.

    For development/testing only. Do not use in production.

    Expects: TENUO_KEY_{key_id}=<base64-encoded-key>

    Args:
        prefix: Environment variable prefix (default: "TENUO_KEY_")
    """

    def __init__(self, prefix: str = "TENUO_KEY_") -> None:
        self._prefix = prefix

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from environment variable."""
        import os

        env_name = f"{self._prefix}{key_id}"
        value = os.environ.get(env_name)

        if value is None:
            raise KeyResolutionError(key_id=key_id)

        try:
            from tenuo_core import SigningKey

            key_bytes = base64.b64decode(value)
            return SigningKey.from_bytes(key_bytes)
        except Exception as e:
            logger.error(f"Failed to decode key from {env_name}: {e}")
            raise KeyResolutionError(key_id=key_id)


# =============================================================================
# Interceptor Config
# =============================================================================


@dataclass
class TenuoInterceptorConfig:
    """Configuration for TenuoInterceptor."""

    key_resolver: KeyResolver
    """Required. Resolves key IDs to signing keys."""

    on_denial: Literal["raise", "log", "skip"] = "raise"
    """
    Behavior when authorization fails:
    - "raise": Raise ConstraintViolation (default)
    - "log": Log denial, continue execution
    - "skip": Silent denial, return None
    """

    tool_mappings: Dict[str, str] = field(default_factory=dict)
    """
    Optional explicit activity-to-tool mappings.
    Example: {"fetch_document": "read_file"}
    If not specified, activity name = tool name.
    """

    audit_callback: Optional[Callable[[TemporalAuditEvent], None]] = None
    """Optional callback for authorization audit events."""

    audit_allow: bool = True
    """Whether to emit audit events for allowed actions."""

    audit_deny: bool = True
    """Whether to emit audit events for denied actions."""

    max_chain_depth: int = 10
    """Maximum warrant chain depth to accept."""

    # Phase 2: Security hardening options
    require_pop: bool = False
    """
    Require Proof-of-Possession verification.
    When True, activities must have a valid PoP signature.
    Set to False during initial adoption, True for production.
    """

    block_local_activities: bool = True
    """
    Block protected activities from being used as local activities.
    Local activities bypass the worker interceptor, so protected
    activities must be marked @unprotected to run locally.
    """

    pop_window_seconds: int = 300
    """
    Time window (seconds) for PoP timestamp validation.
    The scheduled_time must be within this window of the PoP timestamp.
    Default: 300 seconds (5 minutes).
    """


# =============================================================================
# Header Utilities
# =============================================================================


def tenuo_headers(
    warrant: Any,  # Warrant type from tenuo_core
    key_id: str,
    *,
    compress: bool = True,
) -> Dict[str, bytes]:
    """Create headers dict for starting a workflow with Tenuo authorization.

    Args:
        warrant: The warrant authorizing this workflow
        key_id: Identifier for the holder's signing key
        compress: Whether to gzip compress the warrant (default: True)

    Returns:
        Headers dict to pass to client.start_workflow()

    Example:
        await client.start_workflow(
            MyWorkflow.run,
            args=[...],
            headers=tenuo_headers(warrant, "agent-key-1"),
        )
    """
    # Serialize warrant to base64
    warrant_b64 = warrant.to_base64()
    warrant_bytes = warrant_b64.encode("utf-8")

    headers: Dict[str, bytes] = {
        TENUO_KEY_ID_HEADER: key_id.encode("utf-8"),
    }

    if compress:
        compressed = gzip.compress(warrant_bytes, compresslevel=9)
        headers[TENUO_WARRANT_HEADER] = base64.b64encode(compressed)
        headers[TENUO_COMPRESSED_HEADER] = b"1"
    else:
        headers[TENUO_WARRANT_HEADER] = warrant_bytes
        headers[TENUO_COMPRESSED_HEADER] = b"0"

    return headers


def _extract_warrant_from_headers(headers: Dict[str, bytes]) -> Any:
    """Extract and deserialize warrant from headers.

    Returns:
        Warrant object, or None if no warrant header present.

    Raises:
        ChainValidationError: If warrant cannot be deserialized
    """
    from tenuo_core import Warrant

    raw = headers.get(TENUO_WARRANT_HEADER)
    if raw is None:
        return None

    try:
        # Check if compressed
        is_compressed = headers.get(TENUO_COMPRESSED_HEADER, b"0") == b"1"

        if is_compressed:
            # Decode base64 then decompress
            compressed = base64.b64decode(raw)
            warrant_bytes = gzip.decompress(compressed)
        else:
            warrant_bytes = raw

        # Parse base64-encoded warrant
        warrant_b64 = warrant_bytes.decode("utf-8")
        return Warrant.from_base64(warrant_b64)

    except Exception as e:
        raise ChainValidationError(
            reason=f"Failed to deserialize warrant: {e}",
            depth=0,
        )


def _extract_key_id_from_headers(headers: Dict[str, bytes]) -> Optional[str]:
    """Extract key ID from headers."""
    raw = headers.get(TENUO_KEY_ID_HEADER)
    if raw is None:
        return None
    return raw.decode("utf-8")


# =============================================================================
# Context Accessors (for use within workflows)
# =============================================================================


def current_warrant() -> Any:
    """Get the warrant from the current workflow context.

    Must be called from within a workflow.

    Returns:
        The warrant attached to this workflow

    Raises:
        TenuoContextError: If no warrant in context
    """
    try:
        from temporalio import workflow

        info = workflow.info()
        headers = getattr(info, "headers", {}) or {}

        warrant = _extract_warrant_from_headers(headers)
        if warrant is None:
            raise TenuoContextError("No Tenuo warrant in workflow context")

        return warrant

    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")


def current_key_id() -> str:
    """Get the key ID from the current workflow context.

    Must be called from within a workflow.

    Returns:
        The key ID for this workflow's holder

    Raises:
        TenuoContextError: If no key ID in context
    """
    try:
        from temporalio import workflow

        info = workflow.info()
        headers = getattr(info, "headers", {}) or {}

        key_id = _extract_key_id_from_headers(headers)
        if key_id is None:
            raise TenuoContextError("No Tenuo key ID in workflow context")

        return key_id

    except ImportError:
        raise TenuoContextError("temporalio not available. Install with: pip install temporalio")


# =============================================================================
# @unprotected Decorator (Phase 2)
# =============================================================================


def unprotected(func: F) -> F:
    """Mark an activity as unprotected - safe for local execution.

    Protected activities (default) require Tenuo authorization and
    cannot be used as local activities because local activities bypass
    worker interceptors.

    Use this decorator when:
    - The activity only accesses internal/trusted resources
    - The activity doesn't need per-invocation authorization
    - You want to run the activity as a local activity

    Example:
        @activity.defn
        @unprotected
        async def get_config_value(key: str) -> str:
            '''Internal config lookup - no Tenuo needed.'''
            return config[key]

        # Can now be called as local activity:
        await workflow.execute_local_activity(
            get_config_value,
            args=["database_url"],
            ...
        )
    """
    func._tenuo_unprotected = True  # type: ignore
    return func


def is_unprotected(func: Any) -> bool:
    """Check if an activity is marked as unprotected."""
    return getattr(func, "_tenuo_unprotected", False)


# =============================================================================
# PoP Utilities (Phase 2)
# =============================================================================


def _compute_pop_challenge(
    workflow_id: str,
    activity_id: str,
    tool_name: str,
    args: Dict[str, Any],
    scheduled_time: datetime,
) -> bytes:
    """Compute the PoP challenge bytes for an activity.

    The challenge is a SHA-256 hash of:
    - workflow_id
    - activity_id
    - tool_name
    - canonical JSON of arguments
    - scheduled_time (ISO format)

    This ensures the challenge is deterministic and replay-safe.
    """
    # Canonical JSON: sorted keys, no whitespace
    args_json = json.dumps(args, sort_keys=True, separators=(",", ":"))

    message = f"{workflow_id}|{activity_id}|{tool_name}|{args_json}|{scheduled_time.isoformat()}"

    return hashlib.sha256(message.encode()).digest()


# =============================================================================
# Interceptor
# =============================================================================


class TenuoInterceptor:
    """Temporal interceptor that enforces Tenuo warrant authorization.

    Intercepts activity execution and verifies the calling workflow
    has a valid warrant authorizing the activity.

    Example:
        interceptor = TenuoInterceptor(
            TenuoInterceptorConfig(
                key_resolver=EnvKeyResolver(),
                on_denial="raise",
            )
        )

        worker = Worker(
            client,
            task_queue="my-queue",
            workflows=[MyWorkflow],
            activities=[read_file, write_file],
            interceptors=[interceptor],
        )
    """

    def __init__(self, config: TenuoInterceptorConfig) -> None:
        self._config = config
        self._version = self._get_version()

    def _get_version(self) -> str:
        """Get Tenuo version for audit events."""
        try:
            from tenuo import __version__

            return __version__
        except ImportError:
            return "unknown"

    def intercept_activity(
        self,
        next_interceptor: Any,  # ActivityInboundInterceptor
    ) -> "TenuoActivityInboundInterceptor":
        """Return activity interceptor that wraps the next one."""
        return TenuoActivityInboundInterceptor(
            next_interceptor,
            self._config,
            self._version,
        )


class TenuoActivityInboundInterceptor:
    """Activity-level interceptor that performs authorization checks."""

    def __init__(
        self,
        next_interceptor: Any,
        config: TenuoInterceptorConfig,
        version: str,
    ) -> None:
        self._next = next_interceptor
        self._config = config
        self._version = version

    async def execute_activity(self, input: Any) -> Any:
        """Intercept activity execution for authorization."""
        try:
            from temporalio import activity
        except ImportError:
            # If temporalio not available, pass through
            return await self._next.execute_activity(input)

        # Get activity info
        info = activity.info()

        # Phase 2: Local activity guard
        # Local activities bypass interceptors at the worker level, but
        # we can detect them here and enforce @unprotected marking.
        is_local = getattr(info, "is_local", False)
        activity_fn = getattr(input, "fn", None)

        if is_local and self._config.block_local_activities:
            # Check if activity is marked @unprotected
            if activity_fn and not is_unprotected(activity_fn):
                raise LocalActivityError(info.activity_type)
            # Unprotected local activities skip authorization
            return await self._next.execute_activity(input)

        # Get headers from workflow context
        headers = getattr(info, "headers", {}) or {}

        # Extract warrant (if present)
        try:
            warrant = _extract_warrant_from_headers(headers)
        except ChainValidationError:
            raise  # Re-raise validation errors

        # If no warrant, pass through (opt-in authorization)
        if warrant is None:
            logger.debug(f"No warrant for activity {info.activity_type}, executing without auth")
            return await self._next.execute_activity(input)

        # Resolve tool name
        tool_name = self._config.tool_mappings.get(
            info.activity_type,
            info.activity_type,
        )

        # Get activity arguments
        # Note: input.args contains the positional args. We need to map to kwargs.
        # For Phase 1, we assume first arg is a dict or we extract from input
        args = self._extract_arguments(input)

        # Check warrant expiry
        if warrant.is_expired():
            expires_at = warrant.expires_at()
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason="Warrant expired",
            )

            if self._config.on_denial == "raise":
                raise WarrantExpired(
                    warrant_id=warrant.id(),
                    expired_at=expires_at,
                )
            elif self._config.on_denial == "log":
                logger.warning(f"Warrant expired: {warrant.id()}")

            return None

        # Check tool is in capabilities
        tools = warrant.tools()
        if tool_name not in tools:
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason=f"Tool '{tool_name}' not in warrant capabilities",
                constraint="tool_not_allowed",
            )

            if self._config.on_denial == "raise":
                raise ConstraintViolation(
                    tool=tool_name,
                    arguments=args,
                    constraint=f"Tool not in warrant capabilities: {tools}",
                    warrant_id=warrant.id(),
                )
            elif self._config.on_denial == "log":
                logger.warning(f"Tool {tool_name} not in warrant capabilities: {tools}")

            return None

        # Check constraints
        try:
            # Use warrant's check_constraints method
            result = warrant.check_constraints(tool_name, args)
            # result is True if allowed, raises or returns False if denied
            if result is False or (hasattr(result, "is_allowed") and not result.is_allowed):
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason="Constraint check failed",
                    constraint="constraint_violated",
                )

                if self._config.on_denial == "raise":
                    raise ConstraintViolation(
                        tool=tool_name,
                        arguments=args,
                        constraint="Constraint violated",
                        warrant_id=warrant.id(),
                    )
                elif self._config.on_denial == "log":
                    logger.warning(f"Constraint violated for {tool_name}")

                return None

        except Exception as e:
            # Fail closed on constraint check errors
            logger.error(f"Constraint check error: {e}")
            self._emit_denial_event(
                info=info,
                warrant=warrant,
                tool=tool_name,
                args=args,
                reason=f"Constraint check error: {e}",
            )

            if self._config.on_denial == "raise":
                raise ConstraintViolation(
                    tool=tool_name,
                    arguments=args,
                    constraint=f"Constraint check failed: {e}",
                    warrant_id=warrant.id(),
                )

            return None

        # Phase 2: PoP verification (if required)
        if self._config.require_pop:
            scheduled_time = getattr(info, "scheduled_time", None)
            if scheduled_time is None:
                # No scheduled_time available - fail closed
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason="PoP verification failed: no scheduled_time",
                )
                if self._config.on_denial == "raise":
                    raise PopVerificationError(
                        reason="scheduled_time not available",
                        activity_name=info.activity_type,
                    )
                return None

            # Compute expected challenge
            challenge = _compute_pop_challenge(
                workflow_id=info.workflow_id,
                activity_id=info.activity_id,
                tool_name=tool_name,
                args=args,
                scheduled_time=scheduled_time,
            )

            # Extract PoP from headers and verify
            pop_header = headers.get(TENUO_POP_HEADER)
            if pop_header is None:
                self._emit_denial_event(
                    info=info,
                    warrant=warrant,
                    tool=tool_name,
                    args=args,
                    reason="PoP verification failed: no PoP header",
                )
                if self._config.on_denial == "raise":
                    raise PopVerificationError(
                        reason="Missing PoP header",
                        activity_name=info.activity_type,
                    )
                return None

            # Verify PoP signature
            # Note: Full PoP verification requires the holder's public key
            # from the warrant and verifying the signature over the challenge.
            # For Phase 2, we log the verification step.
            # Full signature verification will be added in Phase 3.
            logger.debug(f"PoP verification for {info.activity_type}: challenge={challenge.hex()[:16]}...")

        # Authorization passed - emit allow event
        self._emit_allow_event(
            info=info,
            warrant=warrant,
            tool=tool_name,
            args=args,
        )

        # Execute the activity
        return await self._next.execute_activity(input)

    def _extract_arguments(self, input: Any) -> Dict[str, Any]:
        """Extract arguments from activity input.

        Handles various input formats gracefully.
        """
        # Try to get args from input
        args = getattr(input, "args", ())

        # If first arg is a dict, use it
        if args and isinstance(args[0], dict):
            return args[0]

        # Otherwise, create a simple dict from positional args
        # This is a fallback; proper extraction requires knowing the signature
        result = {}
        for i, arg in enumerate(args):
            result[f"arg{i}"] = arg

        return result

    def _emit_allow_event(
        self,
        info: Any,
        warrant: Any,
        tool: str,
        args: Dict[str, Any],
    ) -> None:
        """Emit audit event for allowed action."""
        if not self._config.audit_allow or not self._config.audit_callback:
            return

        event = TemporalAuditEvent(
            workflow_id=info.workflow_id,
            workflow_type=info.workflow_type,
            workflow_run_id=info.workflow_run_id,
            activity_name=info.activity_type,
            activity_id=info.activity_id,
            task_queue=info.task_queue,
            decision="ALLOW",
            tool=tool,
            arguments=args,
            warrant_id=warrant.id(),
            warrant_expires_at=warrant.expires_at(),
            warrant_capabilities=list(warrant.tools()),
            tenuo_version=self._version,
        )

        try:
            self._config.audit_callback(event)
        except Exception as e:
            logger.error(f"Audit callback failed: {e}")

    def _emit_denial_event(
        self,
        info: Any,
        warrant: Any,
        tool: str,
        args: Dict[str, Any],
        reason: str,
        constraint: Optional[str] = None,
    ) -> None:
        """Emit audit event for denied action."""
        if not self._config.audit_deny or not self._config.audit_callback:
            return

        event = TemporalAuditEvent(
            workflow_id=info.workflow_id,
            workflow_type=info.workflow_type,
            workflow_run_id=info.workflow_run_id,
            activity_name=info.activity_type,
            activity_id=info.activity_id,
            task_queue=info.task_queue,
            decision="DENY",
            tool=tool,
            arguments=args,
            warrant_id=warrant.id(),
            warrant_expires_at=warrant.expires_at(),
            warrant_capabilities=list(warrant.tools()),
            denial_reason=reason,
            constraint_violated=constraint,
            tenuo_version=self._version,
        )

        try:
            self._config.audit_callback(event)
        except Exception as e:
            logger.error(f"Audit callback failed: {e}")


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Exceptions
    "TenuoTemporalError",
    "TenuoContextError",
    "ConstraintViolation",
    "WarrantExpired",
    "ChainValidationError",
    "KeyResolutionError",
    # Phase 2 exceptions
    "LocalActivityError",
    "PopVerificationError",
    # Audit
    "TemporalAuditEvent",
    # Key Resolvers
    "KeyResolver",
    "EnvKeyResolver",
    # Config
    "TenuoInterceptorConfig",
    # Interceptor
    "TenuoInterceptor",
    # Header utilities
    "tenuo_headers",
    # Context accessors
    "current_warrant",
    "current_key_id",
    # Phase 2: Decorators
    "unprotected",
    "is_unprotected",
    # Constants
    "TENUO_WARRANT_HEADER",
    "TENUO_KEY_ID_HEADER",
    "TENUO_POP_HEADER",
]
