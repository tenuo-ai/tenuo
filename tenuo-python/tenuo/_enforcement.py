"""
Tenuo Enforcement - Shared authorization logic for all integrations.

This module provides the core enforcement primitives used by:
- TenuoMiddleware (LangChain/LangGraph)
- TenuoToolNode (LangGraph legacy)
- guard() decorator (FastAPI, CrewAI)
- SecureMCPClient (MCP)

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    Python Layer                              │
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │ Policy Checks (non-security-critical)                   ││
    │  │ - Application-level tool allowlist (allowed_tools)      ││
    │  │ - Critical tool schema requirements (ToolSchema)        ││
    │  │ - UX tool filtering (filter_tools_by_warrant)           ││
    │  └─────────────────────────────────────────────────────────┘│
    └──────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                    Rust Core (tenuo_core)                    │
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │ Security-Critical Enforcement                           ││
    │  │ - Warrant expiration check                              ││
    │  │ - Tool in warrant (including wildcard *)                ││
    │  │ - Proof-of-Possession signature verification            ││
    │  │ - Constraint satisfaction (Range, Pattern, etc.)        ││
    │  └─────────────────────────────────────────────────────────┘│
    └─────────────────────────────────────────────────────────────┘

IMPORTANT: This module requires BoundWarrant instances. Plain Warrant objects
cannot perform Proof-of-Possession signing and are not accepted.

All cryptographic and security-critical checks are performed by the Rust core.
Python-side checks are for UX/policy only and can be bypassed if needed.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, cast

if TYPE_CHECKING:
    from .approval import ApprovalHandler, ApprovalPolicy

from .bound_warrant import BoundWarrant
from .exceptions import (
    ConfigurationError,
    ConstraintViolation,
    ExpiredError,
    TenuoError,
    ToolNotAuthorized,
)
from .schemas import TOOL_SCHEMAS, ToolSchema
from .validation import ValidationResult

logger = logging.getLogger("tenuo.enforcement")


# =============================================================================
# Result Types
# =============================================================================


@dataclass
class EnforcementResult:
    """
    Result of authorization enforcement.

    Attributes:
        allowed: Whether the tool call is authorized
        tool: Name of the tool that was checked
        arguments: Arguments that were passed to the tool
        denial_reason: Human-readable reason for denial (if not allowed)
        constraint_violated: Which constraint failed (if applicable)
        error_type: Structured error category (e.g. "expired", "tool_not_allowed")
        warrant_id: ID of the warrant for audit correlation
    """

    allowed: bool
    tool: str
    arguments: Dict[str, Any]
    denial_reason: Optional[str] = None
    constraint_violated: Optional[str] = None
    error_type: Optional[str] = None
    warrant_id: Optional[str] = None

    def raise_if_denied(self) -> None:
        """
        Raise appropriate exception if authorization was denied.

        Raises:
            ConstraintViolation: If a specific constraint was violated
            ToolNotAuthorized: If tool is not in warrant or general denial
        """
        if not self.allowed:
            if self.constraint_violated:
                raise ConstraintViolation(
                    field=self.constraint_violated,
                    reason=self.denial_reason or "Constraint violation",
                    value=None,
                )
            else:
                raise ToolNotAuthorized(tool=self.tool)


# =============================================================================
# Denial Handling (shared across integrations)
# =============================================================================


class DenialPolicy:
    """
    How to handle authorization denials.

    Used by all integrations (CrewAI, AutoGen, OpenAI, etc.) for consistent
    denial handling behavior.

    Attributes:
        RAISE: Raise an exception immediately (fail-fast)
        LOG: Log warning and return a denial result (soft failure)
        SKIP: Log at debug level only (silent skip)
    """

    RAISE = "raise"
    LOG = "log"
    SKIP = "skip"


@dataclass
class DenialResult:
    """
    Result returned when authorization is denied (for LOG/SKIP modes).

    This is a framework-agnostic denial result. Integrations may extend this
    or use it directly.

    DenialResult is falsy (bool(denial) == False) to allow patterns like:
        result = guard.check(...)
        if not result:  # True if denied
            handle_denial(result)

    Attributes:
        tool: Name of the tool that was denied
        reason: Human-readable denial reason
        error_type: Machine-readable error category (e.g., "expired", "constraint_violation")
        error_code: Legacy error code for backward compatibility (defaults to error_type or "DENIAL")
        warrant_id: Warrant ID for audit correlation
    """

    tool: str
    reason: str
    error_type: Optional[str] = None
    error_code: str = "DENIAL"
    warrant_id: Optional[str] = None

    def __bool__(self) -> bool:
        """DenialResult is always falsy (represents a denial)."""
        return False

    @classmethod
    def from_enforcement(cls, result: EnforcementResult) -> "DenialResult":
        """Create DenialResult from EnforcementResult."""
        error_code = result.error_type.upper() if result.error_type else "DENIAL"
        return cls(
            tool=result.tool,
            reason=result.denial_reason or "Authorization denied",
            error_type=result.error_type,
            error_code=error_code,
            warrant_id=result.warrant_id,
        )


def handle_denial(
    result: EnforcementResult,
    policy: str,
    exception_factory: Optional[Callable[[EnforcementResult], Exception]] = None,
) -> Optional[DenialResult]:
    """
    Handle an authorization denial according to the specified policy.

    This is the shared denial handler for all integrations. It provides
    consistent behavior for raise/log/skip modes.

    Args:
        result: The EnforcementResult from enforce_tool_call()
        policy: One of DenialPolicy.RAISE, LOG, or SKIP
        exception_factory: Optional factory to create framework-specific exceptions.
            If not provided, uses result.raise_if_denied() which raises
            ToolNotAuthorized or ConstraintViolation.

    Returns:
        DenialResult for LOG/SKIP modes, None if allowed

    Raises:
        Exception from exception_factory (or default) if policy is RAISE

    Example:
        result = enforce_tool_call("delete", {}, bound_warrant)
        if not result.allowed:
            return handle_denial(result, self._on_denial)
    """
    if result.allowed:
        return None

    if policy == DenialPolicy.RAISE:
        if exception_factory:
            raise exception_factory(result)
        else:
            result.raise_if_denied()

    denial = DenialResult.from_enforcement(result)

    if policy == DenialPolicy.LOG:
        logger.warning(
            f"Authorization denied for '{result.tool}': {result.denial_reason}"
        )
    else:  # SKIP
        logger.debug(
            f"Authorization skipped for '{result.tool}': {result.denial_reason}"
        )

    return denial


# =============================================================================
# Internal Helpers
# =============================================================================


def _extract_violated_field(reason: Optional[str]) -> Optional[str]:
    """
    Extract the violated constraint field name from a validation reason.

    Args:
        reason: The validation failure reason string

    Returns:
        Field name if extractable, None otherwise

    Examples:
        "Constraint 'path' not satisfied" -> "path"
        "Range exceeded for 'amount'" -> "amount"
    """
    if not reason:
        return None

    # Common patterns from Tenuo error messages
    patterns = [
        r"Constraint '(\w+)' not satisfied",
        r"'(\w+)' constraint violation",
        r"Range exceeded for '(\w+)'",
        r"Pattern mismatch for '(\w+)'",
        r"field '(\w+)'",
    ]

    for pattern in patterns:
        match = re.search(pattern, reason, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def _get_constraints_dict(bound_warrant: BoundWarrant) -> Dict[str, Any]:
    """
    Extract flattened constraints dict from a BoundWarrant.

    Uses BoundWarrant.constraints_dict() which properly extracts and
    flattens constraints from the warrant's capabilities.

    Args:
        bound_warrant: BoundWarrant instance

    Returns:
        Flattened dictionary of all constraints across tools
    """
    # Use the proper method that handles capabilities correctly
    return bound_warrant.constraints_dict()


def _get_allowed_tools(bound_warrant: BoundWarrant) -> Optional[List[str]]:
    """
    Get list of tools allowed by the warrant (for UX filtering only).

    NOTE: This is used by filter_tools_by_warrant() for UX purposes
    (hiding unauthorized tools from LLM). It is NOT a security boundary.
    The Rust core performs the authoritative tool check in authorize().

    Args:
        bound_warrant: BoundWarrant instance

    Returns:
        List of tool names if restricted, None if all tools allowed.
        Note: Empty list [] means NO tools are allowed (blocks all).
    """
    tools = bound_warrant.tools
    if tools is None:
        return None  # No restriction - all tools allowed
    # Return the list even if empty (empty = block all)
    return list(tools)


# =============================================================================
# Approval Policy Enforcement
# =============================================================================


def _check_approval(
    tool_name: str,
    tool_args: Dict[str, Any],
    bound_warrant: BoundWarrant,
    policy: ApprovalPolicy,
    handler: Optional[ApprovalHandler],
    approvals: Optional[List[Any]] = None,
) -> Optional[EnforcementResult]:
    """Run the approval policy check, obtain approvals, verify via Rust core.

    Resolution order when a rule matches:
      1. ``approvals`` — caller-provided SignedApprovals (spec §6 path)
      2. ``handler``   — inline callback (cli_prompt / auto_approve)
      3. raise ApprovalRequired

    ALL cryptographic verification is delegated to the Rust core via
    ``tenuo_core.verify_approvals()``:
      - Signature validity (verify-before-deserialize)
      - Approver membership in trusted set
      - Request hash binding
      - Expiration with 30-second clock tolerance
      - Duplicate detection (one vote per approver key)
      - DoS protection (max 2x trusted_approvers count)
      - m-of-n threshold (policy.threshold, default 1)

    Error diagnostics from the Rust core:
      - 1-of-1: specific reason (e.g. "approver not in trusted set")
      - m-of-n: rejection summary (e.g. "1 expired, 1 untrusted")

    Returns None to proceed (no rule matched or approval verified).
    Raises ApprovalRequired if no approvals and no handler.
    Raises ApprovalDenied if handler denies.
    Raises ApprovalVerificationError if Rust core rejects the approvals.
    """
    from tenuo_core import (
        py_compute_request_hash as _compute_hash,
    )
    from tenuo_core import (
        verify_approvals as _verify_approvals,
    )

    from .approval import (
        ApprovalRequired,
        ApprovalVerificationError,
    )

    warrant_id = getattr(bound_warrant, "id", None) or ""
    holder_key = getattr(bound_warrant, "holder_key", None)

    request_hash = _compute_hash(warrant_id, tool_name, tool_args, holder_key)

    request = policy.check(tool_name, tool_args, warrant_id, request_hash)
    if request is None:
        return None

    # --- Collect SignedApprovals ---

    collected: List[Any] = []

    # Path 1: caller-provided approvals (spec §6 — the cloud / async path)
    if approvals:
        collected = list(approvals)

    # Path 2: handler callback (local / inline path)
    elif handler is not None:
        result = handler(request)

        if inspect.isawaitable(result):
            coro = cast("Any", result)
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    result = pool.submit(asyncio.run, coro).result()
            else:
                result = asyncio.run(coro)

        # Handler may return a single SignedApproval or a list (for m-of-n)
        if isinstance(result, list):
            collected = result
        else:
            collected = [result]

    # Path 3: nothing available
    else:
        raise ApprovalRequired(request)

    if not collected:
        raise ApprovalRequired(request)

    # --- Cryptographic verification (ALL done in Rust core) ---

    trusted = policy.trusted_approvers
    if trusted is None:
        # No trusted set specified — extract unique keys from the approvals.
        # This is the permissive mode (any valid signature accepted).
        seen_keys: set[bytes] = set()
        trusted = []
        for a in collected:
            key_bytes = bytes(a.approver_key.to_bytes())
            if key_bytes not in seen_keys:
                seen_keys.add(key_bytes)
                trusted.append(a.approver_key)

    threshold = policy.threshold

    try:
        verified_payloads = _verify_approvals(
            request_hash,
            collected,
            trusted,
            threshold,
        )
    except Exception as e:
        raise ApprovalVerificationError(
            request, reason=str(e),
        )

    first_payload = verified_payloads[0] if verified_payloads else None
    external_id = getattr(first_payload, "external_id", "unknown") if first_payload else "unknown"

    logger.info(
        f"Approval verified for '{tool_name}' "
        f"({len(verified_payloads)}/{threshold} approvals, "
        f"approver={external_id}, "
        f"hash={request_hash.hex()[:16]}...)",
        extra={"tool": tool_name, "warrant_id": warrant_id},
    )
    return None


# =============================================================================
# Main Enforcement Function
# =============================================================================

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal  # type: ignore


def enforce_tool_call(
    tool_name: str,
    tool_args: Dict[str, Any],
    bound_warrant: BoundWarrant,
    *,
    allowed_tools: Optional[List[str]] = None,
    schemas: Optional[Dict[str, ToolSchema]] = None,
    require_constraints: bool = False,
    verify_mode: Literal["sign", "verify"] = "sign",
    precomputed_signature: Optional[bytes] = None,
    authorizer: Optional[Any] = None,
    approval_policy: Optional[ApprovalPolicy] = None,
    approval_handler: Optional[ApprovalHandler] = None,
    approvals: Optional[List[Any]] = None,
) -> EnforcementResult:
    """
    Core enforcement logic for tool authorization.

    This is the shared implementation used by all Tenuo integrations.
    It performs:
    1. Tool allowlist checking
    2. Critical tool constraint requirements
    3. PoP-authenticated authorization

    Args:
        tool_name: Name of the tool being called
        tool_args: Arguments passed to the tool
        bound_warrant: BoundWarrant instance (warrant + signing key).
            Must be created via warrant.bind(signing_key).
        allowed_tools: Optional explicit allowlist that overrides warrant.tools.
            Use for scoped_task or per-request tool restrictions.
        schemas: Tool risk schemas for critical tool detection.
            Defaults to TOOL_SCHEMAS (standard tools).
            Tools not in schemas are treated as risk_level="standard".
        require_constraints: If True, require at least one constraint for
            tools marked with require_at_least_one in their schema.
            Default False (only enforces critical tool constraints).
        verify_mode: "sign" (default) to generate PoP signature locally (Local PEP),
            or "verify" to validate a pre-computed signature (Remote PEP/FastAPI).
        precomputed_signature: Required if verify_mode="verify". The PoP signature
            provided by the client.
        authorizer: Required when verify_mode="verify". Authorizer instance for
            full chain verification using Authorizer.check_chain(), which performs
            issuer trust, chain linkage, revocation, clearance, capabilities,
            constraints, and PoP verification in one atomic call.
        approval_policy: Optional ApprovalPolicy to check after warrant authorization.
            If a rule matches, the approval_handler is invoked.
        approval_handler: Callable that handles approval requests and returns a
            SignedApproval. Used for inline/local approval (cli_prompt, auto_approve).
        approvals: List of caller-provided SignedApproval objects (spec §6).
            When a policy rule matches, these are checked first — the first
            approval whose request_hash matches is verified. This is the
            primary path for cloud/async workflows where the approval was
            obtained out-of-band. Takes precedence over approval_handler.

    Returns:
        EnforcementResult with allowed status and denial details.

    Raises:
        ConfigurationError: If bound_warrant is not a BoundWarrant instance.
        ApprovalRequired: If approval_policy triggers but no approvals or handler.
        ApprovalDenied: If the handler denies the request.
        ApprovalVerificationError: If the SignedApproval fails cryptographic
            verification (invalid signature, hash mismatch, untrusted key, expired).

    Example:
        from tenuo import Warrant, SigningKey
        from tenuo._enforcement import enforce_tool_call

        key = SigningKey.generate()
        warrant = Warrant.issue(
            key, capabilities={"search": {}}, ttl_seconds=3600,
            holder=key.public_key,
        )
        bound = warrant.bind(key)

        result = enforce_tool_call(
            tool_name="search",
            tool_args={"query": "AI papers"},
            bound_warrant=bound,
        )

        if result.allowed:
            # Proceed with tool execution
            pass
        else:
            print(f"Denied: {result.denial_reason}")
    """
    # Validate input type
    if not isinstance(bound_warrant, BoundWarrant):
        raise ConfigurationError(
            f"Expected BoundWarrant, got {type(bound_warrant).__name__}. "
            "Use warrant.bind(signing_key) to create a BoundWarrant."
        )

    if verify_mode == "verify":
        if precomputed_signature is None:
            raise ConfigurationError("precomputed_signature is required when verify_mode='verify'")
        if authorizer is None:
            raise ConfigurationError("authorizer is required when verify_mode='verify'")

    # Capture warrant_id for audit correlation (available on all results)
    warrant_id = getattr(bound_warrant, "id", None)

    schemas = schemas or TOOL_SCHEMAS
    schema = schemas.get(tool_name)

    # =========================================================================
    # PYTHON-LEVEL POLICY CHECKS (before Rust core)
    # These are application-level policies, not cryptographic enforcement.
    # =========================================================================

    # 1. Application-level tool allowlist (scoped_task, per-request restrictions)
    #    This RESTRICTS beyond what the warrant allows - it's not a security boundary,
    #    just UX/policy (e.g., "this task can only use search, not delete").
    #    The Rust core will still verify the tool is in the warrant.
    if allowed_tools is not None and tool_name not in allowed_tools:
        logger.debug(f"Tool '{tool_name}' not in application allowed_tools: {allowed_tools}")
        return EnforcementResult(
            allowed=False,
            tool=tool_name,
            arguments=tool_args,
            denial_reason=f"Tool '{tool_name}' not in allowed list for this operation",
            error_type="tool_not_allowed",
            warrant_id=warrant_id,
        )

    # 2. Critical tool policy - require relevant constraints for high-risk tools
    #    This is a Python-side policy decision based on ToolSchema.
    #    The Rust core enforces the actual constraints; this just ensures they exist.
    if schema and schema.risk_level == "critical":
        constraints = _get_constraints_dict(bound_warrant)
        has_relevant = any(c in constraints for c in schema.recommended_constraints)

        if not has_relevant:
            logger.warning(
                f"Critical tool '{tool_name}' invoked without relevant constraints. "
                f"Has: {list(constraints.keys())}, Needs one of: {schema.recommended_constraints}"
            )
            return EnforcementResult(
                allowed=False,
                tool=tool_name,
                arguments=tool_args,
                denial_reason=(
                    f"Critical tool '{tool_name}' requires at least one of: "
                    f"{schema.recommended_constraints}"
                ),
                constraint_violated="missing_constraints",
                error_type="policy_violation",
                warrant_id=warrant_id,
            )

    # 3. Optional strict mode - require constraints for require_at_least_one tools
    if require_constraints and schema and schema.require_at_least_one:
        constraints = _get_constraints_dict(bound_warrant)
        if not constraints:
            return EnforcementResult(
                allowed=False,
                tool=tool_name,
                arguments=tool_args,
                denial_reason=f"Tool '{tool_name}' requires at least one constraint",
                constraint_violated="missing_constraints",
                error_type="policy_violation",
                warrant_id=warrant_id,
            )

    # =========================================================================
    # RUST CORE AUTHORIZATION (cryptographic enforcement)
    # All security-critical checks happen here:
    # - Warrant expiration
    # - Tool in warrant (including wildcard *)
    # - Proof-of-Possession signature
    # - Constraint satisfaction
    # =========================================================================
    try:
        if verify_mode == "sign":
            validation_result: ValidationResult = bound_warrant.validate(tool_name, tool_args)

            if not validation_result.success:
                # Extract detailed failure info from ValidationResult
                violated_field = _extract_violated_field(validation_result.reason)

                logger.debug(
                    f"Authorization denied for {tool_name}: {validation_result.reason}"
                )
                return EnforcementResult(
                    allowed=False,
                    tool=tool_name,
                    arguments=tool_args,
                    denial_reason=validation_result.reason or "Authorization failed",
                    constraint_violated=violated_field,
                    error_type="authorization_failed",
                    warrant_id=warrant_id,
                )
        else:
            # verify_mode == "verify"
            # Full chain verification: issuer trust, chain linkage, revocation,
            # clearance, capabilities, constraints, and PoP — all in one call.
            # Defense in depth: re-check authorizer even though validated above
            if authorizer is None:
                raise ConfigurationError("authorizer required for verify_mode='verify'")
            try:
                authorizer.check_chain(
                    [bound_warrant.warrant],
                    tool_name,
                    tool_args,
                    signature=precomputed_signature,
                )
            except Exception as chain_err:
                denial_reason = str(chain_err)
                error_type = "authorization_failed"
                if bound_warrant.warrant.is_expired():
                    denial_reason = "Warrant has expired"
                    error_type = "expired"
                return EnforcementResult(
                    allowed=False,
                    tool=tool_name,
                    arguments=tool_args,
                    denial_reason=denial_reason,
                    constraint_violated=None,
                    error_type=error_type,
                    warrant_id=warrant_id,
                )

        # Success - log for audit trail
        logger.info(
            f"Tool authorized: {tool_name}",
            extra={
                "tool": tool_name,
                "warrant_id": bound_warrant.id,
                "args_keys": list(tool_args.keys()),
            }
        )

        # =================================================================
        # APPROVAL POLICY CHECK (after warrant authorization)
        # The warrant permits this call. The approval policy may still
        # require a human to confirm before execution proceeds.
        # =================================================================
        if approval_policy is not None:
            approval_result = _check_approval(
                tool_name, tool_args, bound_warrant,
                approval_policy, approval_handler, approvals,
            )
            if approval_result is not None:
                return approval_result

        return EnforcementResult(
            allowed=True,
            tool=tool_name,
            arguments=tool_args,
            warrant_id=warrant_id,
        )

    except (ConstraintViolation, ExpiredError, ToolNotAuthorized) as e:
        # Known authorization failures - expected behavior
        logger.debug(f"Authorization denied for {tool_name}: {e}")

        # Map exceptions to error types (use isinstance, not string matching)
        if isinstance(e, ExpiredError):
            err_type = "expired"
        elif isinstance(e, ToolNotAuthorized):
            err_type = "tool_not_allowed"
        elif isinstance(e, ConstraintViolation):
            err_type = "constraint_violation"
        else:
            err_type = "authorization_failed"

        return EnforcementResult(
            allowed=False,
            tool=tool_name,
            arguments=tool_args,
            denial_reason=str(e),
            constraint_violated=_extract_violated_field(str(e)),
            error_type=err_type,
            warrant_id=warrant_id,
        )
    except TenuoError as e:
        # Other Tenuo errors - log as warning
        logger.warning(f"Tenuo error during authorization for {tool_name}: {e}")
        return EnforcementResult(
            allowed=False,
            tool=tool_name,
            arguments=tool_args,
            denial_reason=str(e),
            error_type="tenuo_error",
            warrant_id=warrant_id,
        )
    except Exception as e:
        from .approval import ApprovalDenied, ApprovalRequired, ApprovalVerificationError
        if isinstance(e, (ApprovalRequired, ApprovalDenied, ApprovalVerificationError)):
            raise

        # Catch-all for unexpected runtime errors (fail closed)
        logger.exception(f"Unexpected error during authorization for {tool_name}")
        return EnforcementResult(
            allowed=False,
            tool=tool_name,
            arguments=tool_args,
            denial_reason=f"Internal enforcement error: {str(e)}",
            error_type="internal_error",
            warrant_id=warrant_id,
        )


# =============================================================================
# Tool Filtering
# =============================================================================


def filter_tools_by_warrant(
    tools: List[Any],
    bound_warrant: BoundWarrant,
    *,
    get_name: Optional[Callable[[Any], str]] = None,
) -> List[Any]:
    """
    Filter tools to only those allowed by warrant.

    Used by middleware to present only authorized tools to the LLM,
    improving accuracy by reducing irrelevant options.

    Args:
        tools: List of tools (any type with .name attribute or custom getter)
        bound_warrant: BoundWarrant instance
        get_name: Optional function to extract tool name from tool object.
            Default: uses tool.name, tool.__name__, or repr(tool) as fallback.

    Returns:
        Filtered list containing only tools in the warrant's allowlist.
        If warrant has no tool restrictions, returns all tools.

    Raises:
        ConfigurationError: If bound_warrant is not a BoundWarrant instance.

    Example:
        from tenuo._enforcement import filter_tools_by_warrant

        all_tools = [search_tool, read_tool, delete_tool]
        # Warrant only allows search and read
        allowed = filter_tools_by_warrant(all_tools, bound_warrant)
        # allowed = [search_tool, read_tool]
    """
    if not isinstance(bound_warrant, BoundWarrant):
        raise ConfigurationError(
            f"Expected BoundWarrant, got {type(bound_warrant).__name__}. "
            "Use warrant.bind(signing_key) to create a BoundWarrant."
        )

    if get_name is None:
        # Robust fallback chain for tool name extraction
        def get_name(t: Any) -> str:
            if hasattr(t, "name"):
                return t.name
            if hasattr(t, "__name__"):
                return t.__name__
            return repr(t)

    allowed = _get_allowed_tools(bound_warrant)

    if allowed is None:
        # No tool restriction - allow all
        logger.debug(f"No tool restrictions in warrant, allowing all {len(tools)} tools")
        return tools

    allowed_set: Set[str] = set(allowed)
    filtered = [t for t in tools if get_name(t) in allowed_set]

    logger.debug(
        f"Filtered {len(tools)} tools to {len(filtered)} based on warrant allowlist"
    )

    return filtered


__all__ = [
    "EnforcementResult",
    "DenialPolicy",
    "DenialResult",
    "enforce_tool_call",
    "filter_tools_by_warrant",
    "handle_denial",
]
