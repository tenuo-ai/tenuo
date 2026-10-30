"""
Tenuo OpenAI Adapter - Multi-Tier Authorization

Provides constraint enforcement for OpenAI API calls with two tiers:

**Tier 1 (Guardrails)**: Runtime constraint checking without cryptography.
    Rejects out-of-policy tool calls in trusted application code. Catches hallucinated tool calls,
    argument constraint violations, and streaming TOCTOU attacks.

**Tier 2 (Warrant + PoP)**: Cryptographic authorization with Proof-of-Possession.
    Use it when a verifier must check signed, holder-bound authority. Each tool call is signed
    with the agent's private key, proving the caller holds the warrant.

Security Philosophy (Fail Closed):
    Tenuo follows a "fail closed" security model. When in doubt, deny:
    - Unknown constraint types are rejected (not silently passed)
    - CEL expressions require Rust bindings (Python fallback denies)
    - Missing constraint attributes cause denial
    - Malformed tool calls are blocked
    - Warrant without signing_key raises MissingSigningKey

    This is intentional. A guardrail that silently passes unknown cases
    is not a guardrail - it's a false sense of security.

Usage (Tier 1 - Builder Pattern, Recommended):
    from tenuo.openai import GuardBuilder, Subpath, Pattern

    client = (GuardBuilder(openai.OpenAI())
        .allow("search")
        .allow("read_file", path=Subpath("/data"))
        .allow("send_email", to=Pattern("*@company.com"))
        .deny("delete_file")
        .build())

    response = client.chat.completions.create(...)

Usage (Tier 1 - Dict Style):
    from tenuo.openai import guard, Pattern

    client = guard(
        openai.OpenAI(),
        allow_tools=["search", "read_file"],
        constraints={"read_file": {"path": Pattern("/data/*")}}
    )
    response = client.chat.completions.create(...)

Usage (Tier 2 - Warrant with PoP):
    from tenuo.openai import GuardBuilder
    from tenuo import SigningKey, Warrant

    # Agent holds the warrant and its signing key
    agent_key = SigningKey.generate()
    warrant = Warrant.mint_builder()...  # From control plane

    client = (GuardBuilder(openai.OpenAI())
        .with_warrant(warrant, agent_key)
        .build())

    response = client.chat.completions.create(...)

Async Support:
    Both sync and async OpenAI clients are supported.
    Async streaming has the same TOCTOU protections.

    async_client = guard(openai.AsyncOpenAI(), warrant=w, signing_key=k)
    response = await async_client.chat.completions.create(...)

OpenAI Agents SDK Integration:
    guard_agent() checks every tool call an OpenAI Agents SDK agent makes:

    from agents import Agent
    from tenuo.openai import guard_agent, Pattern

    agent = guard_agent(
        Agent(name="Assistant", tools=[send_email]),
        constraints={"send_email": {"to": Pattern("*@company.com")}},
    )

    For Tier 2 (warrant-based), pass warrant=, signing_key= and trusted_roots=.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import logging
import time
import weakref
import threading
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Tuple,
    Union,
)
# Import constraint types from tenuo core
from tenuo import (
    CEL,
    All,
    AnyOf,
    Cidr,
    Contains,
    Exact,
    Not,
    NotOneOf,
    OneOf,
    Pattern,
    Range,
    Regex,
    SigningKey,
    Subset,
    UrlPattern,
    # Tier 2: Warrant types
    Warrant,
    Wildcard,
)

# Check version compatibility on import (warns, doesn't fail)
from tenuo._version_compat import check_openai_compat

# Import Python-only security constraints (defined in constraints.py, re-exported here)
from tenuo.constraints import Subpath, UrlSafe

check_openai_compat()

# Import shared enforcement logic (after version check)
from tenuo._enforcement import (  # noqa: E402
    DenialPolicy,
    EnforcementResult,
    enforce_tool_call,
    enforce_tool_call_async,
    handle_denial,
    split_presented_warrant,
)
from tenuo.config import resolve_trusted_roots  # noqa: E402
from tenuo.exceptions import InsufficientApprovals  # noqa: E402

logger = logging.getLogger("tenuo.openai")


def _raise_for_enforcement_denial(tool_name: str, result: EnforcementResult) -> None:
    """Map an ``EnforcementResult`` denial to a typed OpenAI adapter exception."""
    if result.error_type == "expired":
        raise WarrantDenied(tool_name, "warrant expired")
    if result.error_type == "insufficient_approvals":
        meta = result.approval_metadata or {}
        raise InsufficientApprovals(
            required=meta.get("need", 0),
            received=meta.get("got", 0),
            detail=result.denial_reason or "",
        )
    if result.error_type == "constraint_violation":
        raise WarrantDenied(tool_name, result.denial_reason or "constraint violation")
    if result.error_type == "tool_not_allowed":
        raise WarrantDenied(tool_name, result.denial_reason or "tool not in warrant")
    if result.error_type == "invalid_pop":
        raise WarrantDenied(tool_name, result.denial_reason or "invalid proof-of-possession")
    raise WarrantDenied(tool_name, result.denial_reason or "not authorized by warrant")


def enable_debug(handler: Optional[logging.Handler] = None) -> None:
    """Enable debug logging for Tenuo OpenAI adapter.

    This shows detailed authorization decisions, constraint checks,
    and PoP signature operations. Useful for troubleshooting.

    Args:
        handler: Optional custom handler. If None, logs to stderr.

    Example::

        from tenuo.openai import enable_debug
        enable_debug()
        # Now all authorization decisions are logged
        client.chat.completions.create(...)
        # DEBUG:tenuo.openai:Verifying tool call: read_file
        # DEBUG:tenuo.openai:Constraint check: path=/data/file.txt against Pattern(/data/*)
        # DEBUG:tenuo.openai:Authorization granted
    """
    logger.setLevel(logging.DEBUG)
    if handler is None:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
    if not logger.handlers:
        logger.addHandler(handler)


# Type alias for constraint types (including Subpath, UrlSafe - imported from tenuo.constraints)
Constraint = Union[
    Pattern,
    Exact,
    OneOf,
    Range,
    Regex,
    Cidr,
    UrlPattern,
    Contains,
    Subset,
    Wildcard,
    AnyOf,
    All,
    Not,
    NotOneOf,
    CEL,
    Subpath,  # Python-only constraint
    "UrlSafe",  # Python-only SSRF-safe constraint
]


# Denial modes
DenialMode = Literal["raise", "skip", "log"]


# =============================================================================
# Exceptions
# =============================================================================


class TenuoOpenAIError(Exception):
    """Base exception for Tenuo OpenAI adapter errors."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


class ToolDenied(TenuoOpenAIError):
    """Raised when a tool call is denied by the guardrail.

    This error includes a quick-fix suggestion to help resolve the issue.
    """

    def __init__(
        self,
        tool_name: str,
        reason: str,
        code: str = "T1_001",
        *,
        quick_fix: Optional[str] = None,
        param: Optional[str] = None,
        value: Any = None,
    ):
        # Build helpful message with quick fix
        msg = f"Tool '{tool_name}' denied: {reason}"

        if quick_fix:
            msg += f"\n\n  Quick fix: {quick_fix}"
        elif "not in allowlist" in reason.lower():
            msg += f'\n\n  Quick fix: Add .allow("{tool_name}") to your GuardBuilder'
        elif "denylist" in reason.lower():
            msg += f'\n\n  Quick fix: Remove "{tool_name}" from your denylist'
        elif param and "constraint" in reason.lower():
            msg += f"\n\n  Quick fix: Check the constraint for '{param}' parameter"

        msg += "\n  Docs: https://tenuo.ai/docs/openai"

        super().__init__(msg, code)
        self.tool_name = tool_name
        self.reason = reason
        self.quick_fix = quick_fix
        self.param = param
        self.value = value


class WarrantDenied(TenuoOpenAIError):
    """Raised when a tool call is denied by the cryptographic warrant (Tier 2).

    This indicates the warrant does not authorize this tool invocation.
    The denial may be due to:
    - Tool not in warrant's capability list
    - Argument constraint violation
    - Invalid/missing Proof-of-Possession signature
    - Warrant expiration
    """

    def __init__(
        self,
        tool_name: str,
        reason: str,
        code: str = "T2_001",
        *,
        param: Optional[str] = None,
        constraint_type: Optional[str] = None,
    ):
        # Build helpful message
        msg = f"Warrant denied tool '{tool_name}': {reason}"

        if param and constraint_type:
            msg += f"\n\n  The '{param}' argument violated a {constraint_type} constraint."
            msg += "\n  This means the value you passed is outside what the warrant allows."
        elif "not in" in reason.lower() or "not authorized" in reason.lower():
            msg += "\n\n  The warrant doesn't include this tool in its capabilities."
            msg += "\n  Request a new warrant with this tool included."

        msg += "\n  Docs: https://tenuo.ai/docs/warrants"

        super().__init__(msg, code)
        self.tool_name = tool_name
        self.reason = reason
        self.param = param
        self.constraint_type = constraint_type


class MissingSigningKey(TenuoOpenAIError):
    """Raised when Tier 2 warrant is provided but no signing key.

    Warrants require Proof-of-Possession signatures, which need a signing key.
    Either provide a signing_key parameter or use Tier 1 guardrails instead.
    """

    def __init__(self):
        super().__init__(
            "Warrant provided without signing_key. "
            "Tier 2 requires a signing key for Proof-of-Possession. "
            "Either add signing_key=... or remove the warrant for Tier 1 only.",
            "T2_002",
        )


class OpenAIConfigurationError(TenuoOpenAIError):
    """Raised when guard() configuration is invalid.

    Common causes:
    - signing_key doesn't match warrant's authorized_holder
    - Warrant is expired before first use
    - Conflicting Tier 1 and Tier 2 settings

    Use client.validate() to catch these errors early.
    """

    pass


# =============================================================================
# Audit Support
# =============================================================================


@dataclass
class AuditEvent:
    """Record of an authorization decision.

    Use with audit_callback to log all decisions for compliance/debugging.

    Attributes:
        session_id: Unique ID for this guard() instance
        timestamp: Unix timestamp of the decision
        tool_name: Name of the tool being authorized
        arguments: Tool arguments (may be redacted)
        decision: "ALLOW" or "DENY"
        reason: Why the decision was made
        tier: "tier1" or "tier2"
        constraint_hash: Hash of Tier 1 constraints for tamper detection
        warrant_id: Warrant ID if Tier 2 is active (for audit correlation)
    """

    session_id: str
    timestamp: float
    tool_name: str
    arguments: Dict[str, Any]
    decision: str  # "ALLOW" or "DENY"
    reason: str
    tier: str  # "tier1" or "tier2"
    constraint_hash: Optional[str] = None
    warrant_id: Optional[str] = None


# Type alias for audit callback
AuditCallback = Callable[[AuditEvent], None]


def _compute_constraint_hash(
    allow_tools: Optional[List[str]],
    deny_tools: Optional[List[str]],
    constraints: Optional[Dict[str, Dict[str, Any]]],
) -> str:
    """Compute SHA-256 hash of constraint configuration.

    This hash can be logged/stored to prove the constraints weren't
    modified between when the client was created and when a call was made.
    """
    # Serialize to canonical JSON
    config = {
        "allow_tools": sorted(allow_tools) if allow_tools else None,
        "deny_tools": sorted(deny_tools) if deny_tools else None,
        "constraints": _serialize_constraints(constraints) if constraints else None,
    }
    canonical = json.dumps(config, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _serialize_constraints(constraints: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    """Serialize constraints to a hashable format."""
    result: Dict[str, Dict[str, str]] = {}
    for tool, params in sorted(constraints.items()):
        result[tool] = {}
        for param, constraint in sorted(params.items()):
            # Include both type and value for proper differentiation
            constraint_repr = str(constraint)  # Uses __repr__ which includes value
            result[tool][param] = f"{type(constraint).__name__}:{constraint_repr}"
    return result


class OpenAIConstraintViolation(TenuoOpenAIError):
    """Raised when a tool argument violates a constraint.

    Attributes:
        tool_name: Name of the tool that was called
        param: The parameter that violated the constraint
        value: The actual value that was passed
        constraint: The constraint that was violated
        type_mismatch: True if the violation was due to wrong type (e.g., string to Range)
        reason: Human-readable explanation of why it failed
    """

    def __init__(
        self,
        tool_name: str,
        param: str,
        value: Any,
        constraint: Constraint,
        type_mismatch: bool = False,
        reason: Optional[str] = None,
    ):
        self.tool_name = tool_name
        self.param = param
        self.value = value
        self.constraint = constraint
        self.type_mismatch = type_mismatch

        # Generate clear, actionable error message
        if reason:
            self.reason = reason
        elif type_mismatch:
            expected = _constraint_expected_type(constraint)
            self.reason = f"expected {expected}, got {type(value).__name__}"
        else:
            # Constraint representations can contain policy values.  In
            # particular, NotOneOf([value]) can echo the rejected value back
            # into logs, model-visible denial text, and control-plane events.
            self.reason = f"value does not satisfy {type(constraint).__name__} constraint"

        # The value stays on the exception for callers, but never in its text:
        # the message is logged, returned to the model, and sent as a denial
        # reason to the control plane.
        message = f"Tool '{tool_name}' argument '{param}': {self.reason}"
        super().__init__(message, "T1_002")


def _constraint_expected_type(constraint: Constraint) -> str:
    """Return human-readable expected type for a constraint."""
    constraint_type = type(constraint).__name__
    if constraint_type == "Range":
        return "numeric type (int/float)"
    elif constraint_type == "Cidr":
        return "valid IP address"
    elif constraint_type == "UrlPattern":
        return "valid URL"
    elif constraint_type == "UrlSafe":
        return "valid safe URL (no SSRF)"
    elif constraint_type == "Subpath":
        return "valid absolute path"
    elif constraint_type in ("Contains", "Subset"):
        return "list/set/tuple"
    elif constraint_type in ("Pattern", "Regex", "Exact"):
        return "string"
    else:
        return "compatible type"


def _loads_tool_arguments(raw: str) -> Any:
    """Parse a tool-argument JSON string, rejecting a repeated key."""
    from tenuo.arguments import parse_strict_json

    return parse_strict_json(raw)


class MalformedToolCall(TenuoOpenAIError):
    """Raised when a tool call has invalid JSON arguments."""

    def __init__(self, tool_name: str, error: str):
        super().__init__(f"Malformed tool call '{tool_name}': {error}", "T1_003")
        self.tool_name = tool_name
        self.error = error


class BufferOverflow(TenuoOpenAIError):
    """Raised when streaming buffer exceeds limit."""

    def __init__(self, tool_name: str, size: int, limit: int):
        super().__init__(f"Tool call '{tool_name}' buffer overflow: {size} bytes exceeds {limit} byte limit", "T1_004")
        self.tool_name = tool_name
        self.size = size
        self.limit = limit


# Import shared constraint checking logic from framework-agnostic core
from tenuo.core import check_constraint  # noqa: E402


def verify_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    allow_tools: Optional[List[str]],
    deny_tools: Optional[List[str]],
    constraints: Optional[Dict[str, Dict[str, Constraint]]],
    warrant: Optional[Warrant] = None,
    signing_key: Optional[SigningKey] = None,
    trusted_roots: Optional[list] = None,
    approval_handler: Optional[Any] = None,
    approvals: Optional[list] = None,
    *,
    warrant_chain: Optional[List[Warrant]] = None,
) -> None:
    """Verify a tool call against guardrails and/or warrant.

    Tier 1 (guardrails): Uses allow_tools, deny_tools, constraints
        - Runtime checks only, no cryptography
        - Local policy enforced in trusted application code

    Tier 2 (warrant + signing_key): Cryptographic authorization
        - Signs Proof-of-Possession (PoP) with holder's key
        - Verifies warrant constraints AND PoP signature
        - Use when a verifier must check signed, holder-bound authority

    Defense in depth when both tiers are configured:
        - Tier 1 allow/deny lists ALWAYS apply (even with warrant)
        - Tier 2 constraints OVERRIDE Tier 1 constraints (warrant is authoritative)

    This means: warrant.constraints take precedence over the constraints parameter,
    but a tool in deny_tools will still be blocked even if the warrant allows it.

    Args:
        tool_name: Name of the tool being called
        arguments: Tool arguments as dict
        allow_tools: Tier 1 - Allowlist of tool names (checked even with warrant)
        deny_tools: Tier 1 - Denylist of tool names (checked even with warrant)
        constraints: Tier 1 - Per-tool argument constraints (skipped if warrant present)
        warrant: Tier 2 - Cryptographic warrant (its constraints take precedence).
            May also be the whole delegation chain as one token: an encoded
            WarrantStack string or a root-first list of warrants (leaf last).
        signing_key: Tier 2 - Key for PoP signature (REQUIRED if warrant provided)
        warrant_chain: Tier 2 - Parent warrants of a delegated ``warrant``,
            root-first and excluding the leaf, so the chain verifies back to a
            trusted root without ``chain_scope``.

    Raises:
        ToolDenied: If tool is not allowed (Tier 1 allow/deny lists)
        WarrantDenied: If warrant doesn't authorize the call (Tier 2)
        OpenAIConstraintViolation: If argument violates constraint (Tier 1, only when no warrant)
        MissingSigningKey: If warrant provided without signing_key
    """
    # ==========================================================================
    # Tier 2: Warrant-based authorization (cryptographic)
    # ==========================================================================
    warrant, warrant_chain = split_presented_warrant(warrant, warrant_chain)
    if warrant is not None:
        logger.debug(f"Tier 2: Verifying tool '{tool_name}' with warrant")

        if signing_key is None:
            logger.debug("Tier 2: Missing signing_key for PoP")
            raise MissingSigningKey()

        # Bind warrant to create BoundWarrant for enforce_tool_call
        bound_warrant = warrant.bind(signing_key)

        # Use shared enforcement logic
        result = enforce_tool_call(
            tool_name=tool_name,
            tool_args=arguments,
            bound_warrant=bound_warrant,
            trusted_roots=resolve_trusted_roots(trusted_roots),
            approval_handler=approval_handler,
            approvals=approvals,
            warrant_chain=warrant_chain,
        )

        if not result.allowed:
            logger.debug(f"Tier 2: Authorization DENIED for '{tool_name}'")
            _raise_for_enforcement_denial(tool_name, result)
        else:
            logger.debug(f"Tier 2: Authorization GRANTED for '{tool_name}'")

    # ==========================================================================
    # Tier 1: Guardrail-based authorization (runtime checks)
    # ==========================================================================
    logger.debug(f"Tier 1: Checking guardrails for '{tool_name}'")

    # Check denylist first
    if deny_tools and tool_name in deny_tools:
        raise ToolDenied(tool_name, "Tool is in denylist")

    # Check allowlist
    if allow_tools is not None and tool_name not in allow_tools:
        raise ToolDenied(tool_name, "Tool not in allowlist")

    # Check Tier 1 constraints only if no warrant present.
    # When warrant exists, its constraints are authoritative (cryptographically signed).
    # Checking both would be redundant and potentially conflicting.
    if warrant is None and constraints and tool_name in constraints:
        tool_constraints = constraints[tool_name]
        # Check for _allow_unknown opt-out (default: Zero Trust = reject unknown)
        allow_unknown = tool_constraints.get("_allow_unknown", False)

        # Iterate over arguments to ensure we catch UNKNOWN arguments (Zero Trust)
        for arg_name, value in arguments.items():
            try:
                if arg_name in tool_constraints:
                    constraint = tool_constraints[arg_name]

                    # Skip meta-params like _allow_unknown
                    if arg_name.startswith("_"):
                        continue

                    # Check compatibility and validity
                    type_mismatch, reason = _check_type_compatibility(constraint, value)
                    if type_mismatch:
                        raise OpenAIConstraintViolation(
                            tool_name, arg_name, value, constraint, type_mismatch=True, reason=reason
                        )

                    if not check_constraint(constraint, value):
                        raise OpenAIConstraintViolation(tool_name, arg_name, value, constraint)
                elif not allow_unknown:
                    # Arg not in constraints -> UNKNOWN argument.
                    # Zero Trust (default): Reject it.
                    raise OpenAIConstraintViolation(
                        tool_name,
                        arg_name,
                        value,
                        constraint=Wildcard(),  # Dummy for error
                        reason=f"Unknown argument '{arg_name}' - not in constraints (set _allow_unknown=True to permit)",
                    )
                # else: allow_unknown=True, so we skip unknown args
            except OpenAIConstraintViolation:
                raise
            except Exception as e:
                # Fail Closed: Internal error during validation = DENY
                logger.error(
                    "Internal validation error for %s.%s: %s",
                    tool_name,
                    arg_name,
                    type(e).__name__,
                )
                raise OpenAIConstraintViolation(
                    tool_name,
                    arg_name,
                    value,
                    constraint=Wildcard(),
                    reason=f"internal validation error ({type(e).__name__})",
                )


async def verify_tool_call_async(
    tool_name: str,
    arguments: Dict[str, Any],
    allow_tools: Optional[List[str]],
    deny_tools: Optional[List[str]],
    constraints: Optional[Dict[str, Dict[str, Constraint]]],
    warrant: Optional[Warrant] = None,
    signing_key: Optional[SigningKey] = None,
    trusted_roots: Optional[list] = None,
    approval_handler: Optional[Any] = None,
    approvals: Optional[list] = None,
    *,
    warrant_chain: Optional[List[Warrant]] = None,
) -> None:
    """Async variant of verify_tool_call — uses enforce_tool_call_async for Tier 2.

    Required for async streaming paths so approval handlers can be awaited.
    See verify_tool_call for full documentation.
    """
    warrant, warrant_chain = split_presented_warrant(warrant, warrant_chain)
    if warrant is not None:
        if signing_key is None:
            raise MissingSigningKey()

        bound_warrant = warrant.bind(signing_key)

        result = await enforce_tool_call_async(
            tool_name=tool_name,
            tool_args=arguments,
            bound_warrant=bound_warrant,
            trusted_roots=resolve_trusted_roots(trusted_roots),
            approval_handler=approval_handler,
            approvals=approvals,
            warrant_chain=warrant_chain,
        )

        if not result.allowed:
            _raise_for_enforcement_denial(tool_name, result)

    if deny_tools and tool_name in deny_tools:
        raise ToolDenied(tool_name, "Tool is in denylist")

    if allow_tools is not None and tool_name not in allow_tools:
        raise ToolDenied(tool_name, "Tool not in allowlist")

    if warrant is None and constraints and tool_name in constraints:
        tool_constraints = constraints[tool_name]
        allow_unknown = tool_constraints.get("_allow_unknown", False)

        for arg_name, value in arguments.items():
            try:
                if arg_name in tool_constraints:
                    constraint = tool_constraints[arg_name]
                    if arg_name.startswith("_"):
                        continue
                    type_mismatch, reason = _check_type_compatibility(constraint, value)
                    if type_mismatch:
                        raise OpenAIConstraintViolation(
                            tool_name, arg_name, value, constraint, type_mismatch=True, reason=reason
                        )
                    if not check_constraint(constraint, value):
                        raise OpenAIConstraintViolation(tool_name, arg_name, value, constraint)
                elif not allow_unknown:
                    raise OpenAIConstraintViolation(
                        tool_name, arg_name, value,
                        constraint=Wildcard(),
                        reason=f"Unknown argument '{arg_name}' - not in constraints",
                    )
            except OpenAIConstraintViolation:
                raise
            except Exception as e:
                raise OpenAIConstraintViolation(
                    tool_name,
                    arg_name,
                    value,
                    constraint=Wildcard(),
                    reason=f"internal validation error ({type(e).__name__})",
                )


def _check_type_compatibility(constraint: Constraint, value: Any) -> tuple:
    """Check if value type is compatible with constraint.

    Returns:
        (is_mismatch: bool, reason: str or None)
    """
    constraint_type = type(constraint).__name__

    if constraint_type == "Range":
        if not isinstance(value, (int, float)):
            return True, f"Range requires numeric type (int/float), got {type(value).__name__}"

    elif constraint_type == "Cidr":
        if not isinstance(value, str):
            return True, f"Cidr requires string IP address, got {type(value).__name__}"

    elif constraint_type in ("Contains", "Subset"):
        if not isinstance(value, (list, set, tuple)):
            return True, f"{constraint_type} requires list/set/tuple, got {type(value).__name__}"

    return False, None


# =============================================================================
# Tool Call Processing
# =============================================================================


@dataclass
class ToolCallBuffer:
    """Buffer for accumulating streaming tool call chunks.

    Security: This buffer holds ALL data until verification is complete.
    No data is released to the consumer until verified.
    """

    id: str
    name: str = ""
    arguments_buffer: str = ""
    chunks: List[Any] = field(default_factory=list)  # Raw chunks to emit after verification
    is_complete: bool = False
    # "function", "custom" (freeform input), or another tool call type
    kind: str = "function"

    def append_arguments(self, chunk: str) -> None:
        self.arguments_buffer += chunk

    def add_chunk(self, chunk: Any) -> None:
        """Buffer a chunk for later emission after verification."""
        self.chunks.append(chunk)

    def get_arguments(self) -> Dict[str, Any]:
        """Parse accumulated arguments as JSON (custom tools: ``{"input": ...}``)."""
        if self.kind == "custom":
            return {"input": self.arguments_buffer}
        if not self.arguments_buffer:
            return {}
        try:
            return _loads_tool_arguments(self.arguments_buffer)
        except ValueError as e:
            raise MalformedToolCall(self.name, str(e))

    def size(self) -> int:
        return len(self.arguments_buffer.encode("utf-8"))


def _field(obj: Any, name: str) -> Any:
    """Read ``name`` from a model or a raw dict (unknown SDK fields stay dicts)."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _stream_index(obj: Any) -> int:
    """Index of a streamed choice or tool call delta (0 when absent)."""
    if isinstance(obj, dict):
        if "index" not in obj:
            return 0
        index = obj["index"]
    else:
        fields_set = getattr(obj, "model_fields_set", None)
        if fields_set is None:
            fields_set = getattr(obj, "__fields_set__", None)
        if fields_set is not None and "index" not in fields_set:
            return 0
        missing = object()
        index = getattr(obj, "index", missing)
        if index is missing:
            return 0

    # An omitted index uses the backwards-compatible default above, but an
    # explicit null is malformed. Treating it as zero would alias it with a
    # real index-0 call in the authorization buffer.
    if index is None:
        raise MalformedToolCall("", "stream index must be a non-negative integer")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise MalformedToolCall("", "stream index must be a non-negative integer")
    return index


# Buffer key slot for a legacy ``function_call`` delta (``functions=`` API),
# which has no tool call index. Real indexes are validated as non-negative.
_LEGACY_FUNCTION_CALL = -1


def _plain_args(obj: Any) -> Dict[str, Any]:
    """Turn a tool call payload (model, dict or object) into an argument dict."""
    if obj is None:
        return {}
    if hasattr(obj, "model_dump"):
        data = obj.model_dump(exclude_none=True)
    elif isinstance(obj, dict):
        data = {k: v for k, v in obj.items() if v is not None}
    elif hasattr(obj, "__dict__"):
        data = {k: v for k, v in vars(obj).items() if v is not None and not k.startswith("_")}
    else:
        return {"value": obj}
    return data if isinstance(data, dict) else {"value": data}


def _require_explicit_allow(
    tool_name: str,
    kind: str,
    allow_tools: Optional[List[str]],
    warrant: Optional[Warrant],
) -> None:
    """Non-function tool calls (custom, shell, patch, computer...) need an explicit grant.

    A denylist alone never authorizes them: Tier 1 needs the name in
    ``allow_tools``; Tier 2 checks the name against the warrant.
    """
    if kind == "function" or warrant is not None:
        return
    if allow_tools is None or tool_name not in allow_tools:
        raise ToolDenied(
            tool_name,
            f"'{kind}' tool calls must be explicitly allowed",
            quick_fix=f'Add .allow("{tool_name}") to your GuardBuilder',
        )


def _chat_tool_call_parts(tool_call: Any) -> Tuple[str, str, Optional[str]]:
    """Return (name, kind, raw_input) for a chat completion tool call."""
    call_type = getattr(tool_call, "type", None)
    func = getattr(tool_call, "function", None)
    if func is not None and not (isinstance(call_type, str) and call_type != "function"):
        return getattr(func, "name", "") or "", "function", getattr(func, "arguments", None)
    custom = _field(tool_call, "custom")
    if custom is not None:
        return _field(custom, "name") or "", "custom", _field(custom, "input") or ""
    kind = call_type if isinstance(call_type, str) and call_type else "unknown"
    return kind, kind, None


# Fields that describe a Responses output item rather than what it asks the app to do.
_RESPONSE_ITEM_META = frozenset({"id", "call_id", "type", "status", "caller", "created_by"})


def _is_app_executed_item(item: Any) -> bool:
    """Whether a Responses output item asks the application to run something.

    Items carrying a ``call_id`` (function_call, custom_tool_call, local_shell_call,
    shell_call, apply_patch_call, computer_call, ...) are executed by the app and
    must be authorized. Hosted tool items (web/file search, code interpreter,
    image generation, MCP) run on OpenAI's side and have no ``call_id``.
    """
    item_type = getattr(item, "type", None)
    if not isinstance(item_type, str):
        return False
    if item_type == "function_call":
        return True
    if item_type == "tool_search_call":
        # Tool search can run either on OpenAI's servers or in the client. A
        # client-executed call is actionable even when the SDK omits call_id.
        return getattr(item, "execution", None) == "client"
    if item_type.endswith("_output"):
        return False
    return bool(getattr(item, "call_id", None))


def _responses_item_parts(item: Any) -> Tuple[str, str, Dict[str, Any]]:
    """Return (tool_name, kind, arguments) for an app-executed Responses item.

    Raises MalformedToolCall for unparseable function_call arguments.
    """
    item_type = item.type
    if item_type == "function_call":
        tool_name = getattr(item, "name", "") or ""
        args_str = getattr(item, "arguments", "{}") or "{}"
        try:
            arguments = _loads_tool_arguments(args_str) if args_str else {}
        except ValueError as e:
            raise MalformedToolCall(tool_name, str(e))
        return tool_name, "function", arguments
    if item_type == "custom_tool_call":
        return getattr(item, "name", "") or "", "custom", {"input": getattr(item, "input", "") or ""}
    # local_shell_call -> "local_shell", shell_call -> "shell", apply_patch_call ->
    # "apply_patch", computer_call -> "computer"; arguments are the action/operation.
    tool_name = item_type[: -len("_call")] if item_type.endswith("_call") else item_type
    payload = getattr(item, "action", None) or getattr(item, "operation", None)
    if payload is not None:
        return tool_name, item_type, _plain_args(payload)
    arguments = {k: v for k, v in _plain_args(item).items() if k not in _RESPONSE_ITEM_META}
    return tool_name, item_type, arguments


# =============================================================================
# Guarded Client
# =============================================================================


class GuardedCompletions:
    """Wrapped completions endpoint with guardrails.

    Supports both Tier 1 (guardrails) and Tier 2 (warrant + PoP) protection.
    """

    def __init__(
        self,
        original: Any,
        allow_tools: Optional[List[str]],
        deny_tools: Optional[List[str]],
        constraints: Optional[Dict[str, Dict[str, Constraint]]],
        on_denial: DenialMode,
        stream_buffer_limit: int,
        warrant: Optional[Warrant] = None,
        signing_key: Optional[SigningKey] = None,
        audit_callback: Optional[AuditCallback] = None,
        session_id: Optional[str] = None,
        constraint_hash: Optional[str] = None,
        approval_handler: Optional[Any] = None,
        approvals: Optional[list] = None,
        trusted_roots: Optional[list] = None,
        warrant_chain: Optional[List[Warrant]] = None,
    ):
        self._original = original
        self._allow_tools = allow_tools
        self._deny_tools = deny_tools
        self._constraints = constraints
        self._on_denial = on_denial
        self._stream_buffer_limit = stream_buffer_limit
        warrant, warrant_chain = split_presented_warrant(warrant, warrant_chain)
        self._warrant = warrant
        self._warrant_chain = warrant_chain
        self._signing_key = signing_key
        self._audit_callback = audit_callback
        self._session_id = session_id or str(uuid.uuid4())[:8]
        self._constraint_hash = constraint_hash
        self._approval_handler = approval_handler
        self._approvals = approvals
        self._trusted_roots = trusted_roots
        # Freeze warrant_id at init time for consistent audit trail
        self._warrant_id = warrant.id if warrant and hasattr(warrant, "id") else None

        from .control_plane import get_or_create
        self._control_plane = get_or_create()

    def create(self, *args, **kwargs) -> Any:
        """Wrapped create method with guardrails.

        Works with both sync and async clients. On an async client the
        underlying create() returns an awaitable; we return a coroutine that
        awaits it and verifies the result, so the raw (unverified) awaitable
        never reaches the caller.
        """
        stream = kwargs.get("stream", False)
        result = self._original.create(*args, **kwargs)

        if inspect.isawaitable(result):
            return self._guard_awaitable(result, stream)
        if stream:
            # Return guarded stream
            return self._guard_stream(result)
        # Non-streaming: verify after response
        return self._guard_response(result)

    def parse(self, *args, **kwargs) -> Any:
        """Wrapped structured-output parse(); tool calls are verified like create()."""
        result = self._original.parse(*args, **kwargs)
        if inspect.isawaitable(result):
            return self._guard_awaitable(result, False)
        return self._guard_response(result)

    async def _guard_awaitable(self, awaitable: Any, stream: bool) -> Any:
        """Await an async client result, then apply the async guards."""
        result = await awaitable
        if stream:
            return self._guard_stream_async(result)
        return self._guard_response(result)

    def _guard_response(self, response: Any) -> Any:
        """Verify tool calls in a non-streaming response."""
        if not hasattr(response, "choices") or not response.choices:
            return response

        for choice in response.choices:
            if not hasattr(choice, "message") or not choice.message:
                continue

            message = choice.message
            # Legacy ``functions=`` API: one call on message.function_call.
            function_call = getattr(message, "function_call", None)
            if function_call:
                try:
                    self._verify_call(
                        getattr(function_call, "name", None) or "",
                        "function",
                        getattr(function_call, "arguments", None),
                    )
                except (ToolDenied, WarrantDenied, OpenAIConstraintViolation, MalformedToolCall) as e:
                    self._handle_denial(e)
                    if self._on_denial == "raise":
                        raise
                    message.function_call = None

            if not hasattr(message, "tool_calls") or not message.tool_calls:
                continue

            # Filter/verify tool calls
            verified_calls = []
            for tool_call in message.tool_calls:
                try:
                    self._verify_single_tool_call(tool_call)
                    verified_calls.append(tool_call)
                except (ToolDenied, WarrantDenied, OpenAIConstraintViolation, MalformedToolCall) as e:
                    self._handle_denial(e)
                    if self._on_denial == "raise":
                        raise
                    # skip or log: exclude from results

            # Update message with verified calls only
            if self._on_denial != "raise":
                message.tool_calls = verified_calls if verified_calls else None

        return response

    def _verify_single_tool_call(self, tool_call: Any) -> None:
        """Verify a single tool call (function, custom, or any other type)."""
        tool_name, kind, raw = _chat_tool_call_parts(tool_call)
        self._verify_call(tool_name, kind, raw)

    @staticmethod
    def _call_arguments(tool_name: str, kind: str, raw: Optional[str]) -> Dict[str, Any]:
        """Turn a chat tool call's raw input into the argument dict to authorize."""
        if not tool_name:
            raise MalformedToolCall(tool_name, "tool call has no name")
        if kind == "custom":
            return {"input": raw or ""}
        if kind != "function":
            raise ToolDenied(tool_name, f"unsupported tool call type '{kind}'")
        try:
            return _loads_tool_arguments(raw) if raw else {}
        except ValueError as e:
            raise MalformedToolCall(tool_name, str(e))

    def _verify_call(self, tool_name: str, kind: str, raw: Optional[str]) -> None:
        """Authorize one chat tool call and audit the decision (allow or deny)."""
        arguments: Dict[str, Any] = {}
        try:
            arguments = self._call_arguments(tool_name, kind, raw)
            _require_explicit_allow(tool_name, kind, self._allow_tools, self._warrant)
            verify_tool_call(
                tool_name,
                arguments,
                self._allow_tools,
                self._deny_tools,
                self._constraints,
                self._warrant,
                self._signing_key,
                self._trusted_roots,
                self._approval_handler,
                self._approvals,
                warrant_chain=self._warrant_chain,
            )
        except (ToolDenied, WarrantDenied, OpenAIConstraintViolation, MalformedToolCall) as e:
            self._record_decision(tool_name, arguments, e)
            raise
        self._record_decision(tool_name, arguments)

    async def _verify_call_async(self, tool_name: str, kind: str, raw: Optional[str]) -> None:
        """Async variant of _verify_call (awaits approval handlers)."""
        arguments: Dict[str, Any] = {}
        try:
            arguments = self._call_arguments(tool_name, kind, raw)
            _require_explicit_allow(tool_name, kind, self._allow_tools, self._warrant)
            await verify_tool_call_async(
                tool_name,
                arguments,
                self._allow_tools,
                self._deny_tools,
                self._constraints,
                self._warrant,
                self._signing_key,
                self._trusted_roots,
                self._approval_handler,
                self._approvals,
                warrant_chain=self._warrant_chain,
            )
        except (ToolDenied, WarrantDenied, OpenAIConstraintViolation, MalformedToolCall) as e:
            self._record_decision(tool_name, arguments, e)
            raise
        self._record_decision(tool_name, arguments)

    def _record_decision(self, tool_name: str, arguments: Dict[str, Any], error: Optional[Exception] = None) -> None:
        """Emit the audit event and control-plane record for one decision."""
        if error is None:
            self._emit_audit(tool_name, arguments, "ALLOW", "passed all checks")
            self._emit_cp(tool_name, arguments, allowed=True)
            return
        tier = "tier2" if isinstance(error, WarrantDenied) else "tier1"
        self._emit_audit(tool_name, arguments, "DENY", str(error), tier=tier)
        self._emit_cp(tool_name, arguments, allowed=False, denial_reason=str(error))

    def _emit_audit(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        decision: str,
        reason: str,
        tier: str = "tier1",
    ) -> None:
        """Emit an audit event if callback is configured."""
        if self._audit_callback is None:
            return

        event = AuditEvent(
            session_id=self._session_id,
            timestamp=time.time(),
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            reason=reason,
            tier=tier,  # Use tier determined by exception type, not warrant presence
            constraint_hash=self._constraint_hash,
            warrant_id=self._warrant_id,  # Frozen at init time
        )

        try:
            self._audit_callback(event)
        except Exception as e:
            # Audit sinks must never crash the caller. Log with exc_info=True
            # so operators can diagnose the callback bug from the traceback
            # rather than a one-line mystery. Cross-adapter contract: every
            # Tenuo audit emission path swallows-and-logs-with-traceback.
            logger.warning("Audit callback failed: %s", e, exc_info=True)

    def _emit_cp(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        *,
        allowed: bool,
        denial_reason: str = "",
    ) -> None:
        """Emit to control plane if connected."""
        if self._control_plane is None:
            return
        try:
            from ._enforcement import EnforcementResult
            res = EnforcementResult(
                allowed=allowed, tool=tool_name, arguments=arguments,
                warrant_id=self._warrant_id or "",
                denial_reason=denial_reason if not allowed else "",
            )
            self._control_plane.emit_for_enforcement(res)
        except Exception:
            logger.warning("Control plane emission failed for '%s'; audit event lost", tool_name, exc_info=True)

    def _guard_stream(self, stream: Iterator) -> Iterator:
        """Buffer-verify-emit pattern for streaming responses.

        SECURITY: This is the critical TOCTOU protection. We MUST:
        1. BUFFER: Accumulate ALL chunks containing tool call data
        2. VERIFY: When a tool call is complete, verify it
        3. EMIT: Only yield verified chunks to the consumer

        NO tool call data is released until verification passes.

        Design Note (STREAM-001):
            Once `in_tool_call` becomes True, it NEVER reverts to False.
            This means Content → Tool → Content will buffer the trailing
            Content until stream end. This is intentional:
            - Security: Ensures no tool data leaks between chunks
            - Trade-off: Trailing content won't stream in real-time
            - Rare in practice: Models typically end with tools or final content
            Conservative approach prioritizes security over UX for edge cases.
        """
        # Keyed by (choice index, tool call index): with n>1 every choice
        # numbers its tool calls from 0.
        buffers: Dict[Tuple[int, int], ToolCallBuffer] = {}
        pending_chunks: List[Any] = []  # Chunks waiting for verification
        in_tool_call = False  # Latch: once True, stays True (see STREAM-001)

        for chunk in stream:
            has_tool_delta = self._has_tool_call_delta(chunk)
            is_final_chunk = self._is_stream_end(chunk)

            if has_tool_delta:
                in_tool_call = True
                # Buffer the chunk — DO NOT YIELD
                pending_chunks.append(chunk)
                self._accumulate_tool_call_data(chunk, buffers)
            elif in_tool_call and not is_final_chunk:
                # Still in a tool call sequence, buffer this too
                pending_chunks.append(chunk)
            else:
                # Not in a tool call, or stream is ending — safe to yield
                if not in_tool_call:
                    yield chunk
                else:
                    pending_chunks.append(chunk)

        # Stream complete — now verify ALL buffered tool calls
        denied_indices: set = set()

        for index, buffer in buffers.items():
            try:
                self._verify_call(buffer.name, buffer.kind, buffer.arguments_buffer)
            except (ToolDenied, WarrantDenied, OpenAIConstraintViolation, MalformedToolCall) as e:
                self._handle_denial(e)
                if self._on_denial == "raise":
                    raise
                denied_indices.add(index)

        # EMIT: Only yield chunks for verified tool calls
        if self._on_denial == "raise" or not denied_indices:
            # All verified (or raise mode where we already raised)
            for chunk in pending_chunks:
                yield chunk
        else:
            # skip/log mode: filter out denied tool calls from chunks
            for chunk in pending_chunks:
                filtered = self._filter_denied_tool_calls(chunk, denied_indices)
                if filtered is not None:
                    yield filtered

    def _accumulate_tool_call_data(
        self,
        chunk: Any,
        buffers: Dict[Tuple[int, int], ToolCallBuffer],
    ) -> None:
        """Accumulate tool call data from a chunk into buffers.

        Fragments are concatenated the way the OpenAI SDK accumulates them,
        including the tool name, so the verified call is the one the app runs.
        """
        for choice in chunk.choices:
            if not hasattr(choice, "delta") or not choice.delta:
                continue

            delta = choice.delta
            choice_index = self._stream_index_or_record(choice)

            function_call = getattr(delta, "function_call", None)
            if function_call:
                key = (choice_index, _LEGACY_FUNCTION_CALL)
                if key not in buffers:
                    buffers[key] = ToolCallBuffer(id=f"fc_{choice_index}")
                self._append_stream_fragment(
                    buffers[key],
                    getattr(function_call, "name", None),
                    getattr(function_call, "arguments", None),
                )

            if not hasattr(delta, "tool_calls") or not delta.tool_calls:
                continue

            for tc_delta in delta.tool_calls:
                call_type = getattr(tc_delta, "type", None)
                custom = _field(tc_delta, "custom")
                if custom is not None or call_type == "custom":
                    kind: Optional[str] = "custom"
                    name_part = _field(custom, "name") if custom is not None else None
                    data_part = _field(custom, "input") if custom is not None else None
                else:
                    kind = call_type if isinstance(call_type, str) and call_type != "function" else None
                    func = getattr(tc_delta, "function", None)
                    name_part = getattr(func, "name", None) if func else None
                    data_part = getattr(func, "arguments", None) if func else None

                key = (choice_index, self._stream_index_or_record(tc_delta, name_part))

                # Initialize buffer if new tool call
                if key not in buffers:
                    tc_id = getattr(tc_delta, "id", None) or f"tc_{key[0]}_{key[1]}"
                    buffers[key] = ToolCallBuffer(id=tc_id)

                buffer = buffers[key]
                if kind is not None:
                    buffer.kind = kind
                self._append_stream_fragment(buffer, name_part, data_part)

    def _stream_index_or_record(self, obj: Any, tool_name: Optional[str] = None) -> int:
        """Validate a stream index and record malformed inputs before failing closed."""
        try:
            return _stream_index(obj)
        except MalformedToolCall as error:
            name = tool_name or "unknown"
            recorded_error = MalformedToolCall(name, error.error)
            self._record_decision(name, {}, recorded_error)
            raise recorded_error

    def _append_stream_fragment(self, buffer: ToolCallBuffer, name_part: Any, data_part: Any) -> None:
        """Append one streamed name/arguments fragment, enforcing the size limit."""
        if name_part:
            buffer.name += name_part
        if data_part:
            buffer.append_arguments(data_part)

            # Check buffer size
            if buffer.size() > self._stream_buffer_limit:
                overflow = BufferOverflow(buffer.name, buffer.size(), self._stream_buffer_limit)
                self._record_decision(buffer.name, {}, overflow)
                raise overflow

    def _has_tool_call_delta(self, chunk: Any) -> bool:
        """Check if chunk contains tool call data (tool_calls or legacy function_call)."""
        if not hasattr(chunk, "choices") or not chunk.choices:
            return False
        for choice in chunk.choices:
            delta = getattr(choice, "delta", None)
            if delta is None:
                continue
            if getattr(delta, "tool_calls", None) or getattr(delta, "function_call", None):
                return True
        return False

    def _is_stream_end(self, chunk: Any) -> bool:
        """Check if this chunk signals stream end."""
        if not hasattr(chunk, "choices") or not chunk.choices:
            return False
        for choice in chunk.choices:
            if hasattr(choice, "finish_reason") and choice.finish_reason:
                return True
        return False

    def _filter_denied_tool_calls(
        self,
        chunk: Any,
        denied_indices: set,
    ) -> Optional[Any]:
        """Filter out denied tool calls from a chunk.

        The remaining deltas must be preserved exactly: dropping an entire
        mixed chunk could remove a fragment from an allowed call, causing the
        application to reconstruct different arguments than were authorized.
        """
        if not self._has_tool_call_delta(chunk):
            return chunk

        for choice in chunk.choices:
            if not hasattr(choice, "delta") or not choice.delta:
                continue
            delta = choice.delta
            choice_index = _stream_index(choice)
            if getattr(delta, "function_call", None) and (choice_index, _LEGACY_FUNCTION_CALL) in denied_indices:
                delta.function_call = None
            if hasattr(delta, "tool_calls") and delta.tool_calls:
                delta.tool_calls = [
                    tc_delta
                    for tc_delta in delta.tool_calls
                    if (choice_index, _stream_index(tc_delta)) not in denied_indices
                ] or None

        return chunk

    def _handle_denial(self, error: TenuoOpenAIError) -> None:
        """Handle a denial according to mode using shared handler."""
        # Note: OpenAI handles "raise" mode separately, so we only handle log/skip here
        pseudo_result = EnforcementResult(
            allowed=False,
            tool=getattr(error, "tool_name", "unknown"),
            arguments={},
            denial_reason=str(error),
            error_type=error.code if hasattr(error, "code") else None,
        )
        # Use LOG or SKIP - raise is handled elsewhere in OpenAI flow
        policy = DenialPolicy.LOG if self._on_denial == "log" else DenialPolicy.SKIP
        handle_denial(pseudo_result, policy)

    async def acreate(self, *args, **kwargs) -> Any:
        """Async wrapped create method with guardrails.

        Equivalent to ``await create(...)`` on an async client.
        """
        stream = kwargs.get("stream", False)
        return await self._guard_awaitable(self._original.create(*args, **kwargs), stream)

    async def _guard_stream_async(self, stream: AsyncIterator) -> AsyncIterator:
        """Async buffer-verify-emit pattern for streaming responses.

        SECURITY: Same TOCTOU protection as sync version.
        Uses verify_tool_call_async for async approval handler support.
        """
        buffers: Dict[Tuple[int, int], ToolCallBuffer] = {}
        pending_chunks: List[Any] = []
        in_tool_call = False

        async for chunk in stream:
            has_tool_delta = self._has_tool_call_delta(chunk)
            is_final_chunk = self._is_stream_end(chunk)

            if has_tool_delta:
                in_tool_call = True
                pending_chunks.append(chunk)
                self._accumulate_tool_call_data(chunk, buffers)
            elif in_tool_call and not is_final_chunk:
                pending_chunks.append(chunk)
            else:
                if not in_tool_call:
                    yield chunk
                else:
                    pending_chunks.append(chunk)

        # Verify all buffered tool calls
        denied_indices: set = set()

        for index, buffer in buffers.items():
            try:
                await self._verify_call_async(buffer.name, buffer.kind, buffer.arguments_buffer)
            except (ToolDenied, WarrantDenied, OpenAIConstraintViolation, MalformedToolCall) as e:
                self._handle_denial(e)
                if self._on_denial == "raise":
                    raise
                denied_indices.add(index)

        # Emit verified chunks
        if self._on_denial == "raise" or not denied_indices:
            for chunk in pending_chunks:
                yield chunk
        else:
            for chunk in pending_chunks:
                filtered = self._filter_denied_tool_calls(chunk, denied_indices)
                if filtered is not None:
                    yield filtered


class GuardedChat:
    """Wrapped chat namespace."""

    def __init__(self, completions: GuardedCompletions):
        self.completions = completions


class GuardedResponses:
    """Wrapped responses endpoint with guardrails.

    Supports the OpenAI Responses API (client.responses.create).
    Uses the same verification logic as chat.completions.
    """

    def __init__(
        self,
        original: Any,
        allow_tools: Optional[List[str]],
        deny_tools: Optional[List[str]],
        constraints: Optional[Dict[str, Dict[str, Constraint]]],
        on_denial: DenialMode,
        warrant: Optional[Warrant] = None,
        signing_key: Optional[SigningKey] = None,
        audit_callback: Optional[AuditCallback] = None,
        session_id: Optional[str] = None,
        constraint_hash: Optional[str] = None,
        approval_handler: Optional[Any] = None,
        approvals: Optional[list] = None,
        trusted_roots: Optional[list] = None,
        warrant_chain: Optional[List[Warrant]] = None,
    ):
        self._original = original
        self._allow_tools = allow_tools
        self._deny_tools = deny_tools
        self._constraints = constraints
        self._on_denial = on_denial
        warrant, warrant_chain = split_presented_warrant(warrant, warrant_chain)
        self._warrant = warrant
        self._warrant_chain = warrant_chain
        self._signing_key = signing_key
        self._audit_callback = audit_callback
        self._session_id = session_id or str(uuid.uuid4())[:8]
        self._constraint_hash = constraint_hash
        self._approval_handler = approval_handler
        self._approvals = approvals
        self._trusted_roots = trusted_roots
        self._warrant_id = warrant.id if warrant and hasattr(warrant, "id") else None

        from .control_plane import get_or_create
        self._control_plane = get_or_create()

    def create(self, *args, **kwargs) -> Any:
        """Wrapped create method with guardrails.

        Works with both sync and async clients. Streaming (``stream=True``) is
        not supported under guard yet and raises OpenAIConfigurationError
        before any request is sent, rather than returning an unverified stream.
        """
        if kwargs.get("stream", False):
            raise OpenAIConfigurationError(
                "Streaming is not supported for responses.create() under Tenuo guard: "
                "function calls in a Responses stream cannot be verified yet. "
                "Use stream=False, or chat.completions.create(stream=True).",
                "CFG_004",
            )
        response = self._original.create(*args, **kwargs)
        if inspect.isawaitable(response):
            return self._guard_response_async(response)
        return self._guard_response(response)

    def parse(self, *args, **kwargs) -> Any:
        """Wrapped structured-output parse(); output items are verified like create()."""
        response = self._original.parse(*args, **kwargs)
        if inspect.isawaitable(response):
            return self._guard_response_async(response)
        return self._guard_response(response)

    async def _guard_response_async(self, awaitable: Any) -> Any:
        """Await an async client result, then verify it."""
        return self._guard_response(await awaitable)

    def _guard_response(self, response: Any) -> Any:
        """Verify tool calls in a Responses API response."""
        # Responses API uses response.output for tool calls
        if not hasattr(response, "output"):
            return response

        output = response.output
        if not output:
            return response

        # Build list of verified items, filtering denied ones in skip/log mode
        verified_items = []
        for item in output:
            if _is_app_executed_item(item):
                try:
                    self._verify_function_call(item)
                    verified_items.append(item)
                except (ToolDenied, WarrantDenied, OpenAIConstraintViolation) as e:
                    self._handle_denial(e)
                    if self._on_denial == "raise":
                        raise
                    # skip or log: exclude from results (don't append)
            else:
                # Messages, reasoning and hosted-tool items pass through unchanged
                verified_items.append(item)

        # Update output with verified items only (mirrors chat.completions behavior)
        if self._on_denial != "raise":
            response.output = verified_items if verified_items else []

        return response

    def _verify_function_call(self, item: Any) -> None:
        """Verify an app-executed Responses item (function, custom, shell, patch, computer...)."""
        tool_name = getattr(item, "name", "") or getattr(item, "type", "") or ""
        arguments: Dict[str, Any] = {}
        try:
            tool_name, kind, arguments = _responses_item_parts(item)
            if not tool_name:
                raise MalformedToolCall(tool_name, "tool call has no name")
            _require_explicit_allow(tool_name, kind, self._allow_tools, self._warrant)
            verify_tool_call(
                tool_name,
                arguments,
                self._allow_tools,
                self._deny_tools,
                self._constraints,
                self._warrant,
                self._signing_key,
                self._trusted_roots,
                self._approval_handler,
                self._approvals,
                warrant_chain=self._warrant_chain,
            )
            self._emit_audit(tool_name, arguments, "ALLOW", "passed all checks")
            self._emit_cp(tool_name, arguments, allowed=True)
        except (ToolDenied, WarrantDenied, OpenAIConstraintViolation, MalformedToolCall) as e:
            tier = "tier2" if isinstance(e, WarrantDenied) else "tier1"
            self._emit_audit(tool_name, arguments, "DENY", str(e), tier=tier)
            self._emit_cp(tool_name, arguments, allowed=False, denial_reason=str(e))
            raise

    def _emit_cp(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        *,
        allowed: bool,
        denial_reason: str = "",
    ) -> None:
        """Emit to control plane if connected."""
        if self._control_plane is None:
            return
        try:
            from ._enforcement import EnforcementResult
            res = EnforcementResult(
                allowed=allowed, tool=tool_name, arguments=arguments,
                warrant_id=self._warrant_id or "",
                denial_reason=denial_reason if not allowed else "",
            )
            self._control_plane.emit_for_enforcement(res)
        except Exception:
            logger.warning("Control plane emission failed for '%s'; audit event lost", tool_name, exc_info=True)

    def _emit_audit(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        decision: str,
        reason: str,
        tier: str = "tier1",
    ) -> None:
        """Emit an audit event if callback is configured."""
        if self._audit_callback is None:
            return

        event = AuditEvent(
            session_id=self._session_id,
            timestamp=time.time(),
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            reason=reason,
            tier=tier,
            constraint_hash=self._constraint_hash,
            warrant_id=self._warrant_id,  # Frozen at init time
        )

        try:
            self._audit_callback(event)
        except Exception as e:
            # Cross-adapter contract: audit emission never crashes the caller,
            # always logs exc_info=True so the traceback reaches operators.
            logger.warning("Audit callback failed: %s", e, exc_info=True)

    def _handle_denial(self, error: Exception) -> None:
        """Handle a denial based on on_denial mode using shared handler."""
        pseudo_result = EnforcementResult(
            allowed=False,
            tool=getattr(error, "tool_name", "unknown"),
            arguments={},
            denial_reason=str(error),
            error_type=getattr(error, "code", None),
        )
        policy = DenialPolicy.LOG if self._on_denial == "log" else DenialPolicy.SKIP
        handle_denial(pseudo_result, policy)


# Client attributes that return model output without going through the guarded
# chat/responses wrappers. Under guard they fail closed instead of passing through.
_UNGUARDED_CLIENT_ATTRS = frozenset(
    {
        "conversations",
        "with_raw_response",
        "with_streaming_response",
        "realtime",
        "request",
        "get",
        "post",
        "put",
        "patch",
        "delete",
    }
)


class _UnguardedEndpoint(OpenAIConfigurationError, AttributeError):
    """An endpoint the guard cannot verify was accessed through the guarded client.

    Also an AttributeError so ``hasattr()`` / ``getattr(..., default)`` probes
    report the endpoint as unavailable instead of raising.
    """

    def __init__(self, path: str):
        super().__init__(
            f"client.{path} is not available under Tenuo guard: tool calls it returns "
            "would not be verified. Use chat.completions or responses on the guarded "
            "client, or call the unguarded client directly for endpoints that "
            "cannot return tool calls.",
            "CFG_005",
        )


def _is_openai_client(obj: Any) -> bool:
    """True for an OpenAI/AsyncOpenAI (or Azure) client instance."""
    try:
        import openai
    except ImportError:  # pragma: no cover - openai is required to use guard()
        return False
    return isinstance(obj, (openai.OpenAI, openai.AsyncOpenAI))


class GuardedBeta:
    """Wrapped beta namespace: only beta.chat.completions is exposed (verified)."""

    def __init__(self, chat: GuardedChat):
        self.chat = chat

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        raise _UnguardedEndpoint(f"beta.{name}")


class GuardedClient:
    """OpenAI client wrapper with Tenuo guardrails.

    Supports both Tier 1 (guardrails) and Tier 2 (warrant + PoP) protection.

    Attributes:
        session_id: Unique identifier for this guard instance (for audit correlation)
        constraint_hash: SHA-256 hash of constraint config (for tamper detection)
    """

    def __init__(
        self,
        client: Any,
        allow_tools: Optional[List[str]] = None,
        deny_tools: Optional[List[str]] = None,
        constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
        on_denial: DenialMode = "raise",
        stream_buffer_limit: int = 65536,
        warrant: Optional[Warrant] = None,
        signing_key: Optional[SigningKey] = None,
        audit_callback: Optional[AuditCallback] = None,
        approval_handler: Optional[Any] = None,
        approvals: Optional[list] = None,
        trusted_roots: Optional[list] = None,
        *,
        warrant_chain: Optional[List[Warrant]] = None,
        session_id: Optional[str] = None,
    ):
        # warrant may also be a WarrantStack string or root-first list; split
        # it once so every wrapped endpoint verifies the same leaf and parents.
        warrant, warrant_chain = split_presented_warrant(warrant, warrant_chain)
        # Kept so clients derived via with_options()/copy() get the same guard.
        self._guard_config: Dict[str, Any] = dict(
            allow_tools=allow_tools,
            deny_tools=deny_tools,
            constraints=constraints,
            on_denial=on_denial,
            stream_buffer_limit=stream_buffer_limit,
            warrant=warrant,
            signing_key=signing_key,
            audit_callback=audit_callback,
            approval_handler=approval_handler,
            approvals=approvals,
            trusted_roots=trusted_roots,
            warrant_chain=warrant_chain,
        )
        self._client = client
        self._allow_tools = allow_tools
        self._deny_tools = deny_tools
        self._constraints = constraints
        self._on_denial = on_denial
        self._stream_buffer_limit = stream_buffer_limit
        self._warrant = warrant
        self._warrant_chain = warrant_chain
        self._signing_key = signing_key
        self._audit_callback = audit_callback
        self._approval_handler = approval_handler
        self._approvals = approvals
        self._trusted_roots = trusted_roots

        # Generate session ID and constraint hash for audit trail
        self.session_id = session_id or "sess_" + str(uuid.uuid4())[:8]
        self.constraint_hash = _compute_constraint_hash(allow_tools, deny_tools, constraints)

        def guarded_completions(original: Any) -> GuardedCompletions:
            return GuardedCompletions(
                original,
                allow_tools,
                deny_tools,
                constraints,
                on_denial,
                stream_buffer_limit,
                warrant,
                signing_key,
                audit_callback,
                self.session_id,
                self.constraint_hash,
                approval_handler,
                approvals,
                trusted_roots,
                warrant_chain,
            )

        # Wrap beta.chat.completions (parse()); the rest of beta fails closed
        beta = getattr(client, "beta", None)
        if beta is not None and hasattr(beta, "chat") and hasattr(beta.chat, "completions"):
            self.beta = GuardedBeta(GuardedChat(guarded_completions(beta.chat.completions)))

        # Wrap chat.completions
        if hasattr(client, "chat") and hasattr(client.chat, "completions"):
            self.chat = GuardedChat(
                GuardedCompletions(
                    client.chat.completions,
                    allow_tools,
                    deny_tools,
                    constraints,
                    on_denial,
                    stream_buffer_limit,
                    warrant,
                    signing_key,
                    audit_callback,
                    self.session_id,
                    self.constraint_hash,
                    approval_handler,
                    approvals,
                    trusted_roots,
                    warrant_chain,
                )
            )

        # Wrap responses API (newer OpenAI API)
        if hasattr(client, "responses"):
            self.responses = GuardedResponses(
                client.responses,
                allow_tools,
                deny_tools,
                constraints,
                on_denial,
                warrant,
                signing_key,
                audit_callback,
                self.session_id,
                self.constraint_hash,
                approval_handler,
                approvals,
                trusted_roots,
                warrant_chain,
            )

    def __getattr__(self, name: str) -> Any:
        """Pass through non-wrapped attributes to underlying client.

        Endpoints that would hand back unverified tool calls (raw responses,
        raw HTTP verbs, realtime, unwrapped beta) fail closed, and a call that
        returns a derived client (``with_options()``, ``copy()``) returns it
        wrapped in the same guard.
        """
        if name.startswith("_"):
            raise AttributeError(name)
        if name in _UNGUARDED_CLIENT_ATTRS:
            raise _UnguardedEndpoint(name)
        value = getattr(self._client, name)
        if _is_openai_client(value):
            return self._rewrap(value)
        if inspect.ismethod(value):
            method = value

            @functools.wraps(method)
            def call(*args: Any, **kwargs: Any) -> Any:
                result = method(*args, **kwargs)
                return self._rewrap(result) if _is_openai_client(result) else result

            return call
        return value

    def _rewrap(self, client: Any) -> "GuardedClient":
        """Guard a client derived from this one with the same policy and session."""
        return GuardedClient(client, **self._guard_config, session_id=self.session_id)

    def validate(self) -> None:
        """Validate configuration before first use.

        Performs pre-flight checks to catch configuration errors early:
        - Warrant + signing_key consistency
        - Key holder binding
        - Warrant expiration

        Call this after guard() to fail fast on misconfiguration.

        Raises:
            MissingSigningKey: If warrant provided without signing_key
            OpenAIConfigurationError: If signing_key doesn't match warrant holder
            OpenAIConfigurationError: If warrant is expired

        Example::

            client = guard(openai.OpenAI(), warrant=w, signing_key=k)
            client.validate()  # Fails early if misconfigured
        """
        if self._warrant is not None:
            # Check signing_key is provided
            if self._signing_key is None:
                raise MissingSigningKey()

            # Check warrant isn't expired via the canonical is_expired() method.
            is_expired = (
                self._warrant.is_expired()
                if callable(getattr(self._warrant, "is_expired", None))
                else getattr(self._warrant, "expired", False)
            )
            if is_expired:
                raise OpenAIConfigurationError("Warrant is expired. Request a new warrant from the control plane.", "CFG_002")

            # Check signing_key matches warrant holder
            try:
                holder = self._warrant.authorized_holder
                signer_pub = self._signing_key.public_key
                if holder.to_bytes() != signer_pub.to_bytes():
                    raise OpenAIConfigurationError(
                        "Signing key does not match warrant holder. "
                        "The signing_key must be the private key corresponding to "
                        "the warrant's authorized_holder public key.",
                        "CFG_003",
                    )
            except AttributeError:
                # If we can't check, skip (older API)
                pass

        logger.debug("Configuration validated successfully")


# =============================================================================
# Public API
# =============================================================================


# Type alias for tool references
ToolRef = Union[str, Dict[str, Any], Callable[..., Any]]


def _extract_tool_name(tool: ToolRef) -> str:
    """Extract tool name from various formats.

    Supports:
    - String: "search" -> "search"
    - OpenAI tool dict: {"type": "function", "function": {"name": "search"}} -> "search"
    - Callable: search_func -> "search_func"
    """
    if isinstance(tool, str):
        return tool
    elif isinstance(tool, dict):
        # OpenAI tool format
        if "function" in tool and "name" in tool["function"]:
            return tool["function"]["name"]
        elif "name" in tool:
            return tool["name"]
        else:
            raise ValueError(f"Cannot extract tool name from dict: {tool}")
    elif callable(tool):
        name = getattr(tool, "__name__", None)
        if name:
            return name
        raise ValueError(f"Callable has no __name__: {tool}")
    else:
        raise TypeError(f"Expected str, dict, or callable, got {type(tool)}")


class GuardBuilder:
    """Fluent builder for creating guarded OpenAI clients.

    Provides a more ergonomic API for defining tool constraints:

        client = (GuardBuilder(openai.OpenAI())
            .allow("search")
            .allow("read_file", path=Subpath("/data"))
            .allow("send_email", to=Pattern("*@company.com"))
            .deny("delete_file")
            .on_denial("raise")
            .build())

    Benefits over dict-based `guard()`:
    - Fluent, chainable API
    - Accepts tool objects (not just strings) for IDE autocomplete
    - Clear separation of allow vs deny
    - Constraints are kwargs, not nested dicts

    For Tier 2 (warrant-based), use `.with_warrant()`:

        client = (GuardBuilder(openai.OpenAI())
            .with_warrant(warrant, signing_key)
            .build())
    """

    def __init__(self, client: Any) -> None:
        """Create a new builder for the given OpenAI client.

        Args:
            client: OpenAI client instance (sync or async)
        """
        self._client = client
        self._allow_tools: List[str] = []
        self._deny_tools: List[str] = []
        self._constraints: Dict[str, Dict[str, Constraint]] = {}
        self._on_denial: DenialMode = "raise"
        self._stream_buffer_limit: int = 65536
        self._audit_callback: Optional[AuditCallback] = None
        self._warrant: Optional[Warrant] = None
        self._warrant_chain: Optional[List[Warrant]] = None
        self._signing_key: Optional[SigningKey] = None
        self._approval_handler: Optional[Any] = None
        self._approvals: Optional[list] = None
        # Tool schema validation
        self._tool_schemas: Dict[str, Dict[str, Any]] = {}
        self._validate_mode: Literal["warn", "strict", False] = "warn"

    def allow(self, tool: ToolRef, **constraints: Constraint) -> "GuardBuilder":
        """Allow a tool, optionally with constraints.

        Args:
            tool: Tool name, OpenAI tool dict, or callable
            **constraints: Parameter constraints (e.g., path=Subpath("/data"))

        Returns:
            self for chaining

        Example:
            builder.allow("read_file", path=Subpath("/data"), encoding=Exact("utf-8"))
        """
        name = _extract_tool_name(tool)
        self._allow_tools.append(name)
        if constraints:
            self._constraints[name] = constraints
        return self

    def allow_all(self, *tools: ToolRef) -> "GuardBuilder":
        """Allow multiple tools without constraints.

        Args:
            *tools: Tool names, dicts, or callables

        Returns:
            self for chaining

        Example:
            builder.allow_all("search", "read_file", "list_files")
        """
        for tool in tools:
            self.allow(tool)
        return self

    def deny(self, tool: ToolRef) -> "GuardBuilder":
        """Explicitly deny a tool.

        Args:
            tool: Tool name, OpenAI tool dict, or callable

        Returns:
            self for chaining

        Example:
            builder.deny("delete_file")
        """
        name = _extract_tool_name(tool)
        self._deny_tools.append(name)
        return self

    def deny_all(self, *tools: ToolRef) -> "GuardBuilder":
        """Deny multiple tools.

        Args:
            *tools: Tool names, dicts, or callables

        Returns:
            self for chaining

        Example:
            builder.deny_all("delete_file", "rm", "drop_table")
        """
        for tool in tools:
            self.deny(tool)
        return self

    def constrain(self, tool: ToolRef, **constraints: Constraint) -> "GuardBuilder":
        """Add constraints to a tool (does NOT add to allow list).

        Use this when you want to constrain a tool without explicitly
        allowing it (e.g., when using a denylist approach).

        Args:
            tool: Tool name, OpenAI tool dict, or callable
            **constraints: Parameter constraints

        Returns:
            self for chaining
        """
        name = _extract_tool_name(tool)
        if name in self._constraints:
            self._constraints[name].update(constraints)
        else:
            self._constraints[name] = constraints
        return self

    def on_denial(self, mode: DenialMode) -> "GuardBuilder":
        """Set behavior when a tool call is denied.

        Args:
            mode: "raise" (default), "skip", or "log"

        Returns:
            self for chaining
        """
        self._on_denial = mode
        return self

    def buffer_limit(self, limit: int) -> "GuardBuilder":
        """Set max buffer size for streaming tool calls.

        Args:
            limit: Max bytes per tool call (default 64KB)

        Returns:
            self for chaining
        """
        self._stream_buffer_limit = limit
        return self

    def audit(self, callback: AuditCallback) -> "GuardBuilder":
        """Set audit callback for all authorization decisions.

        Args:
            callback: Function called with AuditEvent for each decision

        Returns:
            self for chaining

        Example:
            def log_audit(event: AuditEvent):
                print(f"[{event.decision}] {event.tool}: {event.reason}")

            builder.audit(log_audit)
        """
        self._audit_callback = callback
        return self

    def with_warrant(
        self,
        warrant: Warrant,
        signing_key: SigningKey,
        *,
        warrant_chain: Optional[List[Warrant]] = None,
    ) -> "GuardBuilder":
        """Configure Tier 2 (warrant + PoP) authorization.

        When a warrant is configured, its constraints take precedence
        over Tier 1 constraints. The signing key is used to sign
        Proof-of-Possession for each tool call.

        A delegated warrant only verifies when its path back to a trusted
        root is presented with it. Pass the parents as ``warrant_chain``, or
        pass the whole chain as ``warrant`` in one token: an encoded
        WarrantStack string or a root-first list of warrants (leaf last).

        Args:
            warrant: Cryptographic warrant (from control plane), or the whole
                chain as a WarrantStack string or root-first list
            signing_key: Agent's signing key for PoP
            warrant_chain: Parent warrants of a delegated ``warrant``,
                root-first and excluding the leaf

        Returns:
            self for chaining

        Raises:
            ConfigurationError: If a stack and ``warrant_chain`` are both given,
                or a token does not decode

        Example:
            builder.with_warrant(warrant, agent_key)
            builder.with_warrant(leaf, agent_key, warrant_chain=[root])
        """
        self._warrant, self._warrant_chain = split_presented_warrant(warrant, warrant_chain)
        self._signing_key = signing_key
        return self

    def on_approval(self, handler: Any) -> "GuardBuilder":
        """Set the handler invoked when a tool call requires approval.

        Args:
            handler: Callable that receives an ApprovalRequest and returns
                a SignedApproval (or raises ApprovalDenied). Built-in
                handlers: cli_prompt(), auto_approve(), auto_deny().

        Returns:
            self for chaining

        Example:
            from tenuo.approval import cli_prompt
            builder.on_approval(cli_prompt(approver_key=approver_key))
        """
        self._approval_handler = handler
        return self

    def with_approvals(self, approvals: list) -> "GuardBuilder":
        """Set pre-collected signed approvals for warrant approval gates.

        When the warrant requires approval for a tool, these objects are
        checked before invoking ``on_approval``.

        Args:
            approvals: List of pre-collected approval objects

        Returns:
            self for chaining
        """
        self._approvals = approvals
        return self

    def with_tools(self, tools: List[Dict[str, Any]]) -> "GuardBuilder":
        """Register tool schemas for constraint validation.

        When tools are registered, build() validates that constraint
        parameter names match the actual tool schemas. This catches
        typos and schema drift.

        Args:
            tools: List of OpenAI tool definitions

        Returns:
            self for chaining

        Example:
            tools = [{
                "type": "function",
                "function": {
                    "name": "send_email",
                    "parameters": {
                        "properties": {"to": {}, "subject": {}, "body": {}}
                    }
                }
            }]

            client = (GuardBuilder(openai.OpenAI())
                .allow("send_email", to=Pattern("*@company.com"))
                .with_tools(tools)  # Validates "to" exists
                .build())
        """
        for tool in tools:
            if tool.get("type") != "function":
                continue
            func = tool.get("function", {})
            name = func.get("name")
            if name:
                params = func.get("parameters", {})
                self._tool_schemas[name] = params
        return self

    def validate(self, mode: Literal["warn", "strict", False] = "warn") -> "GuardBuilder":
        """Set constraint validation mode.

        Args:
            mode:
                - "warn": Log warnings for invalid constraints (default)
                - "strict": Raise OpenAIConfigurationError for invalid constraints
                - False: Disable validation

        Returns:
            self for chaining
        """
        self._validate_mode = mode
        return self

    def _validate_url_pattern(self, constraint: Any) -> Optional[str]:
        """
        Validate UrlPattern for security best practices.

        Returns error message if pattern is too permissive.
        """
        # Check if this is a UrlPattern constraint
        pattern_str = getattr(constraint, "pattern", None)
        if pattern_str and "://*/" in pattern_str:
            return (
                f"UrlPattern with bare wildcard host ('{pattern_str}') is not allowed. "
                "This would bypass SSRF protection by allowing ANY domain. "
                "Use explicit domains instead:\n"
                "  - UrlPattern('https://api.github.com/*')\n"
                "  - UrlPattern('https://*.example.com/*')\n"
                "  - UrlSafe(allow_domains=['github.com']) for SSRF protection"
            )
        return None

    def _validate_constraints(self) -> List[str]:
        """Validate constraints against tool schemas.

        Returns list of warning messages.
        """
        warnings: List[str] = []

        for tool_name, params in self._constraints.items():
            # Security: Check for overly permissive UrlPattern constraints
            for param_name, constraint in params.items():
                if param_name.startswith("_"):
                    continue
                url_pattern_error = self._validate_url_pattern(constraint)
                if url_pattern_error:
                    warnings.append(f"[{tool_name}.{param_name}] {url_pattern_error}")

            # Check if tool exists in schemas
            if tool_name not in self._tool_schemas:
                # Not an error - tool might not be registered
                continue

            schema = self._tool_schemas[tool_name]
            schema_params = set(schema.get("properties", {}).keys())

            for param_name in params:
                if param_name.startswith("_"):
                    # Skip meta-params like _allow_unknown
                    continue

                if param_name not in schema_params:
                    # Try to suggest similar names
                    suggestion = self._suggest_similar(param_name, schema_params)
                    msg = (
                        f"Constraint parameter '{param_name}' not found in "
                        f"tool '{tool_name}'. Available: {sorted(schema_params)}"
                    )
                    if suggestion:
                        msg += f". Did you mean '{suggestion}'?"
                    warnings.append(msg)

        return warnings

    @staticmethod
    def _suggest_similar(name: str, candidates: set) -> Optional[str]:
        """Suggest a similar parameter name (simple edit distance)."""
        if not candidates:
            return None

        def edit_distance(s1: str, s2: str) -> int:
            """Simple Levenshtein distance."""
            if len(s1) < len(s2):
                s1, s2 = s2, s1  # Swap to ensure s1 is longer
            if len(s2) == 0:
                return len(s1)

            prev_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                curr_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = prev_row[j + 1] + 1
                    deletions = curr_row[j] + 1
                    substitutions = prev_row[j] + (c1 != c2)
                    curr_row.append(min(insertions, deletions, substitutions))
                prev_row = curr_row

            return prev_row[-1]

        # Find closest match
        best_match = None
        best_distance = float("inf")
        for candidate in candidates:
            dist = edit_distance(name.lower(), candidate.lower())
            if dist < best_distance and dist <= 2:  # Max 2 edits
                best_distance = dist
                best_match = candidate

        return best_match

    def build(self) -> GuardedClient:
        """Build the guarded client.

        Returns:
            GuardedClient with configured constraints

        Raises:
            MissingSigningKey: If warrant provided without signing_key
            OpenAIConfigurationError: If validation is strict and constraints are invalid
        """
        # Validate constraints against tool schemas
        if self._tool_schemas and self._validate_mode:
            warnings = self._validate_constraints()
            if warnings:
                if self._validate_mode == "strict":
                    raise OpenAIConfigurationError("Constraint validation failed:\n  " + "\n  ".join(warnings), code="C1_003")
                else:  # warn mode
                    for warning in warnings:
                        logger.warning(f"Constraint validation: {warning}")

        return GuardedClient(
            self._client,
            allow_tools=self._allow_tools if self._allow_tools else None,
            deny_tools=self._deny_tools if self._deny_tools else None,
            constraints=self._constraints if self._constraints else None,
            on_denial=self._on_denial,
            stream_buffer_limit=self._stream_buffer_limit,
            warrant=self._warrant,
            signing_key=self._signing_key,
            audit_callback=self._audit_callback,
            approval_handler=self._approval_handler,
            approvals=self._approvals,
            warrant_chain=self._warrant_chain,
        )


def guard(
    client: Any,
    *,
    allow_tools: Optional[List[str]] = None,
    deny_tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
    warrant: Optional[Warrant] = None,
    signing_key: Optional[SigningKey] = None,
    trusted_roots: Optional[list] = None,
    on_denial: DenialMode = "raise",
    stream_buffer_limit: int = 65536,
    audit_callback: Optional[AuditCallback] = None,
    warrant_chain: Optional[List[Warrant]] = None,
) -> GuardedClient:
    """Wrap an OpenAI client with Tenuo guardrails.

    This function supports two tiers of protection:

    **Tier 1 (Guardrails)**: Runtime constraint checking without cryptography.
    Uses allow_tools, deny_tools, and constraints parameters.
    Enforces local policy in trusted application code.

    **Tier 2 (Warrant + PoP)**: Cryptographic authorization with Proof-of-Possession.
    Requires both a warrant AND a signing_key. For each tool call:
    1. Signs a PoP proving the agent holds the warrant's private key
    2. Verifies constraints AND the cryptographic signature

    This enables distributed/multi-agent scenarios where you cannot trust
    the executor to honestly report what tools it called.

    **Defense in Depth** when both tiers are configured:
    - Tier 1 allow/deny lists ALWAYS apply (even with warrant)
    - Tier 2 constraints OVERRIDE Tier 1 constraints (warrant is authoritative)

    Args:
        client: OpenAI client instance
        allow_tools: Tier 1 - Allowlist of tool names (checked even with warrant)
        deny_tools: Tier 1 - Denylist of tool names (checked even with warrant)
        constraints: Tier 1 - Per-tool argument constraints (skipped if warrant present)
        warrant: Tier 2 - Cryptographic warrant (its constraints take precedence).
            May also be the whole delegation chain as one token: an encoded
            WarrantStack string or a root-first list of warrants (leaf last).
        signing_key: Tier 2 - Agent's signing key for PoP (REQUIRED if warrant provided)
        on_denial: Behavior when tool call is denied:
            - "raise": Raise ToolDenied/WarrantDenied exception (recommended)
            - "skip": Silently skip the tool call
            - "log": Log warning and skip
        stream_buffer_limit: Max bytes per tool call in streaming (default 64KB)
        audit_callback: Optional callback for every authorization decision.
            Receives AuditEvent with session_id, tool, decision, reason.
            Useful for compliance logging and debugging.
        warrant_chain: Tier 2 - Parent warrants of a delegated ``warrant``,
            root-first and excluding the leaf, so the chain verifies back to
            a trusted root without ``chain_scope``.

    Returns:
        Wrapped client that enforces constraints

    Raises:
        MissingSigningKey: If warrant is provided without signing_key

    Warning:
        Using on_denial="skip" or "log" can cause the LLM to hang if it expects
        a tool output that never comes. When a tool call is skipped, the LLM
        may wait indefinitely for a response. Consider either:
        1. Using on_denial="raise" and catching the exception to inject an
           error message into the conversation history
        2. Implementing a wrapper that automatically sends a tool error response
           for denied calls

    Example (Tier 1 - Guardrails)::

        from tenuo.openai import guard, Pattern

        client = guard(
            openai.OpenAI(),
            allow_tools=["search", "read_file"],
            constraints={
                "read_file": {"path": Pattern("/data/*")}
            }
        )

        # Use normally - unauthorized tool calls are blocked
        response = client.chat.completions.create(...)

    Example (Tier 2 - Warrant with PoP)::

        from tenuo.openai import guard
        from tenuo import Warrant, SigningKey, Pattern

        # Agent's keypair (the agent is the warrant holder)
        agent_key = SigningKey.generate()

        # Create a warrant (in production, received from control plane)
        control_plane_key = SigningKey.generate()
        warrant = (Warrant.mint_builder()
            .capability("read_file", {"path": Pattern("/data/*")})
            .holder(agent_key.public_key)  # Agent is the holder
            .ttl(3600)
            .mint(control_plane_key))      # Control plane signs

        # Guard with both warrant AND signing key
        client = guard(
            openai.OpenAI(),
            warrant=warrant,
            signing_key=agent_key,  # Agent signs PoP for each tool call
        )

        # Each tool call is now cryptographically authorized
        response = client.chat.completions.create(...)
    """
    return GuardedClient(
        client,
        allow_tools=allow_tools,
        deny_tools=deny_tools,
        constraints=constraints,
        on_denial=on_denial,
        stream_buffer_limit=stream_buffer_limit,
        warrant=warrant,
        signing_key=signing_key,
        trusted_roots=trusted_roots,
        audit_callback=audit_callback,
        warrant_chain=warrant_chain,
    )


# =============================================================================
# OpenAI Agents SDK Integration
# =============================================================================
#
# The OpenAI Agents SDK (openai-agents) provides a framework for building
# multi-agent systems. Tenuo integrates via the guardrails mechanism:
#
#   from agents import Agent, Runner
#   from tenuo.openai import create_tier1_guardrail, Pattern
#
#   agent = guard_agent(
#       Agent(name="Assistant", instructions="Help the user", tools=[send_email]),
#       constraints={"send_email": {"to": Pattern("*@company.com")}},
#   )
#
# For Tier 2 (warrant-based), pass the warrant:
#
#   agent = guard_agent(agent, warrant=warrant, signing_key=agent_key,
#                       trusted_roots=[control_plane_key.public_key])
#
# guard_agent() attaches a tool guardrail to each tool, so it sees every tool
# call. An Agent's input_guardrails only see the agent's input.


# Try to get the SDK base class for proper inheritance
_GuardrailFunctionOutput: Any = None
try:
    from agents.guardrail import GuardrailFunctionOutput as _GFO  # type: ignore[import-not-found]

    _GuardrailFunctionOutput = _GFO
except ImportError:
    pass


@dataclass
class GuardrailResult:
    """Result of a Tenuo guardrail check.

    This class is compatible with OpenAI Agents SDK's GuardrailFunctionOutput.
    When `tripwire_triggered=True`, the agent run is halted immediately.

    If the openai-agents SDK is installed, to_agents_sdk() returns a proper
    GuardrailFunctionOutput instance for full SDK compatibility.
    """

    output_info: str
    tripwire_triggered: bool = False

    def to_agents_sdk(self) -> Any:
        """Convert to OpenAI Agents SDK GuardrailFunctionOutput.

        Returns a proper GuardrailFunctionOutput if SDK is installed,
        otherwise returns self (which has the same interface).

        Requires: uv pip install openai-agents
        """
        if _GuardrailFunctionOutput is not None:
            return _GuardrailFunctionOutput(
                output_info=self.output_info,
                tripwire_triggered=self.tripwire_triggered,
            )
        # Return self if SDK not installed - has same interface
        return self


class TenuoToolGuardrail:
    """Tenuo authorization settings for the OpenAI Agents SDK.

    Calling the object checks tool calls found in the input passed to it. To
    enforce the tool calls an Agent makes, use :func:`guard_agent`, which
    accepts the same arguments. Placing this object in
    ``Agent(input_guardrails=...)`` raises ``OpenAIConfigurationError``, because
    input guardrails never see the model's tool calls.

    Usage:
        from agents import Agent
        from tenuo.openai import guard_agent, Pattern

        agent = guard_agent(
            Agent(name="Assistant", tools=[send_email]),
            constraints={"send_email": {"to": Pattern("*@company.com")}},
        )
    """

    def __init__(
        self,
        *,
        allow_tools: Optional[List[str]] = None,
        deny_tools: Optional[List[str]] = None,
        constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
        warrant: Optional[Warrant] = None,
        signing_key: Optional[SigningKey] = None,
        trusted_roots: Optional[list] = None,
        tripwire: bool = True,
        audit_callback: Optional[AuditCallback] = None,
        approval_handler: Optional[Any] = None,
        approvals: Optional[list] = None,
        warrant_chain: Optional[List[Warrant]] = None,
    ):
        """Initialize the guardrail.

        Args:
            allow_tools: Allowlist of permitted tool names (None = allow all)
            deny_tools: Denylist of forbidden tool names
            constraints: Per-tool argument constraints
            warrant: Optional Tier 2 warrant for cryptographic authorization, or
                the whole delegation chain as a WarrantStack string or root-first list
            signing_key: Required if warrant is provided (for PoP)
            trusted_roots: Trusted issuer public keys (required for Tier 2 warrant path)
            tripwire: If True, halt agent on violation. If False, log and continue.
            audit_callback: Optional callback for audit events
            approval_handler: Handler invoked when the warrant requires human approval
            approvals: Pre-collected signed approvals for warrant approval gates
            warrant_chain: Parent warrants of a delegated ``warrant``, root-first
                and excluding the leaf
        """
        warrant, warrant_chain = split_presented_warrant(warrant, warrant_chain)
        self.allow_tools = allow_tools
        self.deny_tools = deny_tools
        self.constraints = constraints
        self.warrant = warrant
        self.warrant_chain = warrant_chain
        self.signing_key = signing_key
        self.trusted_roots = trusted_roots
        self.tripwire = tripwire
        self.audit_callback = audit_callback
        self.approval_handler = approval_handler
        self.approvals = approvals
        self.name = "tenuo_tool_guardrail"

        # Generate session ID and constraint hash for audit trail
        self._session_id = str(uuid.uuid4())[:8]
        self._constraint_hash = _compute_constraint_hash(allow_tools, deny_tools, constraints)
        self._warrant_id = warrant.id if warrant and hasattr(warrant, "id") else None

        from .control_plane import get_or_create
        self._control_plane = get_or_create()

        # Validate configuration
        if warrant is not None and signing_key is None:
            raise MissingSigningKey()

    @staticmethod
    def _input_guardrail_misuse() -> "OpenAIConfigurationError":
        return OpenAIConfigurationError(
            "TenuoToolGuardrail cannot enforce tool calls as an Agent input guardrail: "
            "input guardrails only see the agent's input, not the tool calls the model "
            "makes. Use tenuo.openai.guard_agent(agent, ...) to check every tool call.",
            "CFG_006",
        )

    # The Agents SDK reads these from every entry in Agent(input_guardrails=...).
    # Input guardrails only see the input given to the agent, never the tool
    # calls the model makes during the run, so raise with a pointer to
    # guard_agent() instead of running and enforcing nothing.
    @property
    def run_in_parallel(self) -> bool:
        raise self._input_guardrail_misuse()

    def get_name(self) -> str:
        raise self._input_guardrail_misuse()

    async def __call__(self, ctx: Any, agent: Any, input_data: Any) -> Any:
        """Guardrail entry point called by Agents SDK.

        Args:
            ctx: RunContextWrapper from Agents SDK
            agent: The Agent being run
            input_data: Input being validated (may contain tool calls)

        Returns:
            GuardrailFunctionOutput (or compatible dict)
        """
        # Extract tool calls from input
        # SECURITY: MalformedToolCall can be raised here for invalid JSON
        try:
            tool_calls = self._extract_tool_calls(input_data)
        except MalformedToolCall as e:
            # Fail closed on malformed input
            logger.warning(f"Tenuo guardrail blocked malformed input: {e}")
            self._emit_audit(e.tool_name, {}, "DENY", str(e), tier="tier1")
            return GuardrailResult(
                output_info=f"Blocked by Tenuo: {e}",
                tripwire_triggered=self.tripwire,
            ).to_agents_sdk()

        if not tool_calls:
            # No tool calls to validate
            return GuardrailResult(output_info="No tool calls").to_agents_sdk()

        violations = []
        for tool_name, arguments in tool_calls:
            try:
                await verify_tool_call_async(
                    tool_name,
                    arguments,
                    self.allow_tools,
                    self.deny_tools,
                    self.constraints,
                    self.warrant,
                    self.signing_key,
                    self.trusted_roots,
                    self.approval_handler,
                    self.approvals,
                    warrant_chain=self.warrant_chain,
                )
                self._emit_audit(tool_name, arguments, "ALLOW", "passed all checks")
                self._emit_cp(tool_name, arguments, allowed=True)
            except (ToolDenied, WarrantDenied, OpenAIConstraintViolation, MalformedToolCall) as e:
                violations.append(f"{tool_name}: {e}")
                logger.warning(f"Tenuo guardrail blocked: {tool_name} - {e}")
                tier = "tier2" if isinstance(e, WarrantDenied) else "tier1"
                self._emit_audit(tool_name, arguments, "DENY", str(e), tier=tier)
                self._emit_cp(tool_name, arguments, allowed=False, denial_reason=str(e))

        if violations:
            result = GuardrailResult(
                output_info=f"Blocked by Tenuo: {'; '.join(violations)}",
                tripwire_triggered=self.tripwire,
            )
        else:
            result = GuardrailResult(
                output_info=f"Tenuo: {len(tool_calls)} tool call(s) authorized",
                tripwire_triggered=False,
            )

        return result.to_agents_sdk()

    def _emit_audit(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        decision: str,
        reason: str,
        tier: str = "tier1",
    ) -> None:
        """Emit an audit event if callback is configured."""
        if self.audit_callback is None:
            return

        event = AuditEvent(
            session_id=self._session_id,
            timestamp=time.time(),
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            reason=reason,
            tier=tier,
            constraint_hash=self._constraint_hash,
            warrant_id=self._warrant_id,
        )

        try:
            self.audit_callback(event)
        except Exception as e:
            # Cross-adapter contract: audit emission never crashes the caller,
            # always logs exc_info=True so the traceback reaches operators.
            logger.warning("Audit callback failed: %s", e, exc_info=True)

    def _emit_cp(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        *,
        allowed: bool,
        denial_reason: str = "",
    ) -> None:
        """Emit to control plane if connected."""
        if self._control_plane is None:
            return
        try:
            from ._enforcement import EnforcementResult
            res = EnforcementResult(
                allowed=allowed, tool=tool_name, arguments=arguments,
                warrant_id=self._warrant_id or "",
                denial_reason=denial_reason if not allowed else "",
            )
            self._control_plane.emit_for_enforcement(res)
        except Exception:
            logger.warning("Control plane emission failed for '%s'; audit event lost", tool_name, exc_info=True)

    def _extract_tool_calls(self, input_data: Any) -> List[tuple]:
        """Extract tool calls from Agents SDK input.

        The input format varies based on SDK version and context.
        This method handles multiple formats gracefully.
        """
        tool_calls = []

        # Format 1: Direct tool call list
        if isinstance(input_data, list):
            for item in input_data:
                tc = self._parse_tool_call_item(item)
                if tc:
                    tool_calls.append(tc)

        # Format 2: Dict with 'tool_calls' key
        elif isinstance(input_data, dict):
            if "tool_calls" in input_data:
                for item in input_data["tool_calls"]:
                    tc = self._parse_tool_call_item(item)
                    if tc:
                        tool_calls.append(tc)
            # Format 3: Single tool call dict
            elif "name" in input_data or "function" in input_data:
                tc = self._parse_tool_call_item(input_data)
                if tc:
                    tool_calls.append(tc)

        # Format 4: Object with attributes
        elif hasattr(input_data, "tool_calls"):
            for item in input_data.tool_calls or []:
                tc = self._parse_tool_call_item(item)
                if tc:
                    tool_calls.append(tc)

        return tool_calls

    def _parse_tool_call_item(self, item: Any) -> Optional[tuple]:
        """Parse a single tool call item into (name, arguments).

        SECURITY: Malformed JSON raises MalformedToolCall to fail closed.
        We do NOT silently default to {} as that could bypass constraints.
        """
        # Dict format
        if isinstance(item, dict):
            if "function" in item:
                func = item["function"]
                name = func.get("name", "")
                args_str = func.get("arguments", "{}")
            else:
                name = item.get("name", "")
                args_str = item.get("arguments", "{}")

            if not name:
                return None
            try:
                arguments = (
                    _loads_tool_arguments(args_str) if isinstance(args_str, str) else args_str
                )
            except ValueError as e:
                # SECURITY: Fail closed on malformed JSON
                raise MalformedToolCall(name, f"Invalid JSON arguments: {e}")

            return (name, arguments)

        # Object format
        if hasattr(item, "function"):
            func = item.function
            name = getattr(func, "name", "")
            args_str = getattr(func, "arguments", "{}")
            if not name:
                return None
            try:
                arguments = (
                    _loads_tool_arguments(args_str) if isinstance(args_str, str) else args_str
                )
            except ValueError as e:
                raise MalformedToolCall(name, f"Invalid JSON arguments: {e}")
            return (name, arguments)

        if hasattr(item, "name"):
            name = item.name
            args_str = getattr(item, "arguments", "{}")
            if not name:
                return None
            try:
                arguments = (
                    _loads_tool_arguments(args_str) if isinstance(args_str, str) else args_str
                )
            except ValueError as e:
                raise MalformedToolCall(name, f"Invalid JSON arguments: {e}")
            return (name, arguments)

        return None


def create_tier1_guardrail(
    *,
    allow_tools: Optional[List[str]] = None,
    deny_tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
    tripwire: bool = True,
    audit_callback: Optional[AuditCallback] = None,
) -> TenuoToolGuardrail:
    """Create a Tier 1 guardrail for OpenAI Agents SDK.

    This guardrail validates tool calls against constraints without
    cryptographic verification. Use it when trusted application code owns the policy.

    Args:
        allow_tools: Allowlist of permitted tool names
        deny_tools: Denylist of forbidden tool names
        constraints: Per-tool argument constraints
        tripwire: If True, halt agent on violation
        audit_callback: Optional callback for audit events

    Returns:
        A TenuoToolGuardrail. To enforce an Agent's tool calls, pass the same
        arguments to :func:`guard_agent`.

    Example:
        from agents import Agent
        from tenuo.openai import guard_agent, Pattern

        agent = guard_agent(
            Agent(name="Assistant", tools=[send_email, read_file]),
            constraints={
                "send_email": {"to": Pattern("*@company.com")},
                "read_file": {"path": Pattern("/data/*")},
            },
        )
    """
    return TenuoToolGuardrail(
        allow_tools=allow_tools,
        deny_tools=deny_tools,
        constraints=constraints,
        tripwire=tripwire,
        audit_callback=audit_callback,
    )


def create_tier2_guardrail(
    *,
    warrant: Warrant,
    signing_key: SigningKey,
    trusted_roots: Optional[list] = None,
    tripwire: bool = True,
    audit_callback: Optional[AuditCallback] = None,
    warrant_chain: Optional[List[Warrant]] = None,
) -> TenuoToolGuardrail:
    """Create a Tier 2 guardrail for OpenAI Agents SDK.

    This guardrail validates tool calls against a warrant with full
    Proof-of-Possession verification. Required for distributed/multi-agent
    scenarios where cryptographic authorization is needed.

    Args:
        warrant: The warrant authorizing tool usage, or the whole delegation
            chain as a WarrantStack string or root-first list (leaf last)
        signing_key: The agent's signing key (must match warrant holder)
        tripwire: If True, halt agent on violation
        audit_callback: Optional callback for audit events
        warrant_chain: Parent warrants of a delegated ``warrant``, root-first
            and excluding the leaf

    Returns:
        A TenuoToolGuardrail. To enforce an Agent's tool calls, pass the same
        arguments to :func:`guard_agent`.

    Example:
        from agents import Agent, Runner
        from tenuo.openai import guard_agent
        from tenuo import SigningKey, Warrant, Pattern

        # Control plane issues warrant to agent
        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()

        warrant = (Warrant.mint_builder()
            .capability("send_email", {"to": Pattern("*@company.com")})
            .holder(agent_key.public_key)
            .ttl(3600)
            .mint(control_key))

        # Agent uses warrant
        agent = guard_agent(
            Agent(name="Authorized Assistant", tools=[send_email]),
            warrant=warrant,
            signing_key=agent_key,
            trusted_roots=[control_key.public_key],
        )

        result = await Runner.run(agent, "Send email to user@company.com")
    """
    return TenuoToolGuardrail(
        warrant=warrant,
        signing_key=signing_key,
        trusted_roots=trusted_roots,
        tripwire=tripwire,
        audit_callback=audit_callback,
        warrant_chain=warrant_chain,
    )


# =============================================================================
# Agents SDK: tool-call enforcement
# =============================================================================


# Policies registered by guard_agent(), keyed by the agent object. Tools and
# MCP servers are often shared between agents, so the guardrail attached to
# them looks up the policy of whichever agent is calling.
_AGENT_POLICIES: Dict[int, Tuple["weakref.ReferenceType[Any]", TenuoToolGuardrail, str]] = {}
_AGENT_POLICIES_LOCK = threading.Lock()
_TOOL_GUARDRAIL: Any = None


def _register_agent_policy(agent: Any, guard: TenuoToolGuardrail, on_denial: str) -> None:
    key = id(agent)

    def _forget(_ref: Any, key: int = key) -> None:
        with _AGENT_POLICIES_LOCK:
            entry = _AGENT_POLICIES.get(key)
            if entry is not None and entry[0] is _ref:
                del _AGENT_POLICIES[key]

    with _AGENT_POLICIES_LOCK:
        _AGENT_POLICIES[key] = (weakref.ref(agent, _forget), guard, on_denial)


def _agent_policy(agent: Any) -> Optional[Tuple[TenuoToolGuardrail, str]]:
    with _AGENT_POLICIES_LOCK:
        entry = _AGENT_POLICIES.get(id(agent))
    if entry is None or entry[0]() is not agent:
        return None
    return entry[1], entry[2]


def _tenuo_tool_input_guardrail() -> Any:
    """Return the shared Agents SDK ``ToolInputGuardrail`` used by guard_agent().

    It runs before every tool invocation with the tool's name, arguments and
    the calling agent, and authorizes the call against that agent's policy
    using the same decision path as the other OpenAI adapters. An agent with
    no registered policy, and any failure to reach a decision, is denied.
    """
    global _TOOL_GUARDRAIL
    if _TOOL_GUARDRAIL is not None:
        return _TOOL_GUARDRAIL

    from agents.tool_guardrails import (  # type: ignore[import-not-found]
        ToolGuardrailFunctionOutput,
        ToolInputGuardrail,
    )

    def _deny(
        guard: Optional[TenuoToolGuardrail],
        on_denial: str,
        tool_name: str,
        arguments: Dict[str, Any],
        reason: str,
        tier: str,
    ) -> Any:
        logger.warning("Tenuo blocked tool call %s: %s", tool_name, reason)
        if guard is not None:
            guard._emit_audit(tool_name, arguments, "DENY", reason, tier=tier)
            guard._emit_cp(tool_name, arguments, allowed=False, denial_reason=reason)
        message = f"Tool call '{tool_name}' was blocked by Tenuo: {reason}"
        if on_denial == "raise":
            return ToolGuardrailFunctionOutput.raise_exception(output_info=message)
        return ToolGuardrailFunctionOutput.reject_content(message, output_info=message)

    async def check_tool_call(data: Any) -> Any:
        tool_name = getattr(data.context, "tool_name", None) or "<unknown>"
        policy = _agent_policy(getattr(data, "agent", None))
        if policy is None:
            agent_name = getattr(getattr(data, "agent", None), "name", "?")
            return _deny(
                None,
                "reject",
                tool_name,
                {},
                f"agent '{agent_name}' has no Tenuo policy; call guard_agent() on it",
                "tier1",
            )
        guard, on_denial = policy
        raw = getattr(data.context, "tool_arguments", None)
        try:
            arguments = _loads_tool_arguments(raw) if raw else {}
        except Exception as e:  # malformed or duplicate-key JSON
            return _deny(guard, on_denial, tool_name, {}, str(MalformedToolCall(tool_name, str(e))), "tier1")
        if not isinstance(arguments, dict):
            return _deny(guard, on_denial, tool_name, {}, "tool arguments are not a JSON object", "tier1")
        try:
            await verify_tool_call_async(
                tool_name,
                arguments,
                guard.allow_tools,
                guard.deny_tools,
                guard.constraints,
                guard.warrant,
                guard.signing_key,
                guard.trusted_roots,
                guard.approval_handler,
                guard.approvals,
                warrant_chain=guard.warrant_chain,
            )
        except WarrantDenied as e:
            return _deny(guard, on_denial, tool_name, arguments, str(e), "tier2")
        except Exception as e:  # fail closed on every other error
            return _deny(guard, on_denial, tool_name, arguments, str(e), "tier1")
        guard._emit_audit(tool_name, arguments, "ALLOW", "passed all checks")
        guard._emit_cp(tool_name, arguments, allowed=True)
        return ToolGuardrailFunctionOutput.allow()

    candidate: Any = ToolInputGuardrail(guardrail_function=check_tool_call, name="tenuo")
    # guard_agent() may be called concurrently while an application builds its
    # agent graph. Publish one canonical guardrail so identity-based deduplication
    # still works for tools shared by those agents.
    with _AGENT_POLICIES_LOCK:
        if _TOOL_GUARDRAIL is None:
            _TOOL_GUARDRAIL = candidate
        return _TOOL_GUARDRAIL


def _handoff_target(handoff: Any) -> Any:
    """Return the Agent a handoff points to, or None if it can't be resolved."""
    if hasattr(handoff, "tools"):  # an Agent listed directly in handoffs
        return handoff
    ref = getattr(handoff, "_agent_ref", None)
    return ref() if callable(ref) else None


def guard_agent(
    agent: Any,
    *,
    allow_tools: Optional[List[str]] = None,
    deny_tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
    warrant: Optional[Warrant] = None,
    signing_key: Optional[SigningKey] = None,
    trusted_roots: Optional[list] = None,
    warrant_chain: Optional[List[Warrant]] = None,
    approval_handler: Optional[Any] = None,
    approvals: Optional[list] = None,
    audit_callback: Optional[AuditCallback] = None,
    on_denial: str = "reject",
    include_handoffs: bool = True,
) -> Any:
    """Check every tool call an OpenAI Agents SDK agent makes, before it runs.

    Attaches a Tenuo tool guardrail to each function tool, to each MCP server
    on the agent, and (with ``include_handoffs``) to every agent reachable
    through handoffs. Each tool call is authorized against the same Tier 1
    constraints or Tier 2 warrant that :func:`guard` accepts.

    Args:
        agent: The ``agents.Agent`` to protect. It is modified in place and returned.
        on_denial: ``"reject"`` (default) returns the denial to the model as the
            tool result and continues the run. ``"raise"`` halts the run with
            ``ToolInputGuardrailTripwireTriggered``.
        include_handoffs: Also guard agents reachable through ``agent.handoffs``.

    The policy belongs to the agent, not to its tools: agents that share
    tool objects or MCP servers each keep their own policy, and calling
    guard_agent() again on an agent replaces its policy. A tool that has been
    guarded denies calls from any agent without a policy, including copies
    made with ``agent.clone()``; guard those too.

    Only tools present when guard_agent() runs are guarded: call it again
    after adding tools. An agent wrapped with ``agent.as_tool()`` runs its own
    tools inside that call, so guard the inner agent as well.

    Raises:
        OpenAIConfigurationError: A tool can't be checked (for example a hosted
            tool that runs on OpenAI's side), an MCP server can't accept tool
            guardrails with the installed SDK, or a handoff target can't be
            resolved. Guarding fails closed instead of leaving a tool unchecked.

    Requires openai-agents 0.3.3 or later (tool guardrails).

    Example::

        from agents import Agent, Runner
        from tenuo.openai import guard_agent

        agent = guard_agent(
            Agent(name="support", tools=[lookup_order, issue_refund]),
            warrant=task_warrant,
            signing_key=agent_key,
            trusted_roots=[control_plane_key.public_key],
        )
        result = await Runner.run(agent, "...")
    """
    try:
        import agents.tool_guardrails  # type: ignore[import-not-found]  # noqa: F401
    except ImportError as e:
        raise OpenAIConfigurationError(
            "guard_agent requires openai-agents 0.3.3 or later (tool guardrails).", "CFG_006"
        ) from e
    if on_denial not in ("reject", "raise"):
        raise OpenAIConfigurationError("on_denial must be 'reject' or 'raise'", "CFG_006")

    guard = TenuoToolGuardrail(
        allow_tools=allow_tools,
        deny_tools=deny_tools,
        constraints=constraints,
        warrant=warrant,
        signing_key=signing_key,
        trusted_roots=trusted_roots,
        audit_callback=audit_callback,
        approval_handler=approval_handler,
        approvals=approvals,
        warrant_chain=warrant_chain,
    )
    tool_guardrail = _tenuo_tool_input_guardrail()

    def attach(holder: Any) -> None:
        existing = list(getattr(holder, "tool_input_guardrails", None) or [])
        if not any(g is tool_guardrail for g in existing):
            holder.tool_input_guardrails = existing + [tool_guardrail]

    seen: set = set()
    pending = [agent]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        _register_agent_policy(current, guard, on_denial)
        for tool in getattr(current, "tools", None) or []:
            if not hasattr(tool, "tool_input_guardrails"):
                raise OpenAIConfigurationError(
                    f"Tool '{getattr(tool, 'name', type(tool).__name__)}' on agent "
                    f"'{getattr(current, 'name', '?')}' can't be checked by Tenuo "
                    f"({type(tool).__name__} doesn't support tool guardrails). Remove it, "
                    "or replace it with a function tool.",
                    "CFG_006",
                )
            attach(tool)
        for server in getattr(current, "mcp_servers", None) or []:
            if not hasattr(server, "tool_input_guardrails"):
                raise OpenAIConfigurationError(
                    f"MCP server '{getattr(server, 'name', type(server).__name__)}' can't accept "
                    "tool guardrails with the installed openai-agents. Upgrade openai-agents to "
                    "a release with MCP server guardrails.",
                    "CFG_006",
                )
            attach(server)
        if include_handoffs:
            for handoff in getattr(current, "handoffs", None) or []:
                target = _handoff_target(handoff)
                if target is None:
                    raise OpenAIConfigurationError(
                        f"Can't resolve the agent behind handoff "
                        f"'{getattr(handoff, 'tool_name', handoff)}'. Call guard_agent on it "
                        "directly and pass include_handoffs=False here.",
                        "CFG_006",
                    )
                pending.append(target)
    return agent


# =============================================================================
# Exports
# =============================================================================


__all__ = [
    # Main API
    "guard",
    "GuardBuilder",
    "GuardedClient",
    "GuardedResponses",
    "enable_debug",
    # OpenAI Agents SDK Integration
    "TenuoToolGuardrail",
    "GuardrailResult",
    "create_tier1_guardrail",
    "create_tier2_guardrail",
    "guard_agent",
    # Audit
    "AuditEvent",
    "AuditCallback",
    # Exceptions
    "TenuoOpenAIError",
    "ToolDenied",
    "OpenAIConstraintViolation",
    "MalformedToolCall",
    "BufferOverflow",
    "WarrantDenied",
    "MissingSigningKey",
    "OpenAIConfigurationError",
    # Zero-config entry point
    "protect",
    # Re-export constraints for convenience
    "Pattern",
    "Exact",
    "OneOf",
    "Range",
    "Regex",
    "Cidr",
    "UrlPattern",
    "Contains",
    "Subset",
    "Wildcard",
    "AnyOf",
    "All",
    "Not",
    "NotOneOf",
    "CEL",
    "Subpath",  # Python-only secure path containment constraint
    # Tier 2: Warrant types (re-exported for convenience)
    "Warrant",
    "SigningKey",
]


# =============================================================================
# Zero-Config Entry Point
# =============================================================================


def protect(
    client: Any,
    *,
    tools: Optional[List[Any]] = None,
) -> GuardedClient:
    """
    Wrap an OpenAI client with Tenuo protection. Zero configuration required.

    This is the simplest way to add Tenuo to your OpenAI integration.
    It provides "fail-closed" security: only explicitly allowed tools can run.

    Args:
        client: OpenAI client (sync or async)
        tools: List of allowed tools (names, dicts, or functions).
               If not provided, ALL tools are denied by default.

    Returns:
        Protected client that only allows specified tools

    Example - Quick Start::

        from openai import OpenAI
        from tenuo.openai import protect

        # Protect your client - only 'search' is allowed
        client = protect(OpenAI(), tools=["search"])

        # This works:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Search for AI papers"}],
            tools=[{"type": "function", "function": {"name": "search", ...}}]
        )

        # If LLM tries to call 'delete_file', it's blocked automatically

    Example - With Constraints::

        from tenuo.openai import protect, GuardBuilder, Subpath

        # For constraints, use GuardBuilder instead:
        client = (GuardBuilder(OpenAI())
            .allow("search")
            .allow("read_file", path=Subpath("/data"))  # Only /data/ allowed
            .build())

    Next Steps:
        - Add constraints: Use GuardBuilder().allow("tool", param=Constraint)
        - Add warrants: Use GuardBuilder().with_warrant(warrant, key)
        - See docs: https://tenuo.ai/docs/openai
    """
    if tools is None:
        # No tools specified = deny all (fail closed)
        return guard(client, allow_tools=[], on_denial="raise")

    # Extract tool names
    tool_names = []
    for tool in tools:
        if isinstance(tool, str):
            tool_names.append(tool)
        elif isinstance(tool, dict):
            # OpenAI tool format
            if "function" in tool:
                tool_names.append(tool["function"].get("name", ""))
            elif "name" in tool:
                tool_names.append(tool["name"])
        elif callable(tool):
            tool_names.append(getattr(tool, "__name__", str(tool)))
        else:
            tool_names.append(str(tool))

    return guard(client, allow_tools=tool_names, on_denial="raise")
