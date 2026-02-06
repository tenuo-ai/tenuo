"""
Tenuo CrewAI Adapter - Tool Authorization for Multi-Agent Workflows

Uses CrewAI's native hooks system for framework-level enforcement.
All tool calls are intercepted via before_tool_call hooks - no wrapping needed.

Compatibility:
    CrewAI: 0.80.0+ (requires hooks API)
    Python: 3.9+

Version History:
    1.0.0: Initial release (tool wrapping)
    2.0.0: Hooks-based integration (breaking change)

Provides constraint enforcement for CrewAI tool calls with two tiers:

**Tier 1 (Guardrails)**: Runtime constraint checking without cryptography.
    Good for single-process crews. Catches hallucinated tool calls,
    argument constraint violations, and cross-agent tool confusion.

**Tier 2 (Warrant + PoP)**: Cryptographic authorization with Proof-of-Possession.
    Required for distributed crews and delegation chains. Each tool call is
    signed with the agent's private key, proving the caller holds the warrant.

Security Philosophy (Fail Closed):
    Tenuo follows a "fail closed" security model. When in doubt, deny:
    - Unknown constraint types are rejected (not silently passed)
    - Missing constraint attributes cause denial
    - Hallucinated tool arguments are blocked
    - Warrant without signing_key raises MissingSigningKey

Tool Namespacing:
    CrewAI tool names are not globally unique. Multiple agents may have tools
    named `search` with different implementations and security requirements.

    Tenuo internally namespaces tools as `agent_role::tool_name` to prevent
    cross-agent confusion. Resolution order:
    1. Check `agent_role::tool_name` (exact match)
    2. Fall back to `tool_name` (global default)
    3. Reject if neither exists

Usage (Global Hook - Recommended):
    from tenuo.crewai import GuardBuilder, Subpath, Pattern

    guard = (GuardBuilder()
        .allow("read_file", path=Subpath("/data"))
        .allow("send_email", recipients=Pattern("*@company.com"))
        .on_denial("raise")
        .build())

    # Register as global hook - ALL tool calls go through this guard
    guard.register()

Usage (Crew-Scoped Hook):
    from crewai import CrewBase
    from crewai.hooks import before_tool_call_crew

    @CrewBase
    class MyProjCrew:
        def __init__(self):
            self.guard = GuardBuilder().allow(...).build()

        @before_tool_call_crew
        def authorize(self, context):
            return self.guard.authorize_hook(context)

Usage (Tier 2 - Warrant with PoP):
    from tenuo.crewai import GuardBuilder
    from tenuo import SigningKey, Warrant

    agent_key = SigningKey.generate()
    warrant = Warrant.mint_builder()...  # From control plane

    guard = (GuardBuilder()
        .with_warrant(warrant, agent_key)
        .build())

    guard.register()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Union,
)

# Import constraint types from tenuo core
from tenuo import (
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
    # Tier 2: Warrant types
    Warrant,
    SigningKey,
    PublicKey,
)

# Import Python-only security constraints
from tenuo.constraints import Subpath, UrlSafe, Shlex

# Import shared constraint checking logic from framework-agnostic core
from tenuo.core import check_constraint

# Check version compatibility on import (warns, doesn't fail)
from tenuo._version_compat import check_crewai_compat  # noqa: E402
check_crewai_compat()

# Import CrewAI hooks API (required for this integration)
try:
    from crewai.hooks import (  # type: ignore[import-not-found,import-untyped]
        register_before_tool_call_hook,
        unregister_before_tool_call_hook,
        ToolCallHookContext,
    )
    HOOKS_AVAILABLE = True
except ImportError:
    HOOKS_AVAILABLE = False
    ToolCallHookContext = None  # type: ignore[misc,assignment]

logger = logging.getLogger("tenuo.crewai")


def enable_debug(handler: Optional[logging.Handler] = None) -> None:
    """Enable debug logging for Tenuo CrewAI adapter.

    Shows detailed authorization decisions, constraint checks, and namespace
    resolution. Useful for troubleshooting multi-agent crews.

    Args:
        handler: Optional custom handler. If None, logs to stderr.
    """
    logger.setLevel(logging.DEBUG)
    if handler is None:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
    if not logger.handlers:
        logger.addHandler(handler)


# Type alias for constraint types
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
    Subpath,
    UrlSafe,
    Shlex,
]

# Denial modes
DenialMode = Literal["raise", "skip", "log"]


# =============================================================================
# Exceptions
# =============================================================================


class TenuoCrewAIError(Exception):
    """Base exception for Tenuo CrewAI adapter errors."""

    error_code: str = "CREWAI_ERROR"

    def __init__(self, message: str):
        super().__init__(message)


class ToolDenied(TenuoCrewAIError):
    """Raised when a tool is not in the allowed list.

    This error indicates the tool was never authorized, not that a specific
    argument violated a constraint.
    """

    error_code = "TOOL_DENIED"

    def __init__(
        self,
        tool: str,
        reason: str,
        *,
        quick_fix: Optional[str] = None,
        allowed_tools: Optional[List[str]] = None,
    ):
        self.tool = tool
        self.reason = reason
        self.quick_fix = quick_fix or f".allow('{tool}', ...)"
        self.allowed_tools = allowed_tools

        msg = f"Tool '{tool}' denied: {reason}"
        msg += f"\n\n  Quick fix: {self.quick_fix}"
        msg += "\n  Docs: https://tenuo.ai/docs/crewai"

        super().__init__(msg)


class ConstraintViolation(TenuoCrewAIError):
    """Raised when a tool argument violates a constraint.

    Attributes:
        tool: Name of the tool that was called
        argument: The parameter that violated the constraint
        value: The actual value that was passed
        constraint: The constraint that was violated
    """

    error_code = "CONSTRAINT_VIOLATION"

    def __init__(
        self,
        tool: str,
        argument: str,
        value: Any,
        constraint: Constraint,
        *,
        reason: Optional[str] = None,
        quick_fix: Optional[str] = None,
    ):
        self.tool = tool
        self.argument = argument
        self.value = value
        self.constraint = constraint
        self.reason = reason or f"value does not satisfy {constraint}"
        self.quick_fix = quick_fix

        msg = f"Constraint violation on {tool}.{argument}: {self.reason}"
        msg += f"\n  Value: {value!r}"
        msg += f"\n  Constraint: {constraint}"
        if quick_fix:
            msg += f"\n\n  Quick fix: {quick_fix}"
        msg += "\n  Docs: https://tenuo.ai/docs/constraints"

        super().__init__(msg)


class UnlistedArgument(TenuoCrewAIError):
    """Raised when an argument is not covered by any constraint.

    In closed-world semantics, every argument must have an explicit constraint.
    Use Wildcard() to explicitly allow any value.
    """

    error_code = "UNLISTED_ARGUMENT"

    def __init__(
        self,
        tool: str,
        argument: str,
        *,
        allowed_args: Optional[List[str]] = None,
    ):
        self.tool = tool
        self.argument = argument
        self.allowed_args = allowed_args
        self.quick_fix = f".allow('{tool}', {argument}=Wildcard())"

        msg = f"Argument '{argument}' not in constraints for tool '{tool}'"
        if allowed_args:
            msg += f"\n  Allowed arguments: {', '.join(allowed_args)}"
        msg += f"\n\n  Quick fix: {self.quick_fix}"
        msg += "\n  Docs: https://tenuo.ai/docs/constraints"

        super().__init__(msg)


class MissingSigningKey(TenuoCrewAIError):
    """Raised when Tier 2 warrant is provided but no signing key.

    Warrants require Proof-of-Possession signatures, which need a signing key.
    """

    error_code = "MISSING_SIGNING_KEY"

    def __init__(self):
        super().__init__(
            "Warrant provided without signing_key. "
            "Tier 2 requires a signing key for Proof-of-Possession. "
            "See: https://tenuo.ai/docs/tier2"
        )


class ConfigurationError(TenuoCrewAIError):
    """Raised when guard configuration is invalid."""

    error_code = "CONFIGURATION_ERROR"


class EscalationAttempt(TenuoCrewAIError):
    """Raised when delegation attempts to widen authority."""

    error_code = "ESCALATION_ATTEMPT"


class WarrantExpired(TenuoCrewAIError):
    """Raised when a Tier 2 warrant has expired.

    Warrants have a TTL (time-to-live) after which they are no longer valid.
    Renewal or re-issuance is required.
    """

    error_code = "WARRANT_EXPIRED"

    def __init__(
        self,
        warrant_id: Optional[str] = None,
        expired_at: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        self.warrant_id = warrant_id
        self.expired_at = expired_at
        self.reason = reason

        if reason:
            msg = f"Warrant authorization failed: {reason}"
        else:
            msg = "Warrant has expired"
            if warrant_id:
                msg = f"Warrant '{warrant_id}' has expired"
            if expired_at:
                msg += f" (expired at {expired_at})"
        msg += "\n\n  Action: Request a new warrant from the issuer."
        msg += "\n  Docs: https://tenuo.ai/docs/tier2#expiry"

        super().__init__(msg)


class InvalidPoP(TenuoCrewAIError):
    """Raised when Proof-of-Possession signature is invalid.

    This indicates either:
    - The signing key doesn't match the warrant holder
    - The signature was corrupted or tampered with
    - The tool/args don't match what was signed
    """

    error_code = "INVALID_POP"

    def __init__(self, reason: str = "Signature verification failed"):
        self.reason = reason
        super().__init__(
            f"Invalid Proof-of-Possession: {reason}\n"
            "  Docs: https://tenuo.ai/docs/tier2#pop"
        )


class WarrantToolDenied(TenuoCrewAIError):
    """Raised when a warrant doesn't authorize a specific tool.

    Different from ToolDenied which is for Tier 1 constraint-based denials.
    This specifically indicates the cryptographic warrant doesn't include
    authorization for the requested tool.
    """

    error_code = "WARRANT_TOOL_DENIED"

    def __init__(self, tool: str, warrant_id: Optional[str] = None):
        self.tool = tool
        self.warrant_id = warrant_id

        msg = f"Warrant does not authorize tool '{tool}'"
        if warrant_id:
            msg += f" (warrant: {warrant_id})"
        msg += "\n\n  Action: Request a warrant that includes this tool."

        super().__init__(msg)


# =============================================================================
# DenialResult Sentinel
# =============================================================================


@dataclass
class DenialResult:
    """Sentinel returned when on_denial is 'log' or 'skip'.

    Allows CrewAI agents to detect and react to denials deterministically,
    rather than receiving ambiguous None values.

    Attributes:
        tool: Name of the tool that was denied
        reason: Why the tool was denied
        error_code: Machine-readable error code
    """

    tool: str
    reason: str
    error_code: str = "DENIAL"

    def __bool__(self) -> bool:
        """Returns False so `if result:` checks work naturally."""
        return False

    def __repr__(self) -> str:
        return f"DenialResult(tool={self.tool!r}, reason={self.reason!r})"


# =============================================================================
# Audit Support
# =============================================================================


@dataclass
class AuditEvent:
    """Record of an authorization decision.

    Attributes:
        tool: Name of the tool
        arguments: Tool arguments (may be redacted)
        decision: "ALLOW" or "DENY"
        reason: Why the decision was made
        error_code: Machine-readable code if denied
        agent_role: CrewAI agent role (for namespaced tools)
        timestamp: ISO timestamp
    """

    tool: str
    arguments: Dict[str, Any]
    decision: str  # "ALLOW" or "DENY"
    reason: str
    error_code: Optional[str] = None
    agent_role: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


AuditCallback = Callable[[AuditEvent], None]


# =============================================================================
# Explanation API (Phase 2)
# =============================================================================


@dataclass
class ExplanationResult:
    """Result of explaining an authorization decision.

    Used for debugging, CI policy tests, and compliance checks.
    Provides detailed information about why a call would be allowed or denied.

    Attributes:
        tool: Name of the tool being explained
        status: "ALLOWED" or "DENIED"
        reason: Human-readable explanation
        details: Additional context (argument, value, constraint, etc.)
        quick_fix: Suggested code change to fix the issue
    """

    tool: str
    status: str  # "ALLOWED" or "DENIED"
    reason: str
    details: Optional[Dict[str, Any]] = None
    quick_fix: Optional[str] = None

    def __bool__(self) -> bool:
        """Returns True if ALLOWED, False if DENIED."""
        return self.status == "ALLOWED"

    def __repr__(self) -> str:
        if self.status == "ALLOWED":
            return f"ExplanationResult(tool={self.tool!r}, status='ALLOWED')"
        return (
            f"ExplanationResult(tool={self.tool!r}, status='DENIED', "
            f"reason={self.reason!r})"
        )


# =============================================================================
# GuardBuilder
# =============================================================================


class GuardBuilder:
    """Builder for CrewAI tool authorization.

    Supports both Tier 1 (constraints only) and Tier 2 (warrant + PoP).

    Example:
        guard = (GuardBuilder()
            .allow("read_file", path=Subpath("/data"))
            .allow("send_email", recipients=Pattern("*@company.com"))
            .on_denial("raise")
            .build())

        protected_tool = guard.protect(my_tool)

    Security Note:
        By default, protect() returns a NEW tool, and the original is unchanged.
        If you want to ensure the original cannot be used (preventing bypass),
        use .seal(True) to destructively seal the original tool.
    """

    def __init__(self):
        self._allowed: Dict[str, Dict[str, Constraint]] = {}
        self._warrant: Optional[Warrant] = None
        self._signing_key: Optional[SigningKey] = None
        self._on_denial: DenialMode = "raise"
        self._audit_callback: Optional[AuditCallback] = None

    def allow(self, tool_name: str, **constraints: Constraint) -> "GuardBuilder":
        """Allow a tool with parameter constraints.

        Tool names can be:
        - Simple: "read_file" (global default)
        - Namespaced: "researcher::search" (agent-specific)

        Args:
            tool_name: Tool name (optionally namespaced as agent_role::tool_name)
            **constraints: Keyword arguments mapping param names to constraints

        Example:
            .allow("search", query=Wildcard())
            .allow("researcher::search", query=Pattern("arxiv:*"))
        """
        self._allowed[tool_name] = constraints
        return self

    def with_warrant(
        self, warrant: Warrant, signing_key: SigningKey
    ) -> "GuardBuilder":
        """Enable Tier 2 with warrant and signing key.

        Args:
            warrant: Cryptographic warrant authorizing tool access
            signing_key: Agent's signing key for Proof-of-Possession

        Raises:
            MissingSigningKey: If signing_key is None
        """
        if signing_key is None:
            raise MissingSigningKey()
        self._warrant = warrant
        self._signing_key = signing_key
        return self

    def on_denial(self, mode: DenialMode) -> "GuardBuilder":
        """Set denial handling mode.

        Args:
            mode: One of:
                - "raise": Raise exception on denial (default)
                - "log": Log warning and return DenialResult
                - "skip": Return DenialResult silently (still audited)
        """
        if mode not in ("raise", "log", "skip"):
            raise ConfigurationError(f"Invalid on_denial mode: {mode}")
        self._on_denial = mode
        return self

    def audit(self, callback: AuditCallback) -> "GuardBuilder":
        """Set audit callback for authorization decisions.

        The callback is called for EVERY authorization decision (allow and deny).
        """
        self._audit_callback = callback
        return self

    def build(self) -> "CrewAIGuard":
        """Build the guard instance."""
        # SECURITY: Warn if skip mode is used without audit callback
        # "skip + no audit = invisible failure" is a foot-gun
        if self._on_denial == "skip" and self._audit_callback is None:
            logger.warning(
                "on_denial='skip' without audit callback - denials will be silent. "
                "Consider adding .audit(callback) or using on_denial='log' for observability."
            )

        return CrewAIGuard(
            allowed=self._allowed.copy(),
            warrant=self._warrant,
            signing_key=self._signing_key,
            on_denial=self._on_denial,
            audit_callback=self._audit_callback,
        )


# =============================================================================
# CrewAIGuard
# =============================================================================


class CrewAIGuard:
    """Runtime guard for CrewAI tools using hooks API.

    Enforces tool allowlisting and argument constraints via CrewAI's
    before_tool_call hooks. Supports both Tier 1 (constraints only)
    and Tier 2 (warrant + PoP).

    Use register() to install as a global hook, or as_hook() to get
    the hook function for crew-scoped registration.
    """

    def __init__(
        self,
        allowed: Dict[str, Dict[str, Constraint]],
        warrant: Optional[Warrant],
        signing_key: Optional[SigningKey],
        on_denial: DenialMode,
        audit_callback: Optional[AuditCallback],
    ):
        self._allowed = allowed
        self._warrant = warrant
        self._signing_key = signing_key
        self._on_denial = on_denial
        self._audit_callback = audit_callback
        self._registered_hook: Optional[Callable] = None

    def register(self, *, agent_role: Optional[str] = None) -> "CrewAIGuard":
        """Register this guard as a global before_tool_call hook.

        Once registered, ALL tool calls in ANY crew will be authorized
        through this guard. Use unregister() to remove.

        Args:
            agent_role: Optional agent role for namespaced constraint lookup

        Returns:
            Self for chaining

        Raises:
            ImportError: If CrewAI hooks API is not available (requires 0.80.0+)

        Example:
            guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()
            guard.register()

            # All tool calls now go through authorization
            crew.kickoff()

            guard.unregister()  # Cleanup when done
        """
        if not HOOKS_AVAILABLE:
            raise ImportError(
                "CrewAI hooks API not available. "
                "Requires crewai>=0.80.0. Install with: pip install 'crewai>=0.80.0'"
            )

        if self._registered_hook is not None:
            logger.warning("Guard already registered, unregistering previous hook")
            self.unregister()

        hook = self._create_hook(agent_role=agent_role)
        register_before_tool_call_hook(hook)
        self._registered_hook = hook
        logger.info("Registered Tenuo guard as global before_tool_call hook")
        return self

    def unregister(self) -> "CrewAIGuard":
        """Unregister this guard from the global hook.

        Safe to call even if not registered.

        Returns:
            Self for chaining
        """
        if self._registered_hook is not None:
            if HOOKS_AVAILABLE:
                try:
                    unregister_before_tool_call_hook(self._registered_hook)
                except Exception as e:
                    logger.warning(f"Failed to unregister hook: {e}")
            self._registered_hook = None
            logger.info("Unregistered Tenuo guard hook")
        return self

    def as_hook(
        self, *, agent_role: Optional[str] = None
    ) -> Callable[["ToolCallHookContext"], Optional["ToolCallHookContext"]]:
        """Get the hook function for manual registration.

        Use this when you need crew-scoped hooks instead of global registration.

        Args:
            agent_role: Optional agent role for namespaced constraint lookup

        Returns:
            A callable suitable for @before_tool_call_crew decorator

        Example:
            @CrewBase
            class MyProjCrew:
                def __init__(self):
                    self.guard = GuardBuilder().allow(...).build()

                @before_tool_call_crew
                def authorize(self, context):
                    return self.guard.authorize_hook(context)
        """
        return self._create_hook(agent_role=agent_role)

    def _create_hook(
        self, *, agent_role: Optional[str] = None
    ) -> Callable[[Any], Optional[Any]]:
        """Create a before_tool_call hook function.

        The hook receives ToolCallHookContext and returns:
        - The context (possibly modified) to allow the call
        - None to skip/block the call

        Args:
            agent_role: Optional agent role for namespaced constraint lookup

        Returns:
            Hook function compatible with CrewAI hooks API
        """
        guard = self  # Capture reference for closure

        def tenuo_authorize_hook(context: Any) -> Optional[Any]:
            """Tenuo authorization hook for CrewAI before_tool_call."""
            # Extract tool name and arguments from context
            tool_name = getattr(context, 'tool_name', None) or getattr(context, 'name', '')
            args = getattr(context, 'arguments', {}) or getattr(context, 'args', {})

            # Resolve agent role from context if not provided
            effective_role = agent_role
            if effective_role is None:
                # Try to get agent role from context
                agent = getattr(context, 'agent', None)
                if agent and hasattr(agent, 'role'):
                    effective_role = agent.role

            # Authorize the call
            result = guard._authorize(tool_name, args, agent_role=effective_role)

            if result is not None:
                # Denial - return None to skip the tool call
                # The DenialResult contains the reason which was already logged/audited
                logger.info(f"[TENUO] BLOCKED {tool_name}: {result.reason}")
                return None

            # Authorized - return context to proceed
            return context

        return tenuo_authorize_hook

    def authorize_hook(self, context: Any, *, agent_role: Optional[str] = None) -> Optional[Any]:
        """Authorize a tool call from a CrewAI hook context.

        Direct authorization method for use in crew-scoped hooks.
        This is a convenience wrapper around _create_hook for direct use.

        Args:
            context: ToolCallHookContext from CrewAI
            agent_role: Optional agent role (overrides context-derived role)

        Returns:
            The context if authorized, None if denied

        Example:
            @CrewBase
            class MyProjCrew:
                @before_tool_call_crew
                def authorize(self, context):
                    return self.guard.authorize_hook(context)
        """
        hook = self._create_hook(agent_role=agent_role)
        return hook(context)

    def _resolve_tool_name(
        self, tool_name: str, agent_role: Optional[str]
    ) -> Optional[str]:
        """Resolve tool name with namespace fallback.

        Resolution order:
        1. agent_role::tool_name (exact match)
        2. tool_name (global default)
        3. None if neither exists

        Args:
            tool_name: Simple tool name (e.g., "search")
            agent_role: Agent role for namespacing (e.g., "researcher")

        Returns:
            The key to use for constraint lookup, or None if not found
        """
        if agent_role:
            # SECURITY: Reject agent_role containing namespace separator to prevent injection
            if "::" in agent_role:
                logger.warning(f"Rejecting agent_role with '::' injection attempt: {agent_role!r}")
                return None
            namespaced = f"{agent_role}::{tool_name}"
            if namespaced in self._allowed:
                logger.debug(f"Resolved {tool_name} -> {namespaced}")
                return namespaced

        if tool_name in self._allowed:
            return tool_name

        return None

    def _authorize(
        self,
        tool_name: str,
        args: Dict[str, Any],
        *,
        agent_role: Optional[str] = None,
    ) -> Optional[DenialResult]:
        """Check authorization for a tool call.

        Returns:
            None if authorized, DenialResult if denied and on_denial != "raise"

        Raises:
            ToolDenied, ConstraintViolation, UnlistedArgument: If denied and on_denial == "raise"
        """
        logger.debug(f"Authorizing {tool_name} with args {list(args.keys())}")

        # Step 1: Resolve tool name with namespace fallback
        resolved_name = self._resolve_tool_name(tool_name, agent_role)

        if resolved_name is None:
            error = ToolDenied(
                tool=tool_name,
                reason=f"Tool '{tool_name}' not in allowed list",
                allowed_tools=list(self._allowed.keys()),
            )
            return self._handle_denial(error, tool_name, args, agent_role)

        constraints = self._allowed[resolved_name]

        # Step 2: Check all arguments have constraints (closed-world)
        for arg_name in args:
            if arg_name not in constraints:
                error = UnlistedArgument(  # type: ignore[assignment]
                    tool=tool_name,
                    argument=arg_name,
                    allowed_args=list(constraints.keys()),
                )
                return self._handle_denial(error, tool_name, args, agent_role)

        # Step 3: Check each argument satisfies its constraint
        for arg_name, arg_value in args.items():
            constraint = constraints[arg_name]
            if not check_constraint(constraint, arg_value):
                error = ConstraintViolation(  # type: ignore[assignment]
                    tool=tool_name,
                    argument=arg_name,
                    value=arg_value,
                    constraint=constraint,
                )
                return self._handle_denial(error, tool_name, args, agent_role)

        # Step 4: Tier 2 - Warrant authorization with PoP
        if self._warrant and self._signing_key:
            # Check warrant expiry FIRST - no point validating crypto on expired warrant
            try:
                if hasattr(self._warrant, 'is_expired') and self._warrant.is_expired():
                    warrant_id = None
                    if hasattr(self._warrant, 'id'):
                        warrant_id = self._warrant.id()
                    error = WarrantExpired(warrant_id=warrant_id)  # type: ignore[assignment]
                    return self._handle_denial(error, tool_name, args, agent_role)
            except Exception as e:
                # SECURITY: Fail-closed - if we can't check expiry, deny
                logger.warning(f"Warrant expiry check failed, denying (fail-closed): {e}")
                error = WarrantExpired(warrant_id="unknown", reason="Expiry check failed")  # type: ignore[assignment]
                return self._handle_denial(error, tool_name, args, agent_role)

            # SECURITY NOTE: Holder Verification
            # ===================================
            # The Rust core's warrant.authorize() cryptographically verifies that
            # the PoP signature was created by the key matching warrant.holder().
            # This happens inside verify_pop() via holder.verify(signature).
            #
            # From tenuo-core/src/warrant.rs verify_pop():
            #     if self.payload.holder.verify(&preimage, signature).is_ok() {
            #         verified = true;
            #     }
            #
            # If signing_key doesn't match the holder, the signature verification
            # will fail and authorize() will return Error::SignatureInvalid.
            #
            # This cryptographic enforcement at the Rust level makes a Python-side
            # holder check redundant. We trust the Rust core's implementation,
            # consistent with the A2A and Google ADK integrations.

            try:
                pop = self._warrant.sign(self._signing_key, tool_name, args)
                auth_result = self._warrant.authorize(tool_name, args, signature=pop)
                # SECURITY: Fail-closed - explicitly check return value
                if auth_result is False:
                    error = InvalidPoP(reason="Authorization returned False")  # type: ignore[assignment]
                    return self._handle_denial(error, tool_name, args, agent_role)
            except Exception as e:
                # Handle warrant authorization failures
                error_msg = str(e)
                if "expired" in error_msg.lower():
                    error = WarrantExpired()  # type: ignore[assignment]
                elif "tool" in error_msg.lower() and "not" in error_msg.lower():
                    error = WarrantToolDenied(tool=tool_name)  # type: ignore[assignment]
                else:
                    error = InvalidPoP(reason=error_msg)  # type: ignore[assignment]
                return self._handle_denial(error, tool_name, args, agent_role)

        # Authorization granted
        self._emit_audit(tool_name, args, "ALLOW", "Authorized", agent_role=agent_role)
        logger.debug(f"Authorized {tool_name}")
        return None

    def _handle_denial(
        self,
        error: TenuoCrewAIError,
        tool_name: str,
        args: Dict[str, Any],
        agent_role: Optional[str],
    ) -> Optional[DenialResult]:
        """Handle authorization denial based on mode.

        Always emits audit event, regardless of mode.
        """
        # Always audit denials
        self._emit_audit(
            tool_name,
            args,
            "DENY",
            str(error),
            error_code=error.error_code,
            agent_role=agent_role,
        )

        if self._on_denial == "raise":
            raise error

        elif self._on_denial == "log":
            logger.warning(f"Authorization denied: {error}")
            return DenialResult(
                tool=tool_name,
                reason=str(error),
                error_code=error.error_code,
            )

        elif self._on_denial == "skip":
            logger.info(f"Authorization skipped: {tool_name}")
            return DenialResult(
                tool=tool_name,
                reason=str(error),
                error_code=error.error_code,
            )

        return None  # Should never reach here

    def _emit_audit(
        self,
        tool: str,
        arguments: Dict[str, Any],
        decision: str,
        reason: str,
        *,
        error_code: Optional[str] = None,
        agent_role: Optional[str] = None,
    ) -> None:
        """Emit audit event for authorization decision.

        Note: Arguments are passed as-is to the audit callback. If sensitive
        data redaction is required, implement it in your callback.
        """
        if self._audit_callback:
            # SECURITY: Redact potentially sensitive argument values
            # Only include argument names and types, not raw values
            redacted_args = {
                k: f"<{type(v).__name__}:{len(str(v))} chars>"
                for k, v in arguments.items()
            }
            event = AuditEvent(
                tool=tool,
                arguments=redacted_args,
                decision=decision,
                reason=reason,
                error_code=error_code,
                agent_role=agent_role,
            )
            try:
                self._audit_callback(event)
            except Exception as e:
                logger.error(f"Audit callback failed: {e}")

    # =========================================================================
    # Explain API (Phase 2)
    # =========================================================================

    def explain(
        self,
        tool_name: str,
        args: Dict[str, Any],
        *,
        agent_role: Optional[str] = None,
    ) -> ExplanationResult:
        """Explain why a tool call would be allowed or denied.

        This method does NOT execute the tool or emit audit events.
        It's for introspection, debugging, and CI policy tests.

        Args:
            tool_name: Name of the tool to check
            args: Arguments that would be passed to the tool
            agent_role: Optional agent role for namespaced lookup

        Returns:
            ExplanationResult with status and detailed explanation

        Example:
            result = guard.explain("send_email", {"to": "external@gmail.com"})
            if result.status == "DENIED":
                print(f"Would fail: {result.reason}")
                print(f"Fix: {result.quick_fix}")
        """
        # Step 1: Resolve tool name with namespace fallback
        resolved_name = self._resolve_tool_name(tool_name, agent_role)

        if resolved_name is None:
            return ExplanationResult(
                tool=tool_name,
                status="DENIED",
                reason=f"Tool '{tool_name}' not in allowed list",
                details={"allowed_tools": list(self._allowed.keys())},
                quick_fix=f".allow('{tool_name}', ...)",
            )

        constraints = self._allowed[resolved_name]

        # Step 2: Check for unlisted arguments (closed-world)
        for arg_name in args:
            if arg_name not in constraints:
                return ExplanationResult(
                    tool=tool_name,
                    status="DENIED",
                    reason=f"Argument '{arg_name}' not in constraints",
                    details={
                        "argument": arg_name,
                        "allowed_args": list(constraints.keys()),
                    },
                    quick_fix=f".allow('{tool_name}', {arg_name}=Wildcard())",
                )

        # Step 3: Check each constraint
        for arg_name, arg_value in args.items():
            constraint = constraints[arg_name]
            if not check_constraint(constraint, arg_value):
                return ExplanationResult(
                    tool=tool_name,
                    status="DENIED",
                    reason=f"Constraint violation on '{arg_name}'",
                    details={
                        "argument": arg_name,
                        "value": arg_value,
                        "constraint": str(constraint),
                        "constraint_type": type(constraint).__name__,
                    },
                    quick_fix=None,  # Can't auto-fix constraint violations
                )

        # All checks passed
        return ExplanationResult(
            tool=tool_name,
            status="ALLOWED",
            reason="All constraints satisfied",
            details={
                "resolved_name": resolved_name,
                "constraints": {k: str(v) for k, v in constraints.items()},
            },
        )

    def allows(self, tool_name: str, args: Dict[str, Any], **kwargs: Any) -> bool:
        """Convenience method for CI policy tests.

        Returns True if the tool call would be allowed, False otherwise.
        This is simpler than explain() when you just need a boolean.

        Args:
            tool_name: Name of the tool to check
            args: Arguments that would be passed
            **kwargs: Additional args passed to explain() (e.g., agent_role)

        Returns:
            True if allowed, False if denied

        Example:
            # CI policy test
            def test_support_bot_cannot_delete():
                guard = load_guard("support_bot")
                assert not guard.allows("delete_user", {"user_id": "123"})
        """
        return self.explain(tool_name, args, **kwargs).status == "ALLOWED"

    def explain_all(
        self,
        tool_calls: List[tuple],
        *,
        agent_role: Optional[str] = None,
    ) -> List[ExplanationResult]:
        """Explain multiple tool calls at once.

        Useful for debugging failed sessions or validating expected capabilities.

        Args:
            tool_calls: List of (tool_name, args) tuples
            agent_role: Optional agent role for namespaced lookup

        Returns:
            List of ExplanationResult for each call

        Example:
            results = guard.explain_all([
                ("read_file", {"path": "/data/file.txt"}),
                ("send_email", {"to": "external@gmail.com"}),
            ])
            for r in results:
                if r.status == "DENIED":
                    print(f"{r.tool}: {r.reason}")
        """
        return [
            self.explain(tool_name, args, agent_role=agent_role)
            for tool_name, args in tool_calls
        ]

    def validate(self) -> List[str]:
        """Validate guard configuration.

        Checks for common configuration issues like missing constraints.
        Call this at startup to catch issues early.

        Returns:
            List of warning messages (empty if valid)

        Example:
            warnings = guard.validate()
            if warnings:
                for w in warnings:
                    print(f"Warning: {w}")
        """
        warnings = []

        if not self._allowed:
            warnings.append(
                "No tools allowed. All tool calls will be denied. "
                "Add .allow('tool_name', ...) to your GuardBuilder."
            )

        for tool_name, constraints in self._allowed.items():
            if not constraints:
                warnings.append(
                    f"Tool '{tool_name}' has no parameter constraints. "
                    f"All arguments will cause UnlistedArgument errors. "
                    f"Add constraints or use .allow('{tool_name}') for zero-arg tools."
                )

        return warnings

    @property
    def tier(self) -> int:
        """Return the authorization tier: 1 (constraints) or 2 (warrant + PoP).

        Returns:
            1 if using constraints only (Tier 1)
            2 if using warrant with PoP (Tier 2)
        """
        if self._warrant and self._signing_key:
            return 2
        return 1

    @property
    def has_warrant(self) -> bool:
        """Check if this guard has a Tier 2 warrant configured."""
        return self._warrant is not None and self._signing_key is not None

    def warrant_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the configured warrant.

        Returns:
            Dict with warrant details if Tier 2, None if Tier 1.

        Example:
            info = guard.warrant_info()
            if info:
                print(f"Warrant expires in {info['ttl_remaining']}s")
                print(f"Authorized tools: {info['tools']}")
        """
        if not self._warrant:
            return None

        info: Dict[str, Any] = {
            "tier": 2,
        }

        # Get warrant ID if available
        if hasattr(self._warrant, 'id'):
            try:
                info["warrant_id"] = self._warrant.id()
            except Exception:
                pass

        # Get TTL info if available
        if hasattr(self._warrant, 'ttl_seconds'):
            try:
                info["ttl_remaining"] = self._warrant.ttl_seconds()
            except Exception:
                pass

        # Get expiry status if available
        if hasattr(self._warrant, 'is_expired'):
            try:
                info["is_expired"] = self._warrant.is_expired()
            except Exception:
                pass

        # Get authorized tools if available
        if hasattr(self._warrant, 'tools'):
            try:
                info["tools"] = list(self._warrant.tools())
            except Exception:
                pass

        # Get delegation depth if available
        if hasattr(self._warrant, 'depth'):
            try:
                info["depth"] = self._warrant.depth()
            except Exception:
                pass

        return info




# =============================================================================
# Warrant Delegation (Phase 4: Hierarchical Crews)
# =============================================================================


class WarrantDelegator:
    """Handles warrant delegation in hierarchical CrewAI processes.

    In hierarchical crews, a manager agent may need to delegate authority
    to worker agents. This class ensures that delegation follows the
    principle of attenuation: child warrants can only NARROW scope,
    never expand it.

    Example:
        delegator = WarrantDelegator()

        # Manager delegates to researcher with narrowed scope
        researcher_warrant = delegator.delegate(
            parent_warrant=manager_warrant,
            parent_key=manager_key,
            child_holder=researcher.public_key,
            attenuations={
                "search": {"query": Pattern("arxiv:*")},  # Only arxiv
                "fetch": {"url": Pattern("https://arxiv.org/*")},
            }
        )

        # Use the attenuated warrant for the researcher agent
        researcher_guard = (GuardBuilder()
            .allow("search", query=Pattern("arxiv:*"))
            .with_warrant(researcher_warrant, researcher_key)
            .build())

    Security Properties:
        - Attenuation-only: Child constraints must be subsets of parent
        - No new tools: Can only delegate tools the parent has
        - Depth tracking: Delegations count toward MAX_DELEGATION_DEPTH
    """

    def delegate(
        self,
        parent_warrant: Warrant,
        parent_key: SigningKey,
        child_holder: PublicKey,
        attenuations: Dict[str, Dict[str, Constraint]],
        *,
        ttl: Optional[int] = None,
    ) -> Warrant:
        """Create an attenuated child warrant.

        Args:
            parent_warrant: The warrant authorizing the delegator
            parent_key: Signing key matching parent_warrant's holder
            child_holder: Public key of the agent receiving the delegation
            attenuations: Tool constraints for the child (must be narrower)
            ttl: Optional TTL for child warrant (defaults to parent's remaining)

        Returns:
            A new Warrant with narrowed authority

        Raises:
            EscalationAttempt: If attenuation would widen access
            ValueError: If parent_warrant doesn't support delegation

        Example:
            child_warrant = delegator.delegate(
                parent_warrant=manager_warrant,
                parent_key=manager_key,
                child_holder=worker_public_key,
                attenuations={
                    "read_file": {"path": Subpath("/data/reports")},
                },
                ttl=300,  # 5 minute delegation
            )
        """
        # SECURITY: Validate parent warrant is not expired before delegation
        if hasattr(parent_warrant, 'is_expired'):
            try:
                if parent_warrant.is_expired():
                    raise EscalationAttempt(
                        "Cannot delegate from expired parent warrant. "
                        "Parent warrant must be valid at time of delegation."
                    )
            except EscalationAttempt:
                raise
            except Exception as e:
                # Fail-closed: if we can't check expiry, deny delegation
                raise EscalationAttempt(
                    f"Cannot verify parent warrant expiry: {e}. "
                    "Delegation denied (fail-closed)."
                )

        # Validate parent has tools to delegate
        parent_tools = self._get_parent_tools(parent_warrant)

        # Validate each attenuation
        for tool_name, constraints in attenuations.items():
            self._validate_tool_delegation(
                parent_warrant, parent_tools, tool_name, constraints
            )

        # Build the child warrant via parent's grant_builder
        try:
            builder = parent_warrant.grant_builder()
        except AttributeError as e:
            raise ValueError(
                f"Parent warrant doesn't support delegation: {e}. "
                "Ensure the warrant was created with grant capability."
            )

        # Add capabilities with attenuated constraints
        for tool_name, constraints in attenuations.items():
            builder = builder.capability(tool_name, **constraints)

        # Set holder and TTL
        builder = builder.holder(child_holder)
        if ttl is not None:
            builder = builder.ttl(ttl)

        # Sign and return
        return builder.grant(parent_key)

    def _get_parent_tools(self, parent_warrant: Warrant) -> set:
        """Get the set of tools the parent warrant authorizes.

        Returns:
            Set of tool names the parent authorizes

        Raises:
            EscalationAttempt: If tools cannot be retrieved (fail-closed)
        """
        if hasattr(parent_warrant, "tools"):
            try:
                return set(parent_warrant.tools())
            except Exception as e:
                # SECURITY: Fail-closed - if we can't verify parent tools, deny delegation
                raise EscalationAttempt(
                    f"Cannot verify parent warrant tools: {e}. "
                    "Delegation denied (fail-closed)."
                )
        # No tools() method - assume warrant doesn't restrict tools
        return set()

    def _validate_tool_delegation(
        self,
        parent_warrant: Warrant,
        parent_tools: set,
        tool_name: str,
        constraints: Dict[str, Constraint],
    ) -> None:
        """Validate that delegation doesn't escalate privileges.

        Checks:
        1. Parent must have the tool (if parent restricts tools)
        2. Each child constraint must be subset of parent's

        Raises:
            EscalationAttempt: If validation fails

        Note:
            Empty parent_tools set means parent doesn't restrict tools (no tools() method).
            Non-empty parent_tools means parent explicitly lists allowed tools.
        """
        # Check parent has this tool (only if parent restricts tools)
        if parent_tools and tool_name not in parent_tools:
            raise EscalationAttempt(
                f"Cannot grant '{tool_name}': parent warrant doesn't authorize it. "
                f"Parent tools: {sorted(parent_tools)}"
            )

        # For each constraint, verify it's a proper subset
        for arg_name, child_constraint in constraints.items():
            self._validate_constraint_subset(
                parent_warrant, tool_name, arg_name, child_constraint
            )

    def _validate_constraint_subset(
        self,
        parent_warrant: Warrant,
        tool_name: str,
        arg_name: str,
        child_constraint: Constraint,
    ) -> None:
        """Validate that child constraint is subset of parent's.

        Raises:
            EscalationAttempt: If child would widen access or validation fails
        """
        # Try to get parent's constraint for this arg
        parent_constraint = None
        if hasattr(parent_warrant, "constraint_for"):
            try:
                parent_constraint = parent_warrant.constraint_for(tool_name, arg_name)
            except (AttributeError, KeyError, LookupError):
                # These exceptions mean the arg doesn't exist in parent - OK to proceed
                # Parent doesn't constrain this arg, so child can add constraints
                parent_constraint = None
            except Exception as e:
                # SECURITY: Fail-closed - unexpected error means we can't verify safety
                raise EscalationAttempt(
                    f"Cannot verify parent constraint for {tool_name}.{arg_name}: {e}. "
                    "Delegation denied (fail-closed)."
                )

        # If we can get parent constraint, verify subset relationship
        if parent_constraint is not None:
            if hasattr(child_constraint, "is_subset_of"):
                if not child_constraint.is_subset_of(parent_constraint):
                    raise EscalationAttempt(
                        f"Cannot widen constraint on {tool_name}.{arg_name}: "
                        f"child constraint {child_constraint} is not a subset of "
                        f"parent constraint {parent_constraint}"
                    )
            else:
                # SECURITY: Fail-closed - if constraint doesn't support is_subset_of,
                # we cannot verify attenuation. Reject the delegation.
                raise EscalationAttempt(
                    f"Cannot validate attenuation for {tool_name}.{arg_name}: "
                    f"Constraint {type(child_constraint).__name__} does not support "
                    "is_subset_of() check. Use a constraint type that supports subset validation."
                )


# =============================================================================
# Phase 5: Strict Mode Context
# =============================================================================

import contextvars  # noqa: E402 - intentionally grouped in Phase 5 section
from contextlib import contextmanager  # noqa: E402

# Context var to track active guarded zone
_guarded_context: contextvars.ContextVar[Optional["CrewAIGuard"]] = contextvars.ContextVar(
    "tenuo_guarded_context", default=None
)

# Strict mode: track all tool calls and verify they're guarded
_strict_mode: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "tenuo_strict_mode", default=False
)

# Track unguarded calls in strict mode
_unguarded_calls: contextvars.ContextVar[List[str]] = contextvars.ContextVar(
    "tenuo_unguarded_calls", default=[]
)


class UnguardedToolError(TenuoCrewAIError):
    """Raised when strict mode detects unguarded tool calls."""

    def __init__(self, tools: List[str], step_name: str):
        self.tools = tools
        self.step_name = step_name
        super().__init__(
            f"Strict mode violation in step '{step_name}': "
            f"{len(tools)} unguarded tool call(s) detected: {', '.join(tools)}. "
            "Ensure all tools called within a guarded step are protected."
        )


@contextmanager
def _guarded_zone(guard: "CrewAIGuard", strict: bool = False):
    """Context manager for guarded execution zone."""
    token = _guarded_context.set(guard)
    strict_token = _strict_mode.set(strict)
    calls_token = _unguarded_calls.set([])
    try:
        yield
    finally:
        _guarded_context.reset(token)
        _strict_mode.reset(strict_token)
        _unguarded_calls.reset(calls_token)


def get_active_guard() -> Optional["CrewAIGuard"]:
    """Get the currently active guard in this context.

    Returns None if not in a guarded zone.
    """
    return _guarded_context.get()


def is_strict_mode() -> bool:
    """Check if strict mode is active."""
    return _strict_mode.get()


def report_unguarded_call(tool_name: str) -> None:
    """Report an unguarded tool call in strict mode."""
    if is_strict_mode():
        calls = _unguarded_calls.get()
        calls.append(tool_name)
        _unguarded_calls.set(calls)


def get_unguarded_calls() -> List[str]:
    """Get list of unguarded calls in current context."""
    return _unguarded_calls.get()


# =============================================================================
# Phase 5: @guarded_step Decorator
# =============================================================================

def guarded_step(
    allow: Optional[Dict[str, Dict[str, Constraint]]] = None,
    warrant: Optional[Warrant] = None,
    signing_key: Optional[SigningKey] = None,
    ttl: Optional[str] = None,
    on_denial: DenialMode = "raise",
    strict: bool = False,
    audit: Optional[Callable[[AuditEvent], None]] = None,
):
    """Decorator for guarded CrewAI Flow steps.

    Wraps a Flow step with per-step authorization. Creates a scoped guard
    that applies only during step execution.

    Args:
        allow: Dict of tool_name -> constraints for Tier 1
        warrant: Warrant for Tier 2 authorization
        signing_key: Key for PoP signature (required with warrant)
        ttl: TTL string like "10m" or "1h" (parsed for warrant)
        on_denial: How to handle denials ("raise", "log", "skip")
        strict: If True, fail if any unguarded tool calls detected
        audit: Optional audit callback

    Example:
        @guarded_step(
            allow={"web_search": {"query": Wildcard()}},
            ttl="10m",
            strict=True
        )
        def research_step(self, state):
            return self.research_crew.kickoff(state)
    """
    def decorator(func: Callable) -> Callable:
        import functools
        import time

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Build guard for this step
            builder = GuardBuilder()

            if allow:
                for tool_name, constraints in allow.items():
                    builder.allow(tool_name, **constraints)

            if warrant and signing_key:
                builder.with_warrant(warrant, signing_key)

            builder.on_denial(on_denial)

            if audit:
                builder.audit(audit)

            guard = builder.build()

            # Track step start time for TTL enforcement
            step_start = time.time()
            step_name = func.__name__

            # Parse TTL if provided
            ttl_seconds = None
            if ttl:
                ttl_seconds = _parse_ttl(ttl)

            # Execute in guarded zone
            with _guarded_zone(guard, strict=strict):
                try:
                    result = func(*args, **kwargs)
                finally:
                    # Check for strict mode violations
                    if strict:
                        unguarded = get_unguarded_calls()
                        if unguarded:
                            raise UnguardedToolError(unguarded, step_name)

                    # Check TTL if specified
                    if ttl_seconds:
                        elapsed = time.time() - step_start
                        if elapsed > ttl_seconds:
                            logger.warning(
                                f"Step '{step_name}' exceeded TTL of {ttl}: "
                                f"elapsed {elapsed:.1f}s. Warrant would be expired."
                            )

            return result

        return wrapper
    return decorator


def _parse_ttl(ttl: str) -> int:
    """Parse TTL string to seconds.

    Supports: "30s", "10m", "1h", "1d"
    """
    ttl = ttl.strip().lower()

    if ttl.endswith("s"):
        return int(float(ttl[:-1]))
    elif ttl.endswith("m"):
        return int(float(ttl[:-1]) * 60)
    elif ttl.endswith("h"):
        return int(float(ttl[:-1]) * 3600)
    elif ttl.endswith("d"):
        return int(float(ttl[:-1]) * 86400)
    else:
        # Assume seconds
        return int(float(ttl))


# =============================================================================
# Phase 5: GuardedCrew Wrapper
# =============================================================================

class GuardedCrewBuilder:
    """Builder for GuardedCrew with policy-based warrant issuance."""

    def __init__(
        self,
        agents: List[Any],
        tasks: List[Any],
        process: Any = None,
    ):
        """Initialize with CrewAI Crew components.

        Args:
            agents: List of CrewAI Agent instances
            tasks: List of CrewAI Task instances
            process: CrewAI Process (sequential, hierarchical, etc.)
        """
        self._agents = agents
        self._tasks = tasks
        self._process = process
        self._issuer_warrant: Optional[Warrant] = None
        self._issuer_key: Optional[SigningKey] = None
        self._policy: Dict[str, List[str]] = {}
        self._constraints: Dict[str, Dict[str, Dict[str, Constraint]]] = {}
        self._on_denial: DenialMode = "raise"
        self._audit_callback: Optional[Callable[[AuditEvent], None]] = None
        self._strict: bool = False
        self._ttl: Optional[str] = None

    def with_issuer(
        self, warrant: Warrant, signing_key: SigningKey
    ) -> "GuardedCrewBuilder":
        """Set the warrant issuer for Tier 2.

        The issuer will create per-agent warrants based on the policy.
        """
        self._issuer_warrant = warrant
        self._issuer_key = signing_key
        return self

    def policy(
        self, agent_tools: Dict[str, List[str]]
    ) -> "GuardedCrewBuilder":
        """Set which tools each agent is allowed to use.

        Args:
            agent_tools: Dict mapping agent role -> list of allowed tools

        Example:
            .policy({
                "researcher": ["web_search", "read_file"],
                "writer": ["write_file"],
            })
        """
        self._policy = agent_tools
        return self

    def constraints(
        self, agent_constraints: Dict[str, Dict[str, Dict[str, Constraint]]]
    ) -> "GuardedCrewBuilder":
        """Set per-tool constraints for each agent.

        Args:
            agent_constraints: Dict[agent_role, Dict[tool_name, Dict[arg, constraint]]]

        Example:
            .constraints({
                "researcher": {
                    "web_search": {"query": Pattern("arxiv:*")},
                },
            })
        """
        self._constraints = agent_constraints
        return self

    def on_denial(self, mode: DenialMode) -> "GuardedCrewBuilder":
        """Set denial handling mode."""
        self._on_denial = mode
        return self

    def audit(
        self, callback: Callable[[AuditEvent], None]
    ) -> "GuardedCrewBuilder":
        """Set audit callback for all agent guards."""
        self._audit_callback = callback
        return self

    def strict(self, enabled: bool = True) -> "GuardedCrewBuilder":
        """Enable strict mode - fail if unguarded tools detected."""
        self._strict = enabled
        return self

    def ttl(self, ttl: str) -> "GuardedCrewBuilder":
        """Set TTL for generated warrants."""
        self._ttl = ttl
        return self

    def build(self) -> "_GuardedCrewImpl":
        """Build the GuardedCrew instance."""
        return _GuardedCrewImpl(
            agents=self._agents,
            tasks=self._tasks,
            process=self._process,
            issuer_warrant=self._issuer_warrant,
            issuer_key=self._issuer_key,
            policy=self._policy,
            constraints=self._constraints,
            on_denial=self._on_denial,
            audit_callback=self._audit_callback,
            strict=self._strict,
            ttl=self._ttl,
        )


class _GuardedCrewImpl:
    """Crew wrapper with policy-based per-agent authorization.

    Automatically issues warrants and protects tools for each agent
    based on the defined policy.

    Note: Use GuardedCrew() factory function, not this class directly.
    """

    def __init__(
        self,
        agents: List[Any],
        tasks: List[Any],
        process: Any,
        issuer_warrant: Optional[Warrant],
        issuer_key: Optional[SigningKey],
        policy: Dict[str, List[str]],
        constraints: Dict[str, Dict[str, Dict[str, Constraint]]],
        on_denial: DenialMode,
        audit_callback: Optional[Callable[[AuditEvent], None]],
        strict: bool,
        ttl: Optional[str],
    ):
        self._agents = agents
        self._tasks = tasks
        self._process = process
        self._issuer_warrant = issuer_warrant
        self._issuer_key = issuer_key
        self._policy = policy
        self._constraints = constraints
        self._on_denial = on_denial
        self._audit_callback = audit_callback
        self._strict = strict
        self._ttl = ttl

        # Built crew instance (created on first kickoff)
        self._crew = None

        # Per-agent guards
        self._guards: Dict[str, CrewAIGuard] = {}

    def _get_agent_role(self, agent: Any) -> str:
        """Extract role from CrewAI agent."""
        if hasattr(agent, "role"):
            return agent.role
        return str(agent)

    def _build_agent_guard(self, agent: Any) -> CrewAIGuard:
        """Build a guard for a specific agent based on policy."""
        role = self._get_agent_role(agent)
        allowed_tools = self._policy.get(role, [])
        agent_constraints = self._constraints.get(role, {})

        builder = GuardBuilder()

        for tool_name in allowed_tools:
            tool_constraints = agent_constraints.get(tool_name, {})
            if tool_constraints:
                builder.allow(tool_name, **tool_constraints)
            else:
                # Allow tool with no parameter constraints (for zero-arg tools)
                # Note: With closed-world semantics, any arguments will be rejected
                builder.allow(tool_name, **{})

        builder.on_denial(self._on_denial)

        if self._audit_callback:
            builder.audit(self._audit_callback)

        # Tier 2: Issue per-agent warrant from issuer
        if self._issuer_warrant and self._issuer_key:
            # Generate agent-specific signing key (in production, agent provides their own)
            agent_key = SigningKey.generate()

            # Delegate warrant to this agent with narrowed scope
            delegator = WarrantDelegator()
            try:
                agent_warrant = delegator.delegate(
                    parent_warrant=self._issuer_warrant,
                    parent_key=self._issuer_key,
                    child_holder=agent_key.public_key,
                    attenuations={tool: agent_constraints.get(tool, {})
                                  for tool in allowed_tools},
                    ttl=_parse_ttl(self._ttl) if self._ttl else None,
                )
                builder.with_warrant(agent_warrant, agent_key)
                logger.debug(f"Issued Tier 2 warrant to agent '{role}'")
            except EscalationAttempt:
                # Escalation attempt during delegation is always a security error
                raise
            except Exception as e:
                # SECURITY: Fail-closed - if issuer is configured but delegation fails,
                # don't proceed with unguarded agent
                raise ConfigurationError(
                    f"Failed to issue warrant to agent '{role}': {e}. "
                    "Warrant issuance is required when .with_issuer() is configured. "
                    "Check that the issuer warrant has the necessary capabilities."
                )

        return builder.build()

    def _protect_agents(self) -> List[Any]:
        """Protect all agent tools and return modified agent list."""
        protected_agents = []

        for agent in self._agents:
            role = self._get_agent_role(agent)

            if role not in self._policy:
                # SECURITY: Fail-closed - agents not in policy cannot execute
                raise ConfigurationError(
                    f"Agent '{role}' is not listed in policy. "
                    "All agents must be covered by the policy for security. "
                    f"Add '{role}' to .policy() configuration."
                )

            guard = self._build_agent_guard(agent)
            self._guards[role] = guard

            # Protect agent's tools
            if hasattr(agent, "tools") and agent.tools:
                protected_tools = guard.protect_all(agent.tools, agent_role=role)
                agent.tools = protected_tools

            protected_agents.append(agent)

        return protected_agents

    def kickoff(self, inputs: Optional[Dict[str, Any]] = None) -> Any:
        """Execute the crew with authorization enforcement.

        This is the main entry point that mirrors CrewAI's Crew.kickoff().
        """
        try:
            from crewai import Crew  # type: ignore[import-not-found,import-untyped]
        except ImportError:
            raise ImportError(
                "crewai is required for GuardedCrew. "
                "Install with: pip install crewai"
            )

        # Protect all agents
        protected_agents = self._protect_agents()

        # Build the crew
        crew_kwargs = {
            "agents": protected_agents,
            "tasks": self._tasks,
        }
        if self._process is not None:
            crew_kwargs["process"] = self._process

        self._crew = Crew(**crew_kwargs)  # type: ignore[assignment,arg-type]

        # Execute in guarded zone if strict mode
        if self._strict:
            # Use first available guard for context (all agents use same strict setting)
            first_guard = list(self._guards.values())[0] if self._guards else None
            with _guarded_zone(first_guard, strict=True):  # type: ignore[arg-type]
                result = self._crew.kickoff(inputs=inputs)  # type: ignore[attr-defined]

                # Check for strict mode violations
                unguarded = get_unguarded_calls()
                if unguarded:
                    # Deduplicate and sort for cleaner error
                    unique_unguarded = sorted(set(unguarded))
                    raise UnguardedToolError(unique_unguarded, "GuardedCrew.kickoff")

                return result
        else:
            return self._crew.kickoff(inputs=inputs)  # type: ignore[attr-defined]

    @property
    def guards(self) -> Dict[str, CrewAIGuard]:
        """Get per-agent guards for introspection."""
        return self._guards


# Convenience factory function
def GuardedCrew(
    agents: List[Any],
    tasks: List[Any],
    process: Any = None,
) -> GuardedCrewBuilder:
    """Create a GuardedCrew builder.

    Example:
        crew = (GuardedCrew(
            agents=[researcher, writer],
            tasks=[...],
            process=Process.sequential)
            .policy({
                "researcher": ["web_search"],
                "writer": ["write_file"],
            })
            .strict()
            .build())
    """
    return GuardedCrewBuilder(agents, tasks, process)


# =============================================================================
# Re-exports for convenience
# =============================================================================

__all__ = [
    # Builder
    "GuardBuilder",
    "CrewAIGuard",
    # Hooks support
    "HOOKS_AVAILABLE",
    # Delegation (Phase 4)
    "WarrantDelegator",
    # Crew/Flow (Phase 5)
    "guarded_step",
    "GuardedCrew",
    "GuardedCrewBuilder",
    "get_active_guard",
    "is_strict_mode",
    # Exceptions
    "TenuoCrewAIError",
    "ToolDenied",
    "ConstraintViolation",
    "UnlistedArgument",
    "MissingSigningKey",
    "ConfigurationError",
    "EscalationAttempt",
    "UnguardedToolError",
    # Tier 2 exceptions (Phase 3)
    "WarrantExpired",
    "InvalidPoP",
    "WarrantToolDenied",
    # Result types
    "DenialResult",
    "AuditEvent",
    "ExplanationResult",
    # Constraints (re-export for convenience)
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
    "Subpath",
    "UrlSafe",
    "Shlex",
    # Type
    "Constraint",
    "DenialMode",
    # Utility
    "enable_debug",
]
