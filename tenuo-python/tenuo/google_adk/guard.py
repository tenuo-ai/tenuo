"""
Tenuo Google ADK Integration - Warrant-Based Authorization

Provides constraint enforcement for Google ADK agents with two tiers:

**Tier 1 (Guardrails)**: Runtime constraint checking without cryptography.
    Good for single-process scenarios. Uses `allows()` for logic checks.

**Tier 2 (Warrant + PoP)**: Cryptographic authorization with Proof-of-Possession.
    Uses warrant.authorize() which verifies signature, skill grant, AND constraints.

    Note: In ADK (same-process), PoP proves the agent holds the signing key that
    matches the warrant holder. For true distributed PoP where signature is
    generated remotely, use the A2A module instead.

Security Philosophy (Fail Closed):
    Tenuo follows a "fail closed" security model. When in doubt, deny:
    - Unknown constraint types are rejected (not silently passed)
    - Unknown arguments are rejected (zero-trust)
    - Missing constraint attributes cause denial
    - Warrant without signing_key raises MissingSigningKeyError

Usage (Builder Pattern - Recommended):
    from tenuo.google_adk import GuardBuilder
    from tenuo import SigningKey

    guard = (GuardBuilder()
        .with_warrant(my_warrant, agent_key)
        .map_skill("read_file_tool", "read_file", path="file_path")
        .map_skill("search_tool", "search")
        .on_denial("raise")
        .build())

    agent = Agent(
        tools=guard.filter_tools([read_file, search, shell]),
        before_tool_callback=guard.before_tool,
    )

Usage (Direct Constructor):
    from tenuo.google_adk import TenuoGuard
    from tenuo import SigningKey

    guard = TenuoGuard(
        warrant=my_warrant,
        signing_key=agent_key,
        skill_map={"read_file_tool": "read_file"},
    )

    agent = Agent(
        tools=guard.filter_tools([read_file, search, shell]),
        before_tool_callback=guard.before_tool,
    )

Usage (Dry Run - Development):
    guard = TenuoGuard(
        warrant=my_warrant,
        signing_key=agent_key,
        dry_run=True,  # Log denials but don't block
    )
"""

from __future__ import annotations

import json
import logging
from contextlib import ExitStack
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union

from tenuo._enforcement import enforce_tool_call

if TYPE_CHECKING:
    from google.adk.tools.base_tool import BaseTool  # type: ignore[import-not-found,import-untyped]
    from google.adk.tools.tool_context import ToolContext  # type: ignore[import-not-found,import-untyped]
    from tenuo_core import SigningKey, Warrant

logger = logging.getLogger(__name__)


class ToolAuthorizationError(Exception):
    """Raised when tool authorization fails and on_deny='raise'."""

    def __init__(self, message: str, tool_name: str, tool_args: Dict[str, Any]):
        super().__init__(message)
        self.tool_name = tool_name
        self.tool_args = tool_args


class MissingSigningKeyError(Exception):
    """Raised when PoP is required but no signing key is available."""

    def __init__(self):
        super().__init__(
            "Warrant provided without signing_key. For Tier 2 (PoP) authorization, "
            "pass signing_key= to TenuoGuard. For Tier 1 (guardrails only), use "
            "require_pop=False."
        )


class TenuoGuard:
    """
    Tenuo integration for Google ADK.

    Provides warrant-based authorization and constraint enforcement for ADK agents.

    Supports two authorization tiers:
        - Tier 1 (Guardrails): Logic-only checks without cryptography
        - Tier 2 (PoP): Full cryptographic Proof-of-Possession verification

    Security: By default, requires signing_key for PoP. Set require_pop=False
    to use Tier 1 guardrails only (suitable for single-process scenarios).
    """

    def __init__(
        self,
        warrant: Optional["Warrant"] = None,
        signing_key: Optional["SigningKey"] = None,
        warrant_key: Optional[str] = "__tenuo_warrant__",
        skill_map: Optional[Dict[str, str]] = None,
        arg_map: Optional[Dict[str, Dict[str, str]]] = None,
        constraints: Optional[Dict[str, Dict[str, Any]]] = None,  # Direct constraints
        allow_tools: Optional[List[str]] = None,  # Allowlist for Tier 1 (explicit grants)
        denial_detail: str = "full",  # "full", "minimal", "silent"
        audit_log: Union[None, str, Any] = None,
        on_deny: str = "return",  # "return" or "raise"
        require_pop: bool = True,  # Default to secure mode
        dry_run: bool = False,  # Log denials but don't block
        include_hints: bool = True,  # Include recovery hints in denials
        approval_policy: Optional[Any] = None,
        approval_handler: Optional[Any] = None,
        approvals: Optional[list] = None,
    ):
        """
        Initialize TenuoGuard.

        Args:
            warrant: Static warrant to use for all tool calls
            signing_key: Signing key for Proof-of-Possession (required for Tier 2)
            warrant_key: Key to look up warrant in ToolContext.state (for dynamic warrants)
            skill_map: Map ADK tool names to warrant skill names
            arg_map: Map tool argument names to constraint parameter names
            constraints: Direct constraints for Tier 1 mode (no warrant)
                        e.g., {"read_file": {"path": Subpath("/data")}}
            allow_tools: Allowlist of tools (Tier 1 mode) - explicit grants only
            denial_detail: Detail level for denial messages ("full", "minimal", "silent")
            audit_log: File path or file-like object for audit logging
            on_deny: "return" error dict or "raise" exception
            require_pop: If True (default), requires signing_key for Tier 2 authorization.
                        Set to False for Tier 1 guardrails-only mode.
            dry_run: If True, log denials but don't block. Useful for testing.
            include_hints: If True (default), include recovery hints in denial messages.
        """
        self._warrant = warrant
        self._signing_key = signing_key
        self._warrant_key = warrant_key
        self._skill_map = skill_map or {}
        self._arg_map = arg_map or {}
        self._constraints = constraints or {}  # Direct constraints for Tier 1
        self._allow_tools = allow_tools or []  # Allowlist (explicit grants)
        self._denial_detail = denial_detail
        self._on_deny = on_deny
        self._require_pop = require_pop
        self._dry_run = dry_run
        self._include_hints = include_hints
        self._approval_policy = approval_policy
        self._approval_handler = approval_handler
        self._approvals = approvals

        # Handle audit log: string path or file-like object
        self._exit_stack = ExitStack()
        self._owns_audit_log = False
        self._audit_log: Any = None
        if isinstance(audit_log, str):
            self._audit_log = self._exit_stack.enter_context(open(audit_log, "a"))
            self._owns_audit_log = True
        else:
            self._audit_log = audit_log

        # For context tracking
        self._tool_context: Optional["ToolContext"] = None

        # Track last denied constraint for hints
        self._last_denial_constraint: Optional[tuple] = None  # (param, constraint)

    # -------------------------------------------------------------------------
    # Tool Filtering
    # -------------------------------------------------------------------------

    def filter_tools(
        self,
        tools: List[Callable],
        warrant: Optional["Warrant"] = None,
    ) -> List[Callable]:
        """
        Filter tools to only those granted in the warrant or allowlist.

        Args:
            tools: List of tool functions/objects to filter
            warrant: Optional warrant to use (defaults to self._warrant)
                     Pass explicitly for dynamic/per-request warrants.

        Returns:
            List of tools that are granted

        Note:
            - For dynamic warrants (warrant_key), pass warrant explicitly
            - For direct constraints (Tier 1), uses the allowlist/constraints
            - Only explicitly granted tools are returned (Tenuo philosophy)
        """
        effective_warrant = warrant or self._warrant

        # Build set of allowed skills
        if effective_warrant is not None:
            granted = self._get_granted_skills(effective_warrant)
        elif self._constraints or self._allow_tools:
            # Direct constraints mode: use allowlist + constraint keys
            granted = set(self._allow_tools) | set(self._constraints.keys())
        else:
            return []  # No warrant and no allowlist = no tools

        result = []
        for tool in tools:
            # ADK tools usually have a name attribute, or use __name__ for functions
            tool_name = getattr(tool, "name", getattr(tool, "__name__", str(tool)))
            skill_name = self._skill_map.get(tool_name, tool_name)

            # Only include explicitly granted tools
            if skill_name in granted:
                result.append(tool)

        return result

    def _get_granted_skills(self, warrant: Any) -> set[str]:
        """Extract set of granted skill names from warrant."""
        skills: set[str] = set()

        # Priority 1: capabilities (new format)
        caps = getattr(warrant, "capabilities", {})
        if caps:
            skills.update(caps.keys())

        # Priority 2: grants (intermediate format)
        grants = getattr(warrant, "grants", [])
        for grant in grants:
            if isinstance(grant, dict):
                skill = grant.get("skill")
                if skill:
                    skills.add(skill)
            elif isinstance(grant, str):
                skills.add(grant)

        # Priority 3: tools (legacy format)
        tools_attr = getattr(warrant, "tools", [])
        skills.update(tools_attr)

        return skills

    # -------------------------------------------------------------------------
    # Constraint Checking (Tier 1 Only)
    # -------------------------------------------------------------------------
    #
    # NOTE: This is used ONLY for Tier 1 (guardrails-only) mode.
    # Tier 2 uses warrant.authorize() which does ALL checks in Rust core.
    #
    # UNIFIED INTERFACE: All Rust core constraints now support satisfies(value):
    #   - constraint.satisfies(value) -> Rust core (handles type conversion)
    #
    # The satisfies() method is the preferred interface. It:
    #   - Accepts any Python value and converts to appropriate Rust type
    #   - Calls the constraint's native matches() logic in Rust
    #   - Returns True/False consistently
    #
    # WILDCARD SECURITY:
    #   - Runtime check always returns True (matches everything)
    #   - ATTENUATION check in Rust prevents escalation TO Wildcard
    #   - You can narrow FROM Wildcard to any constraint
    #   - You CANNOT expand any constraint TO Wildcard (WildcardExpansion error)
    #
    # For security-critical deployments, use Tier 2 (PoP) which ensures
    # ALL constraint checking happens in the cryptographically-verified
    # Rust core via warrant.authorize().

    def _check_constraint(self, constraint: Any, value: Any) -> bool:
        """
        Check if value satisfies constraint (Tier 1 only).

        SECURITY: Fails closed (returns False) for unknown constraint types.
        This follows Tenuo's "fail closed" philosophy.

        NOTE: For Tier 2, use warrant.authorize() instead - it does
        ALL constraint checking in the Rust core with PoP verification.
        """
        try:
            constraint_type = type(constraint).__name__

            # =================================================================
            # SPECIAL CASES - Type coercion required before satisfies()
            # =================================================================
            # Range requires explicit string-to-number coercion
            if constraint_type == "Range" and hasattr(constraint, "satisfies"):
                try:
                    return constraint.satisfies(float(value))
                except (ValueError, TypeError):
                    return False  # Non-numeric value fails Range check

            # =================================================================
            # UNIFIED INTERFACE - All Rust core constraints support satisfies()
            # =================================================================
            #
            # The satisfies() method is the preferred unified interface for all
            # constraint types. It handles type conversion internally.
            #
            if hasattr(constraint, "satisfies"):
                return constraint.satisfies(value)

            # =================================================================
            # LEGACY FALLBACKS - For older constraint versions without satisfies()
            # =================================================================

            # Subpath - filesystem path containment
            if hasattr(constraint, "contains") and constraint_type == "Subpath":
                return constraint.contains(str(value))

            # UrlSafe - SSRF protection
            if hasattr(constraint, "is_safe"):
                return constraint.is_safe(str(value))

            # Cidr - IP address range
            if hasattr(constraint, "contains_ip"):
                return constraint.contains_ip(str(value))

            # Pattern/Shlex - pattern matching
            if hasattr(constraint, "matches"):
                return constraint.matches(str(value))

            # UrlPattern - URL pattern matching
            if hasattr(constraint, "matches_url"):
                return constraint.matches_url(str(value))

            # Range - numeric bounds
            if hasattr(constraint, "contains") and constraint_type == "Range":
                try:
                    return constraint.contains(float(value))
                except (ValueError, TypeError):
                    return False

            # OneOf - set membership
            if hasattr(constraint, "contains") and constraint_type == "OneOf":
                return constraint.contains(str(value))

            # NotOneOf - exclusion list
            if hasattr(constraint, "allows"):
                return constraint.allows(str(value))

            # Fallback: Exact with .value attribute
            if hasattr(constraint, "value"):
                return constraint.value == value

            # Fallback: OneOf with .values attribute
            if hasattr(constraint, "values"):
                return value in constraint.values

            # Unknown constraint type - FAIL CLOSED
            logger.warning(f"Unknown constraint type '{constraint_type}' - failing closed")
            return False

        except Exception as e:
            # Any exception during constraint check - fail closed
            logger.warning(f"Constraint check failed with exception: {e} - failing closed")
            return False

    def _get_skill_constraints(self, warrant: Any, skill_name: str) -> Dict[str, Any]:
        """Get constraints for a skill from warrant."""
        # Check capabilities first (new format)
        caps = getattr(warrant, "capabilities", {})
        if caps and skill_name in caps:
            return caps[skill_name]

        # Check grants (intermediate format)
        grants = getattr(warrant, "grants", [])
        for grant in grants:
            if isinstance(grant, dict) and grant.get("skill") == skill_name:
                return grant.get("constraints", {})

        return {}

    # -------------------------------------------------------------------------
    # Callbacks (Layer 1.5)
    # -------------------------------------------------------------------------

    def before_tool(
        self,
        tool: "BaseTool",
        args: Dict[str, Any],
        tool_context: "ToolContext",
    ) -> Optional[Dict[str, Any]]:
        """
        ADK before_tool_callback implementation.

        Returns:
            None: Allow tool execution
            Dict: Skip tool, use this as result (denial message)
        """
        # Store context for wrappers if needed
        self._tool_context = tool_context

        # Map tool name to skill
        skill_name = self._skill_map.get(tool.name, tool.name)

        # Remap arguments based on arg_map
        validation_args = self._remap_args(skill_name, args)

        # =======================================================================
        # MODE DETECTION: Warrant vs Direct Constraints
        # =======================================================================
        warrant = self._get_warrant(tool_context)
        use_direct_constraints = warrant is None and (self._constraints or self._allow_tools)

        if warrant is None and not use_direct_constraints:
            return self._deny("No warrant or constraints available", tool.name, args)

        # =======================================================================
        # Tier 2: Warrant + PoP Authorization (Cryptographic)
        # =======================================================================
        if warrant is not None and self._require_pop:
            if self._signing_key is None:
                raise MissingSigningKeyError()

            try:
                # Bind warrant to create BoundWarrant for enforce_tool_call
                bound_warrant = warrant.bind(self._signing_key)

                # Use shared enforcement logic for PoP authorization
                # This verifies: signature, skill grant, expiry, AND constraint satisfaction
                result = enforce_tool_call(
                    tool_name=skill_name,
                    tool_args=validation_args,
                    bound_warrant=bound_warrant,
                    approval_policy=self._approval_policy,
                    approval_handler=self._approval_handler,
                    approvals=self._approvals,
                )

                if not result.allowed:
                    # Map error types to appropriate denial messages
                    if result.error_type == "expired":
                        return self._deny("Warrant expired", tool.name, args)
                    else:
                        # Get detailed reason for other denial types
                        reason, constraint_param, constraint = self._get_denial_info(warrant, skill_name, validation_args)
                        return self._deny(
                            f"Authorization failed: {reason}",
                            tool.name,
                            args,
                            constraint_param=constraint_param,
                            constraint=constraint,
                        )

                # PoP authorized - tool call is allowed
                self._audit("tool_allowed", tool.name, args, warrant)
                return None

            except AttributeError as e:
                # Warrant doesn't have bind() method
                logger.warning(f"Warrant missing required methods: {e}")
                return self._deny(
                    f"Warrant type doesn't support PoP: {type(warrant).__name__}",
                    tool.name,
                    args,
                )

        # =======================================================================
        # Tier 1: Guardrails-Only Authorization (Logic Checks)
        # =======================================================================
        # Note: This mode is less secure - no cryptographic proof of authorization
        # Use only when PoP is not feasible (e.g., single-process scenarios)

        # Determine constraints source
        if use_direct_constraints:
            # Direct constraints from builder (no warrant)
            if skill_name not in self._constraints and skill_name not in self._allow_tools:
                return self._deny(f"Tool '{tool.name}' not in allowlist", tool.name, args)
            constraints = self._constraints.get(skill_name, {})
        else:
            # Warrant-based Tier 1
            # Check expiry
            is_expired = self._check_expiry(warrant)
            if is_expired:
                return self._deny("Warrant expired", tool.name, args)

            # Check skill is granted
            if not self._skill_granted(warrant, skill_name):
                return self._deny(f"Tool '{tool.name}' not authorized", tool.name, args)

            # Get constraints for this skill
            constraints = self._get_skill_constraints(warrant, skill_name)

        # =======================================================================
        # ZERO TRUST: Check ALL arguments against constraints
        # =======================================================================
        # If we have ANY constraints for this skill, we enforce zero-trust:
        # - Arguments matching constraints must pass
        # - Arguments NOT in constraints are REJECTED (unless Wildcard present)
        if constraints:
            has_wildcard = any(type(c).__name__ == "Wildcard" for c in constraints.values())
            allows_unknown = constraints.get("_allow_unknown", False)

            for arg_name, value in validation_args.items():
                if arg_name.startswith("_"):
                    continue  # Skip internal args like _allow_unknown

                try:
                    if arg_name in constraints:
                        constraint = constraints[arg_name]
                        if not self._check_constraint(constraint, value):
                            return self._deny(
                                f"Argument '{arg_name}' violates constraint",
                                tool.name,
                                args,
                                constraint_param=arg_name,
                                constraint=constraint,
                            )
                    elif not has_wildcard and not allows_unknown:
                        # Zero-trust: unknown argument rejected
                        return self._deny(
                            f"Unknown argument '{arg_name}' - not in constraints",
                            tool.name,
                            args,
                        )
                except Exception as e:
                    logger.warning(f"Constraint implementation bug causing denial for '{arg_name}': {e}")
                    return self._deny(
                        f"Argument '{arg_name}' violates constraint (internal validation error)",
                        tool.name,
                        args,
                    )

        # All checks passed
        self._audit("tool_allowed", tool.name, args, warrant)
        return None  # Proceed with tool execution

    def after_tool(
        self,
        tool: "BaseTool",
        args: Dict[str, Any],
        tool_context: "ToolContext",
        result: Any,
    ) -> Optional[Any]:
        """
        ADK after_tool_callback for audit logging.

        Returns:
            None: Use original result
            Any: Replace result (not used here)
        """
        warrant = self._get_warrant(tool_context)
        self._audit("tool_completed", tool.name, args, warrant, result=result)
        return None

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    def _get_warrant(self, tool_context: Optional["ToolContext"]) -> Optional["Warrant"]:
        """Get warrant from instance or session state."""
        if self._warrant is not None:
            return self._warrant
        if self._warrant_key and tool_context:
            # Check session_state (standard) then state (fallback)
            if hasattr(tool_context, "session_state"):
                return tool_context.session_state.get(self._warrant_key)
            if hasattr(tool_context, "state"):
                return tool_context.state.get(self._warrant_key)
        return None

    def _check_expiry(self, warrant: Any) -> bool:
        """Check if warrant is expired.

        Returns True if expired, False if valid or unknown.
        Fails closed on exceptions (treats as expired).
        """
        try:
            is_expired = getattr(warrant, "is_expired", None)

            # Handle method vs property
            if callable(is_expired):
                return is_expired()
            elif is_expired is not None:
                return bool(is_expired)

            # Fallback: check exp claim manually
            import time

            exp = getattr(warrant, "exp", None)
            if exp is not None:
                return time.time() > exp

            return False
        except Exception as e:
            # Fail closed: treat any exception as expired
            logger.warning(f"Expiry check failed: {e} - treating as expired")
            return True

    def _skill_granted(self, warrant: Any, skill_name: str) -> bool:
        """Check if skill is granted in warrant."""
        return skill_name in self._get_granted_skills(warrant)

    def _remap_args(self, skill_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remap tool arguments to constraint parameter names.

        SECURITY: Detects suspicious cases where both original and remapped
        argument names are present (potential validation bypass attempt).
        """
        validation_args = args.copy()
        if skill_name in self._arg_map:
            mapping = self._arg_map[skill_name]

            # SECURITY: Detect if both original and remapped names are present
            # This could indicate an attempt to bypass validation
            for tool_arg, constraint_arg in mapping.items():
                if tool_arg in args and constraint_arg in args:
                    if tool_arg != constraint_arg:
                        logger.warning(
                            f"Security: Both '{tool_arg}' and '{constraint_arg}' "
                            f"present in args for skill '{skill_name}'. This may "
                            f"indicate a validation bypass attempt. Consider using "
                            f"GuardBuilder.allow() instead of map_skill()."
                        )

            for tool_arg, constraint_arg in mapping.items():
                if tool_arg in args:
                    validation_args[constraint_arg] = args[tool_arg]
                    # Remove the old key to prevent zero-trust rejection
                    if tool_arg != constraint_arg:
                        validation_args.pop(tool_arg, None)
        return validation_args

    def _get_denial_reason(self, warrant: Any, skill_name: str, args: Dict[str, Any]) -> str:
        """Get detailed denial reason using why_denied (debug method)."""
        reason, _, _ = self._get_denial_info(warrant, skill_name, args)
        return reason

    def _get_denial_info(self, warrant: Any, skill_name: str, args: Dict[str, Any]) -> tuple:
        """Get denial info including constraint details for hints.

        Returns:
            tuple of (reason_string, constraint_param, constraint_object)
        """
        try:
            why = warrant.why_denied(skill_name, args)
            if why:
                status_str = str(why)
                constraint_param = getattr(why, "field", None)
                constraint = None

                # Try to get the constraint from the warrant
                if constraint_param:
                    caps = getattr(warrant, "capabilities", {})
                    if skill_name in caps:
                        constraint = caps[skill_name].get(constraint_param)

                if hasattr(why, "deny_code"):
                    reason = why.deny_code
                    if constraint_param:
                        reason += f" (field: {constraint_param})"
                    if hasattr(why, "suggestion") and why.suggestion:
                        reason += f" - {why.suggestion}"
                    return reason, constraint_param, constraint
                return status_str, constraint_param, constraint
        except Exception as e:
            logger.debug(f"why_denied() failed: {e}")
        return "not authorized", None, None

    def _deny(
        self,
        reason: str,
        tool_name: str,
        args: Dict[str, Any],
        *,
        constraint_param: Optional[str] = None,
        constraint: Optional[Any] = None,
    ) -> Optional[Dict[str, Any]]:
        """Handle denial based on on_deny setting."""
        # Store for hints
        self._last_denial_constraint = (constraint_param, constraint) if constraint_param else None

        # Dry run mode: log but don't block
        if self._dry_run:
            logger.warning(f"DRY RUN: Would deny {tool_name} - {reason}")
            self._audit("tool_dry_run_denied", tool_name, args, reason=reason)
            return None  # Allow through in dry run

        self._audit("tool_denied", tool_name, args, reason=reason)

        if self._on_deny == "raise":
            raise ToolAuthorizationError(reason, tool_name, args)

        # Construct user-facing message based on detail level
        if self._denial_detail == "full":
            message = f"Authorization denied: {reason}"
        elif self._denial_detail == "minimal":
            message = "Authorization denied."
        else:
            message = "Access denied."

        result: Dict[str, Any] = {
            "error": "authorization_denied",
            "message": message,
            "details": reason if self._denial_detail == "full" else None,
        }

        # Add hints if enabled
        if self._include_hints:
            from .helpers import generate_hints

            hints = generate_hints(
                tool_name=tool_name,
                args=args,
                warrant=self._warrant,
                constraint_param=constraint_param,
                constraint=constraint,
            )
            if hints:
                result["hints"] = hints

        return result

    def _audit(
        self,
        event: str,
        tool_name: str,
        args: Dict[str, Any],
        warrant: Optional[Any] = None,
        **extra,
    ) -> None:
        """Write audit event."""
        if self._audit_log is None:
            return

        try:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                "event": event,
                "tool": tool_name,
                "args": {k: str(v)[:100] for k, v in args.items()},
                **extra,
            }

            if warrant:
                # Convert keys to string representation
                jti: Any = getattr(warrant, "jti", None) or getattr(warrant, "id", None)
                iss: Any = getattr(warrant, "issuer", None) or getattr(warrant, "iss", None)
                # Handle PublicKey objects
                if jti is not None and hasattr(jti, "hex"):
                    jti = jti.hex()
                if iss is not None and hasattr(iss, "hex"):
                    iss = iss.hex()
                record["warrant"] = {
                    "jti": str(jti) if jti else None,
                    "iss": str(iss) if iss else None,
                }

            if hasattr(self._audit_log, "write"):
                self._audit_log.write(json.dumps(record) + "\n")
                self._audit_log.flush()
        except Exception as e:
            # Fallback to standard logging if audit fails
            logger.error(f"Failed to write audit log: {e}", exc_info=True)

    def close(self):
        """Clean up resources (e.g., audit log file handle)."""
        if self._owns_audit_log and hasattr(self._audit_log, "close"):
            self._audit_log.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# =============================================================================
# Builder Pattern
# =============================================================================


class GuardBuilder:
    """
    Fluent builder for TenuoGuard.

    Provides a cleaner API for configuring TenuoGuard with method chaining.

    Usage (Tier 2 - With Warrant):
        from tenuo.google_adk import GuardBuilder

        guard = (GuardBuilder()
            .with_warrant(my_warrant, agent_key)
            .map_skill("read_file_tool", "read_file", path="file_path")
            .on_denial("raise")
            .build())

    Usage (Tier 1 - Direct Constraints, no warrant):
        from tenuo.google_adk import GuardBuilder
        from tenuo.constraints import Subpath, UrlSafe

        guard = (GuardBuilder()
            .allow("read_file", path=Subpath("/data"))
            .allow("web_search", url=UrlSafe(allow_domains=["example.com"]))
            .build())

        # Note: Tools not in .allow() are denied by default (explicit grants)

        agent = Agent(
            tools=guard.filter_tools([read_file, search]),
            before_tool_callback=guard.before_tool,
        )
    """

    def __init__(self):
        """Initialize builder with defaults."""
        self._warrant: Optional["Warrant"] = None
        self._signing_key: Optional["SigningKey"] = None
        self._warrant_key: Optional[str] = None
        self._skill_map: Dict[str, str] = {}
        self._arg_map: Dict[str, Dict[str, str]] = {}
        self._constraints: Dict[str, Dict[str, Any]] = {}  # Direct constraints
        self._allow_tools: List[str] = []  # Allowlist (explicit grants only)
        self._denial_detail: str = "full"
        self._on_deny: str = "return"
        self._require_pop: bool = True
        self._dry_run: bool = False
        self._include_hints: bool = True
        self._audit_log: Union[None, str, Any] = None
        self._approval_policy: Optional[Any] = None
        self._approval_handler: Optional[Any] = None
        self._approvals = None

    @classmethod
    def from_tools(cls, tools: List[Callable]) -> "GuardBuilder":
        """
        Create GuardBuilder by extracting constraints from decorated tools.

        Convenience method for use with @guard_tool decorator.

        Args:
            tools: List of tool functions decorated with @guard_tool

        Returns:
            GuardBuilder with extracted constraints

        Example:
            @guard_tool(path=Subpath("/data"))
            def read_file(path: str):
                ...

            guard = GuardBuilder.from_tools([read_file]).build()
        """
        from .decorators import extract_constraints, is_guarded

        builder = cls()
        for tool in tools:
            if is_guarded(tool):
                tool_name = getattr(tool, "name", getattr(tool, "__name__", str(tool)))
                constraints = extract_constraints(tool)
                if constraints:
                    builder.allow(tool_name, **constraints)
        return builder

    def with_warrant(
        self,
        warrant: "Warrant",
        signing_key: Optional["SigningKey"] = None,
    ) -> "GuardBuilder":
        """
        Set the warrant and optional signing key for PoP.

        Args:
            warrant: The warrant to use for authorization
            signing_key: Signing key for Proof-of-Possession (recommended)

        Returns:
            self for chaining
        """
        self._warrant = warrant
        if signing_key is not None:
            self._signing_key = signing_key
        return self

    def warrant_key(self, key: str) -> "GuardBuilder":
        """
        Set the session state key for dynamic warrant lookup.

        Args:
            key: The key to look up in ToolContext.state

        Returns:
            self for chaining
        """
        self._warrant_key = key
        return self

    def allow(self, tool_name: str, **constraints: Any) -> "GuardBuilder":
        """
        Allow a tool with optional constraints (Tier 1 guardrails).

        This defines constraints directly in the guard without a warrant.
        Use for single-process scenarios where cryptographic authorization
        isn't needed.

        Args:
            tool_name: The tool/skill name to allow
            **constraints: Constraint objects for each parameter
                          e.g., path=Subpath("/data"), url=UrlSafe()

        Returns:
            self for chaining

        Example:
            from tenuo.constraints import Subpath, UrlSafe, Pattern

            guard = (GuardBuilder()
                .allow("read_file", path=Subpath("/data"))
                .allow("search", query=Pattern("*"))
                .allow("fetch_url", url=UrlSafe(allow_domains=["api.example.com"]))
                .build())
        """
        # Deduplicate - don't add same tool twice
        if tool_name not in self._allow_tools:
            self._allow_tools.append(tool_name)
        if constraints:
            # Merge constraints if tool already has some
            if tool_name in self._constraints:
                self._constraints[tool_name].update(constraints)
            else:
                self._constraints[tool_name] = constraints
        # Tier 1 mode when using allow() without warrant
        if self._warrant is None:
            self._require_pop = False
        return self

    def map_skill(
        self,
        tool_name: str,
        skill_name: str,
        **arg_mapping: str,
    ) -> "GuardBuilder":
        """
        Map a tool name to a warrant skill, with optional argument mapping.

        SECURITY WARNING - Argument Remapping Limitation:
            arg_map is for validation mapping only. ADK's before_tool callback
            cannot modify the arguments passed to the tool. This can cause
            validation bypass if an attacker sends both the original and
            remapped parameter names.

            Attack scenario:
                Configuration: .map_skill("read_file", "read_file", path="file_path")
                Attacker sends: {"file_path": "/etc/passwd", "path": "/data/safe.txt"}
                Validation checks: path="/data/safe.txt" ✅ (passes)
                Tool receives: file_path="/etc/passwd" ❌ (bypasses constraint!)

        RECOMMENDATION:
            Use GuardBuilder.allow() instead, which validates on the tool's
            actual parameter names:

            SECURE:
                .allow("read_file", file_path=Subpath("/data"))

            INSECURE:
                .map_skill("read_file", "read_file", path="file_path")

            Only use map_skill() if:
            - You control the tool implementation and know it ignores extra args
            - You're mapping between truly different names (e.g., ADK tool wrapper
              that translates parameter names before calling the real tool)

        Args:
            tool_name: The ADK tool function/class name
            skill_name: The warrant skill name
            **arg_mapping: Map constraint param names to tool arg names
                          e.g., path="file_path" means constraint param "path"
                          corresponds to tool arg "file_path"

        Returns:
            self for chaining

        Example:
            .map_skill("read_file_tool", "read_file", path="file_path")
            # Maps: read_file_tool → read_file skill
            # Maps: constraint param "path" → tool arg "file_path"
        """
        self._skill_map[tool_name] = skill_name
        if arg_mapping:
            # Reverse the mapping: constraint_name -> tool_arg_name
            # becomes tool_arg_name -> constraint_name for arg_map
            self._arg_map[skill_name] = {v: k for k, v in arg_mapping.items()}
        return self

    def on_denial(self, mode: str) -> "GuardBuilder":
        """
        Set denial handling mode.

        Args:
            mode: "return" (return error dict) or "raise" (raise exception)

        Returns:
            self for chaining
        """
        if mode not in ("return", "raise"):
            raise ValueError(f"on_denial must be 'return' or 'raise', got {mode!r}")
        self._on_deny = mode
        return self

    def detail_level(self, level: str) -> "GuardBuilder":
        """
        Set denial message detail level.

        Args:
            level: "full", "minimal", or "silent"

        Returns:
            self for chaining
        """
        if level not in ("full", "minimal", "silent"):
            raise ValueError(f"detail_level must be 'full', 'minimal', or 'silent', got {level!r}")
        self._denial_detail = level
        return self

    def tier1(self) -> "GuardBuilder":
        """
        Configure for Tier 1 (guardrails-only) mode.

        Disables PoP requirement. Use for single-process scenarios only.

        Returns:
            self for chaining
        """
        self._require_pop = False
        return self

    def tier2(self, signing_key: "SigningKey") -> "GuardBuilder":
        """
        Configure for Tier 2 (PoP) mode with signing key.

        Args:
            signing_key: The signing key for Proof-of-Possession

        Returns:
            self for chaining
        """
        self._signing_key = signing_key
        self._require_pop = True
        return self

    def dry_run(self, enabled: bool = True) -> "GuardBuilder":
        """
        Enable dry run mode (log denials but don't block).

        Args:
            enabled: Whether to enable dry run

        Returns:
            self for chaining
        """
        self._dry_run = enabled
        return self

    def audit_log(self, log: Union[str, Any]) -> "GuardBuilder":
        """
        Set audit log destination.

        Args:
            log: File path or file-like object

        Returns:
            self for chaining
        """
        self._audit_log = log
        return self

    def no_hints(self) -> "GuardBuilder":
        """
        Disable recovery hints in denial messages.

        Returns:
            self for chaining
        """
        self._include_hints = False
        return self

    def approval_policy(self, policy: Any) -> "GuardBuilder":
        """Set an approval policy for human-in-the-loop authorization.

        When a tool call matches a policy rule, the approval handler is
        invoked before execution proceeds. Requires Tier 2 (warrant).

        Args:
            policy: ApprovalPolicy with one or more rules.

        Returns:
            self for chaining
        """
        self._approval_policy = policy
        return self

    def on_approval(self, handler: Any) -> "GuardBuilder":
        """Set the handler invoked when a tool call requires approval.

        Args:
            handler: Callable that receives an ApprovalRequest and returns
                a SignedApproval (or raises ApprovalDenied).

        Returns:
            self for chaining
        """
        self._approval_handler = handler
        return self

    def with_approvals(self, approvals: Any) -> "GuardBuilder":
        self._approvals = approvals
        return self

    def build(self) -> TenuoGuard:
        """
        Build the TenuoGuard instance.

        Returns:
            Configured TenuoGuard

        Raises:
            MissingSigningKeyError: If require_pop is True but no signing_key provided
        """
        if self._require_pop and self._signing_key is None and self._warrant is not None:
            raise MissingSigningKeyError()

        return TenuoGuard(
            warrant=self._warrant,
            signing_key=self._signing_key,
            warrant_key=self._warrant_key,
            skill_map=self._skill_map,
            arg_map=self._arg_map,
            constraints=self._constraints,
            allow_tools=self._allow_tools,
            denial_detail=self._denial_detail,
            on_deny=self._on_deny,
            require_pop=self._require_pop,
            dry_run=self._dry_run,
            include_hints=self._include_hints,
            audit_log=self._audit_log,
            approval_policy=self._approval_policy,
            approval_handler=self._approval_handler,
            approvals=self._approvals,
        )
