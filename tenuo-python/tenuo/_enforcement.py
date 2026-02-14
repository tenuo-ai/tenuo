"""
Tenuo Enforcement - Shared authorization logic for all integrations.

This module provides the core enforcement primitives used by:
- TenuoMiddleware (LangChain/LangGraph)
- TenuoToolNode (LangGraph legacy)
- guard() decorator (FastAPI, CrewAI)
- SecureMCPClient (MCP)

The enforcement logic is framework-agnostic and operates on:
- tool_name: str
- tool_args: dict
- bound_warrant: BoundWarrant (warrant + signing key)

IMPORTANT: This module requires BoundWarrant instances. Plain Warrant objects
cannot perform Proof-of-Possession signing and are not accepted.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable, Set
import logging
import re

from .bound_warrant import BoundWarrant
from .validation import ValidationResult
from .exceptions import (
    TenuoError,
    ToolNotAuthorized,
    ConstraintViolation,
    ExpiredError,
    ConfigurationError,
)
from .schemas import ToolSchema, TOOL_SCHEMAS

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
    """

    allowed: bool
    tool: str
    arguments: Dict[str, Any]
    denial_reason: Optional[str] = None
    constraint_violated: Optional[str] = None
    error_type: Optional[str] = None

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
    Get list of tools allowed by the warrant.

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

    Returns:
        EnforcementResult with allowed status and denial details.

    Raises:
        ConfigurationError: If bound_warrant is not a BoundWarrant instance.

    Example:
        from tenuo import Warrant, SigningKey
        from tenuo._enforcement import enforce_tool_call

        warrant, key = Warrant.quick_mint(tools=["search"], ttl=3600)
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

    if verify_mode == "verify" and precomputed_signature is None:
        raise ConfigurationError("precomputed_signature is required when verify_mode='verify'")

    schemas = schemas or TOOL_SCHEMAS
    schema = schemas.get(tool_name)

    # 1. Check tool allowlist (explicit override takes precedence)
    if allowed_tools is not None:
        if tool_name not in allowed_tools:
            logger.debug(f"Tool '{tool_name}' not in explicit allowed_tools: {allowed_tools}")
            return EnforcementResult(
                allowed=False,
                tool=tool_name,
                arguments=tool_args,
                denial_reason=f"Tool '{tool_name}' not in allowed list",
                error_type="tool_not_allowed",
            )
    else:
        # Check warrant's tool allowlist
        warrant_tools = _get_allowed_tools(bound_warrant)
        # Note: warrant_tools=[] means block all, warrant_tools=None means allow all
        if warrant_tools is not None and tool_name not in warrant_tools:
            logger.debug(f"Tool '{tool_name}' not in warrant tools: {warrant_tools}")
            return EnforcementResult(
                allowed=False,
                tool=tool_name,
                arguments=tool_args,
                denial_reason=f"Tool '{tool_name}' not in warrant",
                error_type="tool_not_allowed",
            )

    # 2. Critical tool check - MUST have at least one relevant constraint
    if schema and schema.risk_level == "critical":
        constraints = _get_constraints_dict(bound_warrant)
        has_relevant = any(c in constraints for c in schema.recommended_constraints)

        # Critical tools must have relevant constraints - no bypass with unrelated constraints
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
                error_type="constraint_violation",
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
                error_type="constraint_violation",
            )

    # 4. Authorize with PoP via BoundWarrant.validate() or authorize()
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
                )
        else:
            # verify_mode == "verify"
            # Access underlying warrant directly to verify provided signature
            # We trust bound_warrant type check above
            authorized = bound_warrant.warrant.authorize(tool_name, tool_args, precomputed_signature)

            if not authorized:
                 return EnforcementResult(
                    allowed=False,
                    tool=tool_name,
                    arguments=tool_args,
                    denial_reason="Authorization denied (invalid PoP or constraint violation)",
                    error_type="authorization_failed",
                )

        # Success - log for audit trail
        logger.info(
            f"Tool authorized: {tool_name}",
            extra={
                "tool": tool_name,
                "warrant_id": bound_warrant.id,
                "args_keys": list(tool_args.keys()),  # Log keys only, not values (PII)
            }
        )

        return EnforcementResult(
            allowed=True,
            tool=tool_name,
            arguments=tool_args,
        )

    except (ConstraintViolation, ExpiredError, ToolNotAuthorized) as e:
        # Known authorization failures - expected behavior
        logger.debug(f"Authorization denied for {tool_name}: {e}")

        # Map exceptions to error types
        err_type = "other"
        if isinstance(e, ExpiredError) or "expired" in str(e).lower():
            err_type = "expired"
        elif isinstance(e, ToolNotAuthorized) or "not authorized" in str(e).lower():
            err_type = "tool_not_allowed"
        elif isinstance(e, ConstraintViolation):
             err_type = "constraint_violation"

        return EnforcementResult(
            allowed=False,
            tool=tool_name,
            arguments=tool_args,
            denial_reason=str(e),
            constraint_violated=_extract_violated_field(str(e)),
            error_type=err_type,
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
        )
    except Exception as e:
        # Catch-all for unexpected runtime errors (fail closed)
        logger.exception(f"Unexpected error during authorization for {tool_name}")
        return EnforcementResult(
            allowed=False,
            tool=tool_name,
            arguments=tool_args,
            denial_reason=f"Internal enforcement error: {str(e)}",
            error_type="internal_error",
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
    "enforce_tool_call",
    "filter_tools_by_warrant",
]
