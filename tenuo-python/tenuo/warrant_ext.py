"""
Extensions for Warrant class - convenience methods and DX improvements.

This module provides:
- Core convenience properties (ttl_remaining, expires_at, is_terminal, is_expired)
- Preview methods for UX (preview_can, preview_would_allow)
- Debugging methods (explain, inspect, why_denied)
- Improved delegation with auto-wrapping
- Delegation receipts and chain reconstruction
- Diff computation between warrants (delegates to Rust)

## Method Categories

### Authorization Methods (use in production)
Use `warrant.authorize(tool, args, signature)` for actual authorization decisions.
This performs ALL security checks including PoP verification.

### Diagnostic Methods (use for debugging only)
These methods help understand authorization failures but SKIP security checks:
- `check_constraints(tool, args)` - Check only constraint satisfaction
- `why_denied(tool, args)` - Detailed failure explanation
- `explain()` / `inspect()` - Human-readable warrant info
- `validate()` - Structural validation

DO NOT use diagnostic methods for authorization decisions in production.

### Introspection Methods (safe for any use)
Properties like `tools`, `clearance`, `agent_id()`, etc. are safe to use
anywhere as they only read warrant metadata.

Note on memory management:
    Delegation receipts are stored in a module-level cache keyed by warrant ID.
    For long-running processes that create many warrants, call clear_receipts()
    periodically or clear_receipt(warrant) when individual warrants are no longer needed.
"""

from typing import Optional, Dict, Any, List, TYPE_CHECKING, Union, Protocol, runtime_checkable
from datetime import timedelta, datetime, timezone
from dataclasses import dataclass
import base64
from tenuo_core import Warrant, PublicKey, SigningKey  # type: ignore[import-untyped]
from tenuo_core import (  # type: ignore[import-untyped]
    DelegationDiff,
    DelegationReceipt,
    compute_diff as rust_compute_diff,
)
from .validation import ValidationResult

from .decorators import key_scope

if TYPE_CHECKING:
    from .builder import GrantBuilder


# ============================================================================
# Type Protocols (P1)
# ============================================================================


@runtime_checkable
class ReadableWarrant(Protocol):
    """Protocol for warrant-like objects (read-only operations)."""

    @property
    def id(self) -> str: ...

    @property
    def tools(self) -> List[str]: ...

    @property
    def clearance(self) -> Any: ...

    @property
    def depth(self) -> int: ...

    @property
    def max_depth(self) -> int: ...

    def is_expired(self) -> bool: ...

    def is_terminal(self) -> bool: ...

    def explain(self, include_chain: bool = False) -> str: ...


@runtime_checkable
class SignableWarrant(Protocol):
    """Protocol for warrant-like objects that can sign requests."""

    def headers(self, tool: str, args: dict) -> Dict[str, str]: ...

    def delegate(self, *, to: PublicKey, allow: Union[str, List[str]], ttl: int) -> "Warrant": ...


if TYPE_CHECKING:
    from .bound_warrant import BoundWarrant

# Union type for convenience
AnyWarrant = Union[Warrant, "BoundWarrant"]


# ============================================================================
# Deny Codes (for why_denied)
# ============================================================================


class DenyCode:
    """Stable deny codes for programmatic handling."""

    ALLOWED = "ALLOWED"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    WARRANT_EXPIRED = "WARRANT_EXPIRED"
    CONSTRAINT_MISMATCH = "CONSTRAINT_MISMATCH"
    CONSTRAINT_RANGE = "CONSTRAINT_RANGE"
    CONSTRAINT_MISSING = "CONSTRAINT_MISSING"
    CLEARANCE_INSUFFICIENT = "CLEARANCE_INSUFFICIENT"
    TERMINAL = "TERMINAL"


@dataclass
class WhyDenied:
    """
    Structured explanation for why a request would be denied.

    Use warrant.why_denied(tool, args) to get this.
    """

    denied: bool
    deny_code: str
    deny_path: Optional[str] = None
    tool: str = ""
    field: Optional[str] = None
    constraint: Any = None
    value: Any = None
    suggestion: str = ""

    def __repr__(self) -> str:
        if not self.denied:
            return f"<WhyDenied ALLOWED tool={self.tool!r}>"
        return f"<WhyDenied {self.deny_code} tool={self.tool!r} field={self.field!r}>"


# Store receipts in a dict keyed by warrant ID (string)
# Rust-exposed objects can't store arbitrary Python attributes.
# Use clear_receipt() or clear_receipts() to prevent memory leaks in long-running processes.
_delegation_receipts: Dict[str, DelegationReceipt] = {}

# Maximum receipts to keep (LRU-style eviction)
_MAX_RECEIPTS = 10000


# ============================================================================
# 1. Core Convenience Properties
# ============================================================================


def _warrant_ttl_remaining(self: Warrant) -> timedelta:
    """Time remaining until expiration."""
    # Prefer ttl_seconds() from Rust (accurate, no parsing needed)
    if hasattr(self, "ttl_seconds") and callable(getattr(self, "ttl_seconds", None)):
        return timedelta(seconds=self.ttl_seconds())

    # Fallback: calculate from is_expired() and expires_at()
    # This is less precise but works with older Rust builds
    if self.is_expired():
        return timedelta(0)

    try:
        # expires_at() returns RFC3339 format like "2025-12-22T12:00:00Z"
        expires_str = self.expires_at()
        # Python 3.11+ handles 'Z' directly, older versions need conversion
        if expires_str.endswith("Z"):
            expires_str = expires_str[:-1] + "+00:00"
        expires = datetime.fromisoformat(expires_str)
        now = datetime.now(timezone.utc)
        remaining = expires - now
        return remaining if remaining.total_seconds() > 0 else timedelta(0)
    except (ValueError, AttributeError) as e:
        # If parsing fails, warn and return zero (expired)
        import warnings

        warnings.warn(
            f"Could not parse expires_at: {e}. Consider rebuilding tenuo_core for ttl_seconds() support.", UserWarning
        )
        return timedelta(0)


def _warrant_is_terminal_prop(self: Warrant) -> bool:
    """Property wrapper for is_terminal() method."""
    return self.is_terminal()


def _warrant_is_expired_prop(self: Warrant) -> bool:
    """Property wrapper for is_expired() method."""
    return self.is_expired()


# Add ttl_remaining as a property (wraps ttl_seconds())
if not hasattr(Warrant, "ttl_remaining"):
    Warrant.ttl_remaining = property(_warrant_ttl_remaining)  # type: ignore[attr-defined]

# Short alias: ttl → ttl_remaining
if not hasattr(Warrant, "ttl"):
    Warrant.ttl = property(_warrant_ttl_remaining)  # type: ignore[attr-defined]

# Note: is_expired() and is_terminal() are methods from Rust
# We expose them also as properties for convenience (spec compliance)
# The methods still work, but properties are more Pythonic
if not hasattr(Warrant, "expired"):
    Warrant.expired = property(_warrant_is_expired_prop)  # type: ignore[attr-defined]

if not hasattr(Warrant, "terminal"):
    Warrant.terminal = property(_warrant_is_terminal_prop)  # type: ignore[attr-defined]


# ============================================================================
# 1.5 Capabilities Property (P1)
# ============================================================================


def _warrant_capabilities(self: Warrant) -> Dict[str, Dict[str, str]]:
    """
    Human-readable constraints for each tool.

    Returns:
        Dict mapping tool names to constraint dicts with string representations.

    Example:
        warrant.capabilities
        # {
        #     "read_file": {"path": "Pattern('/data/*')"},
        #     "search": {"query": "Pattern('*')", "max_results": "Range(max=100)"}
        # }
    """
    result: Dict[str, Dict[str, str]] = {}

    # Get constraints for each tool
    for tool in self.tools:
        try:
            # Try to get constraints from Rust if available
            if hasattr(self, "get_constraints"):
                constraints = self.get_constraints(tool)
                if constraints:
                    result[tool] = {k: repr(v) for k, v in constraints.items()}
                else:
                    result[tool] = {}
            else:
                # Fallback: no constraint info available
                result[tool] = {}
        except Exception:
            result[tool] = {}

    return result


if not hasattr(Warrant, "capabilities"):
    Warrant.capabilities = property(_warrant_capabilities)  # type: ignore[attr-defined]


# ============================================================================
# 1.5.1 Warrant __repr__ Redaction (Security)
# ============================================================================


def _warrant_repr(self: Warrant) -> str:
    """
    Safe string representation that doesn't leak sensitive data.

    Shows: id (truncated), tools, TTL remaining
    Hides: signatures, full warrant bytes, session_id
    """
    try:
        ttl = self.ttl_remaining
        ttl_str = str(ttl).split(".")[0]  # Remove microseconds
    except Exception:
        ttl_str = "?"

    tools_str = ", ".join(self.tools[:3])
    if len(self.tools) > 3:
        tools_str += f", +{len(self.tools) - 3} more"

    return f"<Warrant id={self.id[:16]}... tools=[{tools_str}] ttl={ttl_str}>"


# Override Rust's __repr__ with our safe version
Warrant.__repr__ = _warrant_repr  # type: ignore[method-assign]


# ============================================================================
# 1.6 validate on Warrant (P0)
# ============================================================================


def _warrant_validate(
    self: Warrant,
    key: SigningKey,
    tool: str,
    args: dict,
) -> ValidationResult:
    """
    Pre-check if this action would be authorized.

    Args:
        key: Signing key to check
        tool: Tool name
        args: Tool arguments

    Returns:
        ValidationResult
    """
    import time as _time
    pop_signature = self.sign(key, tool, args, int(_time.time()))

    # 2. Verify
    success = self.authorize(tool=tool, args=args, signature=bytes(pop_signature))

    if success:
        return ValidationResult.ok()

    # 3. Rich feedback
    why = self.why_denied(tool, args)
    return ValidationResult.fail(
        reason=why.suggestion or f"Authorization failed ({why.deny_code})",
        suggestions=[why.suggestion] if why.suggestion else [],
    )


if not hasattr(Warrant, "validate"):
    Warrant.validate = _warrant_validate  # type: ignore[attr-defined]


# ============================================================================
# 1.6 headers on Warrant (P0)
# ============================================================================


def _warrant_headers(
    self: Warrant,
    key: SigningKey,
    tool: str,
    args: dict,
) -> Dict[str, str]:
    """
    Generate HTTP authorization headers.

    This creates the X-Tenuo-Warrant and X-Tenuo-PoP headers needed
    for authenticated API calls.

    Args:
        key: Signing key (must match warrant's authorized_holder)
        tool: Tool name being called
        args: Tool arguments

    Returns:
        Dictionary with X-Tenuo-Warrant and X-Tenuo-PoP headers

    Example:
        headers = warrant.headers(key, "search", {"query": "test"})
        response = requests.post(url, headers=headers, json=args)
    """
    # Validate before signing for better error messages
    validation = self.validate(key, tool, args)
    if not validation:
        # Actionable but security-safe error msg
        raise RuntimeError(f"Authorization failed: {validation.reason}")

    import time as _time
    pop_sig = self.sign(key, tool, args, int(_time.time()))
    pop_b64 = base64.b64encode(pop_sig).decode("ascii")

    return {"X-Tenuo-Warrant": self.to_base64(), "X-Tenuo-PoP": pop_b64}


if not hasattr(Warrant, "headers"):
    Warrant.headers = _warrant_headers  # type: ignore[attr-defined]


# ============================================================================
# 2. Preview Methods (DIAGNOSTIC USE ONLY - NOT Authorization)
#
# These methods check constraints without PoP verification.
# Use for UI previews, error messages, and debugging.
# DO NOT use for actual authorization decisions.
# ============================================================================


def _warrant_allows(self: Warrant, tool: str, args: Optional[dict] = None) -> bool:
    """
    Check if the warrant allows the given tool and arguments (DIAGNOSTIC).

    WARNING: This checks constraints only, NOT PoP signatures.
    For actual authorization, use `warrant.authorize(tool, args, signature)`.

    Use this for:
    - UI previews showing what's possible
    - Quick constraint validation before making a request
    - Debugging constraint configurations

    Args:
        tool: Tool name to check
        args: Optional arguments to check against constraints.
              If None, checks only tool presence.

    Returns:
        True if constraints would allow, False otherwise.
    """
    if args is None:
        return tool in self.tools

    if tool not in self.tools:
        return False

    # Use check_constraints to verify args match constraints
    # check_constraints returns None if OK, or error string if not
    result = self.check_constraints(tool, args)
    return result is None


# Removed legacy preview methods

# Attach methods
if not hasattr(Warrant, "allows"):
    Warrant.allows = _warrant_allows  # type: ignore[attr-defined]

# Removed legacy method attachments


# ============================================================================
# 2.5 why_denied Method (DIAGNOSTIC USE ONLY)
#
# Use for debugging and error messages, NOT for authorization decisions.
# ============================================================================


def _enhance_constraint_suggestion(
    failure_reason: str,
    tool: str,
    args: dict,
    warrant: Warrant,
) -> str:
    """
    Enhance constraint failure messages with actionable suggestions.

    Detects common pitfalls and provides helpful guidance:
    - Zero-trust unknown field rejections
    - Multiple fields potentially rejected
    """
    import re

    # Detect zero-trust unknown field rejection
    if "unknown field not allowed (zero-trust mode)" in failure_reason:
        # Extract the field name from the error
        # Format: "Constraint 'fieldname' not satisfied: unknown field..."
        field_match = re.search(r"Constraint '([^']+)' not satisfied", failure_reason)
        rejected_field = field_match.group(1) if field_match else "unknown"

        # Get constrained fields from warrant.capabilities if available
        constrained_fields: set = set()
        try:
            caps = warrant.capabilities
            if tool in caps:
                constrained_fields = set(caps[tool].keys())
        except Exception:
            pass

        # Find unknown fields in args (fields not in constraints)
        unknown_fields = [k for k in args.keys() if k not in constrained_fields]

        if len(unknown_fields) > 1:
            # Multiple unknown fields - strong hint to review constraints
            fields_str = ", ".join(f"'{f}'" for f in unknown_fields[:5])
            if len(unknown_fields) > 5:
                fields_str += f", +{len(unknown_fields) - 5} more"

            return (
                f"{failure_reason}.\n\n"
                f"  Hint: {len(unknown_fields)} fields may be unknown: {fields_str}\n"
                f"  This warrant uses zero-trust mode (constraints defined = closed world).\n\n"
                f"  To fix, either:\n"
                f"  1. Add constraints for needed fields: {', '.join(f'{f}=Any()' for f in unknown_fields[:3])}{'...' if len(unknown_fields) > 3 else ''}\n"
                f"  2. Or use _allow_unknown=True to opt out of zero-trust"
            )
        else:
            # Single unknown field (or couldn't determine)
            return (
                f"{failure_reason}.\n\n"
                f"  Hint: Field '{rejected_field}' not in warrant's constraints.\n"
                f"  This capability uses zero-trust mode (unknown fields rejected).\n\n"
                f"  To fix, either:\n"
                f"  1. Add constraint: {rejected_field}=Any()  (allows any value)\n"
                f"  2. Or use _allow_unknown=True to allow all unknown fields"
            )

    # Default: return original reason
    return failure_reason


def _warrant_why_denied(self: Warrant, tool: str, args: Optional[dict] = None) -> WhyDenied:
    """
    Get structured explanation for why a request would be denied (DIAGNOSTIC).

    WARNING: This is for debugging only. It does NOT verify PoP signatures.
    For actual authorization, use `warrant.authorize(tool, args, signature)`.

    Use this to:
    - Generate helpful error messages for denied requests
    - Debug constraint configuration issues
    - Power interactive debugging UIs

    The returned object includes a `suggestion` with a link to the Tenuo Explorer,
    pre-filled with the warrant and request details for interactive debugging.

    Args:
        tool: Tool name to check
        args: Tool arguments (optional)

    Returns:
        WhyDenied with deny_code, field, suggestion, etc.

    Example:
        result = warrant.why_denied("delete_file", {"path": "/etc/passwd"})
        if result.denied:
            print(f"Denied: {result.deny_code}")
            print(f"Field: {result.field}")
            print(f"Suggestion: {result.suggestion}")
    """
    # Create dynamic playground link
    import json

    playground_url = "https://tenuo.ai/explorer/"
    try:
        # Construct state object matching App.tsx expectation
        state = {
            "warrant": self.to_base64() if hasattr(self, "to_base64") else str(self),
            "tool": tool,
            "args": json.dumps(args) if args else "{}",
        }
        # Encode state: JSON -> Bytes -> Base64
        state_json = json.dumps(state)
        state_b64 = base64.b64encode(state_json.encode("utf-8")).decode("ascii")
        playground_hint = f" Debug at: {playground_url}?s={state_b64}"
    except Exception:
        # Fallback if encoding fails
        playground_hint = f" Debug at: {playground_url}"

    # Check if warrant is expired
    if self.is_expired():
        return WhyDenied(
            denied=True,
            deny_code=DenyCode.WARRANT_EXPIRED,
            deny_path="warrant.expired",
            tool=tool,
            suggestion=f"Warrant expired at {self.expires_at()}. Request a fresh warrant.{playground_hint}",
        )

    # Check if tool is in warrant
    if tool not in self.tools:
        available = ", ".join(self.tools) if self.tools else "none"
        return WhyDenied(
            denied=True,
            deny_code=DenyCode.TOOL_NOT_FOUND,
            deny_path="tool.not_found",
            tool=tool,
            suggestion=f"Tool '{tool}' not in warrant. Available: {available}.{playground_hint}",
        )

    # Check if warrant is terminal (can't delegate)
    # This isn't really a "denial" for execution, but useful info

    # Check constraints via Rust (without requiring PoP)
    # check_constraints_detailed returns None if OK, or (field, reason) tuple on failure
    try:
        # Use structured method if available, fall back to string parsing
        if hasattr(self, "check_constraints_detailed"):
            result = self.check_constraints_detailed(tool, args or {})
            if result:
                failed_field, reason = result
                # Handle internal errors (field="_error")
                if failed_field == "_error":
                    failed_field = None
                failure_reason = f"Constraint '{failed_field}' not satisfied: {reason}" if failed_field else reason
            else:
                failure_reason = None
        else:
            # Fallback for older Rust builds
            failure_reason = self.check_constraints(tool, args or {})
            failed_field = None

        if failure_reason:
            # Enhance suggestions for zero-trust related failures
            enhanced_suggestion = _enhance_constraint_suggestion(failure_reason, tool, args or {}, self)
            return WhyDenied(
                denied=True,
                deny_code=DenyCode.CONSTRAINT_MISMATCH,
                deny_path="constraints.violation",
                tool=tool,
                field=failed_field,
                suggestion=f"{enhanced_suggestion}{playground_hint}",
            )
    except Exception as e:
        # Fallback if check_constraints fails unexpectedly
        return WhyDenied(
            denied=True,
            deny_code=DenyCode.CONSTRAINT_MISMATCH,
            deny_path="constraints.error",
            tool=tool,
            suggestion=f"Could not check constraints: {e}.{playground_hint}",
        )

    # If we got here, authorization would likely succeed
    # (assuming valid PoP signature)
    return WhyDenied(
        denied=False,
        deny_code=DenyCode.ALLOWED,
        tool=tool,
        suggestion="Request would be allowed (assuming valid PoP signature)",
    )


if not hasattr(Warrant, "why_denied"):
    Warrant.why_denied = _warrant_why_denied  # type: ignore[attr-defined]


# ============================================================================
# 3. Debugging Methods (DIAGNOSTIC USE ONLY)
#
# These methods are for understanding warrant structure and diagnosing
# authorization failures. DO NOT use for authorization decisions.
# ============================================================================


def _warrant_explain(self: Warrant, include_chain: bool = False) -> str:
    """Human-readable warrant explanation (diagnostic)."""
    lines = [
        f"Warrant {self.id[:12]}...",
        f"  Type: {self.warrant_type}",
        f"  Tools: {', '.join(self.tools) if self.tools else 'none'}",
        f"  TTL: {self.ttl_remaining}",
        f"  Expires: {self.expires_at()}",  # Rust method returns RFC3339 string
    ]

    if self.clearance is not None:
        lines.append(f"  Clearance: {self.clearance}")

    # max_depth might be None in older Rust builds or for some warrant types
    max_d = getattr(self, "max_depth", None)
    if max_d is None and hasattr(self, "max_issue_depth"):
        max_d = self.max_issue_depth
    lines.append(f"  Depth: {self.depth}/{max_d if max_d is not None else '?'}")

    if self.is_terminal():  # Method, not property
        lines.append("  [WARNING] Terminal - cannot delegate further")

    if self.is_expired():  # Method, not property
        lines.append("  [WARNING] Expired")

    if include_chain and self.parent_hash:
        lines.append(f"  Parent: {self.parent_hash[:12]}...")

    return "\n".join(lines)


def _warrant_inspect(self: Warrant) -> str:
    """Alias for explain() with chain information."""
    return self.explain(include_chain=True)


# Attach debugging methods
if not hasattr(Warrant, "explain"):
    Warrant.explain = _warrant_explain  # type: ignore[attr-defined]

if not hasattr(Warrant, "inspect"):
    Warrant.inspect = _warrant_inspect  # type: ignore[attr-defined]


# ============================================================================
# 4. Delegation Receipts (Existing Code)
# ============================================================================


def get_delegation_receipt(warrant: Warrant) -> Optional[DelegationReceipt]:
    """Get the delegation receipt if this warrant was created via delegation."""
    return _delegation_receipts.get(warrant.id)


def set_delegation_receipt(warrant: Warrant, receipt: DelegationReceipt) -> None:
    """Set the delegation receipt for a warrant."""
    # Simple size limit to prevent unbounded growth
    if len(_delegation_receipts) >= _MAX_RECEIPTS:
        # Remove oldest entry (first key in dict - Python 3.7+ maintains insertion order)
        oldest_key = next(iter(_delegation_receipts))
        del _delegation_receipts[oldest_key]
    _delegation_receipts[warrant.id] = receipt


def clear_receipt(warrant: Warrant) -> None:
    """Clear the delegation receipt for a warrant (memory cleanup)."""
    _delegation_receipts.pop(warrant.id, None)


def clear_receipts() -> None:
    """Clear all stored delegation receipts (memory cleanup)."""
    _delegation_receipts.clear()


# Add delegation_receipt property to Warrant class
def _warrant_get_delegation_receipt(self: Warrant) -> Optional[DelegationReceipt]:
    """Get the delegation receipt if this warrant was created via delegation."""
    return _delegation_receipts.get(self.id)


def _warrant_set_delegation_receipt(self: Warrant, receipt: DelegationReceipt) -> None:
    """Set the delegation receipt (internal use)."""
    set_delegation_receipt(self, receipt)


# Add delegation_receipt property to Warrant
if not hasattr(Warrant, "delegation_receipt"):
    Warrant.delegation_receipt = property(  # type: ignore[attr-defined]
        _warrant_get_delegation_receipt, _warrant_set_delegation_receipt
    )


# ============================================================================
# 5. Attenuation Builder Wrappers (Existing Code)
# ============================================================================

# Store reference to Rust core method (still named attenuate_builder in Rust)
# We wrap this to return our Python GrantBuilder instead
_original_attenuate_builder = Warrant.attenuate_builder


def _wrapped_grant_builder(self: Warrant) -> "GrantBuilder":
    """Wrap grant_builder to return Python GrantBuilder with diff support."""
    from .builder import GrantBuilder

    rust_builder = _original_attenuate_builder(self)
    return GrantBuilder(self, _rust_builder=rust_builder)


# Add new method
Warrant.grant_builder = _wrapped_grant_builder  # type: ignore[attr-defined]


# ============================================================================
# 6. Improved Delegate Method
# ============================================================================


def _warrant_delegate(
    self: Warrant,
    *,
    to: PublicKey,
    allow: Union[str, List[str]],
    ttl: int,
    key: Optional[SigningKey] = None,
    **constraints,
) -> Warrant:
    """
    Convenience method to delegate a warrant to a new holder.

    This creates a new child warrant with narrowed capabilities.

    Args:
        to: The public key of the new holder
        allow: Tool(s) to delegate - string for single tool or list for multiple
        ttl: Time-to-live in seconds for the child warrant
        key: Signing key (optional if using context)
        **constraints: Additional constraints to apply

    Returns:
        The new child warrant

    Raises:
        RuntimeError: If no key provided and no keypair in context

    Example:
        # With explicit key
        child = parent.grant(
            to=worker_key.public_key,
            allow="search",
            ttl=300,
            key=parent_key
        )

        # With context key
        with key_scope(parent_key):
            child = parent.grant(
                to=worker_key.public_key,
                allow=["search", "read_file"],
                ttl=300
            )
    """
    # Get signing key from argument or context
    signing_key = key or key_scope()
    if not signing_key:
        raise RuntimeError(
            "No signing key provided. Either pass key= argument or use inside a task context / key_scope()."
        )

    # Auto-wrap single item to list (if not iterable list/tuple/set, but exclude str)
    if isinstance(allow, str):
        items = [allow]
    elif isinstance(allow, (list, tuple, set)):
        items = list(allow)
    else:
        items = [allow]

    # Build child warrant using attenuation builder
    builder = self.grant_builder()

    # POLA: Start by inheriting all parent capabilities, then narrow
    builder.inherit_all()

    tool_names_only = []

    # Process allow items
    for item in items:
        if isinstance(item, str):
            tool_names_only.append(item)
        elif hasattr(item, "tool") and hasattr(item, "constraints"):
            # Capability object
            builder.capability(item.tool, item.constraints)
        else:
            # Fallback/Error
            raise ValueError(f"Invalid item in 'allow': {item}. Expected string or Capability.")

    # Narrow to specified tools (strings)
    if tool_names_only:
        builder.tools(tool_names_only)

    # Apply additional constraints if provided (only applies to string tools)
    if constraints and tool_names_only:
        from tenuo.constraints import ensure_constraint

        # Apply constraints to each tool specified by name
        for tool in tool_names_only:
            tool_constraints = {}
            for field, value in constraints.items():
                tool_constraints[field] = ensure_constraint(value)
            builder.capability(tool, tool_constraints)

    # Set new holder and TTL
    builder.holder(to)
    builder.ttl(ttl)

    # Sign and return
    return builder.grant(signing_key)


# ============================================================================
# 7. Issue Execution Wrapper (Existing Code)
# ============================================================================

# Store the original issue_execution method
_original_issue_execution = Warrant.issue_execution if hasattr(Warrant, "issue_execution") else None


def _wrapped_issue_execution(self):
    """Wrap issue_execution() to return Python IssuanceBuilder.

    Returns:
        IssuanceBuilder (Python wrapper) with dual-purpose methods
    """
    from .builder import wrap_rust_issuance_builder

    rust_builder = _original_issue_execution(self)
    return wrap_rust_issuance_builder(rust_builder)


# Replace with wrapped version
if _original_issue_execution is not None:
    Warrant.issue_execution = _wrapped_issue_execution


# ============================================================================
# 8. Chain Reconstruction (Existing Code)
# ============================================================================


def get_chain_with_diffs(
    warrant: Warrant,
    warrant_store: Optional[Any] = None,
) -> List[Union[DelegationDiff, Dict[str, Any]]]:
    """
    Reconstruct full delegation chain with diffs.

    NOTE: This is for AUDIT purposes only. Runtime verification
    uses embedded ChainLink data and requires no external fetches.

    Args:
        warrant: The leaf warrant to trace back from
        warrant_store: Optional storage for fetching parent warrants
            Must have a .get(warrant_id) method

    Returns:
        List of DelegationDiff objects (or fallback dicts) from root to leaf
    """
    chain: List[Union[DelegationDiff, Dict[str, Any]]] = []
    current = warrant

    # Without a store, we can only return minimal info
    if warrant_store is None:
        return [_create_minimal_diff(current)]

    # Trace back using parent_hash
    while current.parent_hash is not None:
        parent_hash = current.parent_hash

        # Try to fetch parent from store
        parent: Optional[Warrant] = None
        try:
            if hasattr(warrant_store, "get_by_hash"):
                parent = warrant_store.get_by_hash(parent_hash)
            else:
                # Fallback: assume store might support hash lookup via get
                parent = warrant_store.get(parent_hash)
        except (AttributeError, KeyError, TypeError):
            break

        if parent:
            diff = compute_diff(parent, current)
            chain.append(diff)
            current = parent
        else:
            break

    # Reverse to get root-first order
    return list(reversed(chain))


def _create_minimal_diff(child: Warrant) -> Dict[str, Any]:
    """Create minimal diff dict when parent not available (fallback)."""
    return {
        "parent_warrant_hash": child.parent_hash or "unknown",
        "child_warrant_id": child.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "depth": {"parent": child.depth - 1, "child": child.depth},
        "note": "Minimal diff - parent warrant not available",
    }


def compute_diff(parent: Warrant, child: Warrant) -> DelegationDiff:
    """Compute diff between two warrants (parent and child).

    Delegates to the Rust implementation for performance and consistency.
    """
    return rust_compute_diff(parent, child)


# ============================================================================
# 10. Implicit Serialization Support
# ============================================================================


def _warrant_str(self: Warrant) -> str:
    """
    Return base64 representation for easy serialization.

    This allows warrants to be passed as strings naturally:
        send_to_agent(str(warrant))
        json.dumps({"warrant": str(warrant)})
    """
    return self.to_base64()


if not hasattr(Warrant, "__str__") or Warrant.__str__ is object.__str__:
    Warrant.__str__ = _warrant_str  # type: ignore[method-assign]

# ============================================================================
# 11. Mint Method Alias (New Vocabulary)
# ============================================================================

# Store references to Rust core methods (still named issue/issue_issuer in Rust)
# We wrap these to provide the Python mint() method
_original_issue = Warrant.issue
_original_issue_issuer = Warrant.issue_issuer


def _warrant_mint(**kwargs) -> Warrant:
    """Mint a new root warrant (creates new authority)."""
    return _original_issue(**kwargs)


# Add new method
Warrant.mint = _warrant_mint  # type: ignore[attr-defined]


# ============================================================================
# 12. Grant Method Alias (New Vocabulary)
# ============================================================================


def _warrant_grant(
    self: Warrant,
    *,
    to: PublicKey,
    allow: Union[str, List[str]],
    ttl: int,
    key: Optional[SigningKey] = None,
    **constraints,
) -> Warrant:
    """Convenience method to grant a warrant to a new holder."""
    return _warrant_delegate(self, to=to, allow=allow, ttl=ttl, key=key, **constraints)


# Add new method
Warrant.grant = _warrant_grant  # type: ignore[attr-defined]


# Add from_str as alias for from_base64
def _warrant_from_str(s: str) -> "Warrant":
    """Parse warrant from string (base64 encoded).

    This is an alias for from_base64() that pairs with str(warrant).
    """
    return Warrant.from_base64(s)


Warrant.from_str = _warrant_from_str  # type: ignore[attr-defined]

# ============================================================================
# Property Aliases for Brevity
# ============================================================================


# Add 'type' as alias for 'warrant_type'
def _warrant_type_alias(self: Warrant):
    """Alias for warrant_type property."""
    return self.warrant_type


Warrant.type = property(_warrant_type_alias)  # type: ignore[attr-defined]


# Add 'can_issue' as alias for 'issuable_tools'
def _can_issue_alias(self: Warrant):
    """Alias for issuable_tools property."""
    return self.issuable_tools


Warrant.can_issue = property(_can_issue_alias)  # type: ignore[attr-defined]


# Add 'receipt' as alias for 'delegation_receipt'
def _receipt_alias(self: Warrant):
    """Alias for delegation_receipt property."""
    return self.delegation_receipt


Warrant.receipt = property(_receipt_alias)  # type: ignore[attr-defined]


# Add __bytes__ for bytes(warrant) support
def _warrant_bytes(self: Warrant) -> bytes:
    """Return CBOR-encoded bytes representation.

    This allows warrants to be serialized to bytes:
        warrant_bytes = bytes(warrant)
    """
    return self.to_cbor()


Warrant.__bytes__ = _warrant_bytes  # type: ignore[attr-defined]


# Add from_bytes as alias for from_cbor
def _warrant_from_bytes(data: bytes) -> "Warrant":
    """Parse warrant from bytes (CBOR encoded).

    This is an alias for from_cbor() that pairs with bytes(warrant).
    """
    return Warrant.from_cbor(data)


Warrant.from_bytes = _warrant_from_bytes  # type: ignore[attr-defined]

# ============================================================================
# Chain Traversal
# ============================================================================


def _warrant_chain(self: Warrant, store: Optional[Any] = None) -> List[Warrant]:
    """Get the full delegation chain from root to current warrant.

    Returns a list of warrants starting from the root (issuer) warrant
    and ending with the current warrant.

    Args:
        store: Optional warrant store/cache to look up parents.
               Must have a .get(hash: str) -> Optional[Warrant] method.

    Example:
        chain = warrant.chain(my_store)
        for w in chain:
            print(f"{w.type}: {w.tools or w.can_issue}")

    Returns:
        List of Warrant objects from root to current
    """
    chain = []
    current = self

    # Trace back using parent_hash
    while current is not None:
        chain.append(current)
        if current.parent_hash is None or store is None:
            break

        # Try to fetch parent from store
        try:
            parent = store.get(current.parent_hash)
            if parent is None:
                break
            current = parent
        except Exception:
            break

    # Reverse to get root-first order
    return list(reversed(chain))


Warrant.chain = _warrant_chain  # type: ignore[attr-defined]
