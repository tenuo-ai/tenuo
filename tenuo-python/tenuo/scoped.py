"""
Scoped task context managers for Tenuo Tier 1 API.

Provides mint() and grant() for easy warrant management.

Usage:
    from tenuo import configure, mint, grant, Capability, Pattern

    # Configure once at startup
    configure(issuer_key=my_keypair, dev_mode=True)

    # Use explicit capabilities
    async with mint(
        Capability("read_file", path=Pattern("/data/*")),
        Capability("send_email", to=Pattern("*@company.com")),
    ):
        async with grant(
            Capability("read_file", path=Pattern("/data/reports/*"))
        ):
            result = await agent.run(...)
"""

from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, AsyncIterator, Iterator
from contextvars import Token

from tenuo_core import (  # type: ignore[import-untyped]
    Warrant,
    SigningKey,
)

from .config import get_config, ConfigurationError
from .constraints import Capability
from .decorators import (
    _warrant_context,
    _keypair_context,
    _allowed_tools_context,
    warrant_scope,
    key_scope,
)
from .exceptions import (
    ScopeViolation,
    MonotonicityError,
)


def _extract_pattern_value(value: Any) -> str:
    """Extract the actual pattern string from a constraint value."""
    s = str(value)
    # Handle Pattern('...') wrapper
    if s.startswith("Pattern('") and s.endswith("')"):
        return s[9:-2]
    # Handle Exact('...') wrapper
    if s.startswith("Exact('") and s.endswith("')"):
        return s[7:-2]
    return s


def _is_constraint_contained(child_value: Any, parent_value: Any) -> bool:
    """
    Check if child constraint is contained within parent.

    IMPORTANT: This is a "fast-fail" optimization for the Tier 1 API (grant()).
    The authoritative validation is performed by Rust core during warrant creation.
    This Python-side check provides immediate feedback to developers but may be
    slightly more conservative than Rust in edge cases.

    If this check passes, Rust will also pass. If this check fails, Rust would
    also fail (or the constraint combination is not supported in Tier 1).

    Tier 1 API Containment Rules:

    Universal Containment:
    - Wildcard -> Any: Wildcard parent contains everything (universal superset)
    - Any -> Wildcard: NEVER allowed (would widen permissions)

    Same-Type Containment:
    - Pattern -> Pattern: child pattern must be more restrictive (more literal chars)
    - Regex -> Regex: patterns must be IDENTICAL (subset is undecidable)
    - Exact -> Exact: values must be equal
    - OneOf -> OneOf: child must be a subset of parent
    - NotOneOf -> NotOneOf: child must exclude MORE values (superset of exclusions)
    - Range -> Range: child bounds must be within parent bounds
    - Contains -> Contains: child must require MORE values (superset of required)
    - Subset -> Subset: child must allow FEWER values (subset of allowed)
    - All -> All: conservative check (requires identical repr)
    - CEL -> CEL: child expression must be syntactic extension of parent
    - string -> string: values must be equal (fallback)

    Cross-Type Containment:
    - Pattern -> Exact: exact value must match parent pattern (glob)
    - Pattern -> string: string value must match parent pattern (glob)
    - Regex -> Exact: exact value must match parent regex
    - Regex -> string: string value must match parent regex
    - OneOf -> Exact: exact value must be in parent's set
    - OneOf -> string: string value must be in parent's set
    - Range -> Exact: exact numeric value must be within parent range

    Returns:
        True if child is contained within parent, False otherwise.
    """
    import fnmatch
    import re

    # Get constraint type names
    child_type = type(child_value).__name__
    parent_type = type(parent_value).__name__

    # =========================================================================
    # Wildcard - Universal superset (must check FIRST)
    # =========================================================================
    # Wildcard parent contains ANYTHING
    if parent_type == "Wildcard":
        return True

    # NOTHING can attenuate TO Wildcard (would expand permissions)
    if child_type == "Wildcard":
        return False

    # Extract actual values from wrappers
    child_str = _extract_pattern_value(child_value)
    parent_str = _extract_pattern_value(parent_value)

    # =========================================================================
    # Regex - Must be identical pattern or Exact that matches
    # =========================================================================
    if parent_type == "Regex":
        parent_pattern = getattr(parent_value, "pattern", None)
        if parent_pattern is None:
            return False

        if child_type == "Regex":
            # Regex -> Regex: must be IDENTICAL (subset is undecidable)
            child_pattern = getattr(child_value, "pattern", None)
            return parent_pattern == child_pattern
        else:
            # Regex -> Exact/string: value must match regex
            try:
                return bool(re.match(parent_pattern, child_str))
            except re.error:
                return False

    # =========================================================================
    # Pattern/glob containment - use fnmatch for proper glob matching
    # =========================================================================
    if parent_type == "Pattern" or "*" in parent_str:
        if child_type == "Pattern" or "*" in child_str:
            # Both are patterns - child must be more restrictive
            # A pattern is more restrictive if it has more literal characters
            # or matches a subset of what the parent matches
            child_literal = child_str.replace("*", "")
            parent_literal = parent_str.replace("*", "")

            # Child's literal parts must contain parent's literal parts
            # e.g., "*@company.com" contains "@company.com"
            # and "/data/reports/*" is more restrictive than "/data/*"
            if parent_literal in child_literal or child_literal.startswith(parent_literal):
                return True

            # Also check if child pattern would only match things parent matches
            # by checking if the non-wildcard parts align
            return len(child_literal) >= len(parent_literal) and parent_literal in child_literal
        else:
            # Child is exact value - must match parent pattern using glob
            return fnmatch.fnmatch(child_str, parent_str)

    # OneOf containment - check BEFORE Exact since Exact can be inside OneOf
    if parent_type == "OneOf":
        parent_values = set(getattr(parent_value, "values", []))
        if child_type == "OneOf":
            # Child OneOf must be subset of parent OneOf
            child_values = set(getattr(child_value, "values", []))
            return child_values.issubset(parent_values)
        elif child_type == "Exact":
            # Exact value must be in the parent's OneOf set
            return child_str in parent_values
        else:
            # Plain string value must be in the parent's OneOf set
            return child_str in parent_values

    # Range containment - check BEFORE Exact since Range can contain Exact
    if parent_type == "Range":
        p_min = getattr(parent_value, "min", None)
        p_max = getattr(parent_value, "max", None)

        if child_type == "Range":
            c_min = getattr(child_value, "min", None)
            c_max = getattr(child_value, "max", None)

            min_ok = p_min is None or (c_min is not None and c_min >= p_min)
            max_ok = p_max is None or (c_max is not None and c_max <= p_max)
            return min_ok and max_ok
        elif child_type == "Exact":
            # Range -> Exact: value must be within range
            try:
                value = float(child_str)
                min_ok = p_min is None or value >= p_min
                max_ok = p_max is None or value <= p_max
                return min_ok and max_ok
            except (ValueError, TypeError):
                return False
        else:
            # Range cannot contain non-Range/non-Exact types
            return False

    # Exact containment - must be equal (both Exact or one is Exact)
    if parent_type == "Exact" or child_type == "Exact":
        return child_str == parent_str

    # =========================================================================
    # NotOneOf - Child must exclude MORE values (superset of exclusions)
    # =========================================================================
    if parent_type == "NotOneOf":
        parent_excluded = set(getattr(parent_value, "excluded", []))
        if child_type == "NotOneOf":
            # Child must exclude at least everything parent excludes
            child_excluded = set(getattr(child_value, "excluded", []))
            return parent_excluded.issubset(child_excluded)
        else:
            # Other types cannot attenuate to NotOneOf
            return False

    # =========================================================================
    # Contains - Child must require MORE values (superset of required)
    # =========================================================================
    if parent_type == "Contains":
        parent_required = set(_extract_list_values(getattr(parent_value, "required", [])))
        if child_type == "Contains":
            # Child must require at least everything parent requires
            child_required = set(_extract_list_values(getattr(child_value, "required", [])))
            return parent_required.issubset(child_required)
        else:
            return False

    # =========================================================================
    # Subset - Child must allow FEWER values (subset of allowed)
    # =========================================================================
    if parent_type == "Subset":
        parent_allowed = set(_extract_list_values(getattr(parent_value, "allowed", [])))
        if child_type == "Subset":
            # Child allowed set must be subset of parent allowed set
            child_allowed = set(_extract_list_values(getattr(child_value, "allowed", [])))
            return child_allowed.issubset(parent_allowed)
        else:
            return False

    # =========================================================================
    # All - Compound constraint (all sub-constraints must match)
    # =========================================================================
    if parent_type == "All":
        # All constraints are complex - for now, require same type
        # Full validation would need to check each sub-constraint
        if child_type == "All":
            # Conservative: same repr means same constraints
            return str(parent_value) == str(child_value) or repr(parent_value) == repr(child_value)
        else:
            return False

    # =========================================================================
    # CEL - Child expression must be syntactic extension of parent
    # =========================================================================
    if parent_type == "Cel" or parent_type == "CelConstraint":
        parent_expr = getattr(parent_value, "expression", None)
        if parent_expr is None:
            return False

        if child_type == "Cel" or child_type == "CelConstraint":
            child_expr = getattr(child_value, "expression", None)
            if child_expr is None:
                return False
            # CEL monotonicity: child must be (parent) && additional_predicate
            # or exactly the same expression
            if parent_expr == child_expr:
                return True
            # Check if child is conjunction with parent
            expected_prefix = f"({parent_expr}) &&"
            return child_expr.startswith(expected_prefix)
        else:
            return False

    # =========================================================================
    # Subpath - Child root must be under parent root
    # =========================================================================
    if parent_type == "Subpath":
        parent_root = getattr(parent_value, "root", None)
        if parent_root is None:
            return False

        if child_type == "Subpath":
            child_root = getattr(child_value, "root", None)
            if child_root is None:
                return False
            # Child root must be under parent root (or equal)
            # Normalize paths and check containment
            parent_normalized = parent_root.rstrip("/")
            child_normalized = child_root.rstrip("/")
            # Child is contained if it equals parent or starts with parent + "/"
            if child_normalized == parent_normalized:
                return True
            return child_normalized.startswith(parent_normalized + "/")
        elif child_type == "Exact":
            # Exact path must be under parent root
            return parent_value.matches(child_str)
        else:
            return False

    # =========================================================================
    # UrlSafe - Child must be more restrictive
    # =========================================================================
    if parent_type == "UrlSafe":
        if child_type == "UrlSafe":
            # UrlSafe -> UrlSafe: child must be at least as restrictive
            # For now, use conservative check via Rust
            try:
                parent_value.validate_attenuation(child_value)
                return True
            except Exception:
                # If validate_attenuation fails or doesn't exist, check manually
                # Child can add domains to allowlist (more restrictive)
                # Child cannot remove blocking (private, loopback, etc.)
                p_block_private = getattr(parent_value, "block_private", True)
                c_block_private = getattr(child_value, "block_private", True)
                if p_block_private and not c_block_private:
                    return False

                p_block_loopback = getattr(parent_value, "block_loopback", True)
                c_block_loopback = getattr(child_value, "block_loopback", True)
                if p_block_loopback and not c_block_loopback:
                    return False

                # If parent has domain allowlist, child must be subset
                p_domains = getattr(parent_value, "allow_domains", None)
                c_domains = getattr(child_value, "allow_domains", None)
                if p_domains is not None:
                    if c_domains is None:
                        return False  # Child removes restriction
                    if not set(c_domains).issubset(set(p_domains)):
                        return False

                return True
        elif child_type == "Exact":
            # Exact URL must pass parent's is_safe check
            return parent_value.is_safe(child_str)
        else:
            return False

    # =========================================================================
    # Shlex - Child must have subset of allowed binaries
    # =========================================================================
    if parent_type == "Shlex":
        if child_type == "Shlex":
            # Child allowed_bins must be subset of parent allowed_bins
            p_bins: set = getattr(parent_value, "allowed_bins", set())
            c_bins: set = getattr(child_value, "allowed_bins", set())
            if not c_bins.issubset(p_bins):
                return False
            # Child cannot relax block_globs
            p_block_globs = getattr(parent_value, "block_globs", False)
            c_block_globs = getattr(child_value, "block_globs", False)
            if p_block_globs and not c_block_globs:
                return False
            return True
        elif child_type == "Exact":
            # Exact command must pass parent's matches check
            return parent_value.matches(child_str)
        else:
            return False

    # =========================================================================
    # Cidr - Child must be contained within parent network
    # =========================================================================
    if parent_type == "Cidr":
        if child_type == "Cidr":
            # Child network must be subnet of parent network
            # Use Rust's validate_attenuation if available
            try:
                parent_value.validate_attenuation(child_value)
                return True
            except Exception:
                # Fallback: check cidr_string containment (conservative)
                p_cidr = getattr(parent_value, "cidr_string", str(parent_value))
                c_cidr = getattr(child_value, "cidr_string", str(child_value))
                # Same network is valid attenuation
                return p_cidr == c_cidr
        elif child_type == "Exact":
            # Exact IP must be within parent network
            return parent_value.matches(child_str)
        else:
            return False

    # =========================================================================
    # UrlPattern - Child must be more specific pattern
    # =========================================================================
    if parent_type == "UrlPattern":
        if child_type == "UrlPattern":
            # Child pattern must be more restrictive
            try:
                parent_value.validate_attenuation(child_value)
                return True
            except Exception:
                # Fallback: same pattern is valid
                p_pattern = getattr(parent_value, "pattern", str(parent_value))
                c_pattern = getattr(child_value, "pattern", str(child_value))
                return p_pattern == c_pattern
        elif child_type == "Exact":
            # Exact URL must match parent pattern
            return parent_value.matches(child_str)
        else:
            return False

    # Fallback: string equality
    return child_str == parent_str


def _extract_list_values(values: Any) -> list:
    """Extract string values from a list of constraint values."""
    result = []
    for v in values:
        if isinstance(v, str):
            result.append(v)
        elif hasattr(v, "value"):
            result.append(str(getattr(v, "value")))
        else:
            result.append(str(v))
    return result


@dataclass
class ScopePreview:
    """Preview of derived scope before execution."""

    tools: Optional[List[str]] = None
    parent_tools: Optional[List[str]] = None
    constraints: Optional[Dict[str, Any]] = None
    parent_constraints: Optional[Dict[str, Any]] = None
    ttl: Optional[int] = None
    parent_ttl: Optional[int] = None
    depth: Optional[int] = None
    error: Optional[str] = None

    def print(self) -> None:
        """Pretty-print the preview."""
        if self.error:
            print(f"❌ Cannot create scope: {self.error}")
            return

        print("Derived scope:")
        print(f"  Tools: {self.tools}")
        if self.parent_tools and self.tools != self.parent_tools:
            dropped = set(self.parent_tools) - set(self.tools or [])
            if dropped:
                print(f"    (dropped: {dropped})")

        print("  Constraints:")
        for key, value in (self.constraints or {}).items():
            parent_val = (self.parent_constraints or {}).get(key)
            if parent_val and str(parent_val) != str(value):
                print(f"    {key}: {value} (narrowed from {parent_val})")
            else:
                print(f"    {key}: {value}")

        if self.ttl:
            print(f"  TTL: {self.ttl}s", end="")
            if self.parent_ttl and self.ttl != self.parent_ttl:
                print(f" (reduced from {self.parent_ttl}s)")
            else:
                print()

        if self.depth is not None:
            print(f"  Depth: {self.depth}")


class GrantScope:
    """Context manager for grant() with preview support."""

    def __init__(
        self,
        capabilities_args: tuple,
        ttl: Optional[int],
    ):
        self.capabilities_args = capabilities_args
        self.ttl = ttl
        self._warrant_token: Optional[Token] = None
        self._allowed_tools_token: Optional[Token] = None

    def preview(self) -> ScopePreview:
        """Preview the derived scope without executing."""
        parent = warrant_scope()

        if parent is None:
            return ScopePreview(error="No parent warrant. Use mint() first.")

        try:
            parent_tools = parent.tools if parent.tools else []
            parent_caps = parent.capabilities if hasattr(parent, "capabilities") else {}

            child_capabilities = Capability.merge(*self.capabilities_args)
            child_tools = list(child_capabilities.keys())

            # Validate all child tools exist in parent
            invalid_tools = set(child_tools) - set(parent_tools)
            if invalid_tools:
                return ScopePreview(
                    error=f"Capabilities for tools {invalid_tools} not in parent. Parent has: {parent_tools}"
                )

            # Check containment for each tool's constraints
            for tool, child_constraints in child_capabilities.items():
                parent_constraints = parent_caps.get(tool, {})
                for key, child_value in child_constraints.items():
                    parent_value = parent_constraints.get(key)
                    if parent_value is not None:
                        if not _is_constraint_contained(child_value, parent_value):
                            return ScopePreview(
                                error=f"Constraint '{key}': {child_value} not contained in {parent_value} for tool '{tool}'"
                            )

            # Use first tool's constraints for preview display
            first_tool = child_tools[0] if child_tools else None
            derived_constraints = child_capabilities.get(first_tool, {}) if first_tool else {}
            parent_constraints_preview = parent_caps.get(first_tool, {}) if first_tool else {}

            # Compute TTL
            parent_ttl = None
            if hasattr(parent, "ttl_remaining"):
                parent_ttl = parent.ttl_remaining.total_seconds()

            child_ttl = self.ttl
            if child_ttl and parent_ttl:
                child_ttl = min(child_ttl, parent_ttl)
            elif parent_ttl:
                child_ttl = parent_ttl

            return ScopePreview(
                tools=child_tools,
                parent_tools=parent_tools,
                constraints=derived_constraints,
                parent_constraints=parent_constraints_preview,
                ttl=child_ttl,
                parent_ttl=parent_ttl,
                depth=parent.depth + 1,
            )
        except Exception as e:
            return ScopePreview(error=str(e))

    async def __aenter__(self) -> Warrant:
        """Enter the scoped context (async)."""
        return self._enter()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the scoped context (async)."""
        self._exit()

    def __enter__(self) -> Warrant:
        """Enter the scoped context (sync)."""
        import asyncio

        try:
            asyncio.get_running_loop()
            raise RuntimeError("Cannot use sync 'with grant()' in async context. Use 'async with grant()' instead.")
        except RuntimeError:
            pass
        return self._enter()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the scoped context (sync)."""
        self._exit()

    def _enter(self) -> Warrant:
        """Enter scoped task context."""
        parent = warrant_scope()
        keypair = key_scope()

        if parent is None:
            raise ScopeViolation(
                "grant() requires a parent warrant. Use mint() to create initial authority, then grant() to narrow it."
            )

        if keypair is None:
            raise ConfigurationError("No keypair in context.")

        if not self.capabilities_args:
            raise ConfigurationError(
                "grant requires at least one Capability. "
                "Example: grant(Capability('read_file', path=Pattern('/data/reports/*')))"
            )

        # Build attenuated warrant
        builder = parent.grant_builder()

        parent_caps = parent.capabilities if hasattr(parent, "capabilities") else {}
        parent_tools = parent.tools if parent.tools else list(parent_caps.keys())

        child_capabilities = Capability.merge(*self.capabilities_args)

        # Validate all child tools exist in parent
        invalid_tools = set(child_capabilities.keys()) - set(parent_tools)
        if invalid_tools:
            raise ScopeViolation(
                f"Cannot scope to tools {invalid_tools} - not in parent warrant. Parent has: {parent_tools}"
            )

        target_tools = list(child_capabilities.keys())

        # Restrict to only the specified tools
        builder.tools(target_tools)

        # Validate containment and build capabilities
        for tool, child_constraints in child_capabilities.items():
            parent_tool_constraints = parent_caps.get(tool, {})
            merged_constraints = dict(parent_tool_constraints)

            for key, child_value in child_constraints.items():
                parent_value = parent_tool_constraints.get(key)
                if parent_value is not None:
                    if not _is_constraint_contained(child_value, parent_value):
                        raise MonotonicityError(
                            f"Constraint '{key}': '{child_value}' is not contained within "
                            f"parent's '{parent_value}' for tool '{tool}'"
                        )
                merged_constraints[key] = child_value

            builder.capability(tool, merged_constraints)

        # Apply TTL
        if self.ttl:
            builder.ttl(self.ttl)

        # Build child warrant
        try:
            child = builder.grant(keypair)
        except Exception as e:
            raise MonotonicityError(f"Failed to attenuate warrant: {e}") from e

        # Set in context and save token for restoration
        self._warrant_token = _warrant_context.set(child)
        self._allowed_tools_token = _allowed_tools_context.set(target_tools)

        return child

    def _exit(self) -> None:
        """Exit scoped task context."""
        if self._warrant_token:
            _warrant_context.reset(self._warrant_token)
            self._warrant_token = None

        if self._allowed_tools_token:
            _allowed_tools_context.reset(self._allowed_tools_token)
            self._allowed_tools_token = None


def grant(
    *capabilities: Capability,
    ttl: Optional[int] = None,
) -> GrantScope:
    """
    Create a scoped task that attenuates the current warrant.

    MUST be called within a mint() or another grant().
    Cannot mint new authority - only narrow existing authority.

    Args:
        *capabilities: Capability objects (tools must exist in parent)
        ttl: Shorter TTL in seconds (None = inherit remaining)

    Returns:
        GrantScope that can be used as context manager or previewed

    Raises:
        ScopeViolation: If no parent warrant in context or tool not in parent
        MonotonicityError: If constraints aren't contained within parent's

    Example:
        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            async with grant(Capability("read_file", path=Pattern("/data/reports/*"))):
                result = await agent.run(...)
    """
    return GrantScope(capabilities, ttl)


@asynccontextmanager
async def mint(
    *capabilities: Capability,
    ttl: Optional[int] = None,
    holder_key: Optional[SigningKey] = None,
) -> AsyncIterator[Warrant]:
    """
    Create a root warrant (explicit authority minting).

    This is the ONLY way to mint new authority in Tier 1.
    Use grant() to attenuate within a mint block.

    Args:
        *capabilities: Capability objects defining tool + constraints
        ttl: Time-to-live in seconds (default from configure())
        holder_key: Explicit holder keypair (default: issuer key)

    Raises:
        ConfigurationError: If no issuer key configured or no capabilities

    Example:
        async with mint(
            Capability("read_file", path=Pattern("/data/*")),
            Capability("send_email", to=Pattern("*@company.com")),
        ):
            async with grant(
                Capability("read_file", path=Pattern("/data/reports/*"))
            ):
                result = await agent.run(...)
    """
    config = get_config()

    if config.issuer_key is None:
        raise ConfigurationError(
            "Cannot create root warrant: no issuer key configured. Call configure(issuer_key=...) first."
        )

    if not capabilities:
        raise ConfigurationError(
            "mint requires at least one Capability. Example: mint(Capability('read_file', path=Pattern('/data/*')))"
        )

    issuer = config.issuer_key
    holder = holder_key or issuer
    effective_ttl = ttl or config.default_ttl

    # Build capabilities dict from Capability objects
    capabilities_dict = Capability.merge(*capabilities)

    # Issue the warrant
    warrant = Warrant.mint(
        keypair=issuer,
        capabilities=capabilities_dict,
        ttl_seconds=effective_ttl,
        holder=holder.public_key if holder != issuer else None,
    )

    # Set in context
    warrant_token = _warrant_context.set(warrant)
    keypair_token = _keypair_context.set(holder)

    try:
        yield warrant
    finally:
        _warrant_context.reset(warrant_token)
        _keypair_context.reset(keypair_token)


@contextmanager
def mint_sync(
    *capabilities: Capability,
    ttl: Optional[int] = None,
    holder_key: Optional[SigningKey] = None,
) -> Iterator[Warrant]:
    """
    Synchronous version of mint().

    Use this when not in an async context.

    Example:
        with mint_sync(
            Capability("read_file", path=Pattern("/data/*")),
        ):
            result = protected_read_file(path="/data/report.csv")
    """
    config = get_config()

    if config.issuer_key is None:
        raise ConfigurationError(
            "Cannot create root warrant: no issuer key configured. Call configure(issuer_key=...) first."
        )

    if not capabilities:
        raise ConfigurationError(
            "mint_sync requires at least one Capability. "
            "Example: mint_sync(Capability('read_file', path=Pattern('/data/*')))"
        )

    issuer = config.issuer_key
    holder = holder_key or issuer
    effective_ttl = ttl or config.default_ttl

    # Build capabilities dict from Capability objects
    capabilities_dict = Capability.merge(*capabilities)

    warrant = Warrant.mint(
        keypair=issuer,
        capabilities=capabilities_dict,
        ttl_seconds=effective_ttl,
        holder=holder.public_key if holder != issuer else None,
    )

    warrant_token = _warrant_context.set(warrant)
    keypair_token = _keypair_context.set(holder)

    try:
        yield warrant
    finally:
        _warrant_context.reset(warrant_token)
        _keypair_context.reset(keypair_token)


__all__ = [
    "mint",
    "mint_sync",
    "grant",
    "GrantScope",
    "ScopePreview",
    "Capability",
]
