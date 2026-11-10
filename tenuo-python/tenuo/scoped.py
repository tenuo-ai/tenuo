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
from contextvars import Token
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional

from tenuo_core import (  # type: ignore[import-untyped]
    SigningKey,
    Warrant,
    validate_attenuation,
)

from .config import ConfigurationError, get_config
from .constraints import Capability, ensure_constraint
from .decorators import (
    _allowed_tools_context,
    _chain_context,
    _keypair_context,
    _warrant_context,
    key_scope,
    warrant_scope,
)
from .exceptions import (
    MonotonicityError,
    ScopeViolation,
)


def _is_constraint_contained(child_value: Any, parent_value: Any) -> bool:
    """Check scoped preflight through the same native rules as signed grants.

    Literal shorthand means Exact, including strings containing glob characters.
    A successful check only establishes the constraint relationship; grant()
    still builds and validates the complete child warrant in Rust.
    """
    try:
        validate_attenuation(ensure_constraint(parent_value), ensure_constraint(child_value))
        return True
    except Exception:
        # This boolean preflight fails closed on invalid values or any failure
        # to establish containment. Never substitute Python policy heuristics.
        return False


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
        self._chain_token: Optional[Token] = None

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
                merged_constraints[key] = ensure_constraint(child_value)

            builder.capability(tool, merged_constraints)

        # Apply TTL with atomic core-side clamping. Computing parent remaining
        # here would race the clock read used to build the child.
        if self.ttl:
            builder._ttl_capped_to_parent(self.ttl)

        # Build child warrant
        try:
            child = builder.grant(keypair)
        except Exception as e:
            raise MonotonicityError(f"Failed to attenuate warrant: {e}") from e

        # Set in context and save token for restoration. The parent joins the
        # ambient chain so the child stays verifiable against the root alone.
        self._chain_token = _chain_context.set(list(_chain_context.get() or []) + [parent])
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

        if self._chain_token:
            _chain_context.reset(self._chain_token)
            self._chain_token = None


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

    # A minted warrant is a fresh root, so it must not inherit an outer
    # delegated warrant's parent chain. Restore the outer chain on exit.
    chain_token = _chain_context.set(None)
    warrant_token = _warrant_context.set(warrant)
    keypair_token = _keypair_context.set(holder)

    try:
        yield warrant
    finally:
        _chain_context.reset(chain_token)
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

    # A minted warrant is a fresh root, so it must not inherit an outer
    # delegated warrant's parent chain. Restore the outer chain on exit.
    chain_token = _chain_context.set(None)
    warrant_token = _warrant_context.set(warrant)
    keypair_token = _keypair_context.set(holder)

    try:
        yield warrant
    finally:
        _chain_context.reset(chain_token)
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
