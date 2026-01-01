from typing import Dict, Any, TYPE_CHECKING, List
if TYPE_CHECKING:
    from tenuo_core import Constraint # type: ignore


def ensure_constraint(value: Any) -> Any:
    """
    Ensure value is a constraint object, wrapping in Exact if not.

    NO TYPE INFERENCE is performed for lists/dicts.
    - "foo" -> Exact("foo")
    - [1, 2] -> Exact([1, 2])

    To use broader constraints, you must explicitly construct them:
    - Pattern("foo*")
    - OneOf([1, 2])
    """
    # Check if it's already a constraint (by class name to avoid circular imports of types)
    # We can't import types easily here without circular depends if types import this file
    # But usually Types are in tenuo_core or __init__.
    # Let's try to detect by looking for 'to_dict' or specific names?
    # Or just assume if it's not a primitive, it might be a constraint.
    # Actually, let's use the explicit list of known constraint types from tenuo_core but imported lazily.

    try:
        from tenuo_core import (
            Pattern, Exact, OneOf, Range, Regex, Wildcard, NotOneOf,
            Cidr, UrlPattern, Contains, Subset, All, AnyOf, Not, CEL
        )
        if isinstance(value, (
            Pattern, Exact, OneOf, Range, Regex, Wildcard, NotOneOf,
            Cidr, UrlPattern, Contains, Subset, All, AnyOf, Not, CEL
        )):
            return value
    except ImportError:
        # Fallback if tenuo_core not available (e.g. during build?)
        pass

    # Basic types wrapper
    # We need Exact to be available to wrap.
    from tenuo_core import Exact
    return Exact(value)


class Capability:
    """
    Represents a single capability (tool + constraints) for Tier 1 API.

    A capability binds a tool name to its specific constraints.
    No type inference is performed - use explicit constraint types.

    Example:
        from tenuo import Capability, Pattern, Range

        # Capability with constraints
        cap = Capability("read_file", path=Pattern("/data/*"))

        # Capability without constraints (any args allowed)
        cap = Capability("ping")

        # Multiple constraints
        cap = Capability("query_db",
            table=Pattern("users_*"),
            limit=Range.max_value(100)
        )

    Usage with mint/grant:
        async with mint(
            Capability("read_file", path=Pattern("/data/*")),
            Capability("send_email", to=Pattern("*@company.com")),
        ):
            async with grant(
                Capability("read_file", path=Pattern("/data/reports/*"))
            ):
                ...
    """

    def __init__(self, tool: str, **constraints: Any):
        """
        Create a capability for a tool with optional constraints.

        Args:
            tool: The tool name this capability authorizes
            **constraints: Field constraints (must be explicit constraint types)
        """
        if not tool or not isinstance(tool, str):
            raise ValueError("Capability requires a non-empty tool name")
        self.tool = tool
        self.constraints = constraints

    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        """Convert to capabilities dict format: {tool: {field: constraint}}"""
        return {self.tool: dict(self.constraints)}

    def __repr__(self) -> str:
        if self.constraints:
            constraints_str = ", ".join(f"{k}={v!r}" for k, v in self.constraints.items())
            return f"Capability({self.tool!r}, {constraints_str})"
        return f"Capability({self.tool!r})"

    @staticmethod
    def merge(*capabilities: 'Capability') -> Dict[str, Dict[str, Any]]:
        """Merge multiple capabilities into a single capabilities dict."""
        result: Dict[str, Dict[str, Any]] = {}
        for cap in capabilities:
            if cap.tool in result:
                # Merge constraints for same tool
                result[cap.tool].update(cap.constraints)
            else:
                result[cap.tool] = dict(cap.constraints)
        return result


class Constraints(Dict[str, Any]):
    """
    Helper class for defining capability constraints.

    Acts as a dictionary mapping field names to Constraint objects.

    Example:
        constraints = Constraints()
        constraints.add("cluster", Exact("staging-web"))
        constraints.add("replicas", Range(max=5))

        # Or using kwargs constructor:
        constraints = Constraints(
            cluster=Exact("staging-web"),
            replicas=Range(max=5)
        )
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add(self, field: str, constraint: 'Constraint') -> 'Constraints':
        """Add a constraint for a field."""
        self[field] = constraint
        return self

    @staticmethod
    def for_tool(tool: str, constraints: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Create a capabilities dictionary for a single tool.

        This is a convenience method for Tier 2 API (Warrant.issue).
        For Tier 1 API (mint/grant), use Capability class instead.

        Example:
            warrant = Warrant.mint(
                keypair=kp,
                capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
                ttl_seconds=3600
            )
        """
        return {tool: constraints}

    @staticmethod
    def for_tools(tools: List[str], constraints: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Create a capabilities dictionary for multiple tools with shared constraints.

        Example:
            capabilities = Constraints.for_tools(
                ["read_file", "write_file"],
                {"path": Pattern("/data/*")}
            )
            # Returns: {"read_file": {"path": ...}, "write_file": {"path": ...}}
        """
        return {tool: dict(constraints) for tool in tools}
