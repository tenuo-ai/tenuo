"""
Universal security constraints for Tenuo.

**What are constraints?**
Constraints define WHAT values are allowed for tool arguments.
They're the core security building blocks across all Tenuo integrations.

**Common Constraints:**

    Subpath("/data")
        Only allow paths under /data/. Blocks path traversal attacks.
        Example: /data/file.txt OK, /etc/passwd BLOCKED

    UrlSafe(allow_domains=["api.github.com"])
        Only allow URLs to specific domains. Blocks SSRF attacks.
        Example: https://api.github.com OK, http://localhost BLOCKED

    Pattern("*.txt")
        Allow values matching a glob pattern.
        Example: report.txt OK, config.yaml BLOCKED

    OneOf(["low", "medium", "high"])
        Allow only specific values.
        Example: "medium" OK, "critical" BLOCKED

    Range(0, 100)
        Allow numbers in a range.
        Example: 50 OK, 150 BLOCKED

    Shlex(allow=["ls", "cat"])
        Allow only safe shell commands. Blocks injection.
        Example: "ls -la" OK, "rm -rf /" BLOCKED

**Quick Start:**
    from tenuo.constraints import Subpath, UrlSafe

    # Path containment
    path = Subpath("/data")
    path.contains("/data/file.txt")      # True
    path.contains("/data/../etc/passwd") # False (traversal blocked)

    # SSRF protection
    url = UrlSafe()
    url.is_safe("https://api.github.com/")  # True
    url.is_safe("http://169.254.169.254/")  # False (metadata blocked)

**Usage:**
    # Direct import (recommended)
    from tenuo.constraints import Subpath, UrlSafe

    # Or via main package
    from tenuo import Subpath, UrlSafe

    # Or via adapter (convenience)
    from tenuo.openai import Subpath, UrlSafe
"""

from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from tenuo_core import Constraint  # type: ignore

# =============================================================================
# Import Rust implementations
# =============================================================================

# These are now implemented in Rust (tenuo-core/src/constraints.rs)
# and exposed via PyO3 bindings. The Rust implementations:
# - Can be serialized into Warrants (CBOR wire format)
# - Are consistent across all language bindings (Go, Node, Python)
# - Are stateless/pure (no filesystem or network I/O)

try:
    from tenuo_core import (
        All,  # AND composite, used to build path_glob()
        Pattern,  # Glob over the whole string, used to build path_glob()
        Shlex,  # POSIX shell-command constraint
        Subpath,  # Secure path containment constraint
        UrlSafe,  # SSRF-safe URL constraint
    )
except ImportError:
    # Fallback for type checking or when Rust extension not built
    # This should never happen in production
    class Subpath:  # type: ignore[no-redef]
        """Fallback - Rust extension not available."""

        def __init__(self, root: str, *, case_sensitive: bool = True, allow_equal: bool = True):
            raise ImportError("tenuo_core not available - rebuild with maturin")

        def contains(self, path: str) -> bool:
            raise ImportError("tenuo_core not available")

    class UrlSafe:  # type: ignore[no-redef]
        """Fallback - Rust extension not available."""

        def __init__(self, **kwargs):
            raise ImportError("tenuo_core not available - rebuild with maturin")

        def is_safe(self, url: str) -> bool:
            raise ImportError("tenuo_core not available")

    class All:  # type: ignore[no-redef]
        """Fallback - Rust extension not available."""

        def __init__(self, *args, **kwargs):
            raise ImportError("tenuo_core not available - rebuild with maturin")

    class Pattern:  # type: ignore[no-redef]
        """Fallback - Rust extension not available."""

        def __init__(self, *args, **kwargs):
            raise ImportError("tenuo_core not available - rebuild with maturin")

    class Shlex:  # type: ignore[no-redef]
        """Fallback - Rust extension not available."""

        def __init__(self, allow: List[str]):
            raise ImportError("tenuo_core not available - rebuild with maturin")

        def matches(self, value: Any) -> bool:
            raise ImportError("tenuo_core not available")


# =============================================================================
# Helper Functions
# =============================================================================


def path_glob(
    root: str,
    glob: str,
    *,
    case_sensitive: bool = True,
    allow_equal: bool = True,
) -> Any:
    """
    A traversal-safe filesystem glob: the value must stay under ``root`` and
    match ``glob``.

    ``Pattern`` on its own is a generic string glob whose ``*`` crosses ``/``,
    so ``Pattern("*.json")`` admits ``/etc/passwd.json``. Pairing it with
    ``Subpath`` is what makes it a filesystem boundary.

    The glob is tested against the whole path, not against the part below
    ``root``, so it matches at any depth::

        path_glob("/workspace", "*.json")
        # /workspace/reports/q3.json  OK
        # /workspace/secrets.env      BLOCKED (glob)
        # /etc/passwd.json            BLOCKED (root)

    A delegatee can narrow this to a single ``Exact`` path the parent already
    admits, or to a tighter ``path_glob``. Narrowing to a value outside the
    root, or one the glob rejects, raises ``MonotonicityError``.
    """
    return All(
        [
            Subpath(root, case_sensitive=case_sensitive, allow_equal=allow_equal),
            Pattern(glob),
        ]
    )


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
    try:
        from tenuo_core import (
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
            Subpath,
            Subset,
            UrlPattern,
            UrlSafe,
            Wildcard,
        )

        if isinstance(
            value,
            (
                Pattern,
                Exact,
                OneOf,
                Range,
                Regex,
                Wildcard,
                NotOneOf,
                Cidr,
                UrlPattern,
                Contains,
                Subset,
                All,
                AnyOf,
                Not,
                CEL,
                Subpath,
                UrlSafe,
            ),
        ):
            return value
    except ImportError:
        pass

    # Basic types wrapper
    from tenuo_core import Exact

    return Exact(value)


# =============================================================================
# Capability Class (for Tier 1 API)
# =============================================================================


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
    def merge(*capabilities: "Capability") -> Dict[str, Dict[str, Any]]:
        """Merge multiple capabilities into a single capabilities dict."""
        result: Dict[str, Dict[str, Any]] = {}
        for cap in capabilities:
            if cap.tool in result:
                # Merge constraints for same tool
                result[cap.tool].update(cap.constraints)
            else:
                result[cap.tool] = dict(cap.constraints)
        return result


# =============================================================================
# Constraints Helper Class
# =============================================================================


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

    def add(self, field: str, constraint: "Constraint") -> "Constraints":
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



# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Security constraints (from Rust)
    "Subpath",
    "UrlSafe",
    "Shlex",
    # Helper functions
    "ensure_constraint",
    "path_glob",
    # Capability API
    "Capability",
    "Constraints",
]
