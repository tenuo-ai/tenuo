"""
Universal security constraints for Tenuo.

These are security primitives that apply across all integrations:
- OpenAI, Anthropic, LangChain, or raw Python scripts.

Architecture:
    The constraint LOGIC is implemented in Rust (tenuo-core) for:
    - Cross-language consistency (Go, Node, Python all validate identically)
    - Performance (IP parsing, URL normalization)
    - Serializable constraints that can be embedded in Warrants

    Python provides the CONTEXT-GATHERING layer:
    - Symlink resolution before calling Subpath (optional)
    - DNS pinning before calling UrlSafe (optional)

    This separation follows "Logic vs I/O":
    - Rust: Pure, deterministic, stateless validation
    - Python: Environment-dependent I/O and policy decisions

Usage:
    # Direct import (recommended)
    from tenuo.constraints import Subpath, UrlSafe

    # Or via main package
    from tenuo import Subpath, UrlSafe

    # Or via adapter (convenience for adapter users)
    from tenuo.openai import Subpath, UrlSafe

Example:
    from tenuo.constraints import Subpath, UrlSafe

    # Path containment (blocks traversal attacks)
    path_constraint = Subpath("/data")
    path_constraint.contains("/data/file.txt")      # True
    path_constraint.contains("/data/../etc/passwd") # False

    # SSRF protection (blocks internal IPs, metadata endpoints)
    url_constraint = UrlSafe()
    url_constraint.is_safe("https://api.github.com/")  # True
    url_constraint.is_safe("http://169.254.169.254/")  # False
"""

import logging
import posixpath
import shlex
from typing import Dict, Any, TYPE_CHECKING, List, Set

logger = logging.getLogger("tenuo.constraints")

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


# =============================================================================
# Helper Functions
# =============================================================================


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
# Shlex Constraint (Python-only, Tier 1)
# =============================================================================


class Shlex:
    """Validates that a shell command string is safe and simple.

    Ensures the command is a single executable with literal arguments,
    preventing shell injection (pipes, chaining, subshells, variable expansion).

    Security features:
        - Blocks shell operators: | || & && ; > >> < <<
        - Blocks command substitution: $() and backticks
        - Blocks variable expansion: $VAR, ${VAR}
        - Blocks newline/null byte injection
        - Requires explicit binary allowlist

    Usage:
        from tenuo.openai import Shlex, guard

        client = guard(
            openai.OpenAI(),
            constraints={
                "run_command": {"cmd": Shlex(allow=["ls", "cat", "grep"])}
            }
        )

        # Allowed:   ls -la /tmp
        # Blocked:   ls -la; rm -rf /    (operator)
        # Blocked:   echo $(whoami)      (command substitution)
        # Blocked:   ls $HOME            (variable expansion)

    Warning:
        This constraint validates SHELL SYNTAX, not TOOL SEMANTICS.
        Some tools interpret arguments as commands:

            git --upload-pack='malicious'
            find -exec rm {} \\;
            tar --checkpoint-action=exec=cmd

        For complete protection, use proc_jail which bypasses the shell
        entirely via execve() and validates arguments per-tool.

    Limitations:
        - Parser differential: Python's shlex targets POSIX sh. If the
          system shell is zsh/fish/etc, parsing may differ slightly.
        - Does not resolve symlinks or validate binary paths exist.
        - Does not constrain arguments (only the binary is allowlisted).

        This is Tier 1 mitigation. Upgrade to proc_jail for Tier 2.
    """

    # Operators that combine commands or redirect I/O
    # These are checked as TOKENS after punctuation_chars parsing
    DANGEROUS_TOKENS: Set[str] = {
        "|",
        "||",  # Pipes
        "&",
        "&&",  # Background / logical AND
        ";",  # Command separator
        ">",
        ">>",  # Output redirection
        "<",
        "<<",
        "<<<",  # Input redirection
        "(",
        ")",  # Subshells
    }

    # Characters that trigger shell expansion (checked in raw string)
    # These are dangerous even inside double quotes ("$VAR" expands)
    EXPANSION_CHARS: Set[str] = {"$", "`"}

    # Control characters that could inject commands or cause parsing issues
    # Blocked: null, newlines, carriage returns, vertical tab, form feed, bell, backspace, DEL
    # Allowed: tab (valid whitespace), ANSI escape (not injection vector)
    CONTROL_CHARS: Set[str] = {
        "\x00",  # Null - string terminator in C, security risk
        "\n",    # Newline - command separator in shell
        "\r",    # Carriage return - newline variant
        "\x0b",  # Vertical tab - shlex parsing issues
        "\x0c",  # Form feed - shlex parsing issues
        "\x07",  # Bell - parsing anomalies
        "\x08",  # Backspace - terminal manipulation
        "\x7f",  # DEL - terminal manipulation
    }

    # Glob characters (optional blocking)
    GLOB_CHARS: Set[str] = {"*", "?", "["}

    def __init__(
        self,
        allow: List[str],
        *,
        block_globs: bool = False,
    ):
        """Initialize the Shlex constraint.

        Args:
            allow: List of allowed binary names or full paths.
                   e.g., ["ls", "/usr/bin/git"]
            block_globs: If True, reject glob characters (*, ?, [).
                         Default False since globs are often legitimate.

        Raises:
            ValueError: If allow list is empty.
        """
        if not allow:
            raise ValueError("Shlex requires at least one allowed binary")

        self.allowed_bins: Set[str] = set(allow)
        self.block_globs = block_globs

    def matches(self, value: Any) -> bool:
        """Check if command string is safe to execute.

        Uses "high-definition" parsing with shlex.shlex(punctuation_chars=True)
        which correctly splits operators like ; | & into separate tokens
        UNLESS they are inside quotes.

        Returns True only if:
        - Input is a string
        - No dangerous expansion characters ($, `)
        - No control characters (newlines, null bytes)
        - Parses successfully with shlex
        - First token is in allowlist
        - No shell operator tokens (outside quotes)
        """
        # R1: Type check
        if not isinstance(value, str):
            return False

        # R1: Control character check (before parsing)
        for char in self.CONTROL_CHARS:
            if char in value:
                logger.debug(f"Shlex rejected control char {char!r} in: {value!r}")
                return False

        # R1: Expansion character check (before parsing)
        # Shell expands $VAR and `cmd` even inside double quotes
        for char in self.EXPANSION_CHARS:
            if char in value:
                logger.debug(f"Shlex rejected expansion char '{char}' in: {value!r}")
                return False

        # R6: Optional glob check
        if self.block_globs:
            for char in self.GLOB_CHARS:
                if char in value:
                    logger.debug(f"Shlex rejected glob char '{char}' in: {value!r}")
                    return False

        # R2: "High-definition" parsing with punctuation_chars
        # This splits unquoted operators into separate tokens:
        #   "ls -la; rm" -> ['ls', '-la', ';', 'rm']  (';' detected!)
        # But keeps quoted operators as part of the token:
        #   'ls "foo; bar"' -> ['ls', 'foo; bar']    (safe)
        try:
            lex = shlex.shlex(value, posix=True, punctuation_chars=True)
            tokens = list(lex)
        except ValueError as e:
            # Unbalanced quotes, malformed escapes, etc.
            logger.debug(f"Shlex parse error: {e} in: {value!r}")
            return False

        # R5: Empty command check
        if not tokens:
            return False

        # R4: Binary allowlist check
        binary = tokens[0]

        # Normalize path if absolute/relative (prevents /usr/../bin tricks)
        # Use posixpath for Unix-style paths (shell commands) even on Windows
        if "/" in binary:
            binary = posixpath.normpath(binary)

        bin_name = posixpath.basename(binary)

        if binary not in self.allowed_bins and bin_name not in self.allowed_bins:
            logger.debug(f"Shlex rejected binary '{binary}' not in allowlist: {self.allowed_bins}")
            return False

        # R3: Dangerous token check
        # Because we used punctuation_chars=True, any unquoted operator
        # is guaranteed to be its own token.
        for token in tokens:
            if token in self.DANGEROUS_TOKENS:
                logger.debug(f"Shlex rejected operator token '{token}' in: {value!r}")
                return False

        return True

    def __repr__(self) -> str:
        opts = []
        if self.block_globs:
            opts.append("block_globs=True")
        opts_str = f", {', '.join(opts)}" if opts else ""
        return f"Shlex(allow={sorted(self.allowed_bins)!r}{opts_str})"


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Security constraints (from Rust)
    "Subpath",
    "UrlSafe",
    # Security constraints (Python)
    "Shlex",
    # Helper functions
    "ensure_constraint",
    # Capability API
    "Capability",
    "Constraints",
]
