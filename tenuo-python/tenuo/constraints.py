"""
Universal security constraints for Tenuo.

These are security primitives that apply across all integrations:
- OpenAI, Anthropic, LangChain, or raw Python scripts.

Usage:
    # Direct import (recommended for non-adapter code)
    from tenuo.constraints import Subpath, UrlSafe

    # Or via adapter (convenience for adapter users)
    from tenuo.openai import Subpath, UrlSafe
"""

from typing import Dict, Any, TYPE_CHECKING, List, Optional
import os
import logging
import ipaddress as _ipaddress

if TYPE_CHECKING:
    from tenuo_core import Constraint  # type: ignore

logger = logging.getLogger("tenuo.constraints")


# =============================================================================
# Subpath Constraint (secure path containment)
# =============================================================================


class Subpath:
    """Secure path containment constraint.

    Validates that a path is safely contained within a root directory,
    preventing path traversal attacks. Inspired by path_jail.

    Security features:
        - Normalizes `.` and `..` components
        - Rejects null bytes (C string terminator attack)
        - Requires absolute paths
        - Optionally case-normalizes (Windows compatibility)
        - Does NOT follow symlinks (prevents symlink escapes)

    Usage:
        from tenuo.constraints import Subpath

        constraint = Subpath("/data")
        constraint.matches("/data/file.txt")      # True
        constraint.matches("/data/../etc/passwd") # False (normalized to /etc/passwd)
        constraint.matches("/etc/passwd")         # False (not under /data)

    Warning:
        This constraint does NOT resolve symlinks during matching.
        For symlink-aware validation, perform symlink resolution
        BEFORE Tenuo validation, or in your tool implementation.

        The reason for this design: symlink resolution requires
        filesystem access, which may not be available at validation
        time (e.g., distributed systems where the file is on a
        different machine).

    Defense in Depth:
        For maximum security, combine Subpath with path_jail at execution time:

        - Subpath (Tenuo): Validates path strings stateless, works in distributed
          systems, blocks obvious traversals like /data/../etc/passwd

        - path_jail: Executes file I/O safely, resolves symlinks via realpath(),
          uses O_NOFOLLOW for TOCTOU protection against symlink swap attacks

        See: https://github.com/tenuo-ai/path_jail
    """

    def __init__(
        self,
        root: str,
        *,
        case_sensitive: bool = True,
        allow_equal: bool = True,
    ):
        """Initialize the Subpath constraint.

        Args:
            root: The root directory path (must be absolute).
            case_sensitive: If False, normalize case before comparison.
                            Default True. Set to False for Windows paths.
            allow_equal: If True, path == root is allowed.
                         If False, path must be strictly under root.
        """
        # Validate root is absolute
        # Accept both OS-native absolute paths AND Unix-style paths (for cross-platform tools)
        is_absolute = os.path.isabs(root) or root.startswith("/")
        if not is_absolute:
            raise ValueError(f"Subpath root must be absolute: {root}")

        # Normalize root (resolve . and ..)
        self._root_raw = root
        normalized = os.path.normpath(root)

        # Case normalization
        self._case_sensitive = case_sensitive
        if not case_sensitive:
            normalized = normalized.lower()

        self._root = normalized
        self._allow_equal = allow_equal

    def matches(self, value: Any) -> bool:
        """Check if value is safely contained within root.

        Returns True if the path, after normalization, is under root.
        Returns False for any security violation or malformed path.
        """
        if not isinstance(value, str):
            return False

        # Reject null bytes immediately (C string terminator attack)
        if '\x00' in value:
            logger.debug(f"Subpath rejected null bytes: {value!r}")
            return False

        # Require absolute paths (accept Unix-style on all platforms)
        is_absolute = os.path.isabs(value) or value.startswith("/")
        if not is_absolute:
            logger.debug(f"Subpath rejected relative path: {value}")
            return False

        # Normalize the path (resolve . and ..)
        normalized = os.path.normpath(value)

        # Case normalization
        if not self._case_sensitive:
            normalized = normalized.lower()

        # Check containment
        # For cross-platform compatibility, check both / and os.sep separators
        # This handles Unix-style paths on Windows
        root_with_sep = self._root + os.sep
        root_with_slash = self._root + "/"

        if self._allow_equal and normalized == self._root:
            return True

        if normalized.startswith(root_with_sep) or normalized.startswith(root_with_slash):
            return True

        logger.debug(
            f"Subpath rejected: {value} -> {normalized} not under {self._root}"
        )
        return False

    def __repr__(self) -> str:
        opts = []
        if not self._case_sensitive:
            opts.append("case_sensitive=False")
        if not self._allow_equal:
            opts.append("allow_equal=False")
        opts_str = f", {', '.join(opts)}" if opts else ""
        return f"Subpath({self._root_raw!r}{opts_str})"

    def __str__(self) -> str:
        return repr(self)


# =============================================================================
# UrlSafe Constraint (SSRF protection)
# =============================================================================

# Cloud metadata endpoints (expand as needed)
_METADATA_HOSTS = {
    "169.254.169.254",           # AWS, Azure, DigitalOcean, etc.
    "metadata.google.internal",   # GCP
    "metadata.goog",              # GCP alternate
    "100.100.100.200",           # Alibaba Cloud
}

# Internal TLDs that may indicate private infrastructure
_INTERNAL_TLDS = {".internal", ".local", ".localhost", ".lan", ".corp", ".home"}

# Private/reserved IP ranges
_PRIVATE_NETWORKS = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("fc00::/7"),        # IPv6 private
    _ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
]

_LOOPBACK_NETWORKS = [
    _ipaddress.ip_network("127.0.0.0/8"),
    _ipaddress.ip_network("::1/128"),
]

# Special/reserved ranges that should never be fetched
_RESERVED_NETWORKS = [
    _ipaddress.ip_network("0.0.0.0/8"),       # "This" network
    _ipaddress.ip_network("169.254.0.0/16"),  # Link-local (includes metadata)
    _ipaddress.ip_network("224.0.0.0/4"),     # Multicast
    _ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
]


class UrlSafe:
    """SSRF-safe URL constraint.

    Validates URLs to prevent Server-Side Request Forgery attacks.
    Blocks private IPs, cloud metadata endpoints, dangerous schemes,
    and other common SSRF vectors.

    Security features:
        - Blocks private IP ranges (RFC1918)
        - Blocks loopback (127.x, ::1, localhost)
        - Blocks cloud metadata endpoints (169.254.169.254, etc.)
        - Blocks dangerous schemes (file://, gopher://, etc.)
        - Normalizes IP representations (decimal, octal, hex, IPv6-mapped)
        - Decodes URL-encoded hostnames to prevent bypass
        - Optional domain allowlist for maximum restriction

    Usage:
        from tenuo.constraints import UrlSafe

        # Secure defaults - blocks known SSRF vectors
        constraint = UrlSafe()
        constraint.matches("https://api.github.com/repos")  # True
        constraint.matches("http://169.254.169.254/")       # False (metadata)
        constraint.matches("http://127.0.0.1/")             # False (loopback)

        # Domain allowlist - only specific domains allowed
        constraint = UrlSafe(allow_domains=["api.github.com", "*.googleapis.com"])

    Warning:
        This constraint does NOT perform DNS resolution.
        An attacker-controlled domain could resolve to an internal IP
        (DNS rebinding). For complete SSRF protection, use url_jail
        at execution time which pins DNS resolution.

        String-based validation catches obvious attacks; DNS-aware
        validation catches sophisticated attacks.

    Defense in Depth:
        For maximum security, combine UrlSafe with url_jail:

        - UrlSafe (Tenuo): Validates URL strings stateless, catches
          obvious SSRF like http://169.254.169.254/, works in
          distributed systems

        - url_jail: Performs actual fetch safely, resolves DNS with
          pinning, follows redirects safely, enforces timeouts

        See: https://github.com/tenuo-ai/url_jail
    """

    def __init__(
        self,
        *,
        allow_schemes: Optional[List[str]] = None,
        allow_domains: Optional[List[str]] = None,
        allow_ports: Optional[List[int]] = None,
        block_private: bool = True,
        block_loopback: bool = True,
        block_metadata: bool = True,
        block_reserved: bool = True,
        block_internal_tlds: bool = False,
    ):
        """Initialize the UrlSafe constraint.

        Args:
            allow_schemes: Allowed URL schemes. Default: ["http", "https"]
            allow_domains: If set, only these domains are allowed (supports *.example.com)
            allow_ports: If set, only these ports are allowed
            block_private: Block RFC1918 private IPs (10.x, 172.16.x, 192.168.x)
            block_loopback: Block loopback (127.x, ::1, localhost)
            block_metadata: Block cloud metadata endpoints (169.254.169.254, etc.)
            block_reserved: Block reserved IP ranges (multicast, broadcast, etc.)
            block_internal_tlds: Block internal TLDs (.internal, .local, .localhost)
        """
        self._allow_schemes = allow_schemes or ["http", "https"]
        self._allow_domains = allow_domains
        self._allow_ports = allow_ports
        self._block_private = block_private
        self._block_loopback = block_loopback
        self._block_metadata = block_metadata
        self._block_reserved = block_reserved
        self._block_internal_tlds = block_internal_tlds

    def matches(self, value: Any) -> bool:
        """Check if URL is safe to fetch.

        Returns True if the URL passes all SSRF checks.
        Returns False for any security violation or malformed URL.
        """
        from urllib.parse import urlparse, unquote

        if not isinstance(value, str):
            return False

        # Reject null bytes
        if '\x00' in value:
            logger.debug(f"UrlSafe rejected null bytes: {value!r}")
            return False

        # Parse URL
        try:
            parsed = urlparse(value)
        except Exception:
            logger.debug(f"UrlSafe rejected unparseable URL: {value}")
            return False

        # Check scheme
        scheme = parsed.scheme.lower()
        if scheme not in [s.lower() for s in self._allow_schemes]:
            logger.debug(f"UrlSafe rejected scheme '{scheme}': {value}")
            return False

        # Extract host
        host = parsed.hostname
        if not host:
            logger.debug(f"UrlSafe rejected missing host: {value}")
            return False

        # SECURITY: Decode percent-encoded hostname to prevent SSRF bypass.
        # Python's urlparse does NOT decode hostnames, so an attacker could use
        # http://%31%32%37%2e%30%2e%30%2e%31/ to bypass IP blocking (decodes to 127.0.0.1).
        host = unquote(host).lower()

        # Check port
        port = parsed.port
        if self._allow_ports is not None and port is not None:
            if port not in self._allow_ports:
                logger.debug(f"UrlSafe rejected port {port}: {value}")
                return False

        # Check for localhost names
        if self._block_loopback:
            if host in ("localhost", "localhost.localdomain"):
                logger.debug(f"UrlSafe rejected localhost: {value}")
                return False

        # Check internal TLDs
        if self._block_internal_tlds:
            for tld in _INTERNAL_TLDS:
                if host.endswith(tld) or host == tld[1:]:  # .internal or internal
                    logger.debug(f"UrlSafe rejected internal TLD: {value}")
                    return False

        # Check metadata hosts
        if self._block_metadata:
            if host in _METADATA_HOSTS:
                logger.debug(f"UrlSafe rejected metadata host: {value}")
                return False

        # Try to parse as IP address
        ip = self._parse_ip(host)
        if ip is not None:
            # It's an IP address - check against blocked ranges
            if not self._check_ip_safe(ip):
                return False
        else:
            # It's a hostname - check domain allowlist
            if self._allow_domains is not None:
                if not self._check_domain_allowed(host):
                    logger.debug(f"UrlSafe rejected domain not in allowlist: {host}")
                    return False

        return True

    def _parse_ip(self, host: str) -> Optional[Any]:
        """Parse host as IP address, handling various representations."""
        import re as _re

        # Strip brackets from IPv6
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]

        # Try standard parsing first
        try:
            return _ipaddress.ip_address(host)
        except ValueError:
            pass

        # Try decimal notation (e.g., 2130706433 = 127.0.0.1)
        if host.isdigit():
            try:
                int_val = int(host)
                if 0 <= int_val <= 0xFFFFFFFF:
                    return _ipaddress.IPv4Address(int_val)
            except (ValueError, OverflowError):
                pass

        # Try hex notation (e.g., 0x7f000001 = 127.0.0.1)
        if host.lower().startswith('0x'):
            try:
                int_val = int(host, 16)
                if 0 <= int_val <= 0xFFFFFFFF:
                    return _ipaddress.IPv4Address(int_val)
            except (ValueError, OverflowError):
                pass

        # Try octal notation (e.g., 0177.0.0.1 = 127.0.0.1)
        if _re.match(r'^0[0-7]+\.', host):
            try:
                parts = host.split('.')
                if len(parts) == 4:
                    octets = []
                    for p in parts:
                        if p.startswith('0') and len(p) > 1:
                            octets.append(int(p, 8))
                        else:
                            octets.append(int(p))
                    if all(0 <= o <= 255 for o in octets):
                        return _ipaddress.IPv4Address('.'.join(str(o) for o in octets))
            except (ValueError, OverflowError):
                pass

        return None

    def _check_ip_safe(self, ip: Any) -> bool:
        """Check if IP address is safe to connect to."""
        # Handle IPv6-mapped IPv4 addresses
        if hasattr(ip, 'ipv4_mapped') and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        # Check loopback
        if self._block_loopback:
            for net in _LOOPBACK_NETWORKS:
                if ip in net:
                    logger.debug(f"UrlSafe rejected loopback IP: {ip}")
                    return False

        # Check private ranges
        if self._block_private:
            for net in _PRIVATE_NETWORKS:
                if ip in net:
                    logger.debug(f"UrlSafe rejected private IP: {ip}")
                    return False

        # Check reserved ranges
        if self._block_reserved:
            for net in _RESERVED_NETWORKS:
                if ip in net:
                    logger.debug(f"UrlSafe rejected reserved IP: {ip}")
                    return False

        # Check metadata range (link-local includes 169.254.x.x)
        if self._block_metadata:
            try:
                if ip in _ipaddress.ip_network("169.254.0.0/16"):
                    logger.debug(f"UrlSafe rejected metadata IP: {ip}")
                    return False
            except TypeError:
                pass  # IPv6 address won't match IPv4 network

        return True

    def _check_domain_allowed(self, host: str) -> bool:
        """Check if hostname matches domain allowlist."""
        import fnmatch as _fnmatch

        for pattern in self._allow_domains:  # type: ignore
            pattern = pattern.lower()
            if pattern.startswith("*."):
                # Wildcard subdomain: *.example.com matches sub.example.com
                suffix = pattern[1:]  # .example.com
                if host.endswith(suffix) or host == pattern[2:]:
                    return True
            else:
                # Exact match or glob
                if _fnmatch.fnmatch(host, pattern):
                    return True

        return False

    def __repr__(self) -> str:
        opts = []
        if self._allow_schemes != ["http", "https"]:
            opts.append(f"allow_schemes={self._allow_schemes!r}")
        if self._allow_domains is not None:
            opts.append(f"allow_domains={self._allow_domains!r}")
        if self._allow_ports is not None:
            opts.append(f"allow_ports={self._allow_ports!r}")
        if not self._block_private:
            opts.append("block_private=False")
        if not self._block_loopback:
            opts.append("block_loopback=False")
        if not self._block_metadata:
            opts.append("block_metadata=False")
        if not self._block_reserved:
            opts.append("block_reserved=False")
        if self._block_internal_tlds:
            opts.append("block_internal_tlds=True")

        opts_str = ", ".join(opts)
        return f"UrlSafe({opts_str})" if opts else "UrlSafe()"

    def __str__(self) -> str:
        return repr(self)


# =============================================================================
# Original constraints.py content
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
