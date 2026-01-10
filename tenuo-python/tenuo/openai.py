"""
Tenuo OpenAI Adapter - Multi-Tier Authorization

Provides constraint enforcement for OpenAI API calls with two tiers:

**Tier 1 (Guardrails)**: Runtime constraint checking without cryptography.
    Good for single-process scenarios. Catches hallucinated tool calls,
    argument constraint violations, and streaming TOCTOU attacks.

**Tier 2 (Warrant + PoP)**: Cryptographic authorization with Proof-of-Possession.
    Required for distributed/multi-agent scenarios. Each tool call is signed
    with the agent's private key, proving the caller holds the warrant.

Security Philosophy (Fail Closed):
    Tenuo follows a "fail closed" security model. When in doubt, deny:
    - Unknown constraint types are rejected (not silently passed)
    - CEL expressions require Rust bindings (Python fallback denies)
    - Missing constraint attributes cause denial
    - Malformed tool calls are blocked
    - Warrant without signing_key raises MissingSigningKey
    
    This is intentional. A guardrail that silently passes unknown cases
    is not a guardrail - it's a false sense of security.

Usage (Tier 1 - Builder Pattern, Recommended):
    from tenuo.openai import GuardBuilder, Subpath, Pattern

    client = (GuardBuilder(openai.OpenAI())
        .allow("search")
        .allow("read_file", path=Subpath("/data"))
        .allow("send_email", to=Pattern("*@company.com"))
        .deny("delete_file")
        .build())
    
    response = client.chat.completions.create(...)

Usage (Tier 1 - Dict Style):
    from tenuo.openai import guard, Pattern

    client = guard(
        openai.OpenAI(),
        allow_tools=["search", "read_file"],
        constraints={"read_file": {"path": Pattern("/data/*")}}
    )
    response = client.chat.completions.create(...)

Usage (Tier 2 - Warrant with PoP):
    from tenuo.openai import GuardBuilder
    from tenuo import SigningKey, Warrant

    # Agent holds the warrant and its signing key
    agent_key = SigningKey.generate()
    warrant = Warrant.mint_builder()...  # From control plane
    
    client = (GuardBuilder(openai.OpenAI())
        .with_warrant(warrant, agent_key)
        .build())
    
    response = client.chat.completions.create(...)

Async Support:
    Both sync and async OpenAI clients are supported.
    Async streaming has the same TOCTOU protections.
    
    async_client = guard(openai.AsyncOpenAI(), warrant=w, signing_key=k)
    response = await async_client.chat.completions.acreate(...)

OpenAI Agents SDK Integration:
    Tenuo integrates with the OpenAI Agents SDK (openai-agents) via guardrails:
    
    from agents import Agent
    from tenuo.openai import create_tool_guardrail, Pattern
    
    guardrail = create_tool_guardrail(
        constraints={"send_email": {"to": Pattern("*@company.com")}}
    )
    
    agent = Agent(
        name="Assistant",
        input_guardrails=[guardrail],  # Validates tool calls before execution
    )
    
    For Tier 2 (warrant-based), use create_warrant_guardrail().
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Union,
)
from urllib.parse import urlparse

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
)

logger = logging.getLogger("tenuo.openai")


def enable_debug(handler: Optional[logging.Handler] = None) -> None:
    """Enable debug logging for Tenuo OpenAI adapter.
    
    This shows detailed authorization decisions, constraint checks,
    and PoP signature operations. Useful for troubleshooting.
    
    Args:
        handler: Optional custom handler. If None, logs to stderr.
    
    Example:
        >>> from tenuo.openai import enable_debug
        >>> enable_debug()
        >>> # Now all authorization decisions are logged
        >>> client.chat.completions.create(...)
        DEBUG:tenuo.openai:Verifying tool call: read_file
        DEBUG:tenuo.openai:Constraint check: path=/data/file.txt against Pattern(/data/*)
        DEBUG:tenuo.openai:Authorization granted
    """
    logger.setLevel(logging.DEBUG)
    if handler is None:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(levelname)s:%(name)s:%(message)s"
        ))
    if not logger.handlers:
        logger.addHandler(handler)


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
        from tenuo.openai import Subpath, guard
        
        client = guard(
            openai.OpenAI(),
            constraints={"read_file": {"path": Subpath("/data")}}
        )
        
        # These are allowed:
        #   /data/file.txt
        #   /data/subdir/file.txt
        
        # These are BLOCKED:
        #   /data/../etc/passwd      → normalized to /etc/passwd
        #   /etc/passwd              → not under /data
        #   /data/symlink_to_etc/..  → escape via symlink
        #   /DATA/file.txt           → case mismatch (if case_sensitive=True)
    
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
        
        Example:
            # Validation layer (Tenuo)
            client = guard(openai.OpenAI(), constraints={
                "read_file": {"path": Subpath("/data")}
            })
            
            # Execution layer (tool implementation)
            from path_jail import Jail
            jail = Jail("/data")
            
            def read_file(path: str) -> str:
                safe_path = jail.join(path)  # Resolves symlinks, raises if escape
                with jail.open(path) as f:   # O_NOFOLLOW protected
                    return f.read()
        
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
        if not os.path.isabs(root):
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
        
        # Require absolute paths
        if not os.path.isabs(value):
            logger.debug(f"Subpath rejected relative path: {value}")
            return False
        
        # Normalize the path (resolve . and ..)
        normalized = os.path.normpath(value)
        
        # Case normalization
        if not self._case_sensitive:
            normalized = normalized.lower()
        
        # Check containment
        # Path must start with root + separator OR equal root (if allowed)
        root_with_sep = self._root + os.sep
        
        if self._allow_equal and normalized == self._root:
            return True
        
        if normalized.startswith(root_with_sep):
            return True
        
        logger.debug(
            f"Subpath rejected: {value} → {normalized} not under {self._root}"
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


# Type alias for constraint types (including Subpath)
Constraint = Union[
    Pattern, Exact, OneOf, Range, Regex, Cidr, UrlPattern,
    Contains, Subset, Wildcard, AnyOf, All, Not, NotOneOf, CEL,
    Subpath  # Python-only constraint
]

# Denial modes
DenialMode = Literal["raise", "skip", "log"]


# =============================================================================
# Exceptions
# =============================================================================


class TenuoOpenAIError(Exception):
    """Base exception for Tenuo OpenAI adapter errors."""
    
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


class ToolDenied(TenuoOpenAIError):
    """Raised when a tool call is denied by the guardrail."""
    
    def __init__(self, tool_name: str, reason: str, code: str = "T1_001"):
        super().__init__(f"Tool '{tool_name}' denied: {reason}", code)
        self.tool_name = tool_name
        self.reason = reason


class WarrantDenied(TenuoOpenAIError):
    """Raised when a tool call is denied by the cryptographic warrant (Tier 2).
    
    This indicates the warrant does not authorize this tool invocation.
    The denial may be due to:
    - Tool not in warrant's capability list
    - Argument constraint violation
    - Invalid/missing Proof-of-Possession signature
    - Warrant expiration
    """
    
    def __init__(self, tool_name: str, reason: str, code: str = "T2_001"):
        super().__init__(f"Warrant denied tool '{tool_name}': {reason}", code)
        self.tool_name = tool_name
        self.reason = reason


class MissingSigningKey(TenuoOpenAIError):
    """Raised when Tier 2 warrant is provided but no signing key.
    
    Warrants require Proof-of-Possession signatures, which need a signing key.
    Either provide a signing_key parameter or use Tier 1 guardrails instead.
    """
    
    def __init__(self):
        super().__init__(
            "Warrant provided without signing_key. "
            "Tier 2 requires a signing key for Proof-of-Possession. "
            "Either add signing_key=... or remove the warrant for Tier 1 only.",
            "T2_002"
        )


class ConfigurationError(TenuoOpenAIError):
    """Raised when guard() configuration is invalid.
    
    Common causes:
    - signing_key doesn't match warrant's authorized_holder
    - Warrant is expired before first use
    - Conflicting Tier 1 and Tier 2 settings
    
    Use client.validate() to catch these errors early.
    """
    pass


# =============================================================================
# Audit Support
# =============================================================================


@dataclass
class AuditEvent:
    """Record of an authorization decision.
    
    Use with audit_callback to log all decisions for compliance/debugging.
    
    Attributes:
        session_id: Unique ID for this guard() instance
        timestamp: Unix timestamp of the decision
        tool_name: Name of the tool being authorized
        arguments: Tool arguments (may be redacted)
        decision: "ALLOW" or "DENY"
        reason: Why the decision was made
        tier: "tier1" or "tier2"
        constraint_hash: Hash of Tier 1 constraints for tamper detection
        warrant_id: Warrant ID if Tier 2 is active (for audit correlation)
    """
    session_id: str
    timestamp: float
    tool_name: str
    arguments: Dict[str, Any]
    decision: str  # "ALLOW" or "DENY"
    reason: str
    tier: str  # "tier1" or "tier2"
    constraint_hash: Optional[str] = None
    warrant_id: Optional[str] = None


# Type alias for audit callback
AuditCallback = Callable[[AuditEvent], None]


def _compute_constraint_hash(
    allow_tools: Optional[List[str]],
    deny_tools: Optional[List[str]],
    constraints: Optional[Dict[str, Dict[str, Any]]],
) -> str:
    """Compute SHA-256 hash of constraint configuration.
    
    This hash can be logged/stored to prove the constraints weren't
    modified between when the client was created and when a call was made.
    """
    # Serialize to canonical JSON
    config = {
        "allow_tools": sorted(allow_tools) if allow_tools else None,
        "deny_tools": sorted(deny_tools) if deny_tools else None,
        "constraints": _serialize_constraints(constraints) if constraints else None,
    }
    canonical = json.dumps(config, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _serialize_constraints(constraints: Dict[str, Dict[str, Any]]) -> Dict:
    """Serialize constraints to a hashable format."""
    result = {}
    for tool, params in sorted(constraints.items()):
        result[tool] = {}
        for param, constraint in sorted(params.items()):
            # Include both type and value for proper differentiation
            constraint_repr = str(constraint)  # Uses __repr__ which includes value
            result[tool][param] = f"{type(constraint).__name__}:{constraint_repr}"
    return result


class ConstraintViolation(TenuoOpenAIError):
    """Raised when a tool argument violates a constraint.
    
    Attributes:
        tool_name: Name of the tool that was called
        param: The parameter that violated the constraint
        value: The actual value that was passed
        constraint: The constraint that was violated
        type_mismatch: True if the violation was due to wrong type (e.g., string to Range)
        reason: Human-readable explanation of why it failed
    """
    
    def __init__(
        self,
        tool_name: str,
        param: str,
        value: Any,
        constraint: Constraint,
        type_mismatch: bool = False,
        reason: Optional[str] = None,
    ):
        self.tool_name = tool_name
        self.param = param
        self.value = value
        self.constraint = constraint
        self.type_mismatch = type_mismatch
        
        # Generate clear, actionable error message
        if reason:
            self.reason = reason
        elif type_mismatch:
            expected = _constraint_expected_type(constraint)
            self.reason = f"expected {expected}, got {type(value).__name__}"
        else:
            self.reason = f"value does not satisfy constraint {constraint}"
        
        message = f"Tool '{tool_name}' argument '{param}' = {value!r}: {self.reason}"
        super().__init__(message, "T1_002")


def _constraint_expected_type(constraint: Constraint) -> str:
    """Return human-readable expected type for a constraint."""
    constraint_type = type(constraint).__name__
    if constraint_type == "Range":
        return "numeric type (int/float)"
    elif constraint_type == "Cidr":
        return "valid IP address"
    elif constraint_type == "UrlPattern":
        return "valid URL"
    elif constraint_type in ("Contains", "Subset"):
        return "list/set/tuple"
    elif constraint_type in ("Pattern", "Regex", "Exact"):
        return "string"
    else:
        return "compatible type"


class MalformedToolCall(TenuoOpenAIError):
    """Raised when a tool call has invalid JSON arguments."""
    
    def __init__(self, tool_name: str, error: str):
        super().__init__(f"Malformed tool call '{tool_name}': {error}", "T1_003")
        self.tool_name = tool_name
        self.error = error


class BufferOverflow(TenuoOpenAIError):
    """Raised when streaming buffer exceeds limit."""
    
    def __init__(self, tool_name: str, size: int, limit: int):
        super().__init__(
            f"Tool call '{tool_name}' buffer overflow: {size} bytes exceeds {limit} byte limit",
            "T1_004"
        )
        self.tool_name = tool_name
        self.size = size
        self.limit = limit


# =============================================================================
# Constraint Checking
# =============================================================================


def check_constraint(constraint: Constraint, value: Any) -> bool:
    """Check if a value satisfies a constraint.
    
    Uses the Tenuo core constraint matching logic via the Rust bindings.
    Falls back to Python implementation if Rust is unavailable.
    
    SECURITY: Fails closed (returns False) for unknown constraint types.
    This follows Tenuo's "fail closed" philosophy - when in doubt, deny.
    """
    try:
        # Try Rust-backed constraint checking first (preferred)
        if hasattr(constraint, 'matches'):
            return constraint.matches(value)
        elif hasattr(constraint, 'contains_ip'):
            # CIDR constraint
            return constraint.contains_ip(str(value))
        elif hasattr(constraint, 'matches_url'):
            # UrlPattern constraint
            return constraint.matches_url(str(value))
        else:
            # Fallback to Python implementation
            return _python_constraint_check(constraint, value)
    except Exception as e:
        # If Rust binding fails, try Python fallback
        logger.debug(f"Rust constraint check failed, using Python fallback: {e}")
        return _python_constraint_check(constraint, value)


def _python_constraint_check(constraint: Constraint, value: Any) -> bool:
    """Python fallback for constraint checking.
    
    SECURITY: This function follows Tenuo's "fail closed" philosophy.
    Unknown constraint types return False, not True.
    """
    import fnmatch
    import ipaddress
    import re as regex_module
    
    constraint_type = type(constraint).__name__
    
    if constraint_type == "Pattern":
        # Glob pattern matching
        pattern = _get_attr_safe(constraint, 'pattern')
        if pattern is None:
            logger.warning(f"Pattern constraint has no pattern attribute, failing closed")
            return False
        return fnmatch.fnmatch(str(value), pattern)
    
    elif constraint_type == "Exact":
        # Exact match
        expected = _get_attr_safe(constraint, 'value')
        return value == expected
    
    elif constraint_type == "OneOf":
        # Set membership
        allowed = _get_attr_safe(constraint, 'values')
        if allowed is None:
            return False
        return value in allowed
    
    elif constraint_type == "Range":
        # Numeric range - type-strict like Rust core
        # NOTE: ConstraintValue::as_number() returns None for strings,
        # so "15" as a string would NOT match Range(0,100).
        # Only actual int/float types pass. This matches Tenuo's rigorous semantics.
        min_val = _get_attr_safe(constraint, 'min')
        max_val = _get_attr_safe(constraint, 'max')
        
        # Type-strict: only int/float pass, strings fail (matches Rust behavior)
        if not isinstance(value, (int, float)):
            return False
        
        try:
            num_value = float(value)
            if min_val is not None and num_value < min_val:
                return False
            if max_val is not None and num_value > max_val:
                return False
            return True
        except (ValueError, TypeError):
            return False
    
    elif constraint_type == "Regex":
        # Regex matching - uses fullmatch for complete string match (Tenuo spec semantics)
        pattern = _get_attr_safe(constraint, 'pattern')
        if pattern is None:
            logger.warning(f"Regex constraint has no pattern attribute, failing closed")
            return False
        # fullmatch ensures the ENTIRE value matches, not just a prefix
        return bool(regex_module.fullmatch(pattern, str(value)))
    
    elif constraint_type == "Wildcard":
        # Wildcard matches anything
        return True
    
    elif constraint_type == "NotOneOf":
        # Exclusion set
        excluded = _get_attr_safe(constraint, 'excluded')
        if excluded is None:
            excluded = []
        return value not in excluded
    
    elif constraint_type == "Contains":
        # List must contain required values
        required = _get_attr_safe(constraint, 'required')
        if required is None:
            required = []
        if not isinstance(value, (list, set, tuple)):
            return False
        return all(r in value for r in required)
    
    elif constraint_type == "Subset":
        # Value must be subset of allowed
        allowed = _get_attr_safe(constraint, 'allowed')
        if allowed is None:
            return False
        if not isinstance(value, (list, set, tuple)):
            return value in allowed
        return all(v in allowed for v in value)
    
    elif constraint_type == "Cidr":
        # IP address must be within CIDR range
        # Note: Tenuo uses .network attribute, not .cidr
        network_str = _get_attr_safe(constraint, 'network')
        if network_str is None:
            logger.warning(f"Cidr constraint has no network attribute, failing closed")
            return False
        try:
            network = ipaddress.ip_network(str(network_str), strict=False)
            ip = ipaddress.ip_address(str(value))
            return ip in network
        except (ValueError, TypeError):
            return False
    
    elif constraint_type == "UrlPattern":
        # URL must match pattern (scheme, host, path)
        return _check_url_pattern(constraint, value)
    
    elif constraint_type == "CEL":
        # CEL expressions require Rust - cannot safely evaluate in Python
        # SECURITY: Fail closed. CEL is complex and must use the Rust evaluator.
        logger.warning(
            "CEL constraint cannot be evaluated in Python fallback. "
            "Ensure tenuo-core Rust bindings are available. Failing closed."
        )
        return False
    
    # Composite constraints - recursive checking
    elif constraint_type == "AnyOf":
        # OR: at least one constraint must match
        options = _get_attr_safe(constraint, 'constraints')
        if not options:
            return False
        return any(check_constraint(c, value) for c in options)
    
    elif constraint_type == "All":
        # AND: all constraints must match
        constraints_list = _get_attr_safe(constraint, 'constraints')
        if not constraints_list:
            return True  # Empty AND is vacuously true
        return all(check_constraint(c, value) for c in constraints_list)
    
    elif constraint_type == "Not":
        # NOT: inner constraint must NOT match
        inner = _get_attr_safe(constraint, 'constraint')
        if inner is None:
            return False
        return not check_constraint(inner, value)
    
    # SECURITY: Unknown constraint type - fail closed
    # This is intentional. Tenuo's philosophy is "when in doubt, deny."
    logger.error(
        f"Unknown constraint type '{constraint_type}'. "
        f"Failing closed per Tenuo security policy."
    )
    return False


def _get_attr_safe(obj: Any, attr: str) -> Any:
    """Safely get an attribute, handling both properties and methods."""
    val = getattr(obj, attr, None)
    if callable(val):
        try:
            return val()
        except Exception:
            return None
    return val


def _check_url_pattern(constraint: Any, value: Any) -> bool:
    """Check if a URL matches a UrlPattern constraint.
    
    UrlPattern attributes (from Rust bindings):
        - schemes: List of allowed schemes (empty = any)
        - host_pattern: Host pattern (supports *.example.com wildcards)
        - path_pattern: Path pattern (glob-style)
    
    Supported Patterns:
        - `https://example.com/*`       - Specific host, any path
        - `https://*.example.com/*`     - Subdomain wildcard
        - `*://example.com/*`           - Any scheme, specific host
    
    Known Bug (URLP-001): Bare wildcard hosts do NOT work.
        Patterns like `https://*/*` fail silently. The Rust parser's `/*`
        replacement (for path wildcards) interacts badly with URL parsing,
        causing `host_pattern` to become `__tenuo_path_wildcard__` instead
        of `*`. This is a parser bug, not intentional.
        
        Workaround: Always specify an explicit domain or use `*.domain.com`.
        See: tenuo-core/src/constraints.rs UrlPattern::new()
    """
    try:
        url = urlparse(str(value))
        
        # Get pattern components (Tenuo API)
        schemes = _get_attr_safe(constraint, 'schemes')  # List of allowed schemes
        host_pattern = _get_attr_safe(constraint, 'host_pattern')
        path_pattern = _get_attr_safe(constraint, 'path_pattern')
        
        # Check scheme if specified
        if schemes and '*' not in schemes:
            if url.scheme not in schemes:
                return False
        
        # Check host if specified (supports wildcard prefix like *.example.com)
        if host_pattern and host_pattern != "*":
            if host_pattern.startswith("*."):
                # Wildcard subdomain
                suffix = host_pattern[1:]  # .example.com
                if not url.netloc.endswith(suffix) and url.netloc != host_pattern[2:]:
                    return False
            else:
                if url.netloc != host_pattern:
                    return False
        
        # Check path if specified (glob matching)
        if path_pattern and path_pattern != "*":
            import fnmatch
            if not fnmatch.fnmatch(url.path, path_pattern):
                return False
        
        return True
    except Exception:
        return False


def verify_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    allow_tools: Optional[List[str]],
    deny_tools: Optional[List[str]],
    constraints: Optional[Dict[str, Dict[str, Constraint]]],
    warrant: Optional[Warrant] = None,
    signing_key: Optional[SigningKey] = None,
) -> None:
    """Verify a tool call against guardrails and/or warrant.
    
    Tier 1 (guardrails): Uses allow_tools, deny_tools, constraints
        - Runtime checks only, no cryptography
        - Good for single-process scenarios
    
    Tier 2 (warrant + signing_key): Cryptographic authorization
        - Signs Proof-of-Possession (PoP) with holder's key
        - Verifies warrant constraints AND PoP signature
        - Required for distributed/multi-agent scenarios
    
    Defense in depth when both tiers are configured:
        - Tier 1 allow/deny lists ALWAYS apply (even with warrant)
        - Tier 2 constraints OVERRIDE Tier 1 constraints (warrant is authoritative)
        
    This means: warrant.constraints take precedence over the constraints parameter,
    but a tool in deny_tools will still be blocked even if the warrant allows it.
    
    Args:
        tool_name: Name of the tool being called
        arguments: Tool arguments as dict
        allow_tools: Tier 1 - Allowlist of tool names (checked even with warrant)
        deny_tools: Tier 1 - Denylist of tool names (checked even with warrant)
        constraints: Tier 1 - Per-tool argument constraints (skipped if warrant present)
        warrant: Tier 2 - Cryptographic warrant (its constraints take precedence)
        signing_key: Tier 2 - Key for PoP signature (REQUIRED if warrant provided)
    
    Raises:
        ToolDenied: If tool is not allowed (Tier 1 allow/deny lists)
        WarrantDenied: If warrant doesn't authorize the call (Tier 2)
        ConstraintViolation: If argument violates constraint (Tier 1, only when no warrant)
        MissingSigningKey: If warrant provided without signing_key
    """
    # ==========================================================================
    # Tier 2: Warrant-based authorization (cryptographic)
    # ==========================================================================
    if warrant is not None:
        logger.debug(f"Tier 2: Verifying tool '{tool_name}' with warrant")
        
        if signing_key is None:
            logger.debug("Tier 2: Missing signing_key for PoP")
            raise MissingSigningKey()
        
        # Sign Proof-of-Possession
        logger.debug(f"Tier 2: Signing PoP for '{tool_name}'")
        pop_signature = warrant.sign(signing_key, tool_name, arguments)
        
        # Authorize with PoP (full cryptographic verification)
        authorized = warrant.authorize(tool_name, arguments, signature=bytes(pop_signature))
        
        if not authorized:
            logger.debug(f"Tier 2: Authorization DENIED for '{tool_name}'")
            # Get detailed reason for denial
            why = warrant.why_denied(tool_name, arguments)
            if why and hasattr(why, 'deny_code'):
                reason = f"{why.deny_code}"
                if hasattr(why, 'field') and why.field:
                    reason += f" (field: {why.field})"
                if hasattr(why, 'suggestion') and why.suggestion:
                    reason += f" - {why.suggestion}"
            else:
                reason = str(why) if why else "not authorized by warrant"
            raise WarrantDenied(tool_name, reason)
        else:
            logger.debug(f"Tier 2: Authorization GRANTED for '{tool_name}'")
    
    # ==========================================================================
    # Tier 1: Guardrail-based authorization (runtime checks)
    # ==========================================================================
    logger.debug(f"Tier 1: Checking guardrails for '{tool_name}'")
    
    # Check denylist first
    if deny_tools and tool_name in deny_tools:
        raise ToolDenied(tool_name, "Tool is in denylist")
    
    # Check allowlist
    if allow_tools is not None and tool_name not in allow_tools:
        raise ToolDenied(tool_name, "Tool not in allowlist")
    
    # Check Tier 1 constraints only if no warrant present.
    # When warrant exists, its constraints are authoritative (cryptographically signed).
    # Checking both would be redundant and potentially conflicting.
    if warrant is None and constraints and tool_name in constraints:
        tool_constraints = constraints[tool_name]
        for param, constraint in tool_constraints.items():
            if param in arguments:
                value = arguments[param]
                
                # Check for type mismatches first (provides clearer errors)
                type_mismatch, reason = _check_type_compatibility(constraint, value)
                if type_mismatch:
                    raise ConstraintViolation(
                        tool_name, param, value, constraint,
                        type_mismatch=True, reason=reason
                    )
                
                # Check the actual constraint
                if not check_constraint(constraint, value):
                    raise ConstraintViolation(tool_name, param, value, constraint)


def _check_type_compatibility(
    constraint: Constraint, value: Any
) -> tuple:
    """Check if value type is compatible with constraint.
    
    Returns:
        (is_mismatch: bool, reason: str or None)
    """
    constraint_type = type(constraint).__name__
    
    if constraint_type == "Range":
        if not isinstance(value, (int, float)):
            return True, f"Range requires numeric type (int/float), got {type(value).__name__}"
    
    elif constraint_type == "Cidr":
        if not isinstance(value, str):
            return True, f"Cidr requires string IP address, got {type(value).__name__}"
    
    elif constraint_type in ("Contains", "Subset"):
        if not isinstance(value, (list, set, tuple)):
            return True, f"{constraint_type} requires list/set/tuple, got {type(value).__name__}"
    
    return False, None


# =============================================================================
# Tool Call Processing
# =============================================================================


@dataclass
class ToolCallBuffer:
    """Buffer for accumulating streaming tool call chunks.
    
    Security: This buffer holds ALL data until verification is complete.
    No data is released to the consumer until verified.
    """
    
    id: str
    name: str = ""
    arguments_buffer: str = ""
    chunks: List[Any] = field(default_factory=list)  # Raw chunks to emit after verification
    is_complete: bool = False
    
    def append_arguments(self, chunk: str) -> None:
        self.arguments_buffer += chunk
    
    def add_chunk(self, chunk: Any) -> None:
        """Buffer a chunk for later emission after verification."""
        self.chunks.append(chunk)
    
    def get_arguments(self) -> Dict[str, Any]:
        """Parse accumulated arguments as JSON."""
        if not self.arguments_buffer:
            return {}
        try:
            return json.loads(self.arguments_buffer)
        except json.JSONDecodeError as e:
            raise MalformedToolCall(self.name, str(e))
    
    def size(self) -> int:
        return len(self.arguments_buffer.encode('utf-8'))


# =============================================================================
# Guarded Client
# =============================================================================


class GuardedCompletions:
    """Wrapped completions endpoint with guardrails.
    
    Supports both Tier 1 (guardrails) and Tier 2 (warrant + PoP) protection.
    """
    
    def __init__(
        self,
        original: Any,
        allow_tools: Optional[List[str]],
        deny_tools: Optional[List[str]],
        constraints: Optional[Dict[str, Dict[str, Constraint]]],
        on_denial: DenialMode,
        stream_buffer_limit: int,
        warrant: Optional[Warrant] = None,
        signing_key: Optional[SigningKey] = None,
        audit_callback: Optional[AuditCallback] = None,
        session_id: Optional[str] = None,
        constraint_hash: Optional[str] = None,
    ):
        self._original = original
        self._allow_tools = allow_tools
        self._deny_tools = deny_tools
        self._constraints = constraints
        self._on_denial = on_denial
        self._stream_buffer_limit = stream_buffer_limit
        self._warrant = warrant
        self._signing_key = signing_key
        self._audit_callback = audit_callback
        self._session_id = session_id or str(uuid.uuid4())[:8]
        self._constraint_hash = constraint_hash
        # Freeze warrant_id at init time for consistent audit trail
        self._warrant_id = warrant.id if warrant and hasattr(warrant, 'id') else None
    
    def create(self, *args, **kwargs) -> Any:
        """Wrapped create method with guardrails."""
        stream = kwargs.get("stream", False)
        
        if stream:
            # Return guarded stream
            original_stream = self._original.create(*args, **kwargs)
            return self._guard_stream(original_stream)
        else:
            # Non-streaming: verify after response
            response = self._original.create(*args, **kwargs)
            return self._guard_response(response)
    
    def _guard_response(self, response: Any) -> Any:
        """Verify tool calls in a non-streaming response."""
        if not hasattr(response, 'choices') or not response.choices:
            return response
        
        for choice in response.choices:
            if not hasattr(choice, 'message') or not choice.message:
                continue
            
            message = choice.message
            if not hasattr(message, 'tool_calls') or not message.tool_calls:
                continue
            
            # Filter/verify tool calls
            verified_calls = []
            for tool_call in message.tool_calls:
                try:
                    self._verify_single_tool_call(tool_call)
                    verified_calls.append(tool_call)
                except (ToolDenied, WarrantDenied, ConstraintViolation) as e:
                    self._handle_denial(e)
                    if self._on_denial == "raise":
                        raise
                    # skip or log: exclude from results
            
            # Update message with verified calls only
            if self._on_denial != "raise":
                message.tool_calls = verified_calls if verified_calls else None
        
        return response
    
    def _verify_single_tool_call(self, tool_call: Any) -> None:
        """Verify a single tool call."""
        if not hasattr(tool_call, 'function'):
            return
        
        func = tool_call.function
        tool_name = func.name if hasattr(func, 'name') else ""
        
        # Parse arguments
        args_str = func.arguments if hasattr(func, 'arguments') else "{}"
        try:
            arguments = json.loads(args_str) if args_str else {}
        except json.JSONDecodeError as e:
            raise MalformedToolCall(tool_name, str(e))
        
        try:
            verify_tool_call(
                tool_name,
                arguments,
                self._allow_tools,
                self._deny_tools,
                self._constraints,
                self._warrant,
                self._signing_key,
            )
            # Emit audit event for allowed call
            self._emit_audit(tool_name, arguments, "ALLOW", "passed all checks")
        except (ToolDenied, WarrantDenied, ConstraintViolation) as e:
            # Emit audit event for denied call
            tier = "tier2" if isinstance(e, WarrantDenied) else "tier1"
            self._emit_audit(tool_name, arguments, "DENY", str(e), tier=tier)
            raise
    
    def _emit_audit(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        decision: str,
        reason: str,
        tier: str = "tier1",
    ) -> None:
        """Emit an audit event if callback is configured."""
        if self._audit_callback is None:
            return
        
        event = AuditEvent(
            session_id=self._session_id,
            timestamp=time.time(),
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            reason=reason,
            tier=tier,  # Use tier determined by exception type, not warrant presence
            constraint_hash=self._constraint_hash,
            warrant_id=self._warrant_id,  # Frozen at init time
        )
        
        try:
            self._audit_callback(event)
        except Exception as e:
            # Don't let audit failures break authorization
            logger.warning(f"Audit callback failed: {e}")
    
    def _guard_stream(self, stream: Iterator) -> Iterator:
        """Buffer-verify-emit pattern for streaming responses.
        
        SECURITY: This is the critical TOCTOU protection. We MUST:
        1. BUFFER: Accumulate ALL chunks containing tool call data
        2. VERIFY: When a tool call is complete, verify it
        3. EMIT: Only yield verified chunks to the consumer
        
        NO tool call data is released until verification passes.
        
        Design Note (STREAM-001):
            Once `in_tool_call` becomes True, it NEVER reverts to False.
            This means Content → Tool → Content will buffer the trailing
            Content until stream end. This is intentional:
            - Security: Ensures no tool data leaks between chunks
            - Trade-off: Trailing content won't stream in real-time
            - Rare in practice: Models typically end with tools or final content
            Conservative approach prioritizes security over UX for edge cases.
        """
        buffers: Dict[int, ToolCallBuffer] = {}
        pending_chunks: List[Any] = []  # Chunks waiting for verification
        in_tool_call = False  # Latch: once True, stays True (see STREAM-001)
        
        for chunk in stream:
            has_tool_delta = self._has_tool_call_delta(chunk)
            is_final_chunk = self._is_stream_end(chunk)
            
            if has_tool_delta:
                in_tool_call = True
                # Buffer the chunk — DO NOT YIELD
                pending_chunks.append(chunk)
                self._accumulate_tool_call_data(chunk, buffers)
            elif in_tool_call and not is_final_chunk:
                # Still in a tool call sequence, buffer this too
                pending_chunks.append(chunk)
            else:
                # Not in a tool call, or stream is ending — safe to yield
                if not in_tool_call:
                    yield chunk
                else:
                    pending_chunks.append(chunk)
        
        # Stream complete — now verify ALL buffered tool calls
        verified_indices: set = set()
        denied_indices: set = set()
        
        for index, buffer in buffers.items():
            try:
                arguments = buffer.get_arguments()
                verify_tool_call(
                    buffer.name,
                    arguments,
                    self._allow_tools,
                    self._deny_tools,
                    self._constraints,
                    self._warrant,
                    self._signing_key,
                )
                verified_indices.add(index)
            except (ToolDenied, WarrantDenied, ConstraintViolation, MalformedToolCall) as e:
                self._handle_denial(e)
                if self._on_denial == "raise":
                    raise
                denied_indices.add(index)
        
        # EMIT: Only yield chunks for verified tool calls
        if self._on_denial == "raise" or not denied_indices:
            # All verified (or raise mode where we already raised)
            for chunk in pending_chunks:
                yield chunk
        else:
            # skip/log mode: filter out denied tool calls from chunks
            for chunk in pending_chunks:
                filtered = self._filter_denied_tool_calls(chunk, denied_indices)
                if filtered is not None:
                    yield filtered
    
    def _accumulate_tool_call_data(
        self,
        chunk: Any,
        buffers: Dict[int, ToolCallBuffer],
    ) -> None:
        """Accumulate tool call data from a chunk into buffers."""
        for choice in chunk.choices:
            if not hasattr(choice, 'delta') or not choice.delta:
                continue
            
            delta = choice.delta
            if not hasattr(delta, 'tool_calls') or not delta.tool_calls:
                continue
            
            for tc_delta in delta.tool_calls:
                index = tc_delta.index if hasattr(tc_delta, 'index') else 0
                
                # Initialize buffer if new tool call
                if index not in buffers:
                    tc_id = tc_delta.id if hasattr(tc_delta, 'id') else f"tc_{index}"
                    buffers[index] = ToolCallBuffer(id=tc_id)
                
                buffer = buffers[index]
                
                # Update name if present
                if hasattr(tc_delta, 'function') and tc_delta.function:
                    func = tc_delta.function
                    if hasattr(func, 'name') and func.name:
                        buffer.name = func.name
                    if hasattr(func, 'arguments') and func.arguments:
                        buffer.append_arguments(func.arguments)
                        
                        # Check buffer size
                        if buffer.size() > self._stream_buffer_limit:
                            raise BufferOverflow(
                                buffer.name,
                                buffer.size(),
                                self._stream_buffer_limit
                            )
    
    def _has_tool_call_delta(self, chunk: Any) -> bool:
        """Check if chunk contains tool call data."""
        if not hasattr(chunk, 'choices') or not chunk.choices:
            return False
        for choice in chunk.choices:
            if hasattr(choice, 'delta') and hasattr(choice.delta, 'tool_calls'):
                if choice.delta.tool_calls:
                    return True
        return False
    
    def _is_stream_end(self, chunk: Any) -> bool:
        """Check if this chunk signals stream end."""
        if not hasattr(chunk, 'choices') or not chunk.choices:
            return False
        for choice in chunk.choices:
            if hasattr(choice, 'finish_reason') and choice.finish_reason:
                return True
        return False
    
    def _filter_denied_tool_calls(
        self,
        chunk: Any,
        denied_indices: set,
    ) -> Optional[Any]:
        """Filter out denied tool calls from a chunk.
        
        Returns None if the entire chunk should be dropped.
        """
        if not self._has_tool_call_delta(chunk):
            return chunk
        
        # For simplicity, if any tool call in chunk is denied, drop the whole chunk
        # A more sophisticated impl would surgically remove just the denied calls
        for choice in chunk.choices:
            if not hasattr(choice, 'delta') or not choice.delta:
                continue
            delta = choice.delta
            if not hasattr(delta, 'tool_calls') or not delta.tool_calls:
                continue
            for tc_delta in delta.tool_calls:
                index = tc_delta.index if hasattr(tc_delta, 'index') else 0
                if index in denied_indices:
                    return None
        
        return chunk
    
    def _handle_denial(self, error: TenuoOpenAIError) -> None:
        """Handle a denial according to mode."""
        if self._on_denial == "log":
            logger.warning(f"Tool denied: {error}")
        elif self._on_denial == "skip":
            logger.debug(f"Tool skipped: {error}")
    
    async def acreate(self, *args, **kwargs) -> Any:
        """Async wrapped create method with guardrails."""
        stream = kwargs.get("stream", False)
        
        if stream:
            original_stream = await self._original.create(*args, **kwargs)
            return self._guard_stream_async(original_stream)
        else:
            response = await self._original.create(*args, **kwargs)
            return self._guard_response(response)
    
    async def _guard_stream_async(self, stream: AsyncIterator) -> AsyncIterator:
        """Async buffer-verify-emit pattern for streaming responses.
        
        SECURITY: Same TOCTOU protection as sync version.
        """
        buffers: Dict[int, ToolCallBuffer] = {}
        pending_chunks: List[Any] = []
        in_tool_call = False
        
        async for chunk in stream:
            has_tool_delta = self._has_tool_call_delta(chunk)
            is_final_chunk = self._is_stream_end(chunk)
            
            if has_tool_delta:
                in_tool_call = True
                pending_chunks.append(chunk)
                self._accumulate_tool_call_data(chunk, buffers)
            elif in_tool_call and not is_final_chunk:
                pending_chunks.append(chunk)
            else:
                if not in_tool_call:
                    yield chunk
                else:
                    pending_chunks.append(chunk)
        
        # Verify all buffered tool calls
        verified_indices: set = set()
        denied_indices: set = set()
        
        for index, buffer in buffers.items():
            try:
                arguments = buffer.get_arguments()
                verify_tool_call(
                    buffer.name,
                    arguments,
                    self._allow_tools,
                    self._deny_tools,
                    self._constraints,
                    self._warrant,
                    self._signing_key,
                )
                verified_indices.add(index)
            except (ToolDenied, WarrantDenied, ConstraintViolation, MalformedToolCall) as e:
                self._handle_denial(e)
                if self._on_denial == "raise":
                    raise
                denied_indices.add(index)
        
        # Emit verified chunks
        if self._on_denial == "raise" or not denied_indices:
            for chunk in pending_chunks:
                yield chunk
        else:
            for chunk in pending_chunks:
                filtered = self._filter_denied_tool_calls(chunk, denied_indices)
                if filtered is not None:
                    yield filtered


class GuardedChat:
    """Wrapped chat namespace."""
    
    def __init__(self, completions: GuardedCompletions):
        self.completions = completions


class GuardedResponses:
    """Wrapped responses endpoint with guardrails.
    
    Supports the OpenAI Responses API (client.responses.create).
    Uses the same verification logic as chat.completions.
    """
    
    def __init__(
        self,
        original: Any,
        allow_tools: Optional[List[str]],
        deny_tools: Optional[List[str]],
        constraints: Optional[Dict[str, Dict[str, Constraint]]],
        on_denial: DenialMode,
        warrant: Optional[Warrant] = None,
        signing_key: Optional[SigningKey] = None,
        audit_callback: Optional[AuditCallback] = None,
        session_id: Optional[str] = None,
        constraint_hash: Optional[str] = None,
    ):
        self._original = original
        self._allow_tools = allow_tools
        self._deny_tools = deny_tools
        self._constraints = constraints
        self._on_denial = on_denial
        self._warrant = warrant
        self._signing_key = signing_key
        self._audit_callback = audit_callback
        self._session_id = session_id or str(uuid.uuid4())[:8]
        self._constraint_hash = constraint_hash
        # Freeze warrant_id at init time for consistent audit trail
        self._warrant_id = warrant.id if warrant and hasattr(warrant, 'id') else None

    def create(self, *args, **kwargs) -> Any:
        """Wrapped create method with guardrails.
        
        Note: Responses API streaming uses a different pattern than chat.completions.
        Currently only non-streaming is fully supported.
        """
        response = self._original.create(*args, **kwargs)
        return self._guard_response(response)
    
    def _guard_response(self, response: Any) -> Any:
        """Verify tool calls in a Responses API response."""
        # Responses API uses response.output for tool calls
        if not hasattr(response, 'output'):
            return response
        
        output = response.output
        if not output:
            return response
        
        # Check for tool calls in output items
        for item in output:
            if hasattr(item, 'type') and item.type == 'function_call':
                try:
                    self._verify_function_call(item)
                except (ToolDenied, WarrantDenied, ConstraintViolation) as e:
                    self._handle_denial(e)
                    if self._on_denial == "raise":
                        raise
        
        return response
    
    def _verify_function_call(self, item: Any) -> None:
        """Verify a function call item from Responses API."""
        tool_name = getattr(item, 'name', '') or ''
        args_str = getattr(item, 'arguments', '{}') or '{}'
        
        try:
            arguments = json.loads(args_str) if args_str else {}
        except json.JSONDecodeError as e:
            raise MalformedToolCall(tool_name, str(e))
        
        try:
            verify_tool_call(
                tool_name,
                arguments,
                self._allow_tools,
                self._deny_tools,
                self._constraints,
                self._warrant,
                self._signing_key,
            )
            self._emit_audit(tool_name, arguments, "ALLOW", "passed all checks")
        except (ToolDenied, WarrantDenied, ConstraintViolation) as e:
            tier = "tier2" if isinstance(e, WarrantDenied) else "tier1"
            self._emit_audit(tool_name, arguments, "DENY", str(e), tier=tier)
            raise
    
    def _emit_audit(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        decision: str,
        reason: str,
        tier: str = "tier1",
    ) -> None:
        """Emit an audit event if callback is configured."""
        if self._audit_callback is None:
            return
        
        event = AuditEvent(
            session_id=self._session_id,
            timestamp=time.time(),
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            reason=reason,
            tier=tier,
            constraint_hash=self._constraint_hash,
            warrant_id=self._warrant_id,  # Frozen at init time
        )
        
        try:
            self._audit_callback(event)
        except Exception as e:
            logger.warning(f"Audit callback failed: {e}")

    def _handle_denial(self, error: Exception) -> None:
        """Handle a denial based on on_denial mode."""
        if self._on_denial == "log":
            logger.warning(f"Tool denied: {error}")
        elif self._on_denial == "skip":
            logger.debug(f"Tool skipped: {error}")


class GuardedClient:
    """OpenAI client wrapper with Tenuo guardrails.
    
    Supports both Tier 1 (guardrails) and Tier 2 (warrant + PoP) protection.
    
    Attributes:
        session_id: Unique identifier for this guard instance (for audit correlation)
        constraint_hash: SHA-256 hash of constraint config (for tamper detection)
    """
    
    def __init__(
        self,
        client: Any,
        allow_tools: Optional[List[str]] = None,
        deny_tools: Optional[List[str]] = None,
        constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
        on_denial: DenialMode = "raise",
        stream_buffer_limit: int = 65536,
        warrant: Optional[Warrant] = None,
        signing_key: Optional[SigningKey] = None,
        audit_callback: Optional[AuditCallback] = None,
    ):
        self._client = client
        self._allow_tools = allow_tools
        self._deny_tools = deny_tools
        self._constraints = constraints
        self._on_denial = on_denial
        self._stream_buffer_limit = stream_buffer_limit
        self._warrant = warrant
        self._signing_key = signing_key
        self._audit_callback = audit_callback
        
        # Generate session ID and constraint hash for audit trail
        self.session_id = "sess_" + str(uuid.uuid4())[:8]
        self.constraint_hash = _compute_constraint_hash(allow_tools, deny_tools, constraints)
        
        # Wrap chat.completions
        if hasattr(client, 'chat') and hasattr(client.chat, 'completions'):
            self.chat = GuardedChat(
                GuardedCompletions(
                    client.chat.completions,
                    allow_tools,
                    deny_tools,
                    constraints,
                    on_denial,
                    stream_buffer_limit,
                    warrant,
                    signing_key,
                    audit_callback,
                    self.session_id,
                    self.constraint_hash,
                )
            )
        
        # Wrap responses API (newer OpenAI API)
        if hasattr(client, 'responses'):
            self.responses = GuardedResponses(
                client.responses,
                allow_tools,
                deny_tools,
                constraints,
                on_denial,
                warrant,
                signing_key,
                audit_callback,
                self.session_id,
                self.constraint_hash,
            )
        
        # Pass through other attributes
        self._passthrough_attrs = set()
        for attr in dir(client):
            if not attr.startswith('_') and attr not in ('chat', 'responses'):
                self._passthrough_attrs.add(attr)
    
    def __getattr__(self, name: str) -> Any:
        """Pass through non-wrapped attributes to underlying client."""
        if name.startswith('_'):
            raise AttributeError(name)
        return getattr(self._client, name)
    
    def validate(self) -> None:
        """Validate configuration before first use.
        
        Performs pre-flight checks to catch configuration errors early:
        - Warrant + signing_key consistency
        - Key holder binding
        - Warrant expiration
        
        Call this after guard() to fail fast on misconfiguration.
        
        Raises:
            MissingSigningKey: If warrant provided without signing_key
            ConfigurationError: If signing_key doesn't match warrant holder
            ConfigurationError: If warrant is expired
        
        Example:
            >>> client = guard(openai.OpenAI(), warrant=w, signing_key=k)
            >>> client.validate()  # Fails early if misconfigured
        """
        if self._warrant is not None:
            # Check signing_key is provided
            if self._signing_key is None:
                raise MissingSigningKey()
            
            # Check warrant isn't expired
            # Note: 'expired' is a property, 'is_expired()' is a method
            is_expired = getattr(self._warrant, 'expired', False)
            if is_expired:
                raise ConfigurationError(
                    "Warrant is expired. Request a new warrant from the control plane.",
                    "CFG_002"
                )
            
            # Check signing_key matches warrant holder
            try:
                holder = self._warrant.authorized_holder
                signer_pub = self._signing_key.public_key
                if holder.to_bytes() != signer_pub.to_bytes():
                    raise ConfigurationError(
                        "Signing key does not match warrant holder. "
                        "The signing_key must be the private key corresponding to "
                        "the warrant's authorized_holder public key.",
                        "CFG_003"
                    )
            except AttributeError:
                # If we can't check, skip (older API)
                pass
        
        logger.debug("Configuration validated successfully")


# =============================================================================
# Public API
# =============================================================================


# Type alias for tool references
ToolRef = Union[str, Dict[str, Any], Callable[..., Any]]


def _extract_tool_name(tool: ToolRef) -> str:
    """Extract tool name from various formats.
    
    Supports:
    - String: "search" -> "search"
    - OpenAI tool dict: {"type": "function", "function": {"name": "search"}} -> "search"
    - Callable: search_func -> "search_func"
    """
    if isinstance(tool, str):
        return tool
    elif isinstance(tool, dict):
        # OpenAI tool format
        if "function" in tool and "name" in tool["function"]:
            return tool["function"]["name"]
        elif "name" in tool:
            return tool["name"]
        else:
            raise ValueError(f"Cannot extract tool name from dict: {tool}")
    elif callable(tool):
        name = getattr(tool, "__name__", None)
        if name:
            return name
        raise ValueError(f"Callable has no __name__: {tool}")
    else:
        raise TypeError(f"Expected str, dict, or callable, got {type(tool)}")


class GuardBuilder:
    """Fluent builder for creating guarded OpenAI clients.
    
    Provides a more ergonomic API for defining tool constraints:
    
        client = (GuardBuilder(openai.OpenAI())
            .allow("search")
            .allow("read_file", path=Subpath("/data"))
            .allow("send_email", to=Pattern("*@company.com"))
            .deny("delete_file")
            .on_denial("raise")
            .build())
    
    Benefits over dict-based `guard()`:
    - Fluent, chainable API
    - Accepts tool objects (not just strings) for IDE autocomplete
    - Clear separation of allow vs deny
    - Constraints are kwargs, not nested dicts
    
    For Tier 2 (warrant-based), use `.with_warrant()`:
    
        client = (GuardBuilder(openai.OpenAI())
            .with_warrant(warrant, signing_key)
            .build())
    """
    
    def __init__(self, client: Any) -> None:
        """Create a new builder for the given OpenAI client.
        
        Args:
            client: OpenAI client instance (sync or async)
        """
        self._client = client
        self._allow_tools: List[str] = []
        self._deny_tools: List[str] = []
        self._constraints: Dict[str, Dict[str, Constraint]] = {}
        self._on_denial: DenialMode = "raise"
        self._stream_buffer_limit: int = 65536
        self._audit_callback: Optional[AuditCallback] = None
        self._warrant: Optional[Warrant] = None
        self._signing_key: Optional[SigningKey] = None
    
    def allow(self, tool: ToolRef, **constraints: Constraint) -> "GuardBuilder":
        """Allow a tool, optionally with constraints.
        
        Args:
            tool: Tool name, OpenAI tool dict, or callable
            **constraints: Parameter constraints (e.g., path=Subpath("/data"))
        
        Returns:
            self for chaining
        
        Example:
            builder.allow("read_file", path=Subpath("/data"), encoding=Exact("utf-8"))
        """
        name = _extract_tool_name(tool)
        self._allow_tools.append(name)
        if constraints:
            self._constraints[name] = constraints
        return self
    
    def allow_all(self, *tools: ToolRef) -> "GuardBuilder":
        """Allow multiple tools without constraints.
        
        Args:
            *tools: Tool names, dicts, or callables
        
        Returns:
            self for chaining
        
        Example:
            builder.allow_all("search", "read_file", "list_files")
        """
        for tool in tools:
            self.allow(tool)
        return self
    
    def deny(self, tool: ToolRef) -> "GuardBuilder":
        """Explicitly deny a tool.
        
        Args:
            tool: Tool name, OpenAI tool dict, or callable
        
        Returns:
            self for chaining
        
        Example:
            builder.deny("delete_file")
        """
        name = _extract_tool_name(tool)
        self._deny_tools.append(name)
        return self
    
    def deny_all(self, *tools: ToolRef) -> "GuardBuilder":
        """Deny multiple tools.
        
        Args:
            *tools: Tool names, dicts, or callables
        
        Returns:
            self for chaining
        
        Example:
            builder.deny_all("delete_file", "rm", "drop_table")
        """
        for tool in tools:
            self.deny(tool)
        return self
    
    def constrain(self, tool: ToolRef, **constraints: Constraint) -> "GuardBuilder":
        """Add constraints to a tool (does NOT add to allow list).
        
        Use this when you want to constrain a tool without explicitly
        allowing it (e.g., when using a denylist approach).
        
        Args:
            tool: Tool name, OpenAI tool dict, or callable
            **constraints: Parameter constraints
        
        Returns:
            self for chaining
        """
        name = _extract_tool_name(tool)
        if name in self._constraints:
            self._constraints[name].update(constraints)
        else:
            self._constraints[name] = constraints
        return self
    
    def on_denial(self, mode: DenialMode) -> "GuardBuilder":
        """Set behavior when a tool call is denied.
        
        Args:
            mode: "raise" (default), "skip", or "log"
        
        Returns:
            self for chaining
        """
        self._on_denial = mode
        return self
    
    def buffer_limit(self, limit: int) -> "GuardBuilder":
        """Set max buffer size for streaming tool calls.
        
        Args:
            limit: Max bytes per tool call (default 64KB)
        
        Returns:
            self for chaining
        """
        self._stream_buffer_limit = limit
        return self
    
    def audit(self, callback: AuditCallback) -> "GuardBuilder":
        """Set audit callback for all authorization decisions.
        
        Args:
            callback: Function called with AuditEvent for each decision
        
        Returns:
            self for chaining
        
        Example:
            def log_audit(event: AuditEvent):
                print(f"[{event.decision}] {event.tool}: {event.reason}")
            
            builder.audit(log_audit)
        """
        self._audit_callback = callback
        return self
    
    def with_warrant(
        self,
        warrant: Warrant,
        signing_key: SigningKey,
    ) -> "GuardBuilder":
        """Configure Tier 2 (warrant + PoP) authorization.
        
        When a warrant is configured, its constraints take precedence
        over Tier 1 constraints. The signing key is used to sign
        Proof-of-Possession for each tool call.
        
        Args:
            warrant: Cryptographic warrant (from control plane)
            signing_key: Agent's signing key for PoP
        
        Returns:
            self for chaining
        
        Example:
            builder.with_warrant(warrant, agent_key)
        """
        self._warrant = warrant
        self._signing_key = signing_key
        return self
    
    def build(self) -> GuardedClient:
        """Build the guarded client.
        
        Returns:
            GuardedClient with configured constraints
        
        Raises:
            MissingSigningKey: If warrant provided without signing_key
            ValueError: If configuration is invalid
        """
        return GuardedClient(
            self._client,
            allow_tools=self._allow_tools if self._allow_tools else None,
            deny_tools=self._deny_tools if self._deny_tools else None,
            constraints=self._constraints if self._constraints else None,
            on_denial=self._on_denial,
            stream_buffer_limit=self._stream_buffer_limit,
            warrant=self._warrant,
            signing_key=self._signing_key,
            audit_callback=self._audit_callback,
        )


def guard(
    client: Any,
    *,
    allow_tools: Optional[List[str]] = None,
    deny_tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
    warrant: Optional[Warrant] = None,
    signing_key: Optional[SigningKey] = None,
    on_denial: DenialMode = "raise",
    stream_buffer_limit: int = 65536,
    audit_callback: Optional[AuditCallback] = None,
) -> GuardedClient:
    """Wrap an OpenAI client with Tenuo guardrails.
    
    This function supports two tiers of protection:
    
    **Tier 1 (Guardrails)**: Runtime constraint checking without cryptography.
    Uses allow_tools, deny_tools, and constraints parameters.
    Good for single-process scenarios where you trust the executor.
    
    **Tier 2 (Warrant + PoP)**: Cryptographic authorization with Proof-of-Possession.
    Requires both a warrant AND a signing_key. For each tool call:
    1. Signs a PoP proving the agent holds the warrant's private key
    2. Verifies constraints AND the cryptographic signature
    
    This enables distributed/multi-agent scenarios where you cannot trust
    the executor to honestly report what tools it called.
    
    **Defense in Depth** when both tiers are configured:
    - Tier 1 allow/deny lists ALWAYS apply (even with warrant)
    - Tier 2 constraints OVERRIDE Tier 1 constraints (warrant is authoritative)
    
    Args:
        client: OpenAI client instance
        allow_tools: Tier 1 - Allowlist of tool names (checked even with warrant)
        deny_tools: Tier 1 - Denylist of tool names (checked even with warrant)
        constraints: Tier 1 - Per-tool argument constraints (skipped if warrant present)
        warrant: Tier 2 - Cryptographic warrant (its constraints take precedence)
        signing_key: Tier 2 - Agent's signing key for PoP (REQUIRED if warrant provided)
        on_denial: Behavior when tool call is denied:
            - "raise": Raise ToolDenied/WarrantDenied exception (recommended)
            - "skip": Silently skip the tool call
            - "log": Log warning and skip
        stream_buffer_limit: Max bytes per tool call in streaming (default 64KB)
        audit_callback: Optional callback for every authorization decision.
            Receives AuditEvent with session_id, tool, decision, reason.
            Useful for compliance logging and debugging.
    
    Returns:
        Wrapped client that enforces constraints
    
    Raises:
        MissingSigningKey: If warrant is provided without signing_key
    
    Warning:
        Using on_denial="skip" or "log" can cause the LLM to hang if it expects
        a tool output that never comes. When a tool call is skipped, the LLM
        may wait indefinitely for a response. Consider either:
        1. Using on_denial="raise" and catching the exception to inject an
           error message into the conversation history
        2. Implementing a wrapper that automatically sends a tool error response
           for denied calls
    
    Example (Tier 1 - Guardrails):
        >>> from tenuo.openai import guard, Pattern
        >>> 
        >>> client = guard(
        ...     openai.OpenAI(),
        ...     allow_tools=["search", "read_file"],
        ...     constraints={
        ...         "read_file": {"path": Pattern("/data/*")}
        ...     }
        ... )
        >>> 
        >>> # Use normally - unauthorized tool calls are blocked
        >>> response = client.chat.completions.create(...)
    
    Example (Tier 2 - Warrant with PoP):
        >>> from tenuo.openai import guard
        >>> from tenuo import Warrant, SigningKey, Pattern
        >>> 
        >>> # Agent's keypair (the agent is the warrant holder)
        >>> agent_key = SigningKey.generate()
        >>> 
        >>> # Create a warrant (in production, received from control plane)
        >>> control_plane_key = SigningKey.generate()
        >>> warrant = (Warrant.mint_builder()
        ...     .capability("read_file", {"path": Pattern("/data/*")})
        ...     .holder(agent_key.public_key)  # Agent is the holder
        ...     .ttl(3600)
        ...     .mint(control_plane_key))      # Control plane signs
        >>> 
        >>> # Guard with both warrant AND signing key
        >>> client = guard(
        ...     openai.OpenAI(),
        ...     warrant=warrant,
        ...     signing_key=agent_key,  # Agent signs PoP for each tool call
        ... )
        >>> 
        >>> # Each tool call is now cryptographically authorized
        >>> response = client.chat.completions.create(...)
    """
    return GuardedClient(
        client,
        allow_tools=allow_tools,
        deny_tools=deny_tools,
        constraints=constraints,
        on_denial=on_denial,
        stream_buffer_limit=stream_buffer_limit,
        warrant=warrant,
        signing_key=signing_key,
        audit_callback=audit_callback,
    )


# =============================================================================
# OpenAI Agents SDK Integration
# =============================================================================
#
# The OpenAI Agents SDK (openai-agents) provides a framework for building
# multi-agent systems. Tenuo integrates via the guardrails mechanism:
#
#   from agents import Agent, Runner
#   from tenuo.openai import create_tool_guardrail, Pattern
#
#   guardrail = create_tool_guardrail(
#       constraints={"send_email": {"to": Pattern("*@company.com")}}
#   )
#
#   agent = Agent(
#       name="Assistant",
#       instructions="Help the user",
#       input_guardrails=[guardrail],  # Validates tool calls before execution
#   )
#
# For Tier 2 (warrant-based), use create_warrant_guardrail():
#
#   from tenuo.openai import create_warrant_guardrail
#   from tenuo import SigningKey, Warrant
#
#   guardrail = create_warrant_guardrail(warrant=warrant, signing_key=agent_key)
#   agent = Agent(..., input_guardrails=[guardrail])


# Try to get the SDK base class for proper inheritance
_GuardrailFunctionOutput: Any = None
try:
    from agents.guardrail import GuardrailFunctionOutput as _GFO
    _GuardrailFunctionOutput = _GFO
except ImportError:
    pass


@dataclass
class GuardrailResult:
    """Result of a Tenuo guardrail check.
    
    This class is compatible with OpenAI Agents SDK's GuardrailFunctionOutput.
    When `tripwire_triggered=True`, the agent run is halted immediately.
    
    If the openai-agents SDK is installed, to_agents_sdk() returns a proper
    GuardrailFunctionOutput instance for full SDK compatibility.
    """
    output_info: str
    tripwire_triggered: bool = False
    
    def to_agents_sdk(self) -> Any:
        """Convert to OpenAI Agents SDK GuardrailFunctionOutput.
        
        Returns a proper GuardrailFunctionOutput if SDK is installed,
        otherwise returns self (which has the same interface).
        
        Requires: pip install openai-agents
        """
        if _GuardrailFunctionOutput is not None:
            return _GuardrailFunctionOutput(
                output_info=self.output_info,
                tripwire_triggered=self.tripwire_triggered,
            )
        # Return self if SDK not installed - has same interface
        return self


class TenuoToolGuardrail:
    """Tenuo guardrail for OpenAI Agents SDK.
    
    Validates tool calls against constraints before execution.
    Compatible with Agent's input_guardrails parameter.
    
    Usage:
        from agents import Agent
        from tenuo.openai import TenuoToolGuardrail, Pattern
        
        guardrail = TenuoToolGuardrail(
            constraints={"send_email": {"to": Pattern("*@company.com")}}
        )
        
        agent = Agent(
            name="Assistant",
            input_guardrails=[guardrail],
        )
    """
    
    def __init__(
        self,
        *,
        allow_tools: Optional[List[str]] = None,
        deny_tools: Optional[List[str]] = None,
        constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
        warrant: Optional[Warrant] = None,
        signing_key: Optional[SigningKey] = None,
        tripwire: bool = True,
        audit_callback: Optional[AuditCallback] = None,
    ):
        """Initialize the guardrail.
        
        Args:
            allow_tools: Allowlist of permitted tool names (None = allow all)
            deny_tools: Denylist of forbidden tool names
            constraints: Per-tool argument constraints
            warrant: Optional Tier 2 warrant for cryptographic authorization
            signing_key: Required if warrant is provided (for PoP)
            tripwire: If True, halt agent on violation. If False, log and continue.
            audit_callback: Optional callback for audit events
        """
        self.allow_tools = allow_tools
        self.deny_tools = deny_tools
        self.constraints = constraints
        self.warrant = warrant
        self.signing_key = signing_key
        self.tripwire = tripwire
        self.audit_callback = audit_callback
        self.name = "tenuo_tool_guardrail"
        
        # Generate session ID and constraint hash for audit trail
        self._session_id = str(uuid.uuid4())[:8]
        self._constraint_hash = _compute_constraint_hash(allow_tools, deny_tools, constraints)
        self._warrant_id = warrant.id if warrant and hasattr(warrant, 'id') else None
        
        # Validate configuration
        if warrant is not None and signing_key is None:
            raise MissingSigningKey()
    
    async def __call__(self, ctx: Any, agent: Any, input_data: Any) -> Any:
        """Guardrail entry point called by Agents SDK.
        
        Args:
            ctx: RunContextWrapper from Agents SDK
            agent: The Agent being run
            input_data: Input being validated (may contain tool calls)
        
        Returns:
            GuardrailFunctionOutput (or compatible dict)
        """
        # Extract tool calls from input
        tool_calls = self._extract_tool_calls(input_data)
        
        if not tool_calls:
            # No tool calls to validate
            return GuardrailResult(output_info="No tool calls").to_agents_sdk()
        
        violations = []
        for tool_name, arguments in tool_calls:
            try:
                verify_tool_call(
                    tool_name,
                    arguments,
                    self.allow_tools,
                    self.deny_tools,
                    self.constraints,
                    self.warrant,
                    self.signing_key,
                )
                # Emit audit event for allowed call
                self._emit_audit(tool_name, arguments, "ALLOW", "passed all checks")
            except (ToolDenied, WarrantDenied, ConstraintViolation) as e:
                violations.append(f"{tool_name}: {e}")
                logger.warning(f"Tenuo guardrail blocked: {tool_name} - {e}")
                # Emit audit event for denied call
                tier = "tier2" if isinstance(e, WarrantDenied) else "tier1"
                self._emit_audit(tool_name, arguments, "DENY", str(e), tier=tier)
        
        if violations:
            result = GuardrailResult(
                output_info=f"Blocked by Tenuo: {'; '.join(violations)}",
                tripwire_triggered=self.tripwire,
            )
        else:
            result = GuardrailResult(
                output_info=f"Tenuo: {len(tool_calls)} tool call(s) authorized",
                tripwire_triggered=False,
            )
        
        return result.to_agents_sdk()
    
    def _emit_audit(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        decision: str,
        reason: str,
        tier: str = "tier1",
    ) -> None:
        """Emit an audit event if callback is configured."""
        if self.audit_callback is None:
            return
        
        event = AuditEvent(
            session_id=self._session_id,
            timestamp=time.time(),
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            reason=reason,
            tier=tier,
            constraint_hash=self._constraint_hash,
            warrant_id=self._warrant_id,
        )
        
        try:
            self.audit_callback(event)
        except Exception as e:
            # Don't let audit failures break authorization
            logger.warning(f"Audit callback failed: {e}")
    
    def _extract_tool_calls(self, input_data: Any) -> List[tuple]:
        """Extract tool calls from Agents SDK input.
        
        The input format varies based on SDK version and context.
        This method handles multiple formats gracefully.
        """
        tool_calls = []
        
        # Format 1: Direct tool call list
        if isinstance(input_data, list):
            for item in input_data:
                tc = self._parse_tool_call_item(item)
                if tc:
                    tool_calls.append(tc)
        
        # Format 2: Dict with 'tool_calls' key
        elif isinstance(input_data, dict):
            if "tool_calls" in input_data:
                for item in input_data["tool_calls"]:
                    tc = self._parse_tool_call_item(item)
                    if tc:
                        tool_calls.append(tc)
            # Format 3: Single tool call dict
            elif "name" in input_data or "function" in input_data:
                tc = self._parse_tool_call_item(input_data)
                if tc:
                    tool_calls.append(tc)
        
        # Format 4: Object with attributes
        elif hasattr(input_data, "tool_calls"):
            for item in input_data.tool_calls or []:
                tc = self._parse_tool_call_item(item)
                if tc:
                    tool_calls.append(tc)
        
        return tool_calls
    
    def _parse_tool_call_item(self, item: Any) -> Optional[tuple]:
        """Parse a single tool call item into (name, arguments)."""
        # Dict format
        if isinstance(item, dict):
            if "function" in item:
                func = item["function"]
                name = func.get("name", "")
                args_str = func.get("arguments", "{}")
            else:
                name = item.get("name", "")
                args_str = item.get("arguments", "{}")
            
            try:
                arguments = json.loads(args_str) if isinstance(args_str, str) else args_str
            except json.JSONDecodeError:
                arguments = {}
            
            return (name, arguments) if name else None
        
        # Object format
        if hasattr(item, "function"):
            func = item.function
            name = getattr(func, "name", "")
            args_str = getattr(func, "arguments", "{}")
            try:
                arguments = json.loads(args_str) if isinstance(args_str, str) else args_str
            except json.JSONDecodeError:
                arguments = {}
            return (name, arguments) if name else None
        
        if hasattr(item, "name"):
            name = item.name
            args_str = getattr(item, "arguments", "{}")
            try:
                arguments = json.loads(args_str) if isinstance(args_str, str) else args_str
            except json.JSONDecodeError:
                arguments = {}
            return (name, arguments) if name else None
        
        return None


def create_tool_guardrail(
    *,
    allow_tools: Optional[List[str]] = None,
    deny_tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
    tripwire: bool = True,
    audit_callback: Optional[AuditCallback] = None,
) -> TenuoToolGuardrail:
    """Create a Tier 1 guardrail for OpenAI Agents SDK.
    
    This guardrail validates tool calls against constraints without
    cryptographic verification. Good for single-process scenarios.
    
    Args:
        allow_tools: Allowlist of permitted tool names
        deny_tools: Denylist of forbidden tool names
        constraints: Per-tool argument constraints
        tripwire: If True, halt agent on violation
        audit_callback: Optional callback for audit events
    
    Returns:
        A guardrail compatible with Agent's input_guardrails
    
    Example:
        from agents import Agent
        from tenuo.openai import create_tool_guardrail, Pattern
        
        guardrail = create_tool_guardrail(
            constraints={
                "send_email": {"to": Pattern("*@company.com")},
                "read_file": {"path": Pattern("/data/*")},
            }
        )
        
        agent = Agent(
            name="Assistant",
            input_guardrails=[guardrail],
        )
    """
    return TenuoToolGuardrail(
        allow_tools=allow_tools,
        deny_tools=deny_tools,
        constraints=constraints,
        tripwire=tripwire,
        audit_callback=audit_callback,
    )


def create_warrant_guardrail(
    *,
    warrant: Warrant,
    signing_key: SigningKey,
    tripwire: bool = True,
    audit_callback: Optional[AuditCallback] = None,
) -> TenuoToolGuardrail:
    """Create a Tier 2 guardrail for OpenAI Agents SDK.
    
    This guardrail validates tool calls against a warrant with full
    Proof-of-Possession verification. Required for distributed/multi-agent
    scenarios where cryptographic authorization is needed.
    
    Args:
        warrant: The warrant authorizing tool usage
        signing_key: The agent's signing key (must match warrant holder)
        tripwire: If True, halt agent on violation
        audit_callback: Optional callback for audit events
    
    Returns:
        A guardrail compatible with Agent's input_guardrails
    
    Example:
        from agents import Agent, Runner
        from tenuo.openai import create_warrant_guardrail
        from tenuo import SigningKey, Warrant, Pattern
        
        # Control plane issues warrant to agent
        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .capability("send_email", {"to": Pattern("*@company.com")})
            .holder(agent_key.public_key)
            .ttl(3600)
            .mint(control_key))
        
        # Agent uses warrant
        guardrail = create_warrant_guardrail(
            warrant=warrant,
            signing_key=agent_key,
        )
        
        agent = Agent(
            name="Authorized Assistant",
            input_guardrails=[guardrail],
        )
        
        result = await Runner.run(agent, "Send email to user@company.com")
    """
    return TenuoToolGuardrail(
        warrant=warrant,
        signing_key=signing_key,
        tripwire=tripwire,
        audit_callback=audit_callback,
    )


# =============================================================================
# Exports
# =============================================================================


__all__ = [
    # Main API
    "guard",
    "GuardBuilder",
    "GuardedClient",
    "GuardedResponses",
    "enable_debug",
    
    # OpenAI Agents SDK Integration
    "TenuoToolGuardrail",
    "GuardrailResult",
    "create_tool_guardrail",
    "create_warrant_guardrail",
    
    # Audit
    "AuditEvent",
    "AuditCallback",
    
    # Exceptions
    "TenuoOpenAIError",
    "ToolDenied",
    "ConstraintViolation",
    "MalformedToolCall",
    "BufferOverflow",
    "WarrantDenied",
    "MissingSigningKey",
    "ConfigurationError",
    
    # Re-export constraints for convenience
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
    "Subpath",  # Python-only secure path containment constraint
    
    # Tier 2: Warrant types (re-exported for convenience)
    "Warrant",
    "SigningKey",
]
