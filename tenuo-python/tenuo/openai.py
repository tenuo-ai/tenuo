"""
Tenuo OpenAI Adapter - Tier 1: Guardrails

Provides runtime constraint checking for OpenAI API calls without cryptography.
Catches hallucinated tool calls, argument constraint violations, and streaming TOCTOU attacks.

Security Philosophy (Fail Closed):
    Tenuo follows a "fail closed" security model. When in doubt, deny:
    - Unknown constraint types are rejected (not silently passed)
    - CEL expressions require Rust bindings (Python fallback denies)
    - Missing constraint attributes cause denial
    - Malformed tool calls are blocked
    
    This is intentional. A guardrail that silently passes unknown cases
    is not a guardrail - it's a false sense of security.

Usage:
    from tenuo.openai import guard, Pattern, Range

    client = guard(
        openai.OpenAI(),
        allow_tools=["search", "read_file"],
        constraints={
            "read_file": {"path": Pattern("/data/*")}
        }
    )

    # Use normally - unauthorized tool calls are blocked
    response = client.chat.completions.create(...)

Async Support:
    For async OpenAI clients, use the same guard() wrapper.
    Async streaming is fully supported with the same TOCTOU protections.
    
    async_client = guard(openai.AsyncOpenAI(), ...)
    response = await async_client.chat.completions.acreate(...)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
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
)

logger = logging.getLogger("tenuo.openai")

# Type alias for constraint types
Constraint = Union[
    Pattern, Exact, OneOf, Range, Regex, Cidr, UrlPattern,
    Contains, Subset, Wildcard, AnyOf, All, Not, NotOneOf, CEL
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
) -> None:
    """Verify a tool call against allowlist-denylist and constraints.
    
    Raises:
        ToolDenied: If tool is not allowed
        ConstraintViolation: If argument violates constraint (with detailed reason)
    """
    # Check denylist first
    if deny_tools and tool_name in deny_tools:
        raise ToolDenied(tool_name, "Tool is in denylist")
    
    # Check allowlist
    if allow_tools is not None and tool_name not in allow_tools:
        raise ToolDenied(tool_name, "Tool not in allowlist")
    
    # Check constraints
    if constraints and tool_name in constraints:
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
    """Wrapped completions endpoint with guardrails."""
    
    def __init__(
        self,
        original: Any,
        allow_tools: Optional[List[str]],
        deny_tools: Optional[List[str]],
        constraints: Optional[Dict[str, Dict[str, Constraint]]],
        on_denial: DenialMode,
        stream_buffer_limit: int,
    ):
        self._original = original
        self._allow_tools = allow_tools
        self._deny_tools = deny_tools
        self._constraints = constraints
        self._on_denial = on_denial
        self._stream_buffer_limit = stream_buffer_limit
    
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
                except (ToolDenied, ConstraintViolation) as e:
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
        
        verify_tool_call(
            tool_name,
            arguments,
            self._allow_tools,
            self._deny_tools,
            self._constraints,
        )
    
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
                )
                verified_indices.add(index)
            except (ToolDenied, ConstraintViolation, MalformedToolCall) as e:
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
                )
                verified_indices.add(index)
            except (ToolDenied, ConstraintViolation, MalformedToolCall) as e:
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


class GuardedClient:
    """OpenAI client wrapper with Tenuo guardrails."""
    
    def __init__(
        self,
        client: Any,
        allow_tools: Optional[List[str]] = None,
        deny_tools: Optional[List[str]] = None,
        constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
        on_denial: DenialMode = "raise",
        stream_buffer_limit: int = 65536,
    ):
        self._client = client
        self._allow_tools = allow_tools
        self._deny_tools = deny_tools
        self._constraints = constraints
        self._on_denial = on_denial
        self._stream_buffer_limit = stream_buffer_limit
        
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
                )
            )
        
        # Pass through other attributes
        self._passthrough_attrs = set()
        for attr in dir(client):
            if not attr.startswith('_') and attr != 'chat':
                self._passthrough_attrs.add(attr)
    
    def __getattr__(self, name: str) -> Any:
        """Pass through non-wrapped attributes to underlying client."""
        if name.startswith('_'):
            raise AttributeError(name)
        return getattr(self._client, name)


# =============================================================================
# Public API
# =============================================================================


def guard(
    client: Any,
    *,
    allow_tools: Optional[List[str]] = None,
    deny_tools: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Dict[str, Constraint]]] = None,
    on_denial: DenialMode = "raise",
    stream_buffer_limit: int = 65536,
) -> GuardedClient:
    """Wrap an OpenAI client with Tenuo guardrails.
    
    Args:
        client: OpenAI client instance
        allow_tools: Allowlist of tool names (default: allow all)
        deny_tools: Denylist of tool names (default: deny none)
        constraints: Per-tool argument constraints
        on_denial: Behavior when tool call is denied:
            - "raise": Raise ToolDenied exception (recommended)
            - "skip": Silently skip the tool call
            - "log": Log warning and skip
        stream_buffer_limit: Max bytes per tool call in streaming (default 64KB)
    
    Returns:
        Wrapped client that enforces constraints
    
    Warning:
        Using on_denial="skip" or "log" can cause the LLM to hang if it expects
        a tool output that never comes. When a tool call is skipped, the LLM
        may wait indefinitely for a response. Consider either:
        1. Using on_denial="raise" and catching the exception to inject an
           error message into the conversation history
        2. Implementing a wrapper that automatically sends a tool error response
           for denied calls
    
    Example:
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
        >>> # Use normally — unauthorized tool calls are blocked
        >>> response = client.chat.completions.create(...)
    """
    return GuardedClient(
        client,
        allow_tools=allow_tools,
        deny_tools=deny_tools,
        constraints=constraints,
        on_denial=on_denial,
        stream_buffer_limit=stream_buffer_limit,
    )


# =============================================================================
# Exports
# =============================================================================


__all__ = [
    # Main API
    "guard",
    "GuardedClient",
    
    # Exceptions
    "TenuoOpenAIError",
    "ToolDenied",
    "ConstraintViolation",
    "MalformedToolCall",
    "BufferOverflow",
    
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
]
