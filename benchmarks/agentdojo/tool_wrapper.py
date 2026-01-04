"""
Tool wrapper that adds Tenuo authorization to AgentDojo tools.
"""

import logging
from typing import Callable, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, date, time
import json
from tenuo import Warrant, SigningKey

logger = logging.getLogger(__name__)


def _simplify_args(args: dict) -> dict:
    """
    Convert complex argument types to simple types for Tenuo authorization.

    AgentDojo tools may receive pydantic models, nested dicts, datetime, etc.
    Tenuo's authorize() only accepts: str, int, float, bool, list (of simple), None.

    NOTE: No size limits are applied here to ensure accurate benchmark measurements.
    Production integrations should add size limits at the request handling layer.
    """
    # Deep copy to avoid mutation issues
    try:
        import copy

        args_copy = copy.deepcopy(args)
    except Exception:
        args_copy = dict(args)  # Shallow copy fallback

    simplified = {}
    for key, value in args_copy.items():
        try:
            result = _simplify_value(value)
            # Final safety check - force to simple type
            if result is not None:
                if isinstance(result, list):
                    # Ensure list elements are simple
                    result = [
                        v
                        if isinstance(v, (str, int, float, bool, type(None)))
                        else str(v)
                        for v in result
                    ]
                elif not isinstance(result, (str, int, float, bool)):
                    result = str(result)
            simplified[key] = result
        except Exception:
            # Ultimate fallback: stringify
            try:
                simplified[key] = str(value) if value is not None else None
            except Exception:
                simplified[key] = f"<unparseable:{type(value).__name__}>"
    return simplified


def _simplify_value(value: Any) -> Any:
    """
    Convert a single value to a simple type that Tenuo accepts.

    Tenuo only accepts: str, int, float, bool, list (of simple types), None.
    Everything else must be converted to string.
    """
    if value is None:
        return None

    # Already simple types
    if isinstance(value, bool):  # Check bool first (bool is subclass of int)
        return value
    if isinstance(value, (str, int, float)):
        return value

    # Datetime types -> ISO string
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()

    # Lists -> recursively simplify, but ensure each element is simple
    if isinstance(value, (list, tuple)):
        simplified_list = []
        for v in value:
            s = _simplify_value(v)
            # Ensure no nested complex types remain
            if s is not None and not isinstance(s, (str, int, float, bool)):
                s = str(s)
            simplified_list.append(s)
        return simplified_list

    # Dicts -> serialize to JSON string (Tenuo doesn't accept dicts directly)
    if isinstance(value, dict):
        try:
            return json.dumps(value, default=str)
        except Exception:
            return str(value)

    # Pydantic v2 model
    if hasattr(value, "model_dump"):
        try:
            dumped = value.model_dump(mode="json")
            return json.dumps(dumped, default=str)
        except Exception:
            try:
                return json.dumps(value.model_dump(), default=str)
            except Exception:
                return str(value)

    # Pydantic v1 model
    if hasattr(value, "dict"):
        try:
            return json.dumps(value.dict(), default=str)
        except Exception:
            return str(value)

    # Bytes -> base64
    if isinstance(value, bytes):
        import base64

        return base64.b64encode(value).decode("ascii")

    # Enum -> value or name
    if hasattr(value, "value"):
        v = value.value
        if isinstance(v, (str, int, float, bool)):
            return v
        return str(v)

    # Fallback: convert to string
    return str(value)


class UnauthorizedToolCallError(Exception):
    """Raised when a tool call is not authorized by Tenuo."""

    pass


@dataclass
class AuthorizationMetrics:
    """Tracks which constraints blocked attacks."""

    allowed: int = 0
    denied: int = 0
    denied_by_tool: dict = field(default_factory=dict)
    denied_by_constraint: dict = field(default_factory=dict)

    def record_allowed(self, tool_name: str):
        self.allowed += 1

    def record_denied(self, tool_name: str, constraint: str = "unknown"):
        self.denied += 1
        self.denied_by_tool[tool_name] = self.denied_by_tool.get(tool_name, 0) + 1
        key = f"{tool_name}.{constraint}"
        self.denied_by_constraint[key] = self.denied_by_constraint.get(key, 0) + 1


class TenuoToolWrapper:
    """
    Wraps an AgentDojo tool with Tenuo authorization.

    Before executing the tool, checks that the call is authorized
    according to the warrant's constraints.
    """

    def __init__(
        self,
        tool: Callable,
        tool_name: str,
        warrant: Warrant,
        holder_key: SigningKey,
        metrics: Optional[AuthorizationMetrics] = None,
        opaque_errors: Optional[bool] = None,
    ):
        """
        Args:
            tool: The original tool function
            tool_name: Name of the tool
            warrant: Warrant authorizing this tool
            holder_key: Key for creating PoP signatures
            metrics: Optional metrics tracker
            opaque_errors: If True, return generic "Unauthorized" errors (prevents
                          adaptive attacks). If False, return helpful errors with
                          constraint details (useful for debugging/training attacks).
                          If None (default), uses the default behavior of the wrapper.
        """
        self.tool = tool
        self.tool_name = tool_name
        # Copy all attributes from original tool that AgentDojo expects
        self.name = getattr(tool, "name", tool_name)
        self.description = getattr(tool, "description", "")
        self.parameters = getattr(tool, "parameters", {})
        self.dependencies = getattr(tool, "dependencies", {})
        # Keep Tenuo-specific attributes
        self.warrant = warrant
        self.holder_key = holder_key
        self.metrics = metrics or AuthorizationMetrics()
        self.opaque_errors = opaque_errors if opaque_errors is not None else True
        self.__name__ = getattr(tool, "__name__", tool_name)
        self.__doc__ = getattr(tool, "__doc__", "")

    def __call__(self, **kwargs) -> Any:
        """
        Execute the tool after authorization check.

        Args:
            **kwargs: Tool arguments

        Returns:
            Tool execution result

        Raises:
            UnauthorizedToolCallError: If the call is not authorized
        """
        logger.debug(f"Authorizing {self.tool_name}")
        try:
            # Convert complex args to simple types for Tenuo
            simplified_args = _simplify_args(kwargs)

            # CRITICAL: Tenuo Rust code doesn't accept None values
            # Filter out None values and validate remaining types
            filtered_args = {}
            for k, v in simplified_args.items():
                if v is None:
                    continue  # Skip None values entirely
                elif isinstance(v, list):
                    # Filter None from lists and validate elements
                    cleaned_list = []
                    for elem in v:
                        if elem is None:
                            continue  # Skip None elements
                        elif isinstance(elem, (str, int, float, bool)):
                            cleaned_list.append(elem)
                        else:
                            cleaned_list.append(str(elem))
                    filtered_args[k] = cleaned_list
                elif isinstance(v, (str, int, float, bool)):
                    filtered_args[k] = v
                else:
                    filtered_args[k] = str(v)

            # Create PoP signature for this specific call (includes Ed25519 signing)
            try:
                pop_signature = self.warrant.sign(
                    self.holder_key, self.tool_name, filtered_args
                )
            except ValueError as ve:
                logger.error(f"PoP creation failed for {self.tool_name}: {ve}")
                logger.debug(f"Args: {filtered_args}")
                raise

            logger.debug(f"PoP signature created for {self.tool_name}")

            # Check authorization using warrant.authorize()
            # This includes Ed25519 signature verification for honest latency measurement
            authorized = self.warrant.authorize(
                tool=self.tool_name, args=filtered_args, signature=bytes(pop_signature)
            )

            if not authorized:
                # Get detailed denial reason for metrics (internal tracking)
                denial = self.warrant.why_denied(self.tool_name, filtered_args)
                constraint = denial.field if denial and denial.field else "tool"
                self.metrics.record_denied(self.tool_name, constraint)
                logger.info(f"DENIED: {self.tool_name} (constraint: {constraint})")

                # Choose error message based on opaque_errors setting
                if self.opaque_errors:
                    error_msg = f"Tool call to {self.tool_name} denied: Unauthorized"
                else:
                    error_msg = f"Tool call to {self.tool_name} denied: {denial.suggestion if denial else 'unauthorized'}"

                raise UnauthorizedToolCallError(error_msg)

            # Record success and execute
            self.metrics.record_allowed(self.tool_name)
            logger.debug(f"ALLOWED: {self.tool_name}")
            return self.tool(**kwargs)
        except UnauthorizedToolCallError:
            raise  # Re-raise authorization errors as-is
        except Exception as e:
            logger.error(f"Exception in {self.tool_name}: {type(e).__name__}: {e}")
            raise

    def __repr__(self) -> str:
        return f"TenuoToolWrapper({self.tool_name})"


def wrap_tools(
    tools: dict[str, Callable],
    warrants: dict[str, Warrant],
    holder_key: SigningKey,
    metrics: AuthorizationMetrics = None,
    opaque_errors: bool = True,
) -> tuple[dict[str, TenuoToolWrapper], AuthorizationMetrics]:
    """
    Wrap multiple tools with Tenuo authorization.

    Args:
        tools: Dict mapping tool names to tool functions
        warrants: Dict mapping tool names to warrants
        holder_key: Key to create PoP signatures
        metrics: Optional shared metrics tracker
        opaque_errors: If True (default), return generic "Unauthorized" errors.
                      If False, return helpful errors with constraint details.

    Returns:
        Tuple of (wrapped tools dict, metrics tracker)
    """
    if metrics is None:
        metrics = AuthorizationMetrics()

    wrapped = {}
    for tool_name, tool in tools.items():
        # Handle case mismatch (AgentDojo runtime uses snake_case, Class names using CamelCase)
        warrant = warrants.get(tool_name)
        if not warrant:
            # Try lowercase lookup if exact match fails
            warrant = warrants.get(tool_name.lower())

        if not warrant:
            # Skip tools without warrants (won't be accessible)
            continue

        wrapped[tool_name] = TenuoToolWrapper(
            tool=tool,
            tool_name=tool_name,
            warrant=warrant,
            holder_key=holder_key,
            metrics=metrics,
            opaque_errors=opaque_errors,
        )

    return wrapped, metrics
