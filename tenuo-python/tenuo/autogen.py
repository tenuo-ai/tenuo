"""
Tenuo AutoGen (AgentChat) Integration

This module provides guardrails for AutoGen AgentChat tools:
- Tier 1: constraint-only guardrails (no crypto)
- Tier 2: warrant + Proof-of-Possession (BoundWarrant.validate)
- Streaming TOCTOU protection (buffer-verify-emit)

AutoGen is optional; importing this module does not require the dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
import functools
import importlib.util
import inspect
import json
import logging
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from .exceptions import (
    AuthorizationDenied,
    ConfigurationError,
    ConstraintResult,
    ConstraintViolation,
    ExpiredError,
    MissingSigningKey,
    ToolNotAuthorized,
)
from .validation import ValidationResult
from ._enforcement import EnforcementResult, handle_denial

# Optional AutoGen availability check (best-effort, for feature detection only)
AUTOGEN_AVAILABLE = importlib.util.find_spec("autogen_agentchat") is not None

logger = logging.getLogger("tenuo.autogen")


def _resolve_tool_name(tool: Any, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    name = getattr(tool, "name", None)
    if isinstance(name, str) and name:
        return name
    fn_name = getattr(tool, "__name__", None)
    if isinstance(fn_name, str) and fn_name:
        return fn_name
    return tool.__class__.__name__


def _extract_auth_args(fn: Any, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    # Common pattern: single dict payload
    if len(args) == 1 and not kwargs and isinstance(args[0], dict):
        return dict(args[0])

    # Pydantic v2 models / dataclasses / objects with dict-like export
    if len(args) == 1 and not kwargs:
        obj = args[0]
        if hasattr(obj, "model_dump") and callable(getattr(obj, "model_dump")):
            try:
                return dict(obj.model_dump())  # type: ignore[attr-defined]
            except Exception:
                pass
        if hasattr(obj, "__dict__"):
            try:
                return dict(obj.__dict__)
            except Exception:
                pass

    # Best effort: bind positional + keyword args to signature
    try:
        sig = inspect.signature(fn)
        bound = sig.bind_partial(*args, **kwargs)
        return {k: v for k, v in bound.arguments.items() if k != "self"}
    except Exception:
        pass

    # Fallback: merge kwargs with positional indices
    merged: Dict[str, Any] = dict(kwargs)
    for i, v in enumerate(args):
        merged.setdefault(f"arg{i}", v)
    return merged


def _raise_from_denial(bound: Any, tool_name: str, auth_args: Dict[str, Any]) -> None:
    # Tool not in warrant.tools
    try:
        tools = getattr(bound, "tools", None)
        if isinstance(tools, list) and tool_name not in tools:
            raise ToolNotAuthorized(
                tool=tool_name,
                authorized_tools=tools,
                hint=f"Add Capability('{tool_name}', ...) to your mint() call",
            )
    except ToolNotAuthorized:
        raise
    except Exception:
        pass

    why = None
    try:
        why = bound.why_denied(tool_name, auth_args)
    except Exception:
        why = None

    constraint_results: list[ConstraintResult] = []
    if why is not None and hasattr(why, "constraint_failures") and getattr(why, "constraint_failures"):
        try:
            for field, info in why.constraint_failures.items():  # type: ignore[union-attr]
                constraint_results.append(
                    ConstraintResult(
                        name=field,
                        passed=False,
                        constraint_repr=str(info.get("expected", "?")),
                        value=auth_args.get(field, "<not provided>"),
                        explanation=str(info.get("reason", "Constraint not satisfied")),
                    )
                )
        except Exception:
            constraint_results = []

    if not constraint_results:
        for k, v in auth_args.items():
            constraint_results.append(
                ConstraintResult(
                    name=k,
                    passed=False,
                    constraint_repr="<see warrant>",
                    value=v,
                    explanation="Value does not satisfy constraint",
                )
            )

    hint = getattr(why, "suggestion", None) if why is not None else None
    raise AuthorizationDenied(
        tool=tool_name,
        constraint_results=constraint_results,
        reason="Arguments do not satisfy warrant constraints",
        hint=hint,
    )


def _ensure_authorized_bound(bound: Any, tool_name: str, auth_args: Dict[str, Any]) -> None:
    """
    Tier 2 authorization using BoundWarrant.validate() (PoP required).
    Propagates core errors (MissingSigningKey, ExpiredError, SignatureInvalid, etc.).
    """
    validate = getattr(bound, "validate", None)
    if not callable(validate):
        raise AuthorizationDenied(
            tool=tool_name,
            reason="Bound warrant does not support validate()",
            constraint_results=[],
        )

    result: ValidationResult = validate(tool_name, auth_args)
    if result:
        return

    _raise_from_denial(bound, tool_name, auth_args)


def _check_constraints(
    tool_name: str,
    constraints: Optional[Dict[str, Any]],
    auth_args: Dict[str, Any],
) -> None:
    """
    Tier 1 constraint enforcement (closed-world).
    Unknown args are rejected; missing required args are rejected.
    """
    if constraints is None:
        raise ToolNotAuthorized(tool=tool_name)

    if not constraints:
        if auth_args:
            field = next(iter(auth_args))
            raise ConstraintViolation(
                field=field,
                reason="Argument not allowed",
                value=auth_args[field],
            )
        return

    # Unknown arguments
    for key in auth_args:
        if key not in constraints:
            raise ConstraintViolation(field=key, reason="Argument not allowed", value=auth_args[key])

    # Required arguments + constraint checks
    for key, constraint in constraints.items():
        if key not in auth_args:
            raise ConstraintViolation(field=key, reason="Missing required argument")
        value = auth_args[key]
        if not hasattr(constraint, "satisfies") or not callable(getattr(constraint, "satisfies")):
            raise ConstraintViolation(field=key, reason="Invalid constraint type", value=value)
        try:
            if not constraint.satisfies(value):  # type: ignore[call-arg]
                raise ConstraintViolation(
                    field=key,
                    reason=f"Value does not satisfy {constraint}",
                    value=value,
                )
        except ConstraintViolation:
            raise
        except Exception as e:  # pragma: no cover - defensive
            raise ConstraintViolation(field=key, reason=str(e), value=value)


@dataclass
class _ToolProxy:
    wrapped: Any
    guard: "_Guard"
    tool_name: str

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        auth_args = _extract_auth_args(self.wrapped, args, kwargs)
        return self.guard._execute_call(self.wrapped, self.tool_name, auth_args, args, kwargs)

    def __getattr__(self, item: str) -> Any:
        return getattr(self.wrapped, item)


class GuardBuilder:
    """
    Builder for AutoGen guardrails (Tier 1 + Tier 2).

    API:
        GuardBuilder()
            .allow("tool", arg=Constraint)
            .on_denial("raise"|"log"|"skip")
            .with_warrant(warrant, signing_key)  # Tier 2
            .build()
    """

    def __init__(self) -> None:
        self._constraints: Dict[str, Dict[str, Any]] = {}
        self._warrant = None
        self._signing_key = None
        self._on_denial: str = "raise"

    def allow(self, tool: str, **constraints: Any) -> "GuardBuilder":
        self._constraints[tool] = constraints
        return self

    def on_denial(self, mode: str) -> "GuardBuilder":
        if mode not in {"raise", "log", "skip"}:
            raise ValueError("on_denial must be one of: raise, log, skip")
        self._on_denial = mode
        return self

    def with_warrant(self, warrant: Any, signing_key: Optional[Any]) -> "GuardBuilder":
        self._warrant = warrant
        self._signing_key = signing_key
        return self

    def build(self) -> "_Guard":
        bound = None
        if self._warrant is not None:
            if self._signing_key is None:
                raise MissingSigningKey("Signing key is required for warrant-protected guard")

            # Warrant exposes authorized_holder (PublicKey)
            holder = getattr(self._warrant, "authorized_holder", None)
            pub_key = getattr(self._signing_key, "public_key", None)
            if holder is not None and pub_key is not None:
                mismatch = False
                try:
                    mismatch = holder != pub_key
                except Exception:
                    mismatch = str(holder) != str(pub_key)
                if mismatch:
                    raise ConfigurationError("Signing key does not match warrant holder")

            if hasattr(self._warrant, "is_expired") and self._warrant.is_expired():
                raise ExpiredError("Warrant is expired")

            bound = self._warrant.bind(self._signing_key)

        return _Guard(
            constraints=self._constraints,
            bound=bound,
            on_denial=self._on_denial,
        )


class _Guard:
    """
    Guard instance produced by GuardBuilder.
    Provides:
      - guard_tool / guard_tools
      - guard_stream (buffer-verify-emit)
    """

    def __init__(
        self,
        *,
        constraints: Dict[str, Dict[str, Any]],
        bound: Any,
        on_denial: str,
    ) -> None:
        self._constraints = constraints
        self._bound = bound
        self._on_denial = on_denial

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def guard_tool(self, fn_or_tool: Any, *, tool_name: Optional[str] = None) -> Any:
        resolved = _resolve_tool_name(fn_or_tool, tool_name)

        if callable(fn_or_tool) and inspect.isfunction(fn_or_tool):
            if inspect.iscoroutinefunction(fn_or_tool):

                @functools.wraps(fn_or_tool)
                async def async_wrapper(*args: Any, **kwargs: Any):
                    auth_args = _extract_auth_args(fn_or_tool, args, kwargs)
                    return await self._execute_call_async(fn_or_tool, resolved, auth_args, args, kwargs)

                return async_wrapper

            @functools.wraps(fn_or_tool)
            def wrapper(*args: Any, **kwargs: Any):
                auth_args = _extract_auth_args(fn_or_tool, args, kwargs)
                return self._execute_call(fn_or_tool, resolved, auth_args, args, kwargs)

            return wrapper

        if not callable(fn_or_tool):
            raise TypeError("guard_tool expects a callable or tool-like object")

        return _ToolProxy(wrapped=fn_or_tool, guard=self, tool_name=resolved)

    def guard_tools(
        self,
        tools: Union[Sequence[Any], Mapping[str, Any]],
        *,
        tool_name_fn: Optional[Callable[[Any], str]] = None,
    ) -> Union[list[Any], dict[str, Any]]:
        if isinstance(tools, Mapping):
            out: dict[str, Any] = {}
            for name, tool in tools.items():
                resolved_name_map = tool_name_fn(tool) if tool_name_fn else name
                out[name] = self.guard_tool(tool, tool_name=resolved_name_map)
            return out

        if isinstance(tools, Sequence):
            out_list: list[Any] = []
            for tool in tools:
                resolved_name_list = tool_name_fn(tool) if tool_name_fn else None
                out_list.append(self.guard_tool(tool, tool_name=resolved_name_list))
            return out_list

        raise TypeError("guard_tools expects a list/tuple of tools or a dict of name->tool")

    def guard_stream(self, stream: Iterable[Any]) -> Iterable[Any]:
        """
        Buffer-verify-emit streaming defense (TOCTOU safe).
        Expects chunks with .choices[].delta.tool_calls[].function.arguments (string).
        """
        pending_chunks: list[Any] = []
        arg_buffers: Dict[str, list[str]] = {}
        tool_names: Dict[str, str] = {}

        def _call_id(tc: Any) -> str:
            return str(getattr(tc, "id", None) or getattr(tc, "index", "0"))

        for chunk in stream:
            pending_chunks.append(chunk)

            # Collect tool call deltas
            for choice in getattr(chunk, "choices", []) or []:
                delta = getattr(choice, "delta", None)
                if delta is None:
                    continue
                for tc in getattr(delta, "tool_calls", []) or []:
                    cid = _call_id(tc)
                    func = getattr(tc, "function", None)
                    name = getattr(func, "name", None) if func else None
                    args_piece = getattr(func, "arguments", "") if func else ""
                    if name:
                        tool_names[cid] = name
                    if cid not in arg_buffers:
                        arg_buffers[cid] = []
                    if args_piece:
                        arg_buffers[cid].append(args_piece)

            finished = any(
                getattr(choice, "finish_reason", None) == "tool_calls" for choice in getattr(chunk, "choices", []) or []
            )

            if not finished:
                continue

            # Validate complete args for each buffered tool call
            invalid_ids: set[str] = set()
            final_args: Dict[str, Dict[str, Any]] = {}

            for cid, pieces in arg_buffers.items():
                complete = "".join(pieces)
                name = tool_names.get(cid, "")
                try:
                    args_dict = json.loads(complete) if complete else {}
                except Exception as e:
                    if self._on_denial == "skip":
                        invalid_ids.add(cid)
                        logger.warning(
                            "Failed to parse tool args (%s): %s",
                            name or cid,
                            e,
                        )
                        continue
                    raise ConstraintViolation(
                        field="arguments",
                        reason="Invalid JSON",
                        value=complete,
                    )

                try:
                    self._authorize(name, args_dict)
                    final_args[cid] = {"name": name, "args": args_dict}
                except (
                    AuthorizationDenied,
                    ConstraintViolation,
                    ToolNotAuthorized,
                ) as e:
                    if self._on_denial == "raise":
                        raise
                    if self._on_denial == "log":
                        logger.warning("Denied tool call %s (%s): %s", cid, name, e)
                    invalid_ids.add(cid)

            # Mutate buffered chunks: drop invalid tool calls on skip/log, set full args on valid ones
            for buffered in pending_chunks:
                for choice in getattr(buffered, "choices", []) or []:
                    delta = getattr(choice, "delta", None)
                    if delta is None:
                        continue
                    tool_calls = getattr(delta, "tool_calls", None)
                    if tool_calls is None:
                        continue
                    kept_calls = []
                    for tc in tool_calls:
                        cid = _call_id(tc)
                        if cid in invalid_ids:
                            continue  # filtered out
                        if cid in final_args:
                            func = getattr(tc, "function", None)
                            if func is not None:
                                full = json.dumps(final_args[cid]["args"])
                                try:
                                    func.arguments = full
                                except Exception:
                                    pass
                        kept_calls.append(tc)
                    delta.tool_calls = kept_calls

            # Emit buffered chunks and reset
            for buffered in pending_chunks:
                yield buffered

            pending_chunks = []
            arg_buffers = {}
            tool_names = {}

        # Emit any remaining buffered chunks (non-tool content)
        for buffered in pending_chunks:
            yield buffered

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _authorize(self, tool_name: str, auth_args: Dict[str, Any]) -> None:
        if self._bound is not None:
            _ensure_authorized_bound(self._bound, tool_name, auth_args)
            return
        constraints = self._constraints.get(tool_name)
        _check_constraints(tool_name, constraints, auth_args)

    def _handle_denial(
        self,
        exc: Exception,
        fn: Callable[..., Any],
        args: Tuple[Any, ...],
        kwargs: Dict[str, Any],
        *,
        is_async: bool,
    ) -> Any:
        """Handle denial using shared enforcement logic."""
        # Create pseudo-result for shared handler
        tool_name = getattr(fn, "__name__", "unknown")
        pseudo_result = EnforcementResult(
            allowed=False,
            tool=tool_name,
            arguments=kwargs,
            denial_reason=str(exc),
            error_type=type(exc).__name__.lower(),
        )
        handle_denial(
            pseudo_result,
            self._on_denial,
            exception_factory=lambda _: exc,
        )
        return None

    def _execute_call(
        self,
        fn: Callable[..., Any],
        tool_name: str,
        auth_args: Dict[str, Any],
        args: Tuple[Any, ...],
        kwargs: Dict[str, Any],
    ) -> Any:
        try:
            self._authorize(tool_name, auth_args)
        except (
            AuthorizationDenied,
            ConstraintViolation,
            ToolNotAuthorized,
        ) as exc:
            return self._handle_denial(exc, fn, args, kwargs, is_async=False)
        return fn(*args, **kwargs)

    async def _execute_call_async(
        self,
        fn: Callable[..., Any],
        tool_name: str,
        auth_args: Dict[str, Any],
        args: Tuple[Any, ...],
        kwargs: Dict[str, Any],
    ) -> Any:
        try:
            self._authorize(tool_name, auth_args)
        except (
            AuthorizationDenied,
            ConstraintViolation,
            ToolNotAuthorized,
        ) as exc:
            result = self._handle_denial(exc, fn, args, kwargs, is_async=True)
            if inspect.isawaitable(result):
                return await result
            return result
        return await fn(*args, **kwargs)


def guard_tool(fn_or_tool: Any, bound: Any, *, tool_name: Optional[str] = None) -> Any:
    """
    Guard a single tool/callable with Tenuo authorization using an explicit BoundWarrant.
    """
    guard = _Guard(constraints={}, bound=bound, on_denial="raise")
    return guard.guard_tool(fn_or_tool, tool_name=tool_name)


def guard_tools(
    tools: Union[Sequence[Any], Mapping[str, Any]],
    bound: Any,
    *,
    tool_name_fn: Optional[Callable[[Any], str]] = None,
) -> Union[list[Any], dict[str, Any]]:
    """
    Guard a collection of tools using a BoundWarrant (Tier 2).
    """
    guard = _Guard(constraints={}, bound=bound, on_denial="raise")
    return guard.guard_tools(tools, tool_name_fn=tool_name_fn)


def protect(
    tools: Union[Sequence[Any], Mapping[str, Any]],
    **tool_constraints: Any,
) -> Union[list[Any], dict[str, Any]]:
    """
    Zero-config helper: wraps tools with constraint-only GuardBuilder.

    Usage:
        protected = protect([search], search=Pattern("ok*"))
        protected = protect({"search": search}, search={"query": Pattern("ok*")})
    """
    builder = GuardBuilder()

    def _infer_param_name(tool: Any) -> str:
        try:
            sig = inspect.signature(tool)
            for name in sig.parameters:
                if name != "self":
                    return name
        except Exception:
            pass
        return "arg0"

    if isinstance(tools, Mapping):
        tools_map = dict(tools)
    else:
        tools_map = {_resolve_tool_name(t): t for t in tools}

    for tool_name, constraint_spec in tool_constraints.items():
        constraint_dict: Dict[str, Any]
        if isinstance(constraint_spec, dict):
            constraint_dict = constraint_spec
        else:
            tool = tools_map.get(tool_name)
            param = _infer_param_name(tool) if tool is not None else "arg0"
            constraint_dict = {param: constraint_spec}
        builder.allow(tool_name, **constraint_dict)

    guard = builder.build()
    return guard.guard_tools(tools)


__all__ = [
    "GuardBuilder",
    "guard_tool",
    "guard_tools",
    "protect",
    "AUTOGEN_AVAILABLE",
]
