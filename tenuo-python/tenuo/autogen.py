"""
Tenuo AutoGen (AgentChat) Integration

This module provides guardrails for AutoGen AgentChat tools:
- Tier 1: constraint-only guardrails (no crypto)
- Tier 2: warrant + Proof-of-Possession (BoundWarrant.validate)
- Streaming TOCTOU protection (buffer-verify-emit)

AutoGen is optional; importing this module does not require the dependency.
"""

from __future__ import annotations

import functools
import importlib.util
import inspect
import json
import logging
from dataclasses import dataclass
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

from ._builder import BaseGuardBuilder
from ._enforcement import (
    EnforcementResult,
    _enforcement_result_from_chain_error,
    enforce_tool_call,
    enforce_tool_call_async,
    handle_denial,
    split_presented_warrant,
)
from .config import resolve_trusted_roots
from .exceptions import (
    AuthorizationDenied,
    ConfigurationError,
    ConstraintViolation,
    InsufficientApprovals,
    ToolNotAuthorized,
)

# Optional AutoGen availability check (best-effort, for feature detection only)
AUTOGEN_AVAILABLE = importlib.util.find_spec("autogen_agentchat") is not None

logger = logging.getLogger("tenuo.autogen")


_TOOL_NOT_AUTH_PATTERNS = (
    "not in warrant",
    "does not authorize tool",
    "tool not in warrant",
    "tool not granted",
    "not authorized to call",
)


def _is_tool_not_authorized(denial_reason: str) -> bool:
    """Return True if the denial reason indicates the tool is not in the warrant.

    Clearance, constraint, and PoP failures are intentionally excluded — they
    fall through to ``AuthorizationDenied``, not ``ToolNotAuthorized``.
    """
    low = denial_reason.lower()
    return any(p in low for p in _TOOL_NOT_AUTH_PATTERNS)


# Attribute carrying the EnforcementResult behind a Tier 2 denial, so the
# on_denial="log"/"skip" record reports what was actually checked.
_RESULT_ATTR = "_tenuo_enforcement_result"


def _constraint_repr(bound: Any, tool_name: str, field: str) -> str:
    """Best-effort repr of the warrant constraint on ``field`` for ``tool_name``."""
    try:
        constraint = (bound.capabilities.get(tool_name) or {}).get(field)
    except Exception:
        constraint = None
    return repr(constraint) if constraint is not None else "<see warrant>"


def _denial_exception(
    tool_name: str,
    auth_args: Dict[str, Any],
    result: EnforcementResult,
    bound: Any,
) -> Exception:
    """Map a denied Tier 2 ``EnforcementResult`` to the exception AutoGen raises."""
    from .exceptions import ConstraintResult, ExpiredError

    exc: Exception
    if result.error_type == "expired":
        exc = ExpiredError(result.warrant_id or "unknown")
    elif result.error_type == "tool_not_allowed":
        exc = ToolNotAuthorized(tool=tool_name)
    elif result.error_type == "clearance_insufficient":
        exc = AuthorizationDenied(
            tool=tool_name,
            constraint_results=[],
            reason=result.denial_reason or "Insufficient clearance",
        )
    elif _is_tool_not_authorized(result.denial_reason or ""):
        # Handle tool not in warrant from Rust Authorizer messages
        exc = ToolNotAuthorized(tool=tool_name)
    elif result.error_type == "insufficient_approvals":
        meta = result.approval_metadata or {}
        exc = InsufficientApprovals(
            required=meta.get("need", 0),
            received=meta.get("got", 0),
            detail=result.denial_reason or "",
        )
    else:
        # Default to AuthorizationDenied for constraint violations and others
        constraint_results = []
        if result.constraint_violated:
            constraint_results.append(
                ConstraintResult(
                    name=result.constraint_violated,
                    passed=False,
                    constraint_repr=_constraint_repr(bound, tool_name, result.constraint_violated),
                    value=auth_args.get(result.constraint_violated, "<unknown>"),
                    explanation=result.denial_reason or "Constraint not satisfied",
                )
            )
        exc = AuthorizationDenied(
            tool=tool_name,
            constraint_results=constraint_results,
            reason=result.denial_reason or "Authorization denied",
        )
    setattr(exc, _RESULT_ATTR, result)
    return exc


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


class GuardBuilder(BaseGuardBuilder["GuardBuilder"]):
    """
    Builder for AutoGen guardrails (Tier 1 + Tier 2).

    Inherits common functionality from BaseGuardBuilder:
    - allow(tool, **constraints) - Register tool with constraints
    - with_warrant(warrant, signing_key) - Enable Tier 2
    - on_denial(mode) - Set denial handling

    API:
        GuardBuilder()
            .allow("tool", arg=Constraint)
            .on_denial("raise"|"log"|"skip")
            .with_warrant(warrant, signing_key)  # Tier 2
            .build()

    For a delegated warrant, pass its parents so the chain verifies back to
    a trusted root: ``.with_warrant(leaf, key, warrant_chain=[root])``, or
    pass the whole chain as one token (an encoded WarrantStack string or a
    root-first list of warrants) as ``warrant``.
    """

    def __init__(self) -> None:
        super().__init__()

    def build(self) -> "_Guard":
        bound = self._get_bound_warrant()
        return _Guard(
            constraints=self._constraints,
            bound=bound,
            warrant_chain=self._warrant_chain,
            trusted_roots=self._trusted_roots,
            on_denial=self._on_denial,
            approval_handler=self._approval_handler,
            approvals=self._approvals,
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
        warrant_chain: Optional[Sequence[Any]] = None,
        trusted_roots: Any = None,
        on_denial: str,
        approval_handler: Any = None,
        approvals: Any = None,
    ) -> None:
        self._constraints = constraints
        self._bound = bound
        # Parents of a delegated warrant (root-first, excluding the leaf).
        # None leaves any ambient chain_scope() in effect.
        self._warrant_chain = list(warrant_chain) if warrant_chain else None
        self._trusted_roots = trusted_roots
        self._on_denial = on_denial
        self._approval_handler = approval_handler
        self._approvals = approvals

        from .control_plane import get_or_create
        self._control_plane = get_or_create()

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
            from tenuo.arguments import parse_strict_json

            for cid, pieces in arg_buffers.items():
                complete = "".join(pieces)
                name = tool_names.get(cid, "")
                try:
                    args_dict = parse_strict_json(complete) if complete else {}
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
        """
        Authorize a tool call.

        Tier 2 (with bound warrant): Uses shared enforce_tool_call()
        Tier 1 (no warrant): Uses _check_constraints() for closed-world enforcement
        """
        if self._bound is not None:
            # Tier 2: Use shared enforcement logic
            result = enforce_tool_call(
                tool_name, auth_args, self._bound,
                trusted_roots=resolve_trusted_roots(self._trusted_roots),
                warrant_chain=self._warrant_chain,
                approval_handler=self._approval_handler,
                approvals=self._approvals,
            )

            if self._control_plane is not None:
                try:
                    self._control_plane.emit_for_enforcement(result, chain_result=result.chain_result)
                except Exception:
                    logger.warning("Control plane emission failed for '%s'; audit event lost", tool_name, exc_info=True)

            if not result.allowed:
                raise _denial_exception(tool_name, auth_args, result, self._bound)
            return

        # Tier 1: Constraint-only enforcement (no warrant)
        constraints = self._constraints.get(tool_name)
        _check_constraints(tool_name, constraints, auth_args)

    async def _authorize_async(self, tool_name: str, auth_args: Dict[str, Any]) -> None:
        """Async variant of _authorize — uses enforce_tool_call_async for Tier 2."""
        if self._bound is not None:
            result = await enforce_tool_call_async(
                tool_name, auth_args, self._bound,
                trusted_roots=resolve_trusted_roots(self._trusted_roots),
                warrant_chain=self._warrant_chain,
                approval_handler=self._approval_handler,
                approvals=self._approvals,
            )

            if self._control_plane is not None:
                try:
                    self._control_plane.emit_for_enforcement(result, chain_result=result.chain_result)
                except Exception:
                    logger.warning("Control plane emission failed for '%s'; audit event lost", tool_name, exc_info=True)

            if not result.allowed:
                raise _denial_exception(tool_name, auth_args, result, self._bound)
            return

        constraints = self._constraints.get(tool_name)
        _check_constraints(tool_name, constraints, auth_args)

    def _handle_denial(
        self,
        exc: Exception,
        tool_name: str,
        auth_args: Dict[str, Any],
    ) -> Any:
        """Handle denial using shared enforcement logic."""
        # Tier 2 denials carry the real EnforcementResult; Tier 1 denials are
        # mapped with the same shared helper the enforcement path uses.
        result = getattr(exc, _RESULT_ATTR, None)
        if not isinstance(result, EnforcementResult):
            result = _enforcement_result_from_chain_error(
                exc,
                tool_name,
                auth_args,
                getattr(self._bound, "id", None),
            )
        handle_denial(
            result,
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
            return self._handle_denial(exc, tool_name, auth_args)
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
            await self._authorize_async(tool_name, auth_args)
        except (
            AuthorizationDenied,
            ConstraintViolation,
            ToolNotAuthorized,
        ) as exc:
            return self._handle_denial(exc, tool_name, auth_args)
        return await fn(*args, **kwargs)


def _split_bound(bound: Any, warrant_chain: Optional[Sequence[Any]]) -> Tuple[Any, Optional[list]]:
    """Split ``bound`` (a BoundWarrant or root-first list ending in one) into leaf and parents."""
    from .bound_warrant import BoundWarrant

    leaf, parents = split_presented_warrant(bound, warrant_chain)
    if isinstance(bound, (str, list, tuple)) and not isinstance(leaf, BoundWarrant):
        raise ConfigurationError(
            "The leaf of the presented chain must be a BoundWarrant (warrant.bind(key)). "
            "To pass a WarrantStack string, use GuardBuilder().with_warrant(token, signing_key)."
        )
    return leaf, parents


def guard_tool(
    fn_or_tool: Any,
    bound: Any,
    *,
    tool_name: Optional[str] = None,
    warrant_chain: Optional[Sequence[Any]] = None,
) -> Any:
    """
    Guard a single tool/callable with Tenuo authorization using an explicit BoundWarrant.

    For a delegated warrant, pass its parents (root-first, excluding the leaf)
    as ``warrant_chain``, or pass ``bound`` as a root-first list whose last
    element is the BoundWarrant leaf.
    """
    leaf, parents = _split_bound(bound, warrant_chain)
    guard = _Guard(constraints={}, bound=leaf, warrant_chain=parents, on_denial="raise")
    return guard.guard_tool(fn_or_tool, tool_name=tool_name)


def guard_tools(
    tools: Union[Sequence[Any], Mapping[str, Any]],
    bound: Any,
    *,
    tool_name_fn: Optional[Callable[[Any], str]] = None,
    warrant_chain: Optional[Sequence[Any]] = None,
) -> Union[list[Any], dict[str, Any]]:
    """
    Guard a collection of tools using a BoundWarrant (Tier 2).

    ``bound`` and ``warrant_chain`` accept the same chain forms as guard_tool().
    """
    leaf, parents = _split_bound(bound, warrant_chain)
    guard = _Guard(constraints={}, bound=leaf, warrant_chain=parents, on_denial="raise")
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
