"""Proof-of-Possession argument normalization and pre-validation.

The actual PoP signature is computed in the Rust core via ``Warrant.sign``.
This module provides Python-side helpers that run *before* the FFI boundary:
argument normalization (so dataclasses / nested dicts don't trip the Rust CBOR
encoder) and warrant pre-validation (so we surface a clear error instead of a
cryptic core-side failure).
"""

from __future__ import annotations

import base64
import dataclasses as _dataclasses
import json
import logging
from typing import Any, Dict, List, Optional, Sequence

from tenuo.temporal.exceptions import (
    TenuoArgNormalizationError,
    TenuoPreValidationError,
)

logger = logging.getLogger("tenuo.temporal")


def _args_dict_uses_only_positional_fallback_keys(args_dict: Dict[str, Any]) -> bool:
    """True if every key is arg0, arg1, ... (PoP positional fallback)."""
    if not args_dict:
        return False
    for k in args_dict:
        if not (k.startswith("arg") and k[3:].isdigit()):
            return False
    return True


def _warrant_tool_has_non_empty_field_constraints(warrant: Any, tool_name: str) -> bool:
    """True if the warrant attaches at least one field-level constraint to this tool."""
    try:
        gc = getattr(warrant, "get_constraints", None)
        if callable(gc):
            c = gc(tool_name)
            if isinstance(c, dict) and len(c) > 0:
                return True
    except Exception:
        pass
    try:
        caps = getattr(warrant, "capabilities", None)
        if isinstance(caps, dict):
            fields = caps.get(tool_name)
            if isinstance(fields, dict) and len(fields) > 0:
                return True
    except Exception:
        pass
    return False


def _args_to_dict_by_fn(
    raw_args: Sequence[Any],
    activity_fn: Optional[Any],
) -> Dict[str, Any]:
    """Map positional activity args to their parameter names.

    Uses ``inspect.signature`` when a function reference is available, otherwise
    (and for arguments beyond the declared parameters) falls back to ``arg0``,
    ``arg1``, ... — matching the inbound interceptor's convention.
    """
    import inspect

    result: Dict[str, Any] = {}
    params: List[str] = []

    if activity_fn is not None:
        try:
            sig = inspect.signature(activity_fn)
            for pname, p in sig.parameters.items():
                if p.kind in (
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                ):
                    continue
                if pname == "self":
                    continue
                params.append(pname)
        except (ValueError, TypeError):
            pass

    for i, arg in enumerate(raw_args):
        if i < len(params):
            result[params[i]] = arg
        else:
            result[f"arg{i}"] = arg

    return result


# ---------------------------------------------------------------------------
# PoP arg normalization — Fix for FINDING-002 (loan-underwriting dogfooding)
# ---------------------------------------------------------------------------
# Tenuo's PoP signing runs inside the Temporal workflow sandbox. The Rust
# CBOR encoder (py_to_constraint_value in tenuo-core) only accepts primitive
# types: str, int, float, bool, list. Python dataclasses — idiomatic in
# Temporal activity signatures — would otherwise crash with:
#   ValueError: value must be str, int, float, bool, or list
#
# This layer normalizes non-primitive activity args to canonical JSON strings
# *before* warrant.sign() sees them. Normalization only affects what PoP signs;
# the activity still receives its original Python object via Temporal's data
# converter. Security properties are preserved:
#   - Invocation binding: json.dumps(sort_keys=True) is deterministic; same
#     input → same PoP bytes; substitution requires resigning with holder key.
#   - Constraint scoping: tenuo-core constraints operate on top-level arg names
#     only. Structural matching already requires lifting to primitive top-level
#     args. Stringification does not remove a capability that exists today.

_POP_NORMALIZE_MAX_DEPTH = 32


def _normalize_pop_arg_value(value: Any, field_name: str, depth: int = 0) -> Any:
    """Recursively normalize a single activity arg value for PoP signing.

    Primitives pass through unchanged. Dataclasses, dicts, lists, tuples,
    bytes, and None are normalized to representations the Rust CBOR encoder
    can accept. Anything else raises TenuoArgNormalizationError.
    """
    if depth > _POP_NORMALIZE_MAX_DEPTH:
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' exceeds maximum nesting depth "
            f"({_POP_NORMALIZE_MAX_DEPTH}) for PoP normalization. Flatten the "
            f"structure or lift individual fields to top-level primitive args. "
            f"See docs/temporal.md: 'Structured state in activity arguments'."
        )

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if _dataclasses.is_dataclass(value) and not isinstance(value, type):
        try:
            return json.dumps(_dataclasses.asdict(value), sort_keys=True, default=str, ensure_ascii=False)
        except Exception as exc:
            raise TenuoArgNormalizationError(
                f"Activity argument '{field_name}' is a dataclass but could not be "
                f"converted via dataclasses.asdict(): {exc}. "
                f"See docs/temporal.md: 'Structured state in activity arguments'."
            ) from exc

    if isinstance(value, dict):
        try:
            return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
        except Exception as exc:
            raise TenuoArgNormalizationError(
                f"Activity argument '{field_name}' is a dict but could not be "
                f"serialized: {exc}. "
                f"See docs/temporal.md: 'Structured state in activity arguments'."
            ) from exc

    if isinstance(value, (list, tuple)):
        normalized = [
            _normalize_pop_arg_value(item, f"{field_name}[{i}]", depth + 1)
            for i, item in enumerate(value)
        ]
        if all(isinstance(item, (str, int, float, bool, type(None))) for item in normalized):
            return normalized
        try:
            return json.dumps(normalized, sort_keys=True, default=str, ensure_ascii=False)
        except Exception as exc:
            raise TenuoArgNormalizationError(
                f"Activity argument '{field_name}' (list/tuple) could not be "
                f"serialized: {exc}. "
                f"See docs/temporal.md: 'Structured state in activity arguments'."
            ) from exc

    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")

    type_name = type(value).__qualname__
    raise TenuoArgNormalizationError(
        f"Activity argument '{field_name}' has type '{type_name}' which cannot "
        f"be normalized for PoP signing. Supported types: str, int, float, bool, "
        f"None, bytes, list, tuple, dict, and @dataclass. For {type_name}: "
        f"convert to a @dataclass or dict, or lift the relevant fields to "
        f"top-level primitive arguments with explicit constraints. "
        f"See docs/temporal.md: 'Structured state in activity arguments'."
    )


def _normalize_args_for_pop(args_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize all values in an activity args dict for PoP signing.

    Returns a new dict with the same keys and normalized values. Logs a
    debug message listing which fields were normalized (field names + type/size
    only — values are not logged as they may be PII).
    """
    normalized: Dict[str, Any] = {}
    normalized_fields: List[str] = []
    primitive_fields: List[str] = []
    for fname, value in args_dict.items():
        norm = _normalize_pop_arg_value(value, fname)
        normalized[fname] = norm
        if norm is not value:
            normalized_fields.append(f"{fname}=<{type(value).__name__}, {len(str(norm))} chars>")
        else:
            primitive_fields.append(f"{fname}=<primitive>")
    if normalized_fields:
        logger.debug(
            "PoP args normalized: %s",
            ", ".join(normalized_fields + primitive_fields),
        )
    return normalized


# ---------------------------------------------------------------------------
# Warrant pre-validation — Fix for FINDING-004 (loan-underwriting dogfooding)
# ---------------------------------------------------------------------------

def _prevalidate_args_against_warrant(
    warrant: Any,
    tool_name: str,
    args_dict: Dict[str, Any],
) -> None:
    """Pre-validate activity args against the warrant before PoP signing.

    Raises TenuoPreValidationError listing ALL unknown and missing fields in
    one shot if any are found. If the tool is not in the warrant, or the
    capability is in allow-unknown mode, this function is a no-op.
    """
    try:
        caps = getattr(warrant, "capabilities", None)
        if not isinstance(caps, dict):
            return
        tool_cap = caps.get(tool_name)
        if not isinstance(tool_cap, dict):
            return
        if not tool_cap:
            return
    except Exception:
        return

    declared_fields = set(tool_cap.keys())
    actual_fields = set(args_dict.keys())

    unknown = sorted(actual_fields - declared_fields)
    missing = sorted(declared_fields - actual_fields)

    if not unknown and not missing:
        return

    parts: List[str] = []
    if unknown:
        fields_str = ", ".join(unknown)
        parts.append(
            f"unknown field not allowed (zero-trust mode): {fields_str}"
        )
    if missing:
        fields_str = ", ".join(missing)
        parts.append(f"missing required fields: {fields_str}")

    raise TenuoPreValidationError(
        f"Warrant pre-validation failed for activity '{tool_name}'. "
        + "; ".join(parts)
        + ". Declare all argument names in the warrant capability or use "
        "Wildcard() for fields that don't need structural constraints. "
        "See docs/temporal.md: 'Zero-trust closed-world rule'."
    )


def _positional_pop_mismatch_message(
    tool_name: str,
    *,
    strict_mode: bool,
) -> str:
    action = "configured incorrectly" if not strict_mode else "blocked (strict_mode=True)"
    return (
        f"PoP signing for activity {tool_name!r} uses positional argument keys "
        f"(arg0, arg1, ...) but this warrant has named field constraints for that "
        f"tool. Constraint and PoP verification expect real parameter names "
        f"(e.g. path=...), not argN. Worker {action}: pass "
        f"activity_fns=<same list as Worker(activities=...)> in TenuoPluginConfig, "
        f"or call the activity via tenuo_execute_activity() so the function "
        f"reference is available. See tenuo.temporal module docstring: "
        f"'Activity registry (activity_fns) and PoP argument names'."
    )
