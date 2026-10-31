"""Proof-of-Possession argument normalization and pre-validation.

The actual PoP signature is computed in the Rust core via ``Warrant.sign``.
This module provides Python-side helpers that run *before* the FFI boundary:
argument normalization (so dataclasses / nested dicts don't trip the Rust CBOR
encoder) and warrant pre-validation (so we surface a clear error instead of a
cryptic core-side failure).
"""

from __future__ import annotations

import dataclasses as _dataclasses
import json
import logging
import math
from typing import Any, Dict, List, Optional, Sequence

from tenuo.temporal.exceptions import (
    TenuoArgNormalizationError,
    TenuoContextError,
    TenuoPreValidationError,
)

logger = logging.getLogger("tenuo.temporal")

WORKFLOW_NAMESPACE_ARG = "_workflow_namespace"
WORKFLOW_ID_ARG = "_workflow_id"
WORKFLOW_SCOPE_ARGS = frozenset({WORKFLOW_NAMESPACE_ARG, WORKFLOW_ID_ARG})
"""Reserved workflow-scope arguments filled from Temporal, never from the caller.

When a warrant's capability constrains both fields, the plugin adds the running
workflow's namespace and ID to the arguments it signs and verifies for that
tool. Capabilities that name neither field are unaffected. Naming only one is
rejected because a workflow ID is unique only within its Temporal namespace.
"""


def _add_workflow_scope(
    warrant: Any,
    tool_name: str,
    args: Dict[str, Any],
    workflow_namespace: Optional[str],
    workflow_id: Optional[str],
) -> Dict[str, Any]:
    """Add the Temporal workflow identity when the warrant constrains it.

    Both values come from Temporal (``workflow.info()`` when signing and
    ``activity.info()`` when verifying). Activity arguments may never use the
    reserved names, even when workflow scoping is not enabled for the warrant.
    """
    reserved_args = WORKFLOW_SCOPE_ARGS.intersection(args)
    if reserved_args:
        names = ", ".join(repr(name) for name in sorted(reserved_args))
        raise TenuoContextError(
            f"Activity argument name(s) {names} are reserved: the plugin fills them from the running Temporal workflow"
        )

    try:
        caps = warrant.capabilities
        # As core resolves a tool: its own capability, else the ``"*"`` one.
        fields = caps.get(tool_name, caps.get("*"))
    except Exception as exc:
        raise TenuoContextError(f"Cannot read the warrant's capabilities for {tool_name!r}") from exc

    if not isinstance(fields, dict):
        return args

    has_namespace = WORKFLOW_NAMESPACE_ARG in fields
    has_id = WORKFLOW_ID_ARG in fields
    if not has_namespace and not has_id:
        return args
    if has_namespace != has_id:
        raise TenuoContextError(
            f"Temporal workflow scoping for {tool_name!r} must constrain both "
            f"{WORKFLOW_NAMESPACE_ARG!r} and {WORKFLOW_ID_ARG!r}; a workflow ID "
            "is unique only within its namespace"
        )
    if not workflow_namespace or not workflow_id:
        raise TenuoContextError(f"Temporal did not provide a complete workflow identity for {tool_name!r}")

    return {
        **args,
        WORKFLOW_NAMESPACE_ARG: workflow_namespace,
        WORKFLOW_ID_ARG: workflow_id,
    }


def _validate_no_reserved_workflow_parameters(activity_fn: Optional[Any]) -> None:
    """Reject worker callables whose true signature uses reserved scope names.

    Header-based argument names are authenticated but can differ from the
    worker callable's parameter names. Inspect the callable independently so a
    header alias cannot hide a caller-supplied reserved argument.
    """
    if activity_fn is None:
        return

    import inspect

    try:
        parameter_names = inspect.signature(activity_fn).parameters.keys()
    except (TypeError, ValueError):
        return

    reserved_parameters = WORKFLOW_SCOPE_ARGS.intersection(parameter_names)
    if reserved_parameters:
        names = ", ".join(repr(name) for name in sorted(reserved_parameters))
        raise TenuoContextError(
            f"Activity parameter name(s) {names} are reserved: the plugin fills them from the running Temporal workflow"
        )


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
# Tenuo's PoP signing runs inside the Temporal workflow sandbox. This layer
# converts supported Python objects to the same plain JSON-compatible values
# the activity worker receives. Structured values remain objects/lists when
# passed to the Rust core; converting them to JSON text would let a literal
# string impersonate an object while retaining the same PoP.

_POP_NORMALIZE_MAX_DEPTH = 32
_POP_INT_MIN = -(2**63)
_POP_INT_MAX = 2**63 - 1


def _is_pydantic_model(value: Any) -> bool:
    """A Pydantic (v1 or v2) model instance, detected without importing pydantic."""
    if isinstance(value, type):
        return False
    return any(cls.__module__.startswith("pydantic") and cls.__name__ == "BaseModel" for cls in type(value).__mro__)


_MODEL_UNSIGNABLE = (
    "Its signed form would not cover what the activity receives: {why}. Pass "
    "those fields as separate arguments, or use a model without them."
)


def _pydantic_base_class(cls: type) -> Optional[type]:
    """Return the real Pydantic BaseModel in ``cls``'s MRO."""
    return next(
        (base for base in cls.__mro__ if base.__name__ == "BaseModel" and base.__module__.startswith("pydantic")),
        None,
    )


def _overridden_dump_method(cls: type, base: type) -> Optional[str]:
    """Return a serialization method overridden between ``cls`` and BaseModel."""
    names = (
        ("model_dump", "model_dump_json") if hasattr(base, "model_dump") else ("dict", "json", "_iter", "_get_value")
    )
    for name in names:
        for owner in cls.__mro__:
            if name in owner.__dict__:
                if owner is not base:
                    return name
                break
    return None


def _check_model_is_signable(model: Any, field_name: str) -> None:
    """Refuse a model whose JSON dump can omit or mask a value the activity receives.

    An excluded field, a custom serializer, or a secret type would let a payload
    change that value without changing the signed form.
    """
    cls = type(model)
    base = _pydantic_base_class(cls)
    if base is None:
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' claims to be a Pydantic model "
            "but has no Pydantic BaseModel implementation"
        )
    fields = getattr(cls, "model_fields", None)
    if fields is None:  # Pydantic v1
        fields = {name: getattr(field, "field_info", field) for name, field in getattr(cls, "__fields__", {}).items()}
    excluded = sorted(name for name, info in fields.items() if getattr(info, "exclude", None))
    included = sorted(name for name, info in fields.items() if getattr(info, "include", None) is not None)
    decorators = getattr(cls, "__pydantic_decorators__", None)
    serializers = bool(decorators and (decorators.field_serializers or decorators.model_serializers))
    config = getattr(cls, "__config__", None)  # Pydantic v1
    serializers = serializers or bool(getattr(config, "json_encoders", None))
    overridden = _overridden_dump_method(cls, base)
    secrets = sorted(name for name in fields if _is_secret(getattr(model, name, None)))
    name_collision = _pydantic_serialized_name_collision(model, fields)
    why = (
        f"excluded field(s) {', '.join(excluded)}"
        if excluded
        else f"inclusion-filtered field(s) {', '.join(included)}"
        if included
        else "a custom serializer"
        if serializers
        else f"an overridden {overridden}() method"
        if overridden
        else f"secret field(s) {', '.join(secrets)}"
        if secrets
        else name_collision
        if name_collision
        else _core_schema_hides_values(getattr(cls, "__pydantic_core_schema__", None))
    )
    if why:
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' is a Pydantic model {cls.__name__}. "
            + _MODEL_UNSIGNABLE.format(why=why)
            + " See docs/temporal-reference.md: 'Structured activity arguments'."
        )


def _pydantic_serialized_name_collision(
    model: Any,
    fields: Dict[str, Any],
) -> Optional[str]:
    """Describe a Pydantic v2 output-name collision, if any.

    Pydantic core can emit duplicate JSON object keys for colliding aliases and
    extras. Converting that output to a Python dict silently keeps one value,
    which is not an injective PoP representation.
    """
    if not hasattr(type(model), "model_fields"):
        return None  # Pydantic v1's supported dump uses field names.

    owners: Dict[str, str] = {}

    def add(serialized_name: Any, owner: str) -> Optional[str]:
        if not isinstance(serialized_name, str):
            return f"a non-string serialized name for {owner}"
        previous = owners.get(serialized_name)
        if previous is not None and previous != owner:
            return f"serialized name {serialized_name!r} is shared by {previous} and {owner}"
        owners[serialized_name] = owner
        return None

    for name, info in fields.items():
        alias = getattr(info, "serialization_alias", None)
        collision = add(
            name if alias is None else alias,
            f"field {name!r}",
        )
        if collision:
            return collision

    computed = getattr(type(model), "model_computed_fields", None) or {}
    for name, info in computed.items():
        alias = getattr(info, "alias", None)
        collision = add(
            name if alias is None else alias,
            f"computed field {name!r}",
        )
        if collision:
            return collision

    for name in getattr(model, "__pydantic_extra__", None) or {}:
        collision = add(name, f"extra field {name!r}")
        if collision:
            return collision
    return None


def _core_schema_hides_values(schema: Any) -> Optional[str]:
    """Why a Pydantic v2 schema's JSON dump can drop or rewrite a value, or None.

    The core schema records every serializer and exclusion, including annotated
    serializers, json_encoders, secret types and their subclasses, nested
    models and typed extras. Pydantic's own faithful ones (paths, IP
    addresses) live in pydantic._internal.
    """
    stack, seen = [schema], set()
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
            continue
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        if node.get("serialization_exclude") or node.get("serialization_exclude_if") is not None:
            return "an excluded field"
        if node.get("type") in ("set", "frozenset"):
            return "an unordered set field"
        serialization = node.get("serialization")
        if isinstance(serialization, dict) and str(serialization.get("type", "")).startswith("function"):
            module = getattr(serialization.get("function"), "__module__", "") or ""
            if not module.startswith("pydantic._internal"):
                return "a custom serializer or secret type"
        stack.extend(node.values())
    return None


def _is_secret(value: Any) -> bool:
    return any(cls.__name__ in ("SecretStr", "SecretBytes", "Secret") for cls in type(value).__mro__)


def _check_signable_tree(value: Any, field_name: str, depth: int = 0) -> None:
    """Check every model inside a value before any of it is dumped.

    Dumping an outer model drops a nested model's excluded fields and masks its
    secrets, so the nested model has to be checked while it is still a model.
    """
    if depth > _POP_NORMALIZE_MAX_DEPTH:
        return  # _jsonable reports the depth error
    if _is_secret(value):
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' contains a secret value. "
            + _MODEL_UNSIGNABLE.format(why="a secret value")
            + " See docs/temporal-reference.md: 'Structured activity arguments'."
        )
    if _is_pydantic_model(value):
        _check_model_is_signable(value, field_name)
        # Field values and allowed extras (v2 keeps extras apart; v1 in __dict__).
        children: Any = [
            *vars(value).values(),
            *(getattr(value, "__pydantic_extra__", None) or {}).values(),
        ]
    elif _dataclasses.is_dataclass(value) and not isinstance(value, type):
        children = [getattr(value, f.name) for f in _dataclasses.fields(value)]
    elif isinstance(value, dict):
        children = value.values()
    elif isinstance(value, (set, frozenset)):
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' contains an unordered "
            f"{type(value).__name__}. Use a list with a stable order. "
            "See docs/temporal-reference.md: 'Structured activity arguments'."
        )
    elif isinstance(value, (list, tuple)):
        children = value
    else:
        return
    for child in children:
        _check_signable_tree(child, field_name, depth + 1)


def _json_key(key: Any, field_name: str) -> str:
    """Return an unambiguous key shared by supported JSON converters."""
    if isinstance(key, str):
        return key
    if key is None:
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' has a None dictionary key whose "
            "wire name differs between Temporal's JSON converters. Use an "
            "explicit string key."
        )
    if isinstance(key, float) and not math.isfinite(key):
        raise TenuoArgNormalizationError(f"Activity argument '{field_name}' has a non-finite float dictionary key")
    if isinstance(key, (bool, int, float)):
        return json.dumps(key)
    raise TenuoArgNormalizationError(
        f"Activity argument '{field_name}' has a dict key of type {type(key).__name__}; "
        "JSON keys must be strings, numbers, booleans or None. "
        "See docs/temporal-reference.md: 'Structured activity arguments'."
    )


def _jsonable(value: Any, field_name: str, depth: int = 0) -> Any:
    """Plain JSON data for a structured value, converted the same way at any depth.

    The worker receives nested dataclasses and models as the dicts Temporal's
    JSON converter produces, so the workflow must sign them as those dicts too.
    """
    if depth > _POP_NORMALIZE_MAX_DEPTH:
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' exceeds maximum nesting depth "
            f"({_POP_NORMALIZE_MAX_DEPTH}) for PoP normalization. "
            f"See docs/temporal-reference.md: 'Structured activity arguments'."
        )
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if not _POP_INT_MIN <= value <= _POP_INT_MAX:
            raise TenuoArgNormalizationError(
                f"Activity argument '{field_name}' contains integer {value} outside Tenuo's signed 64-bit range"
            )
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TenuoArgNormalizationError(f"Activity argument '{field_name}' contains a non-finite float")
        return value
    if _is_pydantic_model(value):
        _check_signable_tree(value, field_name, depth)
        base = _pydantic_base_class(type(value))
        assert base is not None  # checked by _check_model_is_signable
        try:
            if hasattr(base, "model_dump"):
                # Temporal's PydanticJSONPlainPayloadConverter uses
                # pydantic_core.to_json(), which applies serialization aliases.
                # Calling the schema serializer directly produces the same plain
                # value without invoking a user-overridden model_dump().
                dumped = type(value).__pydantic_serializer__.to_python(
                    value,
                    mode="json",
                    by_alias=True,
                )
            else:
                # Temporal's default v1 fallback calls BaseModel.dict() and then
                # encodes that value as JSON.
                dumped = getattr(base, "dict")(value)
        except Exception as exc:
            raise TenuoArgNormalizationError(
                f"Activity argument '{field_name}' could not be serialized for "
                f"PoP: {exc}. See docs/temporal-reference.md: "
                "'Structured activity arguments'."
            ) from exc
        return _jsonable(dumped, field_name, depth + 1)
    if _dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _jsonable(getattr(value, field.name), field_name, depth + 1)
            for field in _dataclasses.fields(value)
        }
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key, child in value.items():
            normalized_key = _json_key(key, field_name)
            if normalized_key in result:
                raise TenuoArgNormalizationError(
                    f"Activity argument '{field_name}' has dictionary keys that both encode as {normalized_key!r}"
                )
            result[normalized_key] = _jsonable(child, field_name, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_jsonable(v, field_name, depth + 1) for v in value]
    if isinstance(value, bytes):
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' contains bare bytes whose wire "
            "representation depends on the Temporal data converter. Use a typed "
            "Pydantic field or an explicit string representation."
        )
    if _is_secret(value):  # str() would mask every secret the same way
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' contains a secret value. "
            + _MODEL_UNSIGNABLE.format(why="a secret value")
            + " See docs/temporal-reference.md: 'Structured activity arguments'."
        )
    raise TenuoArgNormalizationError(
        f"Activity argument '{field_name}' contains unsupported nested type "
        f"'{type(value).__qualname__}'. Convert it with a typed Pydantic field "
        "or lift it to a supported top-level argument. "
        "See docs/temporal-reference.md: 'Structured activity arguments'."
    )


def _normalize_pop_arg_value(value: Any, field_name: str, depth: int = 0) -> Any:
    """Recursively normalize a single activity arg value for PoP signing.

    Primitives pass through unchanged. Dataclasses, Pydantic models, dicts,
    lists, tuples, and None are normalized to representations the Rust CBOR
    encoder can accept. Anything else raises TenuoArgNormalizationError.
    """
    if depth > _POP_NORMALIZE_MAX_DEPTH:
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' exceeds maximum nesting depth "
            f"({_POP_NORMALIZE_MAX_DEPTH}) for PoP normalization. Flatten the "
            f"structure or lift individual fields to top-level primitive args. "
            f"See docs/temporal-reference.md: 'Structured activity arguments'."
        )

    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if not _POP_INT_MIN <= value <= _POP_INT_MAX:
            raise TenuoArgNormalizationError(
                f"Activity argument '{field_name}' contains integer {value} outside Tenuo's signed 64-bit range"
            )
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TenuoArgNormalizationError(f"Activity argument '{field_name}' contains a non-finite float")
        return value

    if _is_pydantic_model(value):
        return _jsonable(value, field_name, depth)

    if (_dataclasses.is_dataclass(value) and not isinstance(value, type)) or isinstance(value, dict):
        return _jsonable(value, field_name, depth)

    if isinstance(value, (list, tuple)):
        return _jsonable(value, field_name, depth)

    if isinstance(value, bytes):
        raise TenuoArgNormalizationError(
            f"Activity argument '{field_name}' contains bare bytes whose wire "
            "representation depends on the Temporal data converter and can "
            "collide with a string in PoP. Use a typed Pydantic field or an "
            "explicit string representation."
        )

    type_name = type(value).__qualname__
    raise TenuoArgNormalizationError(
        f"Activity argument '{field_name}' has type '{type_name}' which cannot "
        f"be normalized for PoP signing. Supported types: str, int, float, bool, "
        f"None, list, tuple, dict, @dataclass and Pydantic models. For {type_name}: "
        f"convert to a @dataclass or dict, or lift the relevant fields to "
        f"top-level primitive arguments with explicit constraints. "
        f"See docs/temporal-reference.md: 'Structured activity arguments'."
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
        diagnose_constraints = getattr(warrant, "diagnose_constraints", None)
        if not callable(diagnose_constraints):
            return
        diagnostics = diagnose_constraints(tool_name, args_dict)
        if not isinstance(diagnostics, dict):
            return
        violations = diagnostics.get("violations")
        if not isinstance(violations, list):
            return
    except Exception:
        return

    unknown = [
        item["field"]
        for item in violations
        if isinstance(item, dict) and item.get("kind") == "unknown_field" and isinstance(item.get("field"), str)
    ]
    missing = [
        item["field"]
        for item in violations
        if isinstance(item, dict) and item.get("kind") == "missing_required" and isinstance(item.get("field"), str)
    ]

    if not unknown and not missing:
        return

    parts: List[str] = []
    if unknown:
        fields_str = ", ".join(unknown)
        parts.append(f"unknown field not allowed (zero-trust mode): {fields_str}")
    if missing:
        fields_str = ", ".join(missing)
        parts.append(f"missing required fields: {fields_str}")

    guidance: List[str] = []
    if unknown:
        guidance.append(
            "Declare each expected argument in the warrant capability; prefer "
            "Wildcard() for known fields that do not need a value constraint. "
            "If the capability intentionally accepts every extra field, set "
            "_allow_unknown=True (a broad opt-out from closed-world checking)."
        )
    if missing:
        guidance.append("Provide every argument declared by the warrant capability.")

    raise TenuoPreValidationError(
        f"Warrant pre-validation failed for activity '{tool_name}'. "
        + "; ".join(parts)
        + ". "
        + " ".join(guidance)
        + " "
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


def framework_args(*names: str) -> Dict[str, Any]:
    """Constraints for arguments a framework passes every activity.

    Some frameworks add their own argument to each activity (a Pydantic context
    saying where to publish events, say). Under closed-world constraints a
    warrant has to name it. This declares each one as an ordinary any-value
    constraint, so it stays signed by PoP and recorded in receipts, and a
    narrower warrant can still constrain it::

        warrant = (Warrant.mint_builder()
                   .capability("search", query=Pattern("docs:*"), **framework_args("tool_ctx"))
                   ...)
    """
    from tenuo import AnyValue

    if not names or not all(isinstance(n, str) and n for n in names):
        raise ValueError("framework_args needs one or more argument names")
    reserved = {"_allow_unknown", *WORKFLOW_SCOPE_ARGS}.intersection(names)
    if reserved:
        raise ValueError("framework_args cannot declare reserved argument name(s): " + ", ".join(sorted(reserved)))
    return {name: AnyValue() for name in names}
