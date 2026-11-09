"""Strict JSON-type check of tool arguments against a tool's input schema.

Frameworks validate tool arguments leniently: ``"22"`` becomes ``22`` for an
integer parameter and ``"off"`` becomes ``False`` for a boolean one. Tenuo
authorizes the arguments as the caller sent them, so a value the framework
would convert must not reach the tool. Adapters call
:func:`argument_type_mismatches` with the tool's JSON Schema before
authorizing and deny the call when it reports anything.

Only JSON types are compared. A schema this module cannot read (no ``type``,
an unresolvable ``$ref``, a combinator it does not know) accepts the value.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

_MAX_DEPTH = 16


def _json_type_ok(expected: str, value: Any) -> bool:
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        if isinstance(value, bool):
            return False
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, (list, tuple))
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "null":
        return value is None
    return True


def _resolve(schema: Any, root: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    """Follow local ``$ref`` pointers; ``None`` when the schema is unreadable."""
    for _ in range(_MAX_DEPTH):
        if not isinstance(schema, Mapping):
            return None
        ref = schema.get("$ref")
        if not isinstance(ref, str):
            return schema
        if not ref.startswith("#/"):
            return None
        node: Any = root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, Mapping) or part not in node:
                return None
            node = node[part]
        schema = node
    return None


def _matches(schema: Any, value: Any, root: Mapping[str, Any], depth: int) -> bool:
    resolved = _resolve(schema, root)
    if resolved is None or depth > _MAX_DEPTH:
        return True

    for key in ("anyOf", "oneOf"):
        options = resolved.get(key)
        if isinstance(options, list) and options:
            return any(_matches(option, value, root, depth + 1) for option in options)
    parts = resolved.get("allOf")
    if isinstance(parts, list) and not all(_matches(part, value, root, depth + 1) for part in parts):
        return False

    expected = resolved.get("type")
    if isinstance(expected, list):
        candidates = [t for t in expected if isinstance(t, str)]
        if candidates and not any(_json_type_ok(t, value) for t in candidates):
            return False
    elif isinstance(expected, str):
        if not _json_type_ok(expected, value):
            return False

    if isinstance(value, (list, tuple)):
        items = resolved.get("items")
        if items is not None:
            return all(_matches(items, item, root, depth + 1) for item in value)
    elif isinstance(value, Mapping):
        properties = resolved.get("properties")
        if isinstance(properties, Mapping):
            for name, item in value.items():
                if name in properties and not _matches(properties[name], item, root, depth + 1):
                    return False
    return True


def argument_type_mismatches(schema: Any, arguments: Any) -> List[str]:
    """Names of arguments whose JSON type differs from the tool's schema.

    Args:
        schema: The tool's input JSON Schema (an object schema with
            ``properties``), or ``None`` when the tool declares none.
        arguments: The arguments as received, before framework validation.

    Returns:
        Sorted names of the top-level arguments that do not have the declared
        type. Empty when every declared argument matches, or when there is no
        schema to compare against.
    """
    if not isinstance(schema, Mapping) or not isinstance(arguments, Mapping):
        return []
    resolved = _resolve(schema, schema)
    properties = resolved.get("properties") if resolved is not None else None
    if not isinstance(properties, Mapping):
        return []
    return sorted(
        str(name)
        for name, value in arguments.items()
        if name in properties and not _matches(properties[name], value, schema, 0)
    )


def tool_input_schema(tool: Any) -> Optional[Dict[str, Any]]:
    """Best-effort JSON Schema for a framework tool object.

    Reads, in order: a JSON Schema dict on ``params_json_schema``,
    ``parameters`` or ``inputSchema``; then a pydantic model (or dict) on
    ``args_schema``. Returns ``None`` when the tool exposes none of these.
    """
    for attr in ("params_json_schema", "parameters", "inputSchema"):
        candidate = getattr(tool, attr, None)
        if isinstance(candidate, Mapping):
            return dict(candidate)
    args_schema = getattr(tool, "args_schema", None)
    if isinstance(args_schema, Mapping):
        return dict(args_schema)
    to_schema = getattr(args_schema, "model_json_schema", None)
    if callable(to_schema):
        try:
            produced = to_schema()
        except Exception:
            return None
        if isinstance(produced, Mapping):
            return dict(produced)
    return None


__all__ = ["argument_type_mismatches", "tool_input_schema"]
