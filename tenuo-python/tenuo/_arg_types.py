"""Strict JSON-type check of tool arguments against a tool's input schema.

Frameworks validate tool arguments leniently: ``"22"`` becomes ``22`` for an
integer parameter and ``"off"`` becomes ``False`` for a boolean one. Tenuo
authorizes the arguments as the caller sent them, so a value the framework
would convert must not reach the tool. Adapters call
:func:`argument_type_mismatches` with the tool's JSON Schema before
authorizing and deny the call when it reports anything.

Only JSON types are compared, not the schema's value constraints. Missing
schemas leave validation to the framework. Supplied references and nested
schemas must be readable within the depth limit or the call is denied.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Mapping, Optional

_MAX_DEPTH = 16


def _literal_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_literal_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_literal_equal(a, b) for a, b in zip(left, right))
    return left == right


def _json_type_ok(expected: str, value: Any) -> bool:
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        if isinstance(value, bool):
            return False
        return isinstance(value, int) or (isinstance(value, float) and math.isfinite(value) and value.is_integer())
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and (
            not isinstance(value, float) or math.isfinite(value)
        )
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, (list, tuple))
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "null":
        return value is None
    return False


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
        siblings = {key: value for key, value in schema.items() if key != "$ref"}
        if siblings:
            return {"allOf": [node, siblings]}
        schema = node
    return None


def _matches(schema: Any, value: Any, root: Mapping[str, Any], depth: int) -> bool:
    if isinstance(schema, bool):
        return schema
    if depth > _MAX_DEPTH:
        return False
    resolved = _resolve(schema, root)
    if resolved is None:
        return False

    # A branch that cannot accept its literal/tag must not mask a coercion
    # in another union branch selected by the framework.
    if "const" in resolved and not _literal_equal(value, resolved["const"]):
        return False
    choices = resolved.get("enum")
    if isinstance(choices, list) and not any(_literal_equal(value, choice) for choice in choices):
        return False
    if isinstance(value, str):
        pattern = resolved.get("pattern")
        if isinstance(pattern, str):
            try:
                if re.search(pattern, value) is None:
                    return False
            except re.error:
                return False
        if isinstance(resolved.get("minLength"), int) and len(value) < resolved["minLength"]:
            return False
        if isinstance(resolved.get("maxLength"), int) and len(value) > resolved["maxLength"]:
            return False

    for key in ("anyOf", "oneOf"):
        options = resolved.get(key)
        if isinstance(options, list) and options:
            if not any(_matches(option, value, root, depth + 1) for option in options):
                return False
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
        prefix = resolved.get("prefixItems", [])
        if isinstance(prefix, list):
            for item_schema, item in zip(prefix, value):
                if not _matches(item_schema, item, root, depth + 1):
                    return False
        else:
            prefix = []
        items = resolved.get("items")
        if isinstance(items, list):
            for item_schema, item in zip(items, value):
                if not _matches(item_schema, item, root, depth + 1):
                    return False
            additional = resolved.get("additionalItems", True)
            return all(_matches(additional, item, root, depth + 1) for item in value[len(items):])
        elif items is not None:
            return all(_matches(items, item, root, depth + 1) for item in value[len(prefix):])
    elif isinstance(value, Mapping):
        properties = resolved.get("properties", {})
        additional = resolved.get("additionalProperties", True)
        patterns = resolved.get("patternProperties", {})
        for name, item in value.items():
            covered = False
            if isinstance(properties, Mapping) and name in properties:
                covered = True
                if not _matches(properties[name], item, root, depth + 1):
                    return False
            if isinstance(patterns, Mapping):
                for pattern, item_schema in patterns.items():
                    try:
                        matches = re.search(pattern, str(name)) is not None
                    except (TypeError, re.error):
                        return False
                    if matches:
                        covered = True
                        if not _matches(item_schema, item, root, depth + 1):
                            return False
            if not covered and not _matches(additional, item, root, depth + 1):
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
    if _matches(schema, arguments, schema, 0):
        return []
    mismatches = sorted(
        str(name)
        for name, value in arguments.items()
        if not _matches(schema, {name: value}, schema, 0)
    )
    # Different fields can each match a different union branch while the
    # complete argument object matches none. Report the whole conflicting set.
    return mismatches or sorted(str(name) for name in arguments) or ["<arguments>"]


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
