"""Strict JSON-type check of tool arguments against a tool's input schema.

Frameworks validate tool arguments leniently: ``"22"`` becomes ``22`` for an
integer parameter and ``"off"`` becomes ``False`` for a boolean one. Tenuo
authorizes the arguments as the caller sent them, so a value the framework
would convert must not reach the tool. Adapters call
:func:`argument_type_mismatches` with the tool's JSON Schema before
authorizing and deny the call when it reports anything.

Value restrictions determine which union branches the framework could select;
every such branch must preserve JSON types. Ambiguous unions can be denied.
Missing schemas leave validation to the framework. Supplied references and
nested schemas must be readable within the depth limit. Patterns use the
linear Rust matcher, with 4 KiB patterns and 64 KiB input limits; unsupported
syntax fails closed.
"""

from __future__ import annotations

import math
from functools import lru_cache
from typing import Any, Dict, List, Mapping, Optional

from jsonschema import Draft202012Validator, FormatChecker, validators
from jsonschema.exceptions import ValidationError
from pydantic import ConfigDict, TypeAdapter
from referencing import Registry

_MAX_DEPTH = 16


@lru_cache(maxsize=16)
def _linear_regex(pattern: str) -> Any:
    from tenuo_core import Regex

    if len(pattern.encode("utf-8")) > 4096:
        raise ValueError("schema pattern exceeds limit")
    return Regex(pattern)


def _linear_search(pattern: str, text: str) -> bool:
    if len(text.encode("utf-8")) > 65536:
        raise ValueError("schema pattern input exceeds limit")
    return bool(_linear_regex(pattern).satisfies(text))


def _safe_pattern(validator: Any, pattern: Any, value: Any, schema: Any) -> Any:
    try:
        _linear_regex(pattern)
        if isinstance(value, str) and not _linear_search(pattern, value):
            yield ValidationError("string does not match schema pattern")
    except Exception:
        raise ValueError("schema pattern cannot be checked safely") from None


def _safe_pattern_properties(validator: Any, patterns: Any, value: Any, schema: Any) -> Any:
    if not isinstance(value, Mapping):
        return
    for pattern, subschema in patterns.items():
        for name, item in value.items():
            try:
                matches = _linear_search(pattern, str(name))
            except Exception:
                raise ValueError("schema property pattern cannot be checked safely") from None
            if matches:
                yield from validator.descend(item, subschema, path=name, schema_path=pattern)


def _safe_additional_properties(validator: Any, additional: Any, value: Any, schema: Any) -> Any:
    if not isinstance(value, Mapping):
        return
    properties = schema.get("properties", {})
    patterns = schema.get("patternProperties", {})
    for name, item in value.items():
        try:
            covered = name in properties or any(_linear_search(pattern, str(name)) for pattern in patterns)
        except Exception:
            raise ValueError("schema property pattern cannot be checked safely") from None
        if not covered:
            yield from validator.descend(item, additional, path=name)


def _safe_unevaluated_properties(validator: Any, rule: Any, value: Any, schema: Any) -> Any:
    # jsonschema's evaluated-key discovery uses Python re internally. Refuse
    # this unsupported form rather than invoking a backtracking matcher.
    if rule is not True and isinstance(value, Mapping):
        raise ValueError("unevaluatedProperties cannot be checked safely")
    return ()


_SAFE_FORMATS = FormatChecker()


@_SAFE_FORMATS.checks("regex", raises=Exception)
def _regex_format(value: Any) -> bool:
    return not isinstance(value, str) or _linear_regex(value) is not None


def _safe_format(validator: Any, rule: Any, value: Any, schema: Any) -> Any:
    if isinstance(value, str) and len(value.encode("utf-8")) > 65536:
        raise ValueError("schema format input exceeds limit")
    yield from Draft202012Validator.VALIDATORS["format"](validator, rule, value, schema)


_SAFE_KEYWORDS = {
    "pattern": _safe_pattern,
    "patternProperties": _safe_pattern_properties,
    "additionalProperties": _safe_additional_properties,
    "unevaluatedProperties": _safe_unevaluated_properties,
    "format": _safe_format,
}


def _schema_for_validation(schema: Any, depth: int = 0) -> Any:
    if depth > 64:
        raise ValueError("schema nesting exceeds limit")
    if not isinstance(schema, Mapping):
        return schema
    result: Dict[str, Any] = {}
    for key, value in schema.items():
        if key == "$schema":
            # evolve() must retain the safe validator instead of switching to
            # a stock dialect validator with Python backtracking regexes.
            continue
        if key in {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}:
            result[key] = {name: _schema_for_validation(rule, depth + 1) for name, rule in value.items()}
        elif key in {"allOf", "anyOf", "oneOf", "prefixItems"}:
            result[key] = [_schema_for_validation(rule, depth + 1) for rule in value]
        elif key in {"items", "additionalItems", "additionalProperties", "contains", "not", "if", "then", "else", "propertyNames", "unevaluatedProperties", "unevaluatedItems"}:
            result[key] = ([_schema_for_validation(rule, depth + 1) for rule in value]
                           if isinstance(value, list) else _schema_for_validation(value, depth + 1))
        else:
            result[key] = value
    return result


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


def _no_remote_schema(uri: str) -> Any:
    raise ValueError("Remote schema retrieval is disabled")


_BranchValidator = validators.extend(
    Draft202012Validator,
    validators=_SAFE_KEYWORDS,
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine_many({
        name: (lambda checker, value, expected=name: _json_type_ok(expected, value))
        for name in ("boolean", "integer", "number", "string", "array", "object", "null")
    }),
)

_COERCIVE_SCALARS: Dict[str, Any] = {
    "integer": TypeAdapter(int),
    "number": TypeAdapter(float),
    "boolean": TypeAdapter(bool),
    "string": TypeAdapter(str, config=ConfigDict(coerce_numbers_to_str=True)),
}


def _candidate_type_ok(expected: str, value: Any) -> bool:
    adapter = _COERCIVE_SCALARS.get(expected)
    if adapter is None:
        return _json_type_ok(expected, value)
    try:
        adapter.validate_python(value)
        return True
    except Exception:
        return False


def _candidate_literal_matches(value: Any, literal: Any) -> bool:
    # String tags can rule out a discriminator branch. Numeric/boolean enums
    # can coerce their input, so a raw mismatch cannot rule those branches out.
    if literal is None:
        return value is None
    if isinstance(literal, str):
        try:
            return _COERCIVE_SCALARS["string"].validate_python(value) == literal
        except Exception:
            return False
    return True


def _candidate_const(validator: Any, expected: Any, value: Any, schema: Any) -> Any:
    if not _candidate_literal_matches(value, expected):
        yield ValidationError("branch tag does not match")


def _candidate_enum(validator: Any, expected: Any, value: Any, schema: Any) -> Any:
    if not any(_candidate_literal_matches(value, literal) for literal in expected):
        yield ValidationError("branch tag does not match")


_CandidateValidator = validators.extend(
    Draft202012Validator,
    validators={
        **_SAFE_KEYWORDS,
        "const": _candidate_const,
        "enum": _candidate_enum,
        "oneOf": Draft202012Validator.VALIDATORS["anyOf"],
        # Removing a type error can change which conditional branch applies.
        # Do not infer impossibility from negation or conditionals here.
        "not": lambda *args: (),
        "if": lambda *args: (),
    },
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine_many({
        name: (lambda checker, value, expected=name: _candidate_type_ok(expected, value))
        for name in ("boolean", "integer", "number", "string", "array", "object", "null")
    }),
)


def _potential_branch(schema: Any, value: Any, root: Mapping[str, Any]) -> bool:
    try:
        registry = Registry(retrieve=_no_remote_schema)  # type: ignore[call-arg]  # attrs-generated constructor
        return _CandidateValidator(root, registry=registry).evolve(schema=schema).is_valid(value)
    except Exception:
        # Inability to disprove selection is not proof that a coercive branch
        # is impossible. The strict branch check must still pass.
        return True


def _eligible_branch(schema: Any, value: Any, root: Mapping[str, Any]) -> bool:
    # Type checks alone cannot choose a union branch: a failing minimum,
    # required field, format, or collection bound can make the framework use
    # another branch that converts a value. Use the complete schema rules.
    # References remain local; validation must never retrieve remote schemas.
    try:
        registry = Registry(retrieve=_no_remote_schema)  # type: ignore[call-arg]  # attrs-generated constructor
        validator = _BranchValidator(root, registry=registry, format_checker=_SAFE_FORMATS)
        return validator.evolve(schema=schema).is_valid(value)
    except Exception:
        return False


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
                if not _linear_search(pattern, value):
                    return False
            except Exception:
                return False
        if isinstance(resolved.get("minLength"), int) and len(value) < resolved["minLength"]:
            return False
        if isinstance(resolved.get("maxLength"), int) and len(value) > resolved["maxLength"]:
            return False

    for key in ("anyOf", "oneOf"):
        options = resolved.get(key)
        if isinstance(options, list) and options:
            candidates = [option for option in options if _potential_branch(option, value, root)]
            if not candidates or not all(
                _eligible_branch(option, value, root) and _matches(option, value, root, depth + 1)
                for option in candidates
            ):
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
                        matches = _linear_search(pattern, str(name))
                    except Exception:
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
    try:
        schema = _schema_for_validation(schema)
    except Exception:
        return sorted(str(name) for name in arguments) or ["<arguments>"]
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
