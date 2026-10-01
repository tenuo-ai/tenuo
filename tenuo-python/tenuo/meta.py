"""Translate a host value into the core ``_meta.tenuo`` envelope.

``sign_meta`` and ``decode_meta`` in the core are the only producer and
consumer of that object. This module turns a host dict into the argument
JSON text those functions sign. It does not choose a base64 alphabet, frame
a warrant stack, or drop ``None``.

A dict the framework has already parsed is a lossy input. The original
argument text is what a cross-language vector signs. When only the dict
remains, ``argument_json`` is the translation and the core parses that text.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Dict

from tenuo_core import args_from_json


def _json_ready(value: Any) -> Any:
    """Match ``JSON.stringify`` for numbers and keep ``None`` as null."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise ValueError("integer arguments must fit in i64")
        return value
    if isinstance(value, float):
        if value.is_integer() and abs(value) <= 2**53:
            return int(value)
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("argument keys must be strings")
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def argument_json(args: Mapping[str, Any]) -> str:
    """Host dict to the argument JSON text the core signs.

    Key order is sorted so two hosts with the same values produce the same
    text. ``None`` is JSON null and stays in the text. An integral float is
    written as an integer, matching ``JSON.stringify(1.0)``.
    """
    return json.dumps(
        _json_ready(args),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def signed_arguments(args: Mapping[str, Any]) -> Dict[str, Any]:
    """The core's reading of ``argument_json(args)``, as a host dict.

    JSON null comes back as ``None``. Proof checks use this map, not a
    second pass that drops ``None``.
    """
    return args_from_json(argument_json(args))


@dataclass(frozen=True)
class _ArgumentSnapshot:
    """One captured input; security and execution views never re-read the caller."""

    json: str
    pop_args: Dict[str, Any]
    execution_args: Dict[str, Any]


def _capture_arguments(args: Mapping[str, Any]) -> _ArgumentSnapshot:
    text = argument_json(args)
    # Validate in the core before creating the host's execution copy.
    pop_args = args_from_json(text)
    return _ArgumentSnapshot(text, pop_args, json.loads(text))


__all__ = ["argument_json", "signed_arguments"]
