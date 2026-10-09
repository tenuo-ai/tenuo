"""Constraint view of tool-call arguments.

Proof-of-possession covers the argument JSON, including ``None``. Warrant
matching uses this narrower view so an optional null does not become an
unknown field:

* Drop any top-level key whose value is ``None``.
* Recurse into list values to drop ``None`` elements.
* Leave nested dicts unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def _clean_list(value: List[Any]) -> List[Any]:
    """Drop ``None`` elements from a list, recursing into nested lists.

    Keeps any non-``None`` / non-list element as-is. Lists nested at any
    depth are cleaned in place of being passed through verbatim so the
    final structure is guaranteed ``None``-free end to end.
    """
    cleaned: List[Any] = []
    for item in value:
        if item is None:
            continue
        if isinstance(item, list):
            cleaned.append(_clean_list(item))
        else:
            cleaned.append(item)
    return cleaned


def strip_none_values(args: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the constraint view: top-level ``None`` keys and list nulls dropped.

    Nested dicts are left unchanged. Proof-of-possession does not use this
    view; it signs the argument JSON, nulls included.

    Args:
        args: Tool-call argument dict (e.g., MCP ``params.arguments``).

    Returns:
        A new dict with ``None`` values removed. The input is not modified.
    """
    out: Dict[str, Any] = {}
    for key, value in args.items():
        if value is None:
            continue
        if isinstance(value, list):
            out[key] = _clean_list(value)
        else:
            out[key] = value
    return out


__all__ = ["strip_none_values"]
