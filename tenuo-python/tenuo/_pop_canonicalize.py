"""Constraint view of tool-call arguments.

Proof-of-possession covers the argument JSON, including ``None``. Warrant
matching retains every supplied value for signed optional fields. For legacy
fields, it uses the following normalization:

* Drop any top-level key whose value is ``None``.
* Recurse into list values to drop ``None`` elements.
* Leave nested dicts unchanged.
"""

from __future__ import annotations

from typing import Any, Collection, Dict, Iterable, List, Mapping


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


def strip_none_values(
    args: Mapping[str, Any], *, preserve_fields: Collection[str] = ()
) -> Dict[str, Any]:
    """Return the constraint view: top-level ``None`` keys and list nulls dropped.

    Nested dicts are left unchanged. Proof-of-possession does not use this
    view; it signs the argument JSON, nulls included.

    Args:
        args: Tool-call argument dict (e.g., MCP ``params.arguments``).
        preserve_fields: Fields whose supplied values must remain unchanged,
            including explicit nulls and null elements inside lists.

    Returns:
        A new dict with legacy fields normalized and preserved fields unchanged.
        The input is not modified.
    """
    out: Dict[str, Any] = {}
    for key, value in args.items():
        if key in preserve_fields:
            out[key] = value
            continue
        if value is None:
            continue
        if isinstance(value, list):
            out[key] = _clean_list(value)
        else:
            out[key] = value
    return out


def constraint_view(
    args: Mapping[str, Any], tool: str, warrants: Iterable[Any]
) -> Dict[str, Any]:
    """Keep optional fields intact throughout the presented warrant chain.

    Presence rules are read from the signed native policy. Rust remains the
    authorizer. Required-only warrants retain their legacy null normalization.
    """
    optional = {field for warrant in warrants for field in warrant.optional_fields(tool)}
    return strip_none_values(args, preserve_fields=optional)


__all__ = ["strip_none_values", "constraint_view"]
