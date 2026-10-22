"""Read constraint trees from a signed warrant payload.

The SDK's `All`, `AnyOf` and `Not` objects don't expose their children, but the
signed payload carries them in the published wire format: each constraint is
`[type_id, value]`. This reads that format for display only; authorization
never uses it.
"""

from __future__ import annotations

import json
import struct

_CAPABILITIES = 3
_MAX_DEPTH = 64


def decode(data, start=0, depth=0):
    """Decode one definite-length CBOR item, returning (value, next offset)."""
    if depth > _MAX_DEPTH:
        raise ValueError("CBOR nesting too deep")
    if start >= len(data):
        raise ValueError("truncated CBOR")
    head = data[start]
    major, info, i = head >> 5, head & 31, start + 1
    if info < 24:
        n = info
    elif info <= 27:
        size = 1 << (info - 24)
        raw, i = data[i : i + size], i + size
        if len(raw) != size:
            raise ValueError("truncated CBOR")
        if major == 7 and size > 1:
            return struct.unpack({2: ">e", 4: ">f", 8: ">d"}[size], raw)[0], i
        n = int.from_bytes(raw, "big")
    else:
        raise ValueError("unsupported CBOR length")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        raw = data[i : i + n]
        if len(raw) != n:
            raise ValueError("truncated CBOR")
        return (bytes(raw) if major == 2 else raw.decode()), i + n
    if major == 4:
        items = []
        for _ in range(n):
            item, i = decode(data, i, depth + 1)
            items.append(item)
        return items, i
    if major == 5:
        entries = {}
        for _ in range(n):
            key, i = decode(data, i, depth + 1)
            entries[key], i = decode(data, i, depth + 1)
        return entries, i
    if major == 6:
        return decode(data, i, depth + 1)
    return {20: False, 21: True, 22: None}.get(n), i


def constraint_trees(warrant):
    """{tool: {argument: [type_id, value]}} from the warrant's signed payload, or {} if unreadable."""
    try:
        payload, _ = decode(bytes(warrant.payload_bytes))
        tools = payload[_CAPABILITIES]
        return {tool: dict(entry.get("constraints") or {}) for tool, entry in tools.items()}
    except Exception:
        return {}


def _number(value):
    return int(value) if isinstance(value, float) and value.is_integer() else value


def describe(node):
    """Plain language for a wire constraint, recursing into combinators."""
    type_id, value = node
    if type_id == 1:
        return f"exactly {json.dumps(value['value'])}"
    if type_id == 2:
        return f"glob {json.dumps(value['pattern'])}"
    if type_id == 3:
        low, high = value.get("min"), value.get("max")
        if low is not None and high is not None:
            return f"{_number(low)} to {_number(high)}"
        return f"at least {_number(low)}" if high is None else f"at most {_number(high)}"
    if type_id == 4:
        return "one of: " + ", ".join(map(str, value["values"]))
    if type_id == 5:
        return f"regex {json.dumps(value['pattern'])}"
    if type_id == 7:
        return "anything except: " + ", ".join(map(str, value["excluded"]))
    if type_id == 8:
        return f"an IP in {value}"
    if type_id == 9:
        return f"URLs matching {json.dumps(value)}"
    if type_id == 10:
        return "contains all of: " + ", ".join(map(str, value["required"]))
    if type_id == 11:
        return "only items from: " + ", ".join(map(str, value["allowed"]))
    if type_id in (12, 13):
        parts = [describe(child) for child in value["constraints"]]
        return ("all of: " if type_id == 12 else "any of: ") + "; ".join(parts)
    if type_id == 14:
        return f"not ({describe(value['constraint'])})"
    if type_id == 15:
        return f"CEL {json.dumps(value['expression'])}"
    if type_id == 16:
        return "any value"
    if type_id == 17:
        return f"a path inside {value['root']}"
    if type_id == 18:
        domains = value.get("allow_domains")
        return "a URL passing UrlSafe checks" + (" on: " + ", ".join(domains) if domains else "")
    raise ValueError(f"unknown constraint type {type_id}")
