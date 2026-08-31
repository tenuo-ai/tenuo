#!/usr/bin/env python3
"""Mint or verify live warrants for the TypeScript interop tests."""

from __future__ import annotations

import json
import sys
from typing import Any

from tenuo import (
    Authorizer,
    Exact,
    OneOf,
    Pattern,
    PublicKey,
    Range,
    SigningKey,
    Subpath,
    Warrant,
    now,
)


def constraint_from_expr(expr: dict[str, Any]) -> Any:
    kind = expr["kind"]
    if kind == "under":
        return Subpath(expr["root"])
    if kind == "pattern":
        return Pattern(expr["pattern"])
    if kind == "oneOf":
        return OneOf(expr["values"])
    if kind == "max":
        return Range(max=expr["value"])
    if kind == "exact":
        return Exact(expr["value"])
    if kind == "email":
        return Pattern(f"*@{expr['domain']}")
    raise ValueError(f"unknown constraint kind {kind!r}")


def apply_allow(builder: Any, allow: dict[str, dict[str, Any]]) -> Any:
    for tool, fields in allow.items():
        builder = builder.capability(
            tool,
            {field: constraint_from_expr(expr) for field, expr in fields.items()},
        )
    return builder


def capabilities_from_narrow(
    allow: dict[str, dict[str, Any]],
    narrow: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    field_level = all(isinstance(value, dict) and "kind" in value for value in narrow.values())
    if field_level:
        fields = {field: constraint_from_expr(expr) for field, expr in narrow.items()}
        return {tool: dict(fields) for tool in allow}
    return {
        tool: {field: constraint_from_expr(expr) for field, expr in fields.items()}
        for tool, fields in narrow.items()
    }


def default_allow() -> dict[str, dict[str, Any]]:
    return {"read_file": {"path": {"kind": "under", "root": "/data"}}}


def mint(spec: dict[str, Any] | None = None) -> dict[str, Any]:
    spec = spec or {}
    allow = spec.get("allow") or default_allow()
    ttl = int(spec.get("ttl", 300))
    issuer = SigningKey.from_bytes(bytes([0x01] * 32))
    holder = SigningKey.from_bytes(bytes([0x02] * 32))
    builder = Warrant.mint_builder().holder(holder.public_key).ttl(ttl)
    builder = apply_allow(builder, allow)
    warrant = builder.mint(issuer)
    chain = [warrant]
    if spec.get("narrow"):
        child = warrant.attenuate(
            capabilities=capabilities_from_narrow(allow, spec["narrow"]),
            signing_key=holder,
            holder=holder.public_key,
            ttl_seconds=min(ttl, 200),
        )
        chain.append(child)
    return {
        "warrant": chain[-1].to_base64(),
        "warrants": [item.to_base64() for item in chain],
        "root_hex": issuer.public_key.to_bytes().hex(),
        "holder_hex": holder.secret_key_bytes().hex(),
    }


def mcp_attach(payload: dict[str, Any]) -> dict[str, Any]:
    """Build `_meta.tenuo` the way SecureMCPClient injects it."""
    import base64

    from tenuo import encode_warrant_stack
    from tenuo._pop_canonicalize import strip_none_values

    tokens = payload.get("warrants") or [payload["warrant"]]
    chain = [Warrant.from_base64(token) for token in tokens]
    holder = SigningKey.from_bytes(bytes.fromhex(payload["holder_hex"]))
    tool = payload["tool"]
    args = payload["args"]
    stack = encode_warrant_stack(chain)
    pop = chain[-1].sign(holder, tool, strip_none_values(args), now())
    return {
        "name": tool,
        "arguments": args,
        "_meta": {
            "tenuo": {
                "warrant": stack,
                "signature": base64.b64encode(bytes(pop)).decode("utf-8"),
            }
        },
    }


def mcp_verify(payload: dict[str, Any]) -> dict[str, Any]:
    """Verify a presented `_meta.tenuo` envelope via MCPVerifier."""
    from tenuo.mcp.server import MCPVerifier

    root = PublicKey.from_bytes(bytes.fromhex(payload["root_hex"]))
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[root]))
    result = verifier.verify(payload["tool"], payload["args"], meta=payload.get("meta"))
    return {
        "allowed": bool(result.allowed),
        "reason": result.denial_reason,
        "code": result.jsonrpc_error_code,
    }


def verify(payload: dict[str, Any]) -> dict[str, Any]:
    tokens = payload.get("warrants") or [payload["warrant"]]
    chain = [Warrant.from_base64(token) for token in tokens]
    holder = SigningKey.from_bytes(bytes.fromhex(payload["holder_hex"]))
    root = PublicKey.from_bytes(bytes.fromhex(payload["root_hex"]))
    tool = payload["tool"]
    args = payload["args"]
    leaf = chain[-1]
    signature = leaf.sign(holder, tool, args, now())
    authorizer = Authorizer(trusted_roots=[root])
    try:
        if len(chain) == 1:
            authorizer.authorize_one(leaf, tool, args, signature)
        else:
            authorizer.check_chain(chain, tool, args, signature)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "message": str(exc)}


def read_optional_json() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("stdin must be a JSON object")
    return parsed


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "mint"
    if command == "mint":
        json.dump(mint(read_optional_json()), sys.stdout)
        sys.stdout.write("\n")
        return 0
    if command == "verify":
        json.dump(verify(read_optional_json()), sys.stdout)
        sys.stdout.write("\n")
        return 0
    if command == "mcp_attach":
        json.dump(mcp_attach(read_optional_json()), sys.stdout)
        sys.stdout.write("\n")
        return 0
    if command == "mcp_verify":
        json.dump(mcp_verify(read_optional_json()), sys.stdout)
        sys.stdout.write("\n")
        return 0
    print(f"unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
