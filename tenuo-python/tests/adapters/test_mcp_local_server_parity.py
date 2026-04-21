"""Parity tests between local and server-side MCP authorization.

These tests lock in a key invariant for SecureMCPClient integrations:

For the same warrant + wire arguments, local preflight authorization
(``enforce_tool_call`` / ``warrant_context=True`` path) and server-side
verification (``MCPVerifier.verify`` over injected warrant + PoP) should
agree on allow/deny outcomes.

Historically, we had drift where server-side canonicalized ``None`` values
for PoP but local enforcement passed raw args through Rust FFI, causing local
denials/crashes that server-side would not produce. This matrix protects
against that class of split-brain behavior.
"""

from __future__ import annotations

import base64
import time

from tenuo import Pattern
from tenuo._enforcement import enforce_tool_call
from tenuo._pop_canonicalize import strip_none_values
from tenuo.mcp.server import MCPVerifier
from tenuo_core import Authorizer, SigningKey, Warrant


def _build_meta(warrant: Warrant, holder_key: SigningKey, tool_name: str, wire_args: dict) -> dict:
    canonical = strip_none_values(wire_args)
    pop = warrant.sign(holder_key, tool_name, canonical, int(time.time()))
    return {
        "tenuo": {
            "warrant": warrant.to_base64(),
            "signature": base64.b64encode(bytes(pop)).decode(),
        }
    }


def test_local_and_server_enforcement_parity_matrix():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()

    warrant = Warrant.issue(
        issuer,
        capabilities={"read_file": {"path": Pattern("/tmp/*")}},
        holder=holder.public_key,
    )
    bound = warrant.bind(holder)
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[issuer.public_key]))

    cases = [
        # Happy path.
        {"name": "allow_basic", "tool": "read_file", "args": {"path": "/tmp/allowed.txt"}, "expected_allowed": True},
        # Constraint violation.
        {"name": "deny_path_constraint", "tool": "read_file", "args": {"path": "/etc/passwd"}, "expected_allowed": False},
        # Previously problematic shape for local enforcement.
        {"name": "allow_none_optional", "tool": "read_file", "args": {"path": "/tmp/allowed.txt", "max_size": None}, "expected_allowed": True},
        # Unknown fields should fail in zero-trust mode on both sides.
        {
            "name": "deny_unknown_field_after_none_strip",
            "tool": "read_file",
            "args": {"path": "/tmp/allowed.txt", "tags": [1, None, 2]},
            "expected_allowed": False,
        },
    ]

    for case in cases:
        tool = case["tool"]
        args = case["args"]
        meta = _build_meta(warrant, holder, tool, args)

        local = enforce_tool_call(
            tool,
            args,
            bound,
            trusted_roots=[issuer.public_key],
        )
        server = verifier.verify(tool, args, meta=meta)

        assert local.allowed == case["expected_allowed"], f"local mismatch in {case['name']}: {local.denial_reason}"
        assert server.allowed == case["expected_allowed"], f"server mismatch in {case['name']}: {server.denial_reason}"
        assert local.allowed == server.allowed, f"local/server drift in {case['name']}"

