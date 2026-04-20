"""Regression tests for the MCP split-view authorize path.

Two bugs were found by an external integrator while wiring Tenuo warrants
into an MCP server:

1. *PoP byte parity*: a client without a ``CompiledMcpConfig`` loaded was
   rejected by a server that did have one loaded. The client signed PoP
   over raw wire args; the server canonicalized the extracted constraint
   view for PoP verification, and the two views had different CBOR shapes.

2. *None-valued arguments*: tool signatures with ``Optional[...] = None``
   defaults put explicit ``None`` values on the wire. Both ``warrant.sign``
   and ``Authorizer.verify`` crashed with ``ValueError: value must be str,
   int, float, bool, or list`` because the Rust ``ConstraintValue``
   converter doesn't accept ``None``.

The fix:

* PoP is always computed over the raw wire args on **both** sides, with
  :func:`tenuo._pop_canonicalize.strip_none_values` applied.
* The Rust core exposes split-view ``authorize_*_with_pop_args`` methods
  so the server can extract constraints independently of PoP bytes.

These tests lock in both behaviors end-to-end.
"""

from __future__ import annotations

import base64
import time

import pytest
from tenuo_core import (
    Authorizer,
    CompiledMcpConfig,
    McpConfig,
    SigningKey,
    Warrant,
)

from tenuo._pop_canonicalize import strip_none_values
from tenuo.mcp.server import MCPVerifier


# ---------------------------------------------------------------------------
# strip_none_values unit tests
# ---------------------------------------------------------------------------


class TestStripNoneValues:
    def test_drops_none_top_level(self):
        assert strip_none_values({"a": 1, "b": None, "c": "x"}) == {"a": 1, "c": "x"}

    def test_drops_none_inside_list(self):
        assert strip_none_values({"xs": [1, None, 2, None, 3]}) == {"xs": [1, 2, 3]}

    def test_empty_dict_is_empty(self):
        assert strip_none_values({}) == {}

    def test_all_none_returns_empty(self):
        assert strip_none_values({"a": None, "b": None}) == {}

    def test_does_not_mutate_input(self):
        original = {"a": 1, "b": None, "xs": [1, None]}
        before = dict(original)
        strip_none_values(original)
        assert original == before

    def test_preserves_falsey_non_none_values(self):
        # 0, "", False, [] are not None and must survive.
        assert strip_none_values({"z": 0, "s": "", "b": False, "l": []}) == {
            "z": 0,
            "s": "",
            "b": False,
            "l": [],
        }


# ---------------------------------------------------------------------------
# End-to-end fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def issuer_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def agent_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def authorizer(issuer_key: SigningKey) -> Authorizer:
    return Authorizer(trusted_roots=[issuer_key.public_key])


@pytest.fixture
def mcp_config(tmp_path) -> CompiledMcpConfig:
    """Server-side mcp-config.yaml with a field rename: maxSize → max_size."""
    yaml = tmp_path / "mcp.yaml"
    yaml.write_text(
        """
version: "1"
tools:
  read_file:
    description: "Read a file"
    constraints:
      path:
        from: body
        path: "path"
        required: true
      max_size:
        from: body
        path: "maxSize"
        type: integer
        default: 1048576
"""
    )
    return CompiledMcpConfig.compile(McpConfig.from_file(str(yaml)))


def _sign_pop(warrant: Warrant, key: SigningKey, tool: str, args: dict) -> str:
    sig = warrant.sign(key, tool, args, int(time.time()))
    return base64.b64encode(bytes(sig)).decode()


def _meta(warrant: Warrant, key: SigningKey, tool: str, wire_args: dict) -> dict:
    """Build an MCP ``params._meta`` envelope for the given wire args."""
    return {
        "tenuo": {
            "warrant": warrant.to_base64(),
            "signature": _sign_pop(warrant, key, tool, wire_args),
        }
    }


# ---------------------------------------------------------------------------
# Bug #1 — PoP byte parity when only one side has a CompiledMcpConfig
# ---------------------------------------------------------------------------


class TestPopParityAcrossConfigAsymmetry:
    """Client and server MUST interoperate regardless of which side has a
    ``CompiledMcpConfig`` loaded. PoP covers the raw wire args; extraction
    is server-only.
    """

    def test_no_client_config_with_server_config_authorizes(
        self,
        authorizer: Authorizer,
        issuer_key: SigningKey,
        agent_key: SigningKey,
        mcp_config: CompiledMcpConfig,
    ):
        from tenuo import Pattern, Range

        warrant = Warrant.issue(
            issuer_key,
            capabilities={
                "read_file": {
                    "path": Pattern("/data/*"),
                    "max_size": Range(max=10 * 1024 * 1024),
                }
            },
            holder=agent_key.public_key,
        )
        # Client signs raw wire args (camelCase maxSize) with no config.
        wire_args = {"path": "/data/log.txt", "maxSize": 2048}
        meta = _meta(warrant, agent_key, "read_file", wire_args)

        # Server has config, extracts maxSize → max_size, still authorizes.
        verifier = MCPVerifier(authorizer=authorizer, config=mcp_config)
        result = verifier.verify("read_file", wire_args, meta=meta)

        assert result.allowed, result.denial_reason
        assert result.constraints["max_size"] == 2048

    def test_neither_side_has_config_authorizes(
        self,
        authorizer: Authorizer,
        issuer_key: SigningKey,
        agent_key: SigningKey,
    ):
        from tenuo import Pattern

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"read_file": {"path": Pattern("/data/*")}},
            holder=agent_key.public_key,
        )
        wire_args = {"path": "/data/log.txt"}
        meta = _meta(warrant, agent_key, "read_file", wire_args)

        result = MCPVerifier(authorizer=authorizer).verify(
            "read_file", wire_args, meta=meta
        )
        assert result.allowed, result.denial_reason

    def test_wire_arg_mutation_breaks_pop(
        self,
        authorizer: Authorizer,
        issuer_key: SigningKey,
        agent_key: SigningKey,
        mcp_config: CompiledMcpConfig,
    ):
        """Basic integrity check: tampering with the wire args after signing
        must still fail. The split-view fix only widens what signs — it must
        not weaken the underlying PoP guarantee.
        """
        from tenuo import Pattern, Range

        warrant = Warrant.issue(
            issuer_key,
            capabilities={
                "read_file": {
                    "path": Pattern("/data/*"),
                    "max_size": Range(max=10 * 1024 * 1024),
                }
            },
            holder=agent_key.public_key,
        )
        signed_args = {"path": "/data/log.txt", "maxSize": 2048}
        meta = _meta(warrant, agent_key, "read_file", signed_args)

        # Attacker bumps maxSize on the wire to sneak past the constraint.
        tampered = {"path": "/data/log.txt", "maxSize": 9_999_999}
        result = MCPVerifier(authorizer=authorizer, config=mcp_config).verify(
            "read_file", tampered, meta=meta
        )
        assert not result.allowed


# ---------------------------------------------------------------------------
# Bug #2 — None values in wire args no longer crash the Rust canonicalizer
# ---------------------------------------------------------------------------


class TestNoneValuedArguments:
    """None values on the wire used to crash both ``warrant.sign`` and
    ``Authorizer.*`` with ``ValueError``. They are now stripped symmetrically
    on client and server, so an optional argument left as ``None`` flows
    through authorization cleanly.
    """

    def test_warrant_sign_accepts_none_after_strip(
        self,
        issuer_key: SigningKey,
        agent_key: SigningKey,
    ):
        from tenuo import Pattern

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"read_file": {"path": Pattern("/data/*")}},
            holder=agent_key.public_key,
        )
        # Shape a caller would naturally produce: optional `encoding=None`.
        wire_args = {"path": "/data/log.txt", "encoding": None}
        canon = strip_none_values(wire_args)

        # Without the helper this would raise ValueError.
        sig = warrant.sign(agent_key, "read_file", canon, int(time.time()))
        assert sig is not None

    def test_end_to_end_none_values_authorize(
        self,
        authorizer: Authorizer,
        issuer_key: SigningKey,
        agent_key: SigningKey,
    ):
        """Wire args with None values go through MCPVerifier without raising."""
        from tenuo import Pattern

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"read_file": {"path": Pattern("/data/*")}},
            holder=agent_key.public_key,
        )
        wire_args = {
            "path": "/data/log.txt",
            "encoding": None,
            "limit": None,
        }
        meta = _meta(warrant, agent_key, "read_file", strip_none_values(wire_args))

        result = MCPVerifier(authorizer=authorizer).verify(
            "read_file", wire_args, meta=meta
        )
        assert result.allowed, result.denial_reason
        # None keys are not exposed as constraints
        assert "encoding" not in result.constraints
        assert "limit" not in result.constraints
        assert result.constraints["path"] == "/data/log.txt"

    def test_list_with_none_elements_is_cleaned(
        self,
        authorizer: Authorizer,
        issuer_key: SigningKey,
        agent_key: SigningKey,
    ):
        from tenuo import Pattern, Subset

        warrant = Warrant.issue(
            issuer_key,
            capabilities={
                "read_file": {
                    "path": Pattern("/data/*"),
                    "tags": Subset(["a", "b", "c"]),
                }
            },
            holder=agent_key.public_key,
        )
        wire_args = {"path": "/data/log.txt", "tags": ["a", None, "b"]}
        meta = _meta(warrant, agent_key, "read_file", strip_none_values(wire_args))

        result = MCPVerifier(authorizer=authorizer).verify(
            "read_file", wire_args, meta=meta
        )
        assert result.allowed, result.denial_reason
        # None elements were stripped inside the list before constraint check.
        assert result.constraints["tags"] == ["a", "b"]
