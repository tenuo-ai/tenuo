"""Asymmetric-by-default fixtures for MCP handshake tests.

The MCP handshake has two sides that are deployed independently:

* the **client** inside the calling agent (``SecureMCPClient`` / a custom
  caller) — holds the agent signing key, has an optional ``CompiledMcpConfig``
  loaded, signs PoP, and sends the warrant in ``params._meta``;
* the **server** behind the tool handler (``MCPVerifier``) — holds the
  trusted-root public key, has its own optional ``CompiledMcpConfig``
  loaded, and verifies PoP + extracts constraints.

In production those two sides will drift: one is upgraded before the other,
configs land out of sync, a debugging client runs without a config against
a server that has one, etc. A test that constructs both sides from the
same helper silently masks the drift path — symmetry is a convenience
artifact of the test harness, not a property of the deployed system.

This module is deliberately **asymmetric by default**. Each side is built
independently via :func:`make_client_side` / :func:`make_server_side` and
they share only the issuer's public key (the trust anchor). Tests compose
a handshake via :func:`perform_handshake`, which produces the
``(wire_args, params_meta, verifier_result)`` tuple a real MCP call
produces.

Use this for any new MCP test that hinges on client/server agreement.
Happy-path tests (same config both sides) just pass the same config into
both factories; drift tests diverge the inputs and assert whatever
invariant the PR is committing to.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from tenuo_core import Authorizer, CompiledMcpConfig, SigningKey, Warrant

from tenuo._pop_canonicalize import strip_none_values
from tenuo.mcp.server import MCPVerificationResult, MCPVerifier


# ---------------------------------------------------------------------------
# Side dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ClientSide:
    """Everything the calling side owns: its key, its warrant, its config.

    ``config`` intentionally defaults to ``None`` to model the common case
    where the client has no ``CompiledMcpConfig`` loaded.
    """

    agent_key: SigningKey
    warrant: Warrant
    config: Optional[CompiledMcpConfig] = None

    def sign_pop(self, tool: str, wire_args: Dict[str, Any]) -> str:
        """Sign PoP over the (None-stripped) wire args the way
        ``SecureMCPClient`` does in production."""
        canonical = strip_none_values(wire_args)
        sig = self.warrant.sign(self.agent_key, tool, canonical, int(time.time()))
        return base64.b64encode(bytes(sig)).decode()

    def build_meta(self, tool: str, wire_args: Dict[str, Any]) -> Dict[str, Any]:
        """Return a ``params._meta``-shaped envelope for the given wire args."""
        return {
            "tenuo": {
                "warrant": self.warrant.to_base64(),
                "signature": self.sign_pop(tool, wire_args),
            }
        }


@dataclass
class ServerSide:
    """Everything the serving side owns: its authorizer and its config.

    ``config`` is independent of any client-side ``config`` — that's the
    point of this fixture pair.
    """

    authorizer: Authorizer
    config: Optional[CompiledMcpConfig] = None
    verifier: MCPVerifier = field(init=False)

    def __post_init__(self) -> None:
        self.verifier = MCPVerifier(authorizer=self.authorizer, config=self.config)

    def verify(
        self,
        tool: str,
        wire_args: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> MCPVerificationResult:
        return self.verifier.verify(tool, wire_args, meta=meta)


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


IssuerKey = SigningKey
AgentKey = SigningKey


def make_issuer_and_agent() -> tuple[IssuerKey, AgentKey]:
    """Fresh issuer + agent key pair, shared as the trust anchor only."""
    return SigningKey.generate(), SigningKey.generate()


def make_client_side(
    *,
    issuer_key: IssuerKey,
    agent_key: AgentKey,
    capabilities: Dict[str, Dict[str, Any]],
    config: Optional[CompiledMcpConfig] = None,
) -> ClientSide:
    """Build the client side. Defaults to **no config loaded** — override
    ``config`` if the test needs the client to share a config with the
    server."""
    warrant = Warrant.issue(
        issuer_key,
        capabilities=capabilities,
        holder=agent_key.public_key,
    )
    return ClientSide(agent_key=agent_key, warrant=warrant, config=config)


def make_server_side(
    *,
    issuer_key: IssuerKey,
    config: Optional[CompiledMcpConfig] = None,
) -> ServerSide:
    """Build the server side, trust-anchored on ``issuer_key.public_key``.
    Defaults to **no config loaded** — override ``config`` independently
    from whatever the client is using."""
    authorizer = Authorizer(trusted_roots=[issuer_key.public_key])
    return ServerSide(authorizer=authorizer, config=config)


# ---------------------------------------------------------------------------
# Composed handshake
# ---------------------------------------------------------------------------


@dataclass
class HandshakeResult:
    wire_args: Dict[str, Any]
    meta: Dict[str, Any]
    verify_result: MCPVerificationResult


def perform_handshake(
    client: ClientSide,
    server: ServerSide,
    tool: str,
    wire_args: Dict[str, Any],
) -> HandshakeResult:
    """Drive the full MCP handshake with the given client and server sides.

    The returned :class:`HandshakeResult` exposes the verifier result so
    the test can assert on ``allowed`` / ``denial_reason`` /
    ``constraints`` — the three things callers actually observe.
    """
    meta = client.build_meta(tool, wire_args)
    verify_result = server.verify(tool, wire_args, meta=meta)
    return HandshakeResult(wire_args=wire_args, meta=meta, verify_result=verify_result)


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def write_config_yaml(tmp_path: Any, yaml: str) -> CompiledMcpConfig:
    """Compile a ``CompiledMcpConfig`` from an inline YAML string.

    ``tmp_path`` is a pytest ``tmp_path`` fixture-like object with a
    ``__truediv__`` that produces a file Path (works with the standard
    pytest fixture unchanged)."""
    from tenuo_core import McpConfig

    path = tmp_path / "mcp.yaml"
    path.write_text(yaml)
    return CompiledMcpConfig.compile(McpConfig.from_file(str(path)))


# Canonical YAMLs used across asymmetry tests.
CONFIG_A_MAXSIZE_TO_MAX_SIZE = """
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

CONFIG_B_MAXSIZE_TO_MAX_SIZE_DIFFERENT_DEFAULT = """
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
        default: 512
"""

CONFIG_C_NO_EXTRACTION_RENAMES = """
version: "1"
tools:
  read_file:
    description: "Read a file"
    constraints:
      path:
        from: body
        path: "path"
        required: true
"""


__all__ = [
    "ClientSide",
    "ServerSide",
    "HandshakeResult",
    "make_issuer_and_agent",
    "make_client_side",
    "make_server_side",
    "perform_handshake",
    "write_config_yaml",
    "CONFIG_A_MAXSIZE_TO_MAX_SIZE",
    "CONFIG_B_MAXSIZE_TO_MAX_SIZE_DIFFERENT_DEFAULT",
    "CONFIG_C_NO_EXTRACTION_RENAMES",
]
