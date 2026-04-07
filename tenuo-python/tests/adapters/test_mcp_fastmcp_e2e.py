"""
End-to-end tests: ``SecureMCPClient`` ↔ stdio FastMCP + :class:`TenuoMiddleware`.

Requires ``tenuo[fastmcp]`` (MCP SDK + FastMCP). Skips when dependencies or the
fixture server script are missing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

try:
    from tenuo.mcp import MCP_AVAILABLE, SecureMCPClient

    from tenuo import Capability, SigningKey, configure, mint
except ImportError:
    MCP_AVAILABLE = False
    SecureMCPClient = None  # type: ignore[misc, assignment]

pytest.importorskip("fastmcp")

pytestmark = [
    pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed"),
]


def _server_script() -> Path:
    return Path(__file__).resolve().parent.parent / "fixtures" / "fastmcp_middleware_e2e_server.py"


def _repo_pythonpath() -> str:
    """``tenuo-python`` root so the child process loads this tree, not stale site-packages."""
    root = Path(__file__).resolve().parent.parent.parent
    existing = os.environ.get("PYTHONPATH", "")
    return f"{root}{os.pathsep}{existing}" if existing else str(root)


@pytest.fixture
def e2e_server() -> Path:
    p = _server_script()
    if not p.is_file():
        pytest.skip("FastMCP E2E server fixture not found")
    return p


@pytest.mark.asyncio
async def test_e2e_middleware_accepts_injected_warrant(e2e_server: Path) -> None:
    """Wire path: client injects _meta.tenuo; server middleware verifies before tool runs."""
    issuer = SigningKey.generate()
    pub_hex = issuer.public_key.to_bytes().hex()
    configure(issuer_key=issuer, dev_mode=True)
    env = {
        **os.environ,
        "TENUO_MCP_E2E_ISSUER_PUB": pub_hex,
        "PYTHONPATH": _repo_pythonpath(),
    }

    async with SecureMCPClient(
        command=sys.executable,
        args=[str(e2e_server)],
        env=env,
        inject_warrant=True,
    ) as client:
        async with mint(Capability("ping")):
            raw = await client.call_tool(
                "ping",
                {},
                warrant_context=False,
                inject_warrant=True,
            )
    text = "".join(getattr(b, "text", str(b)) for b in raw)
    assert "pong" in text


@pytest.mark.asyncio
async def test_e2e_middleware_denies_without_warrant_structured(e2e_server: Path) -> None:
    """No _meta.tenuo → middleware denies; MCP client surfaces isError + structured tenuo."""
    issuer = SigningKey.generate()
    pub_hex = issuer.public_key.to_bytes().hex()
    configure(issuer_key=issuer, dev_mode=True)
    env = {
        **os.environ,
        "TENUO_MCP_E2E_ISSUER_PUB": pub_hex,
        "PYTHONPATH": _repo_pythonpath(),
    }

    async with SecureMCPClient(
        command=sys.executable,
        args=[str(e2e_server)],
        env=env,
        inject_warrant=True,
    ) as client:
        assert client.session is not None
        result = await client.session.call_tool("ping", {}, meta=None)

    assert result.isError is True
    assert result.structuredContent is not None
    tenuo = result.structuredContent.get("tenuo")
    assert isinstance(tenuo, dict)
    assert tenuo.get("code") == -32001
    assert "message" in tenuo
    assert "No warrant" in (tenuo.get("message") or "")
