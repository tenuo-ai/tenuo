"""
``tenuo.mcp.gateway``: a verifying proxy in front of an unmodified MCP server.

Upstream and gateway run in process (FastMCP in-memory transport); calls carry
``_meta.tenuo`` signed by the holder, as ``SecureMCPClient`` and other Tenuo
clients send them.
"""

from __future__ import annotations

import json
import time

import pytest

pytest.importorskip("fastmcp")

from fastmcp import Client, FastMCP  # noqa: E402
from tenuo_core import sign_meta  # noqa: E402

from tenuo import SigningKey, Warrant  # noqa: E402
from tenuo.cli import verify_receipt_chain  # noqa: E402
from tenuo.identity import HolderIdentity  # noqa: E402
from tenuo.mcp.gateway import create_gateway  # noqa: E402

from .._mcp_sdk_support import (  # noqa: E402
    FASTMCP_SERVER_AVAILABLE,
    FASTMCP_SERVER_SKIP_REASON,
)

pytestmark = pytest.mark.skipif(not FASTMCP_SERVER_AVAILABLE, reason=FASTMCP_SERVER_SKIP_REASON)


def _upstream() -> tuple[FastMCP, list[str]]:
    server = FastMCP("upstream")
    ran: list[str] = []

    @server.tool
    def echo(text: str) -> str:
        ran.append("echo")
        return f"echo: {text}"

    @server.tool
    def wipe() -> str:
        ran.append("wipe")
        return "wiped"

    return server, ran


def _meta(warrants, holder, tool, args):
    return {"tenuo": sign_meta(warrants, holder, tool, json.dumps(args), int(time.time()))}


async def _call(client, tool, args, meta):
    return await client.call_tool(tool, args, meta=meta, raise_on_error=False)


def _text(result) -> str:
    return result.content[0].text if result.content else ""


@pytest.mark.asyncio
async def test_forwards_warranted_calls_and_refuses_the_rest(tmp_path) -> None:
    root, agent = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().holder(agent.public_key).capability("echo").ttl(600).mint(root)
    upstream, ran = _upstream()
    receipts = tmp_path / "receipts.jsonl"
    gateway = create_gateway(
        upstream,
        trusted_roots=[root.public_key],
        identity=HolderIdentity.load_or_create(tmp_path / "gateway.key"),
        receipts=receipts,
    )

    async with Client(gateway) as client:
        assert {tool.name for tool in await client.list_tools()} == {"echo", "wipe"}

        allowed = await _call(client, "echo", {"text": "hi"}, _meta([warrant], agent, "echo", {"text": "hi"}))
        assert not allowed.is_error and _text(allowed) == "echo: hi"

        refused = await _call(client, "wipe", {}, _meta([warrant], agent, "wipe", {}))
        assert refused.is_error

        unsigned = await _call(client, "echo", {"text": "hi"}, None)
        assert unsigned.is_error

    assert ran == ["echo"], "refused calls must never reach the upstream"
    lines = receipts.read_text().splitlines()
    assert len(lines) == 2, "one receipt per decision over presented authority"
    assert verify_receipt_chain(str(receipts))


@pytest.mark.asyncio
async def test_untrusted_root_is_refused(tmp_path) -> None:
    root, other_root, agent = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().holder(agent.public_key).capability("echo").ttl(600).mint(other_root)
    upstream, ran = _upstream()
    gateway = create_gateway(upstream, trusted_roots=[root.public_key])

    async with Client(gateway) as client:
        result = await _call(client, "echo", {"text": "hi"}, _meta([warrant], agent, "echo", {"text": "hi"}))
    assert result.is_error
    assert ran == []


@pytest.mark.asyncio
async def test_attenuated_child_verifies_against_the_root(tmp_path) -> None:
    root, agent, worker = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    parent = Warrant.mint_builder().holder(agent.public_key).capability("echo").capability("wipe").ttl(600).mint(root)
    builder = parent.attenuate_builder()
    builder.with_holder(worker.public_key)
    builder.inherit_all()
    builder.retain_tool("echo")
    builder.with_ttl(300)
    child = builder.delegate(agent)
    upstream, ran = _upstream()
    gateway = create_gateway(upstream, trusted_roots=[root.public_key])

    async with Client(gateway) as client:
        ok = await _call(client, "echo", {"text": "hi"}, _meta([parent, child], worker, "echo", {"text": "hi"}))
        narrowed = await _call(client, "wipe", {}, _meta([parent, child], worker, "wipe", {}))
    assert not ok.is_error
    assert narrowed.is_error, "the child dropped wipe, so the gateway must refuse it"
    assert ran == ["echo"]


def test_receipts_need_an_identity(tmp_path) -> None:
    upstream, _ = _upstream()
    with pytest.raises(ValueError):
        create_gateway(upstream, trusted_roots=[SigningKey.generate().public_key], receipts=tmp_path / "r.jsonl")
