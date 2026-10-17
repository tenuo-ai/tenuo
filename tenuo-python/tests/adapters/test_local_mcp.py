"""Exercise local MCP verification and real client/server stdio transport."""

import json
import os
import sys
import time

import pytest

pytest.importorskip("mcp")
pytest.importorskip("fastmcp")

from tenuo import SigningKey, WarrantTemplate
from tenuo.approval import ApprovalRequired
from tenuo.local_cli.approvals import sign_response
from tenuo.local_cli.files import load_yaml, publish, update_revocations, write_yaml
from tenuo.local_cli.warrants import encode_chain
from tenuo.local_cli.workspace import Workspace
from tenuo.mcp import MCPVerifier, SecureMCPClient
from tenuo_core import sign_meta


@pytest.fixture
def local_mcp(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    document = {
        "version": 2,
        "ttl": "30m",
        "capabilities": {"refund": {"order_id": "A-1001", "amount_cents": "1..12000"}},
    }
    warrant = WarrantTemplate(document).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    path = tmp_path / "agent.warrant"
    path.write_text(encode_chain([warrant]))
    return workspace, path, document


def test_server_needs_only_public_files_and_denies_missing_proof(local_mcp):
    workspace, path, _ = local_mcp
    from tenuo.local_cli.warrants import load_chain

    chain, agent = load_chain(path), workspace.signing_key("agent")
    for private in workspace.path.glob("keys/*.key"):
        private.unlink()
    verifier = MCPVerifier.local(path=workspace.path)
    args = {"order_id": "A-1001", "amount_cents": 5000}
    meta = {"tenuo": sign_meta(chain, agent, "refund", json.dumps(args), int(time.time()))}
    assert verifier.verify("refund", args, meta=meta).allowed
    assert not verifier.verify("refund", args).allowed
    assert not verifier.verify("refund", dict(args, order_id="OTHER"), meta=meta).allowed
    (workspace.path / "trust/issuer.pub").unlink()
    assert not verifier.verify("refund", args, meta=meta).allowed


@pytest.mark.parametrize("value", [False, None, 0, ""])
def test_local_verifier_rejects_every_falsey_require_warrant(local_mcp, value):
    workspace, _, _ = local_mcp
    with pytest.raises(Exception):
        MCPVerifier.local(path=workspace.path, require_warrant=value)


@pytest.mark.parametrize("value", [False, None, 0, ""])
def test_local_client_requires_an_explicit_presentation_mode(local_mcp, value):
    workspace, path, _ = local_mcp
    with pytest.raises(Exception):
        SecureMCPClient.local(path=workspace.path, warrant=path, command="python", inject_warrant=value)


@pytest.mark.asyncio
async def test_a15_real_fastmcp_middleware_blocks_before_handler(local_mcp):
    from fastmcp import Client, FastMCP
    from tenuo.mcp import TenuoMiddleware
    from tenuo.local_cli.warrants import load_chain

    workspace, path, _ = local_mcp
    chain, agent = load_chain(path), workspace.signing_key("agent")
    verifier = MCPVerifier.local(path=workspace.path)
    server = FastMCP("local-test", middleware=[TenuoMiddleware(verifier)])
    calls = []

    @server.tool()
    def refund(order_id: str, amount_cents: int) -> str:
        calls.append(order_id)
        return "refunded"

    async with Client(server) as client:
        for order in ("A-1001", "OTHER"):
            args = {"order_id": order, "amount_cents": 5000}
            meta = {"tenuo": sign_meta(chain, agent, "refund", json.dumps(args), int(time.time()))}
            result = await client.call_tool("refund", args, meta=meta, raise_on_error=False)
            assert result.is_error is (order != "A-1001")
        update_revocations(workspace.path / "revocations.srl", workspace.signing_key("issuer"), [chain[-1].id])
        args = {"order_id": "A-1001", "amount_cents": 5000}
        meta = {"tenuo": sign_meta(chain, agent, "refund", json.dumps(args), int(time.time()))}
        assert (await client.call_tool("refund", args, meta=meta, raise_on_error=False)).is_error
    assert calls == ["A-1001"]


@pytest.mark.asyncio
@pytest.mark.parametrize("delegated", [False, True])
async def test_a16_local_client_stdio_and_file_approval_reach_server(local_mcp, tmp_path, monkeypatch, delegated):
    workspace, path, document = local_mcp
    document["approvals"] = {"keys": [str(workspace.path / "keys/approver.pub")], "required": {"refund": "always"}}
    warrant = WarrantTemplate(document).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    chain = [warrant]
    if delegated:
        child = (warrant.grant_builder().holder(workspace.public_key("agent"))
                 .capability("refund", **warrant.capabilities["refund"]).ttl(600)
                 .grant(workspace.signing_key("agent")))
        chain.append(child)
    publish(path, (encode_chain(chain) + "\n").encode(), replace=True)
    # Local Runtime authority must remain independent of ambient configure().
    unrelated = SigningKey.generate().public_key
    monkeypatch.setattr("tenuo.config.resolve_trusted_roots", lambda *a, **kw: [unrelated])
    script = tmp_path / "server.py"
    marker = tmp_path / "effects.txt"
    script.write_text(
        "from pathlib import Path\nfrom fastmcp import FastMCP\n"
        "from tenuo.mcp import MCPVerifier, TenuoMiddleware\n"
        f"server = FastMCP('local-test', middleware=[TenuoMiddleware(MCPVerifier.local(path={str(workspace.path)!r}))])\n"
        "@server.tool()\ndef refund(order_id: str, amount_cents: int) -> str:\n"
        f"    with Path({str(marker)!r}).open('a') as out: out.write(order_id + '\\n')\n"
        "    return 'refunded'\nserver.run(show_banner=False)\n"
    )
    env = dict(os.environ)
    async with SecureMCPClient.local(
        path=workspace.path, warrant=path, command=sys.executable, args=[str(script)], env=env
    ) as client:
        args = {"order_id": "A-1001", "amount_cents": 6000}
        with pytest.raises(ApprovalRequired):
            await client.call_tool("refund", args)
        assert not marker.exists()
        request_path = next((workspace.path / "requests").glob("*.yaml"))
        request = load_yaml(request_path)
        write_yaml(
            workspace.path / "approvals" / request_path.name,
            sign_response(request, workspace.authorizer(), workspace.signing_key("approver")),
        )
        await client.call_tool("refund", args)
        with pytest.raises(Exception):
            await client.call_tool("refund", dict(args, order_id="OTHER"))
        with pytest.raises(Exception):
            await client.call_tool("refund", args, warrant_context=False)
    assert marker.read_text().splitlines() == ["A-1001"]
