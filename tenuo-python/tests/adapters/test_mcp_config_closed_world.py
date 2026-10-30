"""``MCPVerifier(config=CompiledMcpConfig)`` is closed-world, like raw mode.

Arguments no extraction rule reads used to run unchecked (``follow_symlinks``,
a nested ``query.where``), and a config default was checked while the tool
ran with its own default. These tests call tools through FastMCP's client and
the official SDK client and record what each tool actually received.
"""

from __future__ import annotations

import asyncio
import base64
import time
from typing import Any, Dict, List

import pytest

from tenuo import Authorizer, CompiledMcpConfig, McpConfig, OneOf, Range, SigningKey, Subpath, Warrant, Wildcard
from tenuo.mcp import MCPVerifier

ROOT = SigningKey.generate()
AGENT = SigningKey.generate()

CONFIG_YAML = """
version: "1"
tools:
  read_file:
    description: "read_file"
    constraints:
      path:
        from: body
        path: "path"
        required: true
      max_size:
        from: body
        path: "maxSize"
        type: integer
        default: 1024
  database_query:
    description: "database_query"
    constraints:
      table:
        from: body
        path: "query.table"
        required: true
      operation:
        from: body
        path: "query.operation"
        required: true
      row_limit:
        from: body
        path: "query.limit"
        type: integer
        default: 100
  batch:
    description: "batch"
    constraints:
      ids:
        from: body
        path: "items.*.id"
"""


@pytest.fixture
def config(tmp_path: Any) -> Any:
    path = tmp_path / "mcp-config.yaml"
    path.write_text(CONFIG_YAML)
    return CompiledMcpConfig.compile(McpConfig.from_file(str(path)))


def _warrant(allow_unknown: bool = False) -> Any:
    extra = {"_allow_unknown": True} if allow_unknown else {}
    return (
        Warrant.mint_builder()
        .capability("read_file", path=Subpath("/data"), max_size=Range(0, 2048), **extra)
        .capability("database_query", table=OneOf(["reports"]), operation=OneOf(["select"]), row_limit=Range(0, 500))
        .capability("batch", ids=Wildcard())
        .holder(AGENT.public_key)
        .ttl(300)
        .mint(ROOT)
    )


def _meta(warrant: Any, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    signature = warrant.sign(AGENT, tool, args, int(time.time()))
    return {"tenuo": {"warrant": warrant.to_base64(), "signature": base64.b64encode(bytes(signature)).decode()}}


def _verifier(config: Any) -> MCPVerifier:
    return MCPVerifier(authorizer=Authorizer(trusted_roots=[ROOT.public_key]), config=config)


# --------------------------------------------------------------------- FastMCP


def _fastmcp_server(config: Any, ran: List[Any]) -> Any:
    fastmcp = pytest.importorskip("fastmcp")
    from tenuo.mcp import TenuoMiddleware

    mcp = fastmcp.FastMCP("cfg", middleware=[TenuoMiddleware(_verifier(config))])

    @mcp.tool()
    async def read_file(path: str, maxSize: int = 4096, follow_symlinks: bool = False) -> str:
        ran.append(("read_file", path, maxSize, follow_symlinks))
        return "ok"

    @mcp.tool()
    async def database_query(query: dict) -> str:
        ran.append(("database_query", query.get("table"), query.get("limit", 10000), sorted(query)))
        return "ok"

    @mcp.tool()
    async def batch(items: list) -> str:
        ran.append(("batch", items))
        return "ok"

    return mcp


def _fastmcp_call(config: Any, tool: str, args: Dict[str, Any], warrant: Any = None) -> List[Any]:
    fastmcp = pytest.importorskip("fastmcp")
    ran: List[Any] = []
    server = _fastmcp_server(config, ran)

    async def go() -> None:
        async with fastmcp.Client(server) as client:
            await client.call_tool(tool, args, meta=_meta(warrant or _warrant(), tool, args), raise_on_error=False)

    asyncio.run(go())
    return ran


def test_fastmcp_valid_call_runs(config: Any) -> None:
    assert _fastmcp_call(config, "read_file", {"path": "/data/a", "maxSize": 100}) == [("read_file", "/data/a", 100, False)]


def test_fastmcp_unread_top_level_argument_is_denied(config: Any) -> None:
    args = {"path": "/data/a", "maxSize": 100, "follow_symlinks": True}
    assert _fastmcp_call(config, "read_file", args) == []


def test_fastmcp_unread_argument_allowed_when_warrant_allows_unknown(config: Any) -> None:
    args = {"path": "/data/a", "maxSize": 100, "follow_symlinks": True}
    assert _fastmcp_call(config, "read_file", args, _warrant(allow_unknown=True)) == [("read_file", "/data/a", 100, True)]


def test_fastmcp_unread_nested_key_is_denied(config: Any) -> None:
    args = {"query": {"table": "reports", "operation": "select", "limit": 5, "where": "1=1; DROP"}}
    assert _fastmcp_call(config, "database_query", args) == []


def test_fastmcp_tool_receives_the_checked_default(config: Any) -> None:
    ran = _fastmcp_call(config, "database_query", {"query": {"table": "reports", "operation": "select"}})
    assert ran == [("database_query", "reports", 100, ["limit", "operation", "table"])]


def test_fastmcp_default_over_warrant_is_denied(config: Any, tmp_path: Any) -> None:
    path = tmp_path / "big.yaml"
    path.write_text(CONFIG_YAML.replace("default: 100", "default: 5000"))
    big = CompiledMcpConfig.compile(McpConfig.from_file(str(path)))
    assert _fastmcp_call(big, "database_query", {"query": {"table": "reports", "operation": "select"}}) == []


def test_fastmcp_wildcard_rule_reads_each_item(config: Any) -> None:
    assert _fastmcp_call(config, "batch", {"items": [{"id": "a"}, {"id": "b"}]}) == [("batch", [{"id": "a"}, {"id": "b"}])]
    assert _fastmcp_call(config, "batch", {"items": [{"id": "a", "force": True}]}) == []
    assert _fastmcp_call(config, "batch", {"items": [{"id": "a"}, "raw"]}) == []


# ---------------------------------------------------------------- official SDK


def _sdk_call(config: Any, tool: str, args: Dict[str, Any]) -> List[Any]:
    pytest.importorskip("mcp.server.context", reason="requires the MCP SDK 2.x server middleware")
    from mcp.client.client import Client
    from mcp.server.mcpserver import MCPServer

    from tenuo.mcp import TenuoServerMiddleware

    ran: List[Any] = []
    authorization = TenuoServerMiddleware(_verifier(config))
    server = MCPServer("cfg", middleware=[authorization])

    @authorization.tool(server)
    def database_query(query: dict) -> str:
        ran.append(("database_query", query.get("limit", 10000), sorted(query)))
        return "ok"

    @authorization.tool(server)
    def read_file(path: str, maxSize: int, follow_symlinks: bool) -> str:
        ran.append(("read_file", path, maxSize, follow_symlinks))
        return "ok"

    async def go() -> None:
        async with Client(server) as client:
            await client.call_tool(tool, args, meta=_meta(_warrant(), tool, args))

    asyncio.run(go())
    return ran


def test_sdk_tool_receives_the_checked_default(config: Any) -> None:
    ran = _sdk_call(config, "database_query", {"query": {"table": "reports", "operation": "select"}})
    assert ran == [("database_query", 100, ["limit", "operation", "table"])]


def test_sdk_unread_arguments_are_denied(config: Any) -> None:
    assert _sdk_call(config, "read_file", {"path": "/data/a", "maxSize": 10, "follow_symlinks": True}) == []
    args = {"query": {"table": "reports", "operation": "select", "limit": 5, "where": "x"}}
    assert _sdk_call(config, "database_query", args) == []
    assert _sdk_call(config, "read_file", {"path": "/data/a", "maxSize": 10, "follow_symlinks": False}) == []


# ------------------------------------------------------------------- verifier


def test_verifier_passes_the_checked_nested_default(config: Any) -> None:
    args = {"query": {"table": "reports", "operation": "select"}}
    result = _verifier(config).verify(
        "database_query", args, meta=_meta(_warrant(), "database_query", args)
    )

    assert result.allowed, result.denial_reason
    assert result.clean_arguments["query"]["limit"] == 100


def test_wildcard_default_is_denied_when_it_cannot_be_injected(
    tmp_path: Any,
) -> None:
    path = tmp_path / "wildcard-default.yaml"
    path.write_text(
        '''version: "1"
tools:
  batch:
    description: batch
    constraints:
      ids:
        from: body
        path: "items.*.id"
        default: [safe]
'''
    )
    cfg = CompiledMcpConfig.compile(McpConfig.from_file(str(path)))
    args = {"items": [{}]}
    result = _verifier(cfg).verify(
        "batch", args, meta=_meta(_warrant(), "batch", args)
    )

    assert not result.allowed
    assert result.jsonrpc_error_code == -32602
    assert "cannot be passed to the tool" in result.denial_reason


def test_conflicting_defaults_for_one_argument_path_are_denied(
    tmp_path: Any,
) -> None:
    path = tmp_path / "conflicting-defaults.yaml"
    path.write_text(
        '''version: "1"
tools:
  conflicting:
    description: conflicting
    constraints:
      first:
        from: body
        path: "option"
        default: one
      second:
        from: body
        path: "option"
        default: two
'''
    )
    cfg = CompiledMcpConfig.compile(McpConfig.from_file(str(path)))
    warrant = (
        Warrant.mint_builder()
        .capability("conflicting", first=Wildcard(), second=Wildcard())
        .holder(AGENT.public_key)
        .ttl(60)
        .mint(ROOT)
    )
    args: Dict[str, Any] = {}
    result = _verifier(cfg).verify(
        "conflicting", args, meta=_meta(warrant, "conflicting", args)
    )

    assert not result.allowed
    assert result.jsonrpc_error_code == -32602
    assert "cannot be passed to the tool" in result.denial_reason


@pytest.mark.parametrize("items", [[], [{}]])
def test_empty_containers_that_never_reach_a_rule_are_unread(
    config: Any, items: List[Any]
) -> None:
    args = {"items": items}
    result = _verifier(config).verify(
        "batch", args, meta=_meta(_warrant(), "batch", args)
    )

    assert not result.allowed


def test_unread_argument_named_like_a_constraint_is_refused(tmp_path: Any) -> None:
    path = tmp_path / "c.yaml"
    path.write_text('version: "1"\ntools:\n  read_file:\n    description: x\n    constraints:\n      path:\n        from: body\n        path: "file.path"\n')
    cfg = CompiledMcpConfig.compile(McpConfig.from_file(str(path)))
    args = {"file": {"path": "/data/a"}, "path": "/etc/passwd"}
    w = Warrant.mint_builder().capability("read_file", path=Subpath("/data")).holder(AGENT.public_key).ttl(60).mint(ROOT)
    result = _verifier(cfg).verify("read_file", args, meta=_meta(w, "read_file", args))
    assert not result.allowed and result.jsonrpc_error_code == -32602


def test_config_without_rule_listing_fails_closed(config: Any) -> None:
    class Opaque:
        def extract_constraints(self, tool: str, args: Dict[str, Any]) -> Any:
            return config.extract_constraints(tool, args)

    args = {"path": "/data/a", "maxSize": 100}
    result = _verifier(Opaque()).verify("read_file", args, meta=_meta(_warrant(), "read_file", args))
    assert not result.allowed and result.jsonrpc_error_code == -32602
