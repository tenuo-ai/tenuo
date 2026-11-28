"""Adapters refuse arguments their framework would convert after authorization."""

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, List, Optional

import pytest

pytest.importorskip("tenuo_core")

from tenuo import SigningKey, Warrant, Wildcard  # noqa: E402

DEPLOY_SCHEMA = {
    "type": "object",
    "properties": {
        "env": {"type": "string"},
        "dry_run": {"type": "boolean"},
        "replicas": {"type": "integer"},
    },
}


def test_mcp_verifier_denies_arguments_the_schema_would_convert():
    from tenuo_core import Authorizer

    from tenuo.mcp.server import MCPVerifier

    key = SigningKey.generate()
    verifier = MCPVerifier(
        authorizer=Authorizer(trusted_roots=[key.public_key]),
        require_warrant=False,
        control_plane=False,
    )

    for arguments in ({"dry_run": "off"}, {"replicas": "22"}, {"dry_run": 0}):
        result = verifier.verify("deploy", arguments, input_schema=DEPLOY_SCHEMA)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32602
        assert result.clean_arguments == {}

    honest = {"env": "prod", "dry_run": False, "replicas": 2}
    assert verifier.verify("deploy", honest, input_schema=DEPLOY_SCHEMA).allowed
    # Without a schema the verifier has nothing to compare against.
    assert verifier.verify("deploy", {"dry_run": "off"}).allowed


@pytest.mark.asyncio
async def test_fastmcp_middleware_reads_the_registered_schema_before_execution():
    fastmcp = pytest.importorskip("fastmcp")
    from fastmcp.exceptions import ToolError
    from tenuo_core import Authorizer

    from tenuo.mcp import MCPVerifier, TenuoMiddleware

    issuer = SigningKey.generate()
    server = fastmcp.FastMCP("typed", middleware=[TenuoMiddleware(MCPVerifier(
        authorizer=Authorizer(trusted_roots=[issuer.public_key]), require_warrant=False, control_plane=False,
    ))])
    ran = []

    @server.tool()
    def deploy(dry_run: bool) -> str:
        ran.append(dry_run)
        return "ok"

    async with fastmcp.Client(server) as client:
        with pytest.raises(ToolError, match="type does not match"):
            await client.call_tool("deploy", {"dry_run": "off"})
        assert ran == []
        await client.call_tool("deploy", {"dry_run": False})
    assert ran == [False]


@pytest.mark.asyncio
async def test_fastmcp_schema_checks_injected_config_defaults(tmp_path):
    fastmcp = pytest.importorskip("fastmcp")
    from tenuo import Authorizer, CompiledMcpConfig, McpConfig
    from tenuo.mcp import MCPVerifier, TenuoMiddleware

    issuer = SigningKey.generate()
    ran = []
    config_path = tmp_path / "default.yaml"
    config_path.write_text('''version: "1"
tools:
  deploy:
    description: Deploy
    constraints:
      dry_run:
        from: body
        path: dry_run
        default: "off"
''')

    async def call():
        config = CompiledMcpConfig.compile(McpConfig.from_file(str(config_path)))
        verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[issuer.public_key]),
                               config=config, require_warrant=False, control_plane=False)
        server = fastmcp.FastMCP("defaults", middleware=[TenuoMiddleware(verifier)])

        @server.tool()
        def deploy(dry_run: bool = True) -> str:
            ran.append(dry_run)
            return "ok"

        async with fastmcp.Client(server) as client:
            return await client.call_tool("deploy", {}, raise_on_error=False)

    result = await call()
    assert result.is_error
    assert ran == []
    config_path.write_text(config_path.read_text().replace('"off"', 'false'))
    result = await call()
    assert not result.is_error
    assert ran == [False]


@pytest.mark.asyncio
async def test_fastmcp_left_to_right_union_never_executes_a_converted_value():
    from typing import Annotated, Union

    fastmcp = pytest.importorskip("fastmcp")
    from pydantic import Field
    from tenuo import Authorizer
    from tenuo.mcp import MCPVerifier, TenuoMiddleware

    issuer = SigningKey.generate()
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[issuer.public_key]),
                           require_warrant=False, control_plane=False)
    server = fastmcp.FastMCP("unions", middleware=[TenuoMiddleware(verifier)])
    ran = []

    @server.tool()
    def deploy(mode: Annotated[Union[bool, str], Field(union_mode="left_to_right")]) -> str:
        ran.append(mode)
        return "ok"

    async with fastmcp.Client(server) as client:
        assert (await client.call_tool("deploy", {"mode": "off"}, raise_on_error=False)).is_error
        assert ran == []
        await client.call_tool("deploy", {"mode": False})
        await client.call_tool("deploy", {"mode": "draft"})
    assert ran == [False, "draft"]


def test_langgraph_denies_before_the_tool_validates():
    pytest.importorskip("langgraph")
    tools = pytest.importorskip("langchain_core.tools")

    from tenuo.langgraph import _authorize_tool_request

    ran: List[Any] = []

    def open_port(port: int, force: bool = False) -> str:
        """Open a port."""
        ran.append((port, force))
        return "ok"

    tool = tools.StructuredTool.from_function(open_port)
    issuer, key = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .capability("open_port", port=Wildcard(), force=Wildcard())
        .holder(key.public_key)
        .ttl(300)
        .mint(issuer)
    )

    def run(args):
        request = SimpleNamespace(
            tool=tool,
            tool_call={"name": "open_port", "args": args, "id": "call-1"},
        )
        return _authorize_tool_request(
            request,
            lambda req: tool.invoke(req.tool_call["args"]),
            bw_factory=lambda req: warrant.bind(key),
            trusted_roots=[issuer.public_key],
        )

    for args in ({"port": "22"}, {"port": 8080, "force": "yes"}, {"port": 8080, "force": 1}):
        message = run(args)
        assert getattr(message, "status", None) == "error"
    assert ran == []

    assert run({"port": 8080, "force": True}) == "ok"
    assert ran == [(8080, True)]


def test_crewai_hook_blocks_before_the_tool_validates():
    pytest.importorskip("crewai")
    pydantic = pytest.importorskip("pydantic")

    from tenuo.crewai import GuardBuilder

    class TransferArgs(pydantic.BaseModel):
        amount: float
        dry_run: bool = True

    guard = GuardBuilder().allow("transfer", amount=Wildcard(), dry_run=Wildcard()).build()
    hook = guard._create_hook()

    def call(tool_input):
        return hook(
            SimpleNamespace(
                tool_name="transfer",
                tool_input=tool_input,
                tool=SimpleNamespace(args_schema=TransferArgs),
                agent=None,
            )
        )

    assert call({"amount": 5, "dry_run": "off"}) is False
    assert call({"amount": "5000", "dry_run": True}) is False
    assert call({"amount": 5, "dry_run": True}) is None


def test_openai_parse_arguments_must_match_the_parsed_model():
    pytest.importorskip("openai")
    pydantic = pytest.importorskip("pydantic")

    from tenuo.openai import ToolDenied, _parsed_arguments_schema, _require_declared_argument_types

    class Deploy(pydantic.BaseModel):
        env: str
        dry_run: bool
        budget: float

    parsed = Deploy(env="prod", dry_run=False, budget=50000.0)
    call = SimpleNamespace(function=SimpleNamespace(name="deploy", parsed_arguments=parsed))
    schema = _parsed_arguments_schema(call)

    with pytest.raises(ToolDenied):
        _require_declared_argument_types(
            "deploy", schema, {"env": "prod", "dry_run": "off", "budget": "50000"}
        )
    _require_declared_argument_types("deploy", schema, {"env": "prod", "dry_run": False, "budget": 5})

    # A plain create() call carries no parsed model, so there is no schema.
    plain = SimpleNamespace(function=SimpleNamespace(name="deploy", arguments="{}"))
    assert _parsed_arguments_schema(plain) is None
    _require_declared_argument_types("deploy", None, {"dry_run": "off"})


@dataclass
class _Function:
    name: str
    arguments: str


@dataclass
class _ToolCallDelta:
    index: int
    id: Optional[str] = None
    function: Optional[_Function] = None


@dataclass
class _Delta:
    tool_calls: Optional[List[Any]] = None
    content: Optional[str] = None


@dataclass
class _Choice:
    index: int
    delta: _Delta
    finish_reason: Optional[str] = None


@dataclass
class _Chunk:
    id: str
    choices: List[_Choice]


def _stream(arguments: str) -> List[_Chunk]:
    call = _ToolCallDelta(index=0, id="call_0", function=_Function("open_port", arguments))
    return [_Chunk("chunk_0", [_Choice(0, _Delta(tool_calls=[call]), "tool_calls")])]


def test_autogen_guard_stream_uses_tool_schemas_when_given():
    from tenuo.autogen import GuardBuilder

    guard = GuardBuilder().allow("open_port", port=Wildcard()).on_denial("skip").build()
    schemas = {"open_port": {"type": "object", "properties": {"port": {"type": "integer"}}}}

    def emitted(arguments: str, **kwargs) -> List[Any]:
        chunks = list(guard.guard_stream(iter(_stream(arguments)), **kwargs))
        return [tc for c in chunks for ch in c.choices for tc in (ch.delta.tool_calls or [])]

    assert emitted('{"port": "22"}', tool_schemas=schemas) == []
    assert len(emitted('{"port": 22}', tool_schemas=schemas)) == 1
    # Without schemas the stream guard cannot know the declared type.
    assert len(emitted('{"port": "22"}')) == 1
