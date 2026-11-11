"""Rust-issued signed policies must retain presence semantics at Python receivers.

Regenerate fixtures with the ignored Rust optional_arguments fixture generator.
The signing key is public synthetic test data, never a deployed trust root.
"""

import base64
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tenuo import Authorizer, Exact, Range, SigningKey, Warrant
from tenuo._enforcement import enforce_tool_call, enforce_tool_call_async
from tenuo._pop_canonicalize import constraint_view


@pytest.fixture
def policy():
    fixtures = Path(__file__).resolve().parents[3] / "tenuo-core/tests/fixtures/optional_arguments.json"
    tokens = json.loads(fixtures.read_text())
    return SigningKey.from_bytes(bytes([7] * 32)), {
        name: Warrant.from_base64(token) for name, token in tokens.items()
    }


CASES = [
    ("range", {}, True),
    ("range", {"head": None}, False),
    ("range", {"head": 200}, True),
    ("range", {"head": 201}, False),
    ("range", {"head": "200"}, False),
    ("list", {}, True),
    ("list", {"head": [1]}, True),
    ("list", {"head": [1, None]}, False),
    ("wildcard", {}, True),
    ("wildcard", {"head": None}, False),
    ("null", {}, True),
    ("null", {"head": None}, True),
    ("null", {"head": 1}, False),
    ("exact_precedence", {}, False),
    ("exact_precedence", {"head": 100}, True),
    ("exact_precedence", {"head": 101}, False),
]


@pytest.mark.parametrize("name,args,allowed", CASES)
@pytest.mark.parametrize("async_path", [False, True])
@pytest.mark.asyncio
async def test_python_enforcement_matches_native(policy, name, args, allowed, async_path):
    key, warrants = policy
    warrant = warrants[name]
    signature = warrant.sign(key, "read", args, int(time.time()))
    authorizer = Authorizer(trusted_roots=[key.public_key])
    if allowed:
        authorizer.authorize_one(warrant, "read", args, signature)
    else:
        with pytest.raises(Exception):
            authorizer.authorize_one(warrant, "read", args, signature)
    kwargs = dict(
        tool_name="read", tool_args=args, bound_warrant=warrant.bind(key),
        trusted_roots=[key.public_key], verify_mode="verify", authorizer=authorizer,
        precomputed_signature=signature,
    )
    result = await enforce_tool_call_async(**kwargs) if async_path else enforce_tool_call(**kwargs)
    assert result.allowed == allowed, result.denial_reason


@pytest.mark.parametrize("name,args,allowed", CASES)
def test_mcp_signed_receiver(policy, name, args, allowed):
    from tenuo.mcp.client import _constraint_view
    from tenuo.mcp.server import MCPVerifier

    key, warrants = policy
    warrant = warrants[name]
    signature = warrant.sign(key, "read", args, int(time.time()))
    result = MCPVerifier(authorizer=Authorizer(trusted_roots=[key.public_key])).verify(
        "read", args, meta={"tenuo": {
            "warrant": warrant.to_base64(),
            "signature": base64.b64encode(bytes(signature)).decode(),
        }},
    )
    assert result.allowed == allowed, result.denial_reason
    # Client extraction must not erase values before enforcement sees the policy.
    assert _constraint_view(args) == args
    assert _constraint_view({}, args) == args


def test_chain_preserves_parent_optional_fields_and_legacy_normalization(policy):
    key, warrants = policy
    legacy = Warrant.issue(key, capabilities={"read": {"head": Range(max=200)}}, holder=key.public_key)
    args = {"head": None, "legacy": None, "xs": [1, None]}
    assert constraint_view(args, "read", [legacy]) == {"xs": [1]}
    assert constraint_view(args, "read", [warrants["range"], legacy]) == {"head": None, "xs": [1]}
    assert warrants["wildcard"].optional_fields("read") == ["head"]
    assert warrants["range"].optional_fields("other") == []
    assert warrants["exact_precedence"].optional_fields("read") == []
    assert warrants["exact_precedence"].optional_fields("other") == ["head"]


@pytest.mark.parametrize("async_path", [False, True])
@pytest.mark.asyncio
async def test_required_child_cannot_erase_optional_parent_list_nulls(policy, async_path):
    key, warrants = policy
    parent = warrants["list"]
    child = (parent.grant_builder().capability("read", head=Exact([1]))
             .holder(key.public_key).ttl(300).grant(key))
    kwargs = dict(tool_name="read", tool_args={"head": [1, None]}, bound_warrant=child.bind(key),
                  warrant_chain=[parent], trusted_roots=[key.public_key])
    result = await enforce_tool_call_async(**kwargs) if async_path else enforce_tool_call(**kwargs)
    assert not result.allowed


@pytest.mark.parametrize("args,allowed", [({}, True), ({"head": None}, False), ({"head": 200}, True)])
def test_mcp_extracted_optional_values(policy, tmp_path, args, allowed):
    from tenuo_core import CompiledMcpConfig, McpConfig

    from tenuo.mcp.server import MCPVerifier

    config_file = tmp_path / "optional.yaml"
    config_file.write_text('''version: "1"
tools:
  read:
    description: "Read with optional head"
    constraints:
      head:
        from: body
        path: "head"
        required: false
''')
    config = CompiledMcpConfig.compile(McpConfig.from_file(str(config_file)))
    key, warrants = policy
    warrant = warrants["range"]
    signature = warrant.sign(key, "read", args, int(time.time()))
    result = MCPVerifier(authorizer=Authorizer(trusted_roots=[key.public_key]), config=config).verify(
        "read", args, meta={"tenuo": {"warrant": warrant.to_base64(),
                                     "signature": base64.b64encode(bytes(signature)).decode()}},
    )
    assert result.allowed == allowed, result.denial_reason


@pytest.mark.parametrize("args,allowed", [({}, True), ({"head": None}, False), ({"head": 201}, False)])
@pytest.mark.asyncio
async def test_temporal_signed_receiver(policy, args, allowed):
    pytest.importorskip("temporalio")
    from temporalio.exceptions import ApplicationError

    from tenuo.temporal._config import TenuoPluginConfig
    from tenuo.temporal._constants import TENUO_POP_HEADER
    from tenuo.temporal._headers import tenuo_headers
    from tenuo.temporal._interceptors import TenuoWorkerInterceptor
    from tenuo.temporal._resolvers import EnvKeyResolver

    key, warrants = policy
    warrant = warrants["range"]
    signature = warrant.sign(key, "read", args, int(time.time()))
    headers = {
        k: (v if isinstance(v, bytes) else str(v).encode())
        for k, v in tenuo_headers(warrant, "agent1").items() if k.startswith("x-tenuo-")
    }
    headers[TENUO_POP_HEADER] = base64.b64encode(bytes(signature))
    info = MagicMock(activity_type="read", activity_id="1", workflow_id="wf", workflow_run_id="run",
                     workflow_type="W", task_queue="q", attempt=1, is_local=False)

    def read(head=None):
        return head

    inp = MagicMock(fn=read, args=tuple(args.values()),
                    headers={k: MagicMock(data=v) for k, v in headers.items()})
    next_activity = MagicMock(execute_activity=AsyncMock(return_value="ok"), init=MagicMock())
    interceptor = TenuoWorkerInterceptor(TenuoPluginConfig(
        key_resolver=EnvKeyResolver(), trusted_roots=[key.public_key]
    )).intercept_activity(next_activity)
    with patch("temporalio.activity.info", return_value=info):
        if allowed:
            assert await interceptor.execute_activity(inp) == "ok"
        else:
            with pytest.raises(ApplicationError):
                await interceptor.execute_activity(inp)
            next_activity.execute_activity.assert_not_awaited()
