"""Parametric contract tests: one enforcement error_type, many integrations."""

from __future__ import annotations

import ast
import base64
import inspect
import time
from unittest.mock import MagicMock, patch

import pytest

from tests.contracts.error_type_contract import (
    AUTH_CATCH_GUARD_MODULES,
    CANONICAL_ERROR_TYPES,
    CONTRACT_ROWS,
    ErrorTypeContract,
)


def _row_ids(row: ErrorTypeContract) -> str:
    return row.error_type


def _integration_rows(integration: str) -> list[ErrorTypeContract]:
    return [row for row in CONTRACT_ROWS if integration in row.integrations]


# ---------------------------------------------------------------------------
# Core: EnforcementResult.raise_if_denied
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", CONTRACT_ROWS, ids=_row_ids)
def test_core_raise_if_denied_matches_contract(row: ErrorTypeContract) -> None:
    exp = row.integrations["core"]
    assert exp.raises is not None
    with pytest.raises(exp.raises):
        row.result_factory().raise_if_denied()


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", _integration_rows("openai"), ids=_row_ids)
def test_openai_mapper_matches_contract(row: ErrorTypeContract) -> None:
    from tenuo.openai import _raise_for_enforcement_denial

    exp = row.integrations["openai"]
    assert exp.raises is not None
    with pytest.raises(exp.raises):
        _raise_for_enforcement_denial("transfer", row.result_factory())


# ---------------------------------------------------------------------------
# CrewAI
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", _integration_rows("crewai"), ids=_row_ids)
def test_crewai_mapper_matches_contract(row: ErrorTypeContract) -> None:
    from tenuo.crewai import CrewAIGuard

    exp = row.integrations["crewai"]
    assert exp.raises is not None
    guard = CrewAIGuard.__new__(CrewAIGuard)
    guard._warrant = None
    guard._signing_key = None
    result = row.result_factory()
    err = guard._map_enforcement_error(result, "transfer", result.arguments, result.denial_reason or "")
    assert isinstance(err, exp.raises)


# ---------------------------------------------------------------------------
# LangGraph
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", _integration_rows("langgraph"), ids=_row_ids)
def test_langgraph_denial_matches_contract(row: ErrorTypeContract) -> None:
    from langchain_core.messages import ToolMessage

    from tenuo.langgraph import _authorize_tool_request

    exp = row.integrations["langgraph"]
    result = row.result_factory()
    request = MagicMock()
    request.tool_call = {"name": "transfer", "args": result.arguments, "id": "call-1"}
    handler = MagicMock(return_value="ok")
    bw = MagicMock()

    with patch("tenuo.langgraph.enforce_tool_call", return_value=result):
        if exp.raises is not None:
            with pytest.raises(exp.raises):
                _authorize_tool_request(
                    request,
                    handler,
                    bw_factory=lambda _req: bw,
                )
        elif exp.returns_tool_message:
            out = _authorize_tool_request(
                request,
                handler,
                bw_factory=lambda _req: bw,
            )
            assert isinstance(out, ToolMessage)
            assert out.status == "error"
            handler.assert_not_called()
        else:
            pytest.fail(f"langgraph contract for {row.error_type} has no signal")


# ---------------------------------------------------------------------------
# FastAPI (TenuoGuard enforcement result path)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", _integration_rows("fastapi"), ids=_row_ids)
def test_fastapi_enforcement_path_matches_contract(row: ErrorTypeContract) -> None:
    pytest.importorskip("fastapi")
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from tenuo import SigningKey, Warrant
    from tenuo.fastapi import TenuoGuard, X_TENUO_POP, X_TENUO_WARRANT, configure_tenuo

    exp = row.integrations["fastapi"]
    assert exp.http_status is not None
    assert exp.http_error is not None

    key = SigningKey.generate()
    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[key.public_key])

    @app.get("/transfer")
    def transfer(ctx=Depends(TenuoGuard("transfer"))):
        return {"ok": True}

    warrant = Warrant.mint_builder().tool("transfer").mint(key)
    args = row.result_factory().arguments
    pop_sig = warrant.sign(key, "transfer", args, int(time.time()))
    pop_b64 = base64.b64encode(pop_sig).decode("ascii")
    headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64}

    with patch.object(
        TenuoGuard,
        "_enforce_with_pop_signature",
        return_value=row.result_factory(),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/transfer", params=args, headers=headers)

    assert resp.status_code == exp.http_status, resp.text
    detail = resp.json()["detail"]
    assert detail["error"] == exp.http_error
    if exp.got_need_in_payload:
        assert detail["got"] == 1
        assert detail["need"] == 2


# ---------------------------------------------------------------------------
# MCP (JSON-RPC payload contract)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", _integration_rows("mcp"), ids=_row_ids)
def test_mcp_jsonrpc_payload_matches_contract(row: ErrorTypeContract) -> None:
    from tenuo.exceptions import InsufficientApprovals
    from tenuo.mcp.server import MCPVerificationResult

    exp = row.integrations["mcp"]
    assert exp.jsonrpc_code is not None

    if row.error_type == "insufficient_approvals":
        exc = InsufficientApprovals(required=2, received=1)
        meta = {"got": exc.details["received"], "need": exc.details["required"]}
        mcp_result = MCPVerificationResult(
            allowed=False,
            tool="transfer",
            clean_arguments={},
            constraints={},
            denial_reason=str(exc),
            jsonrpc_error_code=-32002,
            approval_metadata=meta,
        )
    else:
        mcp_result = MCPVerificationResult(
            allowed=False,
            tool="transfer",
            clean_arguments={},
            constraints={},
            denial_reason=row.result_factory().denial_reason or "",
            jsonrpc_error_code=exp.jsonrpc_code,
        )

    err = mcp_result.to_jsonrpc_error()
    assert err["code"] == exp.jsonrpc_code
    if exp.got_need_in_payload:
        assert err["data"]["got"] == 1
        assert err["data"]["need"] == 2


# ---------------------------------------------------------------------------
# A2A
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", _integration_rows("a2a"), ids=_row_ids)
def test_a2a_error_payload_matches_contract(row: ErrorTypeContract) -> None:
    from tenuo.a2a.errors import InsufficientApprovalsError
    from tenuo.exceptions import InsufficientApprovals

    exp = row.integrations["a2a"]
    assert exp.raises is not None

    core_exc = InsufficientApprovals(required=2, received=1)
    a2a_exc = InsufficientApprovalsError(
        str(core_exc),
        required=core_exc.details["required"],
        received=core_exc.details["received"],
    )
    assert isinstance(a2a_exc, exp.raises)
    rpc = a2a_exc.to_jsonrpc_error()
    if exp.tenuo_wire_code is not None:
        assert rpc["data"]["tenuo_code"] == exp.tenuo_wire_code
    if exp.got_need_in_payload:
        assert rpc["data"]["required"] == 2
        assert rpc["data"]["received"] == 1


# ---------------------------------------------------------------------------
# Temporal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row", _integration_rows("temporal"), ids=_row_ids)
def test_temporal_wire_type_matches_contract(row: ErrorTypeContract) -> None:
    from tenuo.temporal._interceptors import _error_type_for_wire

    exp = row.integrations["temporal"]
    assert exp.wire_type is not None
    exc = row.core_exception
    if row.error_type == "insufficient_approvals":
        instance = exc(required=2, received=1)
    elif row.error_type == "tool_not_allowed":
        instance = exc(tool="transfer")
    elif row.error_type == "constraint_violation":
        instance = exc(field="amount", reason="bad", value=999)
    elif row.error_type == "expired":
        instance = exc("warrant expired")
    elif row.error_type == "invalid_pop":
        instance = exc("bad signature")
    else:
        instance = exc("contract sweep")
    assert _error_type_for_wire(instance) == exp.wire_type


# ---------------------------------------------------------------------------
# Structural: explicit auth exception catch lists
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module_path,required_names",
    list(AUTH_CATCH_GUARD_MODULES.items()),
)
def test_auth_exceptions_in_explicit_catch_list(
    module_path: str,
    required_names: tuple[str, ...],
) -> None:
    """Each auth-family exception must have its own explicit except handler."""
    mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
    source = inspect.getsource(mod)
    tree = ast.parse(source)

    caught: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            continue
        if isinstance(node.type, ast.Tuple):
            names = [ast.unparse(elt) for elt in node.type.elts]
        else:
            names = [ast.unparse(node.type)]
        for req in required_names:
            if any(req in n for n in names):
                caught.add(req)

    missing = set(required_names) - caught
    assert not missing, (
        f"{module_path} is missing explicit except handlers for {sorted(missing)} — "
        f"generic fallthrough causes integration drift"
    )


# ---------------------------------------------------------------------------
# Taxonomy sync: property tests use CANONICAL_ERROR_TYPES
# ---------------------------------------------------------------------------


def test_contract_covers_all_distinct_error_types() -> None:
    """Every contract row error_type is in the canonical taxonomy."""
    for row in CONTRACT_ROWS:
        assert row.error_type in CANONICAL_ERROR_TYPES


def test_canonical_error_types_include_contract_rows() -> None:
    contract_types = {row.error_type for row in CONTRACT_ROWS}
    assert contract_types <= set(CANONICAL_ERROR_TYPES)


class TestEnforcementObservability:
    def test_signature_trust_denial_logs_warning_and_invalid_pop(self):
        """Trust/signature failures stay typed as invalid_pop and log at WARNING."""
        import logging

        from tenuo import SigningKey, Warrant
        from tenuo._enforcement import enforce_tool_call

        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        untrusted = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search")
            .holder(holder.public_key)
            .ttl(3600)
            .mint(issuer)
        )
        bound = warrant.bind(holder)

        records: list[logging.LogRecord] = []

        class _H(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        log = logging.getLogger("tenuo.enforcement")
        handler = _H()
        prev_level = log.level
        log.addHandler(handler)
        log.setLevel(logging.DEBUG)
        try:
            result = enforce_tool_call(
                "search",
                {},
                bound,
                trusted_roots=[untrusted.public_key],
            )
        finally:
            log.removeHandler(handler)
            log.setLevel(prev_level)

        assert not result.allowed
        assert result.error_type == "invalid_pop"
        assert any(r.levelno >= logging.WARNING for r in records), (
            "Signature/trust denials must log at WARNING for operator visibility"
        )


# ---------------------------------------------------------------------------
# Temporal: typed auth branch observability + denial modes
# ---------------------------------------------------------------------------


class TestTemporalExplicitDenialContract:
    """Guard the explicit auth-denial path added for typed wire errors."""

    def test_typed_auth_branch_emits_before_wrap_or_continue(self) -> None:
        import inspect

        from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

        source = inspect.getsource(TenuoActivityInboundInterceptor.execute_activity)
        anchor = source.index(") as auth_exc:")
        block = source[anchor : anchor + 2500]
        emit_at = block.index("_emit_denial_event")
        next_action = min(
            i for i in (
                block.find("_wrap_as_non_retryable(auth_exc)"),
                block.find("_deny_or_continue"),
            )
            if i >= 0
        )
        assert emit_at < next_action, (
            "Typed auth denials must emit metrics/audit before wrap or continue"
        )

    def test_typed_auth_branch_honors_dry_run_and_log_mode(self) -> None:
        import inspect

        from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

        source = inspect.getsource(TenuoActivityInboundInterceptor.execute_activity)
        anchor = source.index(") as auth_exc:")
        block = source[anchor : anchor + 2500]
        assert 'on_denial == "raise"' in block and "dry_run" in block
        assert "_deny_or_continue" in block

    @pytest.mark.asyncio
    async def test_typed_constraint_denial_records_metrics(self) -> None:
        pytest.importorskip("temporalio")
        import base64
        import time as _time
        from unittest.mock import AsyncMock, MagicMock, patch

        from tenuo import SigningKey, Warrant
        from tenuo_core import Subpath
        from tenuo.temporal._config import TenuoPluginConfig
        from tenuo.temporal._constants import TENUO_ARG_KEYS_HEADER, TENUO_POP_HEADER
        from tenuo.temporal._headers import tenuo_headers
        from tenuo.temporal._interceptors import TenuoWorkerInterceptor
        from tenuo.temporal._observability import TenuoMetrics
        from tenuo.temporal._resolvers import EnvKeyResolver

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("read_file", path=Subpath("/tmp/safe"))
            .ttl(3600)
            .mint(control_key)
        )
        metrics = TenuoMetrics()
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            metrics=metrics,
        )
        plugin = TenuoWorkerInterceptor(cfg)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        ai = plugin.intercept_activity(nxt)

        h = tenuo_headers(warrant, "agent1")
        pop = warrant.sign(
            agent_key, "read_file", {"path": "/etc/passwd"}, int(_time.time())
        )
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items()
            if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))
        act_headers[TENUO_ARG_KEYS_HEADER] = b"path"

        class FakePayload:
            def __init__(self, data: bytes) -> None:
                self.data = data

        info = MagicMock(
            activity_type="read_file",
            activity_id="1",
            workflow_id="wf-contract-deny",
            workflow_run_id="run-1",
            workflow_type="ContractDenyWF",
            task_queue="test-q",
            attempt=1,
            is_local=False,
        )
        inp = MagicMock(
            fn=None,
            args=("/etc/passwd",),
            headers={k: FakePayload(v) for k, v in act_headers.items()},
        )

        with patch("temporalio.activity.info", return_value=info):
            with pytest.raises(Exception):
                await ai.execute_activity(inp)

        assert metrics.get_stats()["latency_count"] >= 1

    @pytest.mark.asyncio
    async def test_typed_denial_dry_run_executes_activity(self) -> None:
        pytest.importorskip("temporalio")
        import base64
        import time as _time
        from unittest.mock import AsyncMock, MagicMock, patch

        from tenuo import SigningKey, Warrant
        from tenuo_core import Subpath
        from tenuo.temporal._config import TenuoPluginConfig
        from tenuo.temporal._constants import TENUO_ARG_KEYS_HEADER, TENUO_POP_HEADER
        from tenuo.temporal._headers import tenuo_headers
        from tenuo.temporal._interceptors import TenuoWorkerInterceptor
        from tenuo.temporal._resolvers import EnvKeyResolver

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("read_file", path=Subpath("/tmp/safe"))
            .ttl(3600)
            .mint(control_key)
        )
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            on_denial="raise",
            dry_run=True,
        )
        plugin = TenuoWorkerInterceptor(cfg)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="executed")
        nxt.init = MagicMock()
        ai = plugin.intercept_activity(nxt)

        h = tenuo_headers(warrant, "agent1")
        pop = warrant.sign(
            agent_key, "read_file", {"path": "/etc/passwd"}, int(_time.time())
        )
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items()
            if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))
        act_headers[TENUO_ARG_KEYS_HEADER] = b"path"

        class FakePayload:
            def __init__(self, data: bytes) -> None:
                self.data = data

        info = MagicMock(
            activity_type="read_file",
            activity_id="1",
            workflow_id="wf-dry",
            workflow_run_id="run-1",
            workflow_type="DryWF",
            task_queue="test-q",
            attempt=1,
            is_local=False,
        )
        inp = MagicMock(
            fn=None,
            args=("/etc/passwd",),
            headers={k: FakePayload(v) for k, v in act_headers.items()},
        )

        with patch("temporalio.activity.info", return_value=info):
            result = await ai.execute_activity(inp)

        assert result == "executed"
        nxt.execute_activity.assert_called_once()

    @pytest.mark.asyncio
    async def test_typed_denial_log_mode_skips_activity(self) -> None:
        pytest.importorskip("temporalio")
        import base64
        import time as _time
        from unittest.mock import AsyncMock, MagicMock, patch

        from tenuo import SigningKey, Warrant
        from tenuo_core import Subpath
        from tenuo.temporal._config import TenuoPluginConfig
        from tenuo.temporal._constants import TENUO_ARG_KEYS_HEADER, TENUO_POP_HEADER
        from tenuo.temporal._headers import tenuo_headers
        from tenuo.temporal._interceptors import TenuoWorkerInterceptor
        from tenuo.temporal._resolvers import EnvKeyResolver

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("read_file", path=Subpath("/tmp/safe"))
            .ttl(3600)
            .mint(control_key)
        )
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            on_denial="log",
        )
        plugin = TenuoWorkerInterceptor(cfg)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="real")
        nxt.init = MagicMock()
        ai = plugin.intercept_activity(nxt)

        h = tenuo_headers(warrant, "agent1")
        pop = warrant.sign(
            agent_key, "read_file", {"path": "/etc/passwd"}, int(_time.time())
        )
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items()
            if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))
        act_headers[TENUO_ARG_KEYS_HEADER] = b"path"

        class FakePayload:
            def __init__(self, data: bytes) -> None:
                self.data = data

        info = MagicMock(
            activity_type="read_file",
            activity_id="1",
            workflow_id="wf-log",
            workflow_run_id="run-1",
            workflow_type="LogWF",
            task_queue="test-q",
            attempt=1,
            is_local=False,
        )
        inp = MagicMock(
            fn=None,
            args=("/etc/passwd",),
            headers={k: FakePayload(v) for k, v in act_headers.items()},
        )

        with patch("temporalio.activity.info", return_value=info):
            result = await ai.execute_activity(inp)

        nxt.execute_activity.assert_not_called()
        assert result != "real"
