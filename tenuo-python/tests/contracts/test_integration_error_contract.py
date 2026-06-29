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
