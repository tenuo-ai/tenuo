"""Runtime receipt collection through Temporal, MCP, and LangGraph."""

from __future__ import annotations

import pytest
from tenuo_core import Authorizer, Pattern, SigningKey, Warrant, encode_warrant_stack

from tenuo import HolderIdentity, Runtime
from tenuo.decorators import chain_scope, warrant_scope
from tenuo.mcp.server import MCPVerifier


def _runtime_for(root: SigningKey, holder: HolderIdentity) -> Runtime:
    return Runtime(
        identity=holder,
        trusted_roots=[root.public_key],
        receipts="collect",
    )


def test_mcp_client_encodes_parent_chain_from_session_scope():
    pytest.importorskip("tenuo.mcp")
    import base64
    import time

    root_key = SigningKey.generate()
    mid = SigningKey.generate()
    worker = SigningKey.generate()
    holder = HolderIdentity.generate()
    root = (
        Warrant.mint_builder()
        .capability("read_file")
        .capability("list_dir")
        .holder(mid.public_key)
        .ttl(3600)
        .mint(root_key)
    )
    intermediate = (
        root.grant_builder()
        .capability("read_file")
        .capability("list_dir")
        .holder(worker.public_key)
        .ttl(1800)
        .grant(mid)
    )
    leaf = (
        intermediate.grant_builder()
        .capability("read_file")
        .holder(holder.public_key)
        .ttl(900)
        .grant(worker)
    )
    runtime = _runtime_for(root_key, holder)
    session = runtime.session_from_wire([root, intermediate, leaf])
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[root_key.public_key]))

    with runtime.session_scope(session):
        parents = chain_scope()
        warrant = warrant_scope()
        assert parents
        assert warrant is not None
        wire = encode_warrant_stack(list(parents) + [warrant])
        pop = warrant.sign(holder.signing_key, "read_file", {"path": "/data"}, int(time.time()))
        meta = {
            "tenuo": {
                "warrant": wire,
                "signature": base64.b64encode(bytes(pop)).decode(),
            }
        }
        allowed = verifier.verify("read_file", {"path": "/data"}, meta=meta)
        orphan_pop = leaf.sign(holder.signing_key, "read_file", {"path": "/data"}, int(time.time()))
        orphan = verifier.verify(
            "read_file",
            {"path": "/data"},
            meta={
                "tenuo": {
                    "warrant": leaf.to_base64(),
                    "signature": base64.b64encode(bytes(orphan_pop)).decode(),
                }
            },
        )

    assert allowed.allowed
    assert not orphan.allowed
    receipts = runtime.peek_receipts()
    assert len(receipts) == 2


def test_mcp_verify_collects_allow_and_deny():
    pytest.importorskip("tenuo.mcp")
    root = SigningKey.generate()
    holder = HolderIdentity.generate()
    warrant = Warrant.issue(
        root,
        capabilities={"read_file": {"path": Pattern("/data/*")}},
        holder=holder.public_key,
    )
    runtime = _runtime_for(root, holder)
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[root.public_key]))
    session = runtime.session_from_wire(warrant)

    from tests.adapters.test_mcp_server import _make_arguments

    args, meta = _make_arguments(warrant, holder.signing_key, "read_file", {"path": "/data/a.txt"})
    with runtime.session_scope(session):
        allowed = verifier.verify("read_file", args, meta=meta)
        denied = verifier.verify(
            "read_file",
            {"path": "/etc/passwd"},
            meta=_make_arguments(
                warrant, holder.signing_key, "read_file", {"path": "/etc/passwd"}
            )[1],
        )
    assert allowed.allowed
    assert not denied.allowed
    receipts = runtime.peek_receipts()
    assert len(receipts) == 2
    import tenuo_core

    assert tenuo_core.verify_receipt(receipts[0]).outcome == "allow"
    assert tenuo_core.verify_receipt(receipts[1]).outcome == "deny"


def test_langgraph_authorize_path_collects_receipts():
    pytest.importorskip("langchain_core")
    from types import SimpleNamespace

    from tenuo.bound_warrant import BoundWarrant
    from tenuo.langgraph import _authorize_tool_request

    root = SigningKey.generate()
    holder = HolderIdentity.generate()
    warrant = Warrant.issue(
        root,
        capabilities={"search": {}},
        holder=holder.public_key,
    )
    runtime = _runtime_for(root, holder)
    session = runtime.session_from_wire(warrant)
    request = SimpleNamespace(
        tool_call={"id": "t1", "name": "search", "args": {"query": "AI"}},
        state={"warrant": warrant},
    )

    def handler(_request):
        return "ok"

    with runtime.session_scope(session):
        result = _authorize_tool_request(
            request,
            handler,
            bw_factory=lambda _req: BoundWarrant(
                warrant, holder.signing_key, trusted_roots=[root.public_key]
            ),
            trusted_roots=[root.public_key],
        )
    assert result == "ok"
    receipts = runtime.peek_receipts()
    assert len(receipts) == 1
    import tenuo_core

    assert tenuo_core.verify_receipt(receipts[0]).outcome == "allow"


def test_temporal_nexus_collects_allow_and_deny():
    pytest.importorskip("temporalio")
    pytest.importorskip("nexusrpc")
    from tenuo_core import Exact, Range
    import tenuo_core
    from tenuo.exceptions import ConstraintViolation
    from tenuo.temporal._config import TenuoPluginConfig
    from tenuo.temporal._nexus import (
        nexus_tool_name,
        tenuo_nexus_headers,
        verify_nexus_operation,
    )

    from tests.adapters.test_temporal_nexus import RefundInput, StaticResolver

    root_key, agent_key = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability(
            nexus_tool_name("billing-prod", "refund", service="BillingService"),
            order_id=Exact("ord_123"),
            amount_cents=Range(0, 5000),
        )
        .ttl(3600)
        .mint(root_key)
    )
    identity = HolderIdentity(agent_key)
    runtime = Runtime(
        identity=identity,
        trusted_roots=[root_key.public_key],
        receipts="collect",
    )
    session = runtime.session_from_wire(warrant)
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    allow_input = RefundInput("ord_123", 2500)
    from types import SimpleNamespace

    ctx = SimpleNamespace(
        request_id="req-runtime-nexus",
        service="BillingService",
        operation="refund",
        headers=tenuo_nexus_headers(
            warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="refund",
            input=allow_input,
        ),
    )
    with runtime.session_scope(session):
        verify_nexus_operation(ctx, allow_input, config, endpoint="billing-prod")
        bad = RefundInput("ord_999", 2500)
        deny_ctx = SimpleNamespace(
            request_id="req-runtime-nexus-deny",
            service="BillingService",
            operation="refund",
            headers=tenuo_nexus_headers(
                warrant,
                "agent-key",
                agent_key,
                endpoint="billing-prod",
                service="BillingService",
                operation="refund",
                input=bad,
            ),
        )
        with pytest.raises(ConstraintViolation):
            verify_nexus_operation(deny_ctx, bad, config, endpoint="billing-prod")

    receipts = runtime.peek_receipts()
    assert len(receipts) == 2
    assert tenuo_core.verify_receipt(receipts[0]).outcome == "allow"
    assert tenuo_core.verify_receipt(receipts[1]).outcome == "deny"
    assert tenuo_core.verify_receipt(receipts[0]).action == nexus_tool_name(
        "billing-prod", "refund", service="BillingService"
    )
