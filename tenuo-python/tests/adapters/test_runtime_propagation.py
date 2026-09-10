"""Runtime receipt collection through inbound adapters and the shared PEP."""

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


def test_mcp_process_install_collects_without_session_scope():
    pytest.importorskip("tenuo.mcp")
    root = SigningKey.generate()
    holder = HolderIdentity.generate()
    warrant = Warrant.issue(
        root,
        capabilities={"read_file": {"path": Pattern("/data/*")}},
        holder=holder.public_key,
    )
    runtime = _runtime_for(root, holder)
    runtime.install()
    try:
        verifier = MCPVerifier(runtime=runtime)
        from tests.adapters.test_mcp_server import _make_arguments

        args, meta = _make_arguments(
            warrant, holder.signing_key, "read_file", {"path": "/data/a.txt"}
        )
        allowed = verifier.verify("read_file", args, meta=meta)
        denied = verifier.verify(
            "read_file",
            {"path": "/etc/passwd"},
            meta=_make_arguments(
                warrant, holder.signing_key, "read_file", {"path": "/etc/passwd"}
            )[1],
        )
    finally:
        Runtime.uninstall()
    assert allowed.allowed
    assert not denied.allowed
    receipts = runtime.peek_receipts()
    assert len(receipts) == 2
    import tenuo_core

    assert tenuo_core.verify_receipt(receipts[0]).outcome == "allow"
    assert tenuo_core.verify_receipt(receipts[1]).outcome == "deny"


def test_fastapi_runtime_collects_allow_and_deny():
    pytest.importorskip("fastapi")
    from types import SimpleNamespace

    from tenuo import fastapi as fastapi_mod
    from tenuo.fastapi import TenuoGuard, configure_tenuo

    root = SigningKey.generate()
    holder = HolderIdentity.generate()
    warrant = Warrant.issue(
        root,
        capabilities={"search": {}},
        holder=holder.public_key,
    )
    runtime = _runtime_for(root, holder)
    previous = dict(fastapi_mod._config)
    try:
        configure_tenuo(SimpleNamespace(state=SimpleNamespace()), runtime=runtime)
        guard = TenuoGuard("search")
        import time

        pop = bytes(warrant.sign(holder.signing_key, "search", {"query": "ok"}, int(time.time())))
        allow = guard._enforce_with_pop_signature(
            warrant, "search", {"query": "ok"}, pop
        )
        deny = guard._enforce_with_pop_signature(
            warrant, "delete", {}, bytes(warrant.sign(holder.signing_key, "delete", {}, int(time.time())))
        )
    finally:
        fastapi_mod._config.clear()
        fastapi_mod._config.update(previous)
    assert allow.allowed
    assert not deny.allowed
    receipts = runtime.peek_receipts()
    assert len(receipts) == 2
    import tenuo_core

    assert tenuo_core.verify_receipt(receipts[0]).outcome == "allow"
    assert tenuo_core.verify_receipt(receipts[1]).outcome == "deny"


@pytest.mark.asyncio
async def test_a2a_runtime_three_hop_and_orphan_leaf():
    pytest.importorskip("tenuo.a2a")
    import time

    from tenuo.a2a import A2AServer
    from tenuo.a2a.errors import UntrustedIssuerError
    from tenuo.exceptions import UntrustedRoot

    root_key = SigningKey.generate()
    mid = SigningKey.generate()
    worker = SigningKey.generate()
    holder = HolderIdentity.generate()
    root = (
        Warrant.mint_builder()
        .capability("search", query=Pattern("ok*"))
        .holder(mid.public_key)
        .ttl(3600)
        .mint(root_key)
    )
    intermediate = (
        root.grant_builder()
        .capability("search", query=Pattern("ok*"))
        .holder(worker.public_key)
        .ttl(1800)
        .grant(mid)
    )
    leaf = (
        intermediate.grant_builder()
        .capability("search", query=Pattern("ok*"))
        .holder(holder.public_key)
        .ttl(900)
        .grant(worker)
    )
    runtime = _runtime_for(root_key, holder)
    server = A2AServer(
        name="Runtime Agent",
        url="https://runtime.example.com",
        public_key=holder.public_key.to_bytes().hex(),
        trusted_issuers=[root_key.public_key.to_bytes().hex()],
        require_pop=True,
        require_audience=False,
        check_replay=False,
        runtime=runtime,
    )
    pop = bytes(leaf.sign(holder.signing_key, "search", {"query": "ok"}, int(time.time())))
    allowed = await server.validate_warrant(
        leaf.to_base64(),
        "search",
        {"query": "ok"},
        _preloaded_parents=[root, intermediate],
        pop_signature=pop,
    )
    assert allowed.id == leaf.id
    from tenuo.a2a.errors import ConstraintViolationError

    deny_pop = bytes(leaf.sign(holder.signing_key, "search", {"query": "nope"}, int(time.time())))
    with pytest.raises(ConstraintViolationError):
        await server.validate_warrant(
            leaf.to_base64(),
            "search",
            {"query": "nope"},
            _preloaded_parents=[root, intermediate],
            pop_signature=deny_pop,
        )
    orphan_pop = bytes(leaf.sign(holder.signing_key, "search", {"query": "ok"}, int(time.time())))
    with pytest.raises((UntrustedIssuerError, UntrustedRoot)):
        await server.validate_warrant(
            leaf.to_base64(),
            "search",
            {"query": "ok"},
            pop_signature=orphan_pop,
        )
    receipts = runtime.peek_receipts()
    assert len(receipts) >= 2
    import tenuo_core

    outcomes = [tenuo_core.verify_receipt(r).outcome for r in receipts]
    assert "allow" in outcomes
    assert "deny" in outcomes


def test_fastapi_overflow_does_not_deny():
    pytest.importorskip("fastapi")
    from types import SimpleNamespace

    from tenuo import fastapi as fastapi_mod
    from tenuo.fastapi import TenuoGuard, configure_tenuo

    root = SigningKey.generate()
    holder = HolderIdentity.generate()
    warrant = Warrant.issue(
        root,
        capabilities={"search": {}},
        holder=holder.public_key,
    )
    runtime = Runtime(
        identity=holder,
        trusted_roots=[root.public_key],
        receipts="collect",
        receipt_maxsize=1,
    )
    previous = dict(fastapi_mod._config)
    try:
        configure_tenuo(SimpleNamespace(state=SimpleNamespace()), runtime=runtime)
        guard = TenuoGuard("search")
        import time

        first = guard._enforce_with_pop_signature(
            warrant,
            "search",
            {"q": "a"},
            bytes(warrant.sign(holder.signing_key, "search", {"q": "a"}, int(time.time()))),
        )
        second = guard._enforce_with_pop_signature(
            warrant,
            "search",
            {"q": "b"},
            bytes(warrant.sign(holder.signing_key, "search", {"q": "b"}, int(time.time()))),
        )
    finally:
        fastapi_mod._config.clear()
        fastapi_mod._config.update(previous)
    assert first.allowed
    assert second.allowed
    assert len(runtime.peek_receipts()) == 1
    assert runtime.receipt_overflows >= 1


def test_adk_guard_collects_through_runtime_scope():
    pytest.importorskip("google.adk")
    from types import SimpleNamespace

    from tenuo.google_adk.guard import TenuoGuard

    root = SigningKey.generate()
    holder = HolderIdentity.generate()
    warrant = Warrant.issue(
        root,
        capabilities={"search": {}},
        holder=holder.public_key,
    )
    runtime = _runtime_for(root, holder)
    session = runtime.session_from_wire(warrant)
    guard = TenuoGuard(
        warrant=warrant,
        signing_key=holder.signing_key,
        trusted_roots=[root.public_key],
        on_denial="return",
    )
    tool = SimpleNamespace(name="search")
    ctx = SimpleNamespace(state={})
    with runtime.session_scope(session):
        allowed = guard.before_tool(tool, {"query": "ok"}, ctx)
        denied = guard.before_tool(SimpleNamespace(name="delete"), {}, ctx)
    assert allowed is None or allowed is True
    assert denied not in (None, True)
    receipts = runtime.peek_receipts()
    assert len(receipts) >= 1
