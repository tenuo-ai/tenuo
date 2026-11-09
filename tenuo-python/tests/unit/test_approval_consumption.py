"""At-most-once use of approvals at the enforcement point.

A holder that is rewound (a restored or forked checkpoint, a retried worker)
re-runs the same gated call and signs a fresh PoP, so the PoP nonce store does
not see a repeat. The approval consumption store does.
"""

from __future__ import annotations

import os
import time

import pytest

from tenuo import SigningKey, Warrant
from tenuo._enforcement import enforce_tool_call, enforce_tool_call_async
from tenuo.consumption import (
    ApprovalConsumptionStore,
    current_idempotency_key,
    disable_default_consumption_store,
    enable_default_consumption_store,
)
from tenuo.exceptions import InvalidApproval
from tenuo.nonce import NonceStore


def _gated_warrant(issuer, holder, approvers, min_approvals=1):
    return Warrant.issue(
        issuer,
        capabilities={"transfer": {}},
        holder=holder.public_key,
        approval_gates={"transfer": None},
        required_approvers=[k.public_key for k in approvers],
        min_approvals=min_approvals,
        ttl_seconds=3600,
    )


def _approval(warrant, tool, args, holder, approver, ttl=300):
    from tenuo_core import ApprovalPayload, SignedApproval
    from tenuo_core import py_compute_request_hash as compute_request_hash

    now = int(time.time())
    payload = ApprovalPayload(
        request_hash=compute_request_hash(warrant.id, tool, args, holder.public_key),
        nonce=os.urandom(16),
        external_id="approver@example.com",
        approved_at=now,
        expires_at=now + ttl,
    )
    return SignedApproval.create(payload, approver)


@pytest.fixture
def setup():
    issuer, holder, approver = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    warrant = _gated_warrant(issuer, holder, [approver])
    args = {"amount": 100}
    return {
        "issuer": issuer,
        "holder": holder,
        "approver": approver,
        "warrant": warrant,
        "bound": warrant.bind(holder),
        "args": args,
        "approval": _approval(warrant, "transfer", args, holder, approver),
    }


def _call(s, approvals, **kw):
    return enforce_tool_call(
        "transfer", s["args"], s["bound"],
        trusted_roots=[s["issuer"].public_key],
        approvals=approvals,
        **kw,
    )


def _next_pop_window(monkeypatch):
    """Move the holder's clock into a later PoP window (30 s buckets)."""
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 31)


@pytest.fixture(autouse=True)
def _no_default_store():
    disable_default_consumption_store()
    yield
    disable_default_consumption_store()


class TestRewoundHolder:
    def test_without_store_the_same_approval_authorizes_twice(self, setup, monkeypatch):
        # The PoP nonce store does not help: the rerun signs in a later PoP
        # window, so its PoP is new bytes.
        nonces = NonceStore()
        first = _call(setup, [setup["approval"]], nonce_store=nonces)
        _next_pop_window(monkeypatch)
        second = _call(setup, [setup["approval"]], nonce_store=nonces)
        assert first.allowed and second.allowed

    def test_store_denies_second_use_of_the_same_approval(self, setup, monkeypatch):
        nonces, store = NonceStore(), ApprovalConsumptionStore()
        first = _call(setup, [setup["approval"]], nonce_store=nonces, consumption_store=store)
        _next_pop_window(monkeypatch)
        second = _call(setup, [setup["approval"]], nonce_store=nonces, consumption_store=store)

        assert first.allowed
        assert not second.allowed
        assert second.error_type == "approval_consumed"
        assert second.approval_metadata == {"state": "in_flight"}
        with pytest.raises(InvalidApproval):
            second.raise_if_denied()

    def test_default_store_applies_without_explicit_param(self, setup):
        enable_default_consumption_store()
        assert _call(setup, [setup["approval"]]).allowed
        assert _call(setup, [setup["approval"]]).error_type == "approval_consumed"

    def test_fresh_approval_for_the_same_call_is_allowed(self, setup):
        store = ApprovalConsumptionStore()
        assert _call(setup, [setup["approval"]], consumption_store=store).allowed
        again = _approval(setup["warrant"], "transfer", setup["args"], setup["holder"], setup["approver"])
        assert _call(setup, [again], consumption_store=store).allowed

    def test_ungated_calls_are_untouched(self):
        issuer, holder = SigningKey.generate(), SigningKey.generate()
        warrant = Warrant.issue(issuer, capabilities={"search": {}}, holder=holder.public_key, ttl_seconds=60)
        store = ApprovalConsumptionStore()
        for _ in range(2):
            r = enforce_tool_call(
                "search", {"q": "x"}, warrant.bind(holder),
                trusted_roots=[issuer.public_key], consumption_store=store,
            )
            assert r.allowed and r.idempotency_key is None and r.approval_reservation is None
        assert len(store) == 0

    def test_verify_path_consumes_too(self, setup):
        from tenuo import Authorizer

        store = ApprovalConsumptionStore()
        auth = Authorizer(trusted_roots=[setup["issuer"].public_key])
        for expected in (True, False):
            pop = bytes(setup["warrant"].sign(setup["holder"], "transfer", setup["args"], int(time.time())))
            r = enforce_tool_call(
                "transfer", setup["args"], setup["bound"],
                verify_mode="verify", precomputed_signature=pop, authorizer=auth,
                approvals=[setup["approval"]], consumption_store=store,
            )
            assert r.allowed is expected

    @pytest.mark.asyncio
    async def test_async_path(self, setup):
        store = ApprovalConsumptionStore()
        kw = dict(trusted_roots=[setup["issuer"].public_key], approvals=[setup["approval"]], consumption_store=store)
        first = await enforce_tool_call_async("transfer", setup["args"], setup["bound"], **kw)
        second = await enforce_tool_call_async("transfer", setup["args"], setup["bound"], **kw)
        assert first.allowed
        assert second.error_type == "approval_consumed"


class TestReserveCommit:
    def test_commit_reports_consumed(self, setup):
        store = ApprovalConsumptionStore()
        first = _call(setup, [setup["approval"]], consumption_store=store)
        first.approval_reservation.commit()
        second = _call(setup, [setup["approval"]], consumption_store=store)
        assert second.approval_metadata == {"state": "consumed"}

    def test_crash_before_commit_leaves_in_flight(self, setup):
        # A worker that reserved and died never commits or releases. A retry
        # must not see the approval as unused.
        store = ApprovalConsumptionStore()
        assert _call(setup, [setup["approval"]], consumption_store=store).allowed
        retry = _call(setup, [setup["approval"]], consumption_store=store)
        assert retry.approval_metadata == {"state": "in_flight"}

    def test_release_allows_retry(self, setup):
        store = ApprovalConsumptionStore()
        first = _call(setup, [setup["approval"]], consumption_store=store)
        first.approval_reservation.release()
        assert _call(setup, [setup["approval"]], consumption_store=store).allowed

    def test_release_after_commit_is_a_no_op(self, setup):
        store = ApprovalConsumptionStore()
        first = _call(setup, [setup["approval"]], consumption_store=store)
        first.approval_reservation.commit()
        first.approval_reservation.release()
        assert not _call(setup, [setup["approval"]], consumption_store=store).allowed

    def test_partial_multi_approval_reservation_is_rolled_back(self):
        issuer, holder = SigningKey.generate(), SigningKey.generate()
        a1, a2 = SigningKey.generate(), SigningKey.generate()
        warrant = _gated_warrant(issuer, holder, [a1, a2], min_approvals=2)
        bound = warrant.bind(holder)
        args = {"amount": 5}
        p1 = _approval(warrant, "transfer", args, holder, a1)
        p2 = _approval(warrant, "transfer", args, holder, a2)
        store = ApprovalConsumptionStore()
        kw = dict(trusted_roots=[issuer.public_key], consumption_store=store)

        # Consume p2 alone by pairing it with a fresh a1 approval.
        assert enforce_tool_call("transfer", args, bound, approvals=[_approval(warrant, "transfer", args, holder, a1), p2], **kw).allowed
        # p1 + p2: p2 is spent, so the call is denied and p1 stays unused.
        denied = enforce_tool_call("transfer", args, bound, approvals=[p1, p2], **kw)
        assert denied.error_type == "approval_consumed"
        assert enforce_tool_call("transfer", args, bound, approvals=[p1, _approval(warrant, "transfer", args, holder, a2)], **kw).allowed

    def test_entry_lives_until_the_approval_expires(self, setup):
        store = ApprovalConsumptionStore(margin_seconds=0)
        _call(setup, [setup["approval"]], consumption_store=store)
        ttl = store._backend.ttl_remaining(next(iter(store._backend._store)))
        # Small tolerance: monotonic clock arithmetic is not exact on every platform.
        assert 290 <= ttl <= 300 + 1e-3

    def test_backend_protocol(self):
        from tenuo.consumption import ConsumptionBackend, InMemoryConsumptionBackend

        b = InMemoryConsumptionBackend()
        assert isinstance(b, ConsumptionBackend)
        assert b.reserve("k", 60, "ik", owner_token="first") is None
        assert b.reserve("k", 60, "other", owner_token="second") == ("in_flight", "ik")
        b.commit("k", owner_token="second")
        b.release("k", owner_token="second")
        assert b.reserve("k", 60, owner_token="second").state == "in_flight"
        b.commit("k", owner_token="first")
        assert b.reserve("k", 60, owner_token="second") == ("consumed", "ik")
        b.release("k", owner_token="first")
        assert b.reserve("k", 60, owner_token="second").state == "consumed"


class TestIdempotencyKey:
    def test_key_is_stable_for_the_same_authorization(self, setup):
        first = _call(setup, [setup["approval"]])
        second = _call(setup, [setup["approval"]])
        assert first.idempotency_key is not None
        assert len(first.idempotency_key) == 64
        assert first.idempotency_key == second.idempotency_key

    def test_key_differs_for_a_fresh_approval(self, setup):
        first = _call(setup, [setup["approval"]])
        again = _approval(setup["warrant"], "transfer", setup["args"], setup["holder"], setup["approver"])
        assert _call(setup, [again]).idempotency_key != first.idempotency_key

    def test_key_matches_core(self, setup):
        r = _call(setup, [setup["approval"]])
        verified = r.chain_result.verified_approvals[0]
        assert r.idempotency_key == bytes(r.chain_result.idempotency_key).hex()
        # Reuses the request hash receipts already carry.
        assert bytes(r.chain_result.request_hash) == bytes(verified.request_hash)
        assert len(bytes(verified.nonce)) == 16

    def test_key_is_visible_to_the_tool_handler(self, setup):
        store = ApprovalConsumptionStore()
        r = _call(setup, [setup["approval"]], consumption_store=store)
        assert current_idempotency_key() == r.idempotency_key
        _call(setup, [setup["approval"]], consumption_store=store)
        # A denied call clears it so a stale key is never reused.
        assert current_idempotency_key() is None


class TestThroughAnAdapter:
    def test_langgraph_restored_checkpoint_reruns_once(self, setup, monkeypatch):
        """A run restored from a checkpoint taken before the approved call
        re-executes the node; with the store enabled the rerun is refused, and
        the handler saw the idempotency key on the run that did execute."""
        pytest.importorskip("langchain_core")
        from types import SimpleNamespace

        from tenuo.langgraph import _authorize_tool_request

        enable_default_consumption_store()
        seen = []

        def handler(request):
            seen.append(current_idempotency_key())
            return "done"

        def run_node():
            request = SimpleNamespace(
                tool_call={"name": "transfer", "args": dict(setup["args"]), "id": "call-1"},
                state={}, runtime=None,
            )
            return _authorize_tool_request(
                request, handler,
                bw_factory=lambda _r: setup["bound"],
                trusted_roots=[setup["issuer"].public_key],
                approvals=[setup["approval"]],
            )

        assert run_node() == "done"
        _next_pop_window(monkeypatch)
        rerun = run_node()
        assert rerun != "done"
        assert len(seen) == 1 and seen[0] is not None


class TestReviewFollowUps:
    def test_reordered_surplus_approvals_are_one_authorization(self, monkeypatch):
        issuer, holder = SigningKey.generate(), SigningKey.generate()
        a, b = SigningKey.generate(), SigningKey.generate()
        warrant = _gated_warrant(issuer, holder, [a, b], min_approvals=1)
        bound, args = warrant.bind(holder), {"amount": 7}
        pa = _approval(warrant, "transfer", args, holder, a)
        pb = _approval(warrant, "transfer", args, holder, b)
        store = ApprovalConsumptionStore()
        kw = dict(trusted_roots=[issuer.public_key], consumption_store=store)

        first = enforce_tool_call("transfer", args, bound, approvals=[pa, pb], **kw)
        assert first.allowed
        assert len(first.approval_reservation.keys) == 2
        _next_pop_window(monkeypatch)
        retry = enforce_tool_call("transfer", args, bound, approvals=[pb, pa], **kw)
        assert retry.error_type == "approval_consumed"
        assert retry.idempotency_key == first.idempotency_key
        # Either approval alone is spent too.
        assert enforce_tool_call("transfer", args, bound, approvals=[pb], **kw).error_type == "approval_consumed"

    def test_store_uses_the_core_consumption_key(self, setup):
        r = _call(setup, [setup["approval"]], consumption_store=ApprovalConsumptionStore())
        va = r.chain_result.verified_approvals[0]
        assert r.approval_reservation.keys == [va.consumption_key]
        assert va.consumption_key == f"{bytes(va.approver_key).hex()}:{bytes(va.nonce).hex()}"

    def test_denial_keeps_the_idempotency_key(self, setup):
        store = ApprovalConsumptionStore()
        first = _call(setup, [setup["approval"]], consumption_store=store)
        retry = _call(setup, [setup["approval"]], consumption_store=store)
        assert retry.error_type == "approval_consumed"
        assert retry.idempotency_key == first.idempotency_key
        assert current_idempotency_key() is None

    def test_preflight_does_not_consume(self, setup):
        enable_default_consumption_store()
        assert _call(setup, [setup["approval"]], consumption_store=False).allowed
        final = _call(setup, [setup["approval"]])
        assert final.allowed and final.approval_reservation is not None

    def test_backend_failure_rolls_back_earlier_reservations(self):
        from types import SimpleNamespace

        from tenuo.consumption import InMemoryConsumptionBackend

        class Flaky(InMemoryConsumptionBackend):
            fail = True

            def reserve(self, key, ttl_seconds, idempotency_key=None, *, owner_token):
                if key.startswith("bb") and self.fail:
                    raise ConnectionError("backend down")
                return super().reserve(key, ttl_seconds, idempotency_key, owner_token=owner_token)

        backend = Flaky()
        store = ApprovalConsumptionStore(backend=backend)
        far = int(time.time()) + 300
        result = SimpleNamespace(verified_approvals=[
            SimpleNamespace(consumption_key="aa:01", expires_at=far),
            SimpleNamespace(consumption_key="bb:02", expires_at=far),
        ])
        with pytest.raises(ConnectionError):
            store.reserve(result)
        assert len(backend) == 0
        backend.fail = False
        reservation, denial = store.reserve(result)
        assert denial is None and reservation.keys == ["aa:01", "bb:02"]

    def test_verify_inbound_call_publishes_the_key(self, setup):
        from tenuo import Authorizer
        from tenuo._enforcement import verify_inbound_call

        auth = Authorizer(trusted_roots=[setup["issuer"].public_key])
        pop = bytes(setup["warrant"].sign(setup["holder"], "transfer", setup["args"], int(time.time())))
        r = verify_inbound_call(
            tool_name="transfer", tool_args=setup["args"], warrant=setup["warrant"],
            pop_signature=pop, authorizer=auth, approvals=[setup["approval"]],
            apply_observe=False,
        )
        assert r.allowed and r.idempotency_key
        assert current_idempotency_key() == r.idempotency_key
        with pytest.raises(Exception):
            verify_inbound_call(
                tool_name="transfer", tool_args=setup["args"], warrant=setup["warrant"],
                pop_signature=None, authorizer=auth, approvals=[setup["approval"]],
            )
        assert current_idempotency_key() is None

    @pytest.mark.asyncio
    async def test_langchain_threaded_tool_sees_the_key(self, setup):
        pytest.importorskip("langchain_core")
        from tenuo.langchain import TenuoTool

        seen = []

        class SyncOnly:
            name = "transfer"
            description = "transfer"
            args_schema = None

            def _run(self, *args, **kwargs):
                seen.append(current_idempotency_key())
                return "done"

        tool = TenuoTool.__new__(TenuoTool)
        object.__setattr__(tool, "wrapped", SyncOnly())

        async def _authorize(_tool_input):
            r = await enforce_tool_call_async(
                "transfer", setup["args"], setup["bound"],
                trusted_roots=[setup["issuer"].public_key], approvals=[setup["approval"]],
            )
            assert r.allowed

        object.__setattr__(tool, "_acheck_authorization", _authorize)
        object.__setattr__(tool, "_build_tool_input", lambda a, k: dict(k))
        assert await TenuoTool._arun(tool, **setup["args"]) == "done"
        assert seen and seen[0] is not None

    def test_openai_key_travels_with_the_tool_call(self, setup):
        pytest.importorskip("openai")
        from types import SimpleNamespace

        from tenuo.openai import _attach_idempotency_key, idempotency_key_for, verify_tool_call

        key = verify_tool_call(
            "transfer", setup["args"], None, None, None,
            setup["warrant"], setup["holder"], [setup["issuer"].public_key],
            None, [setup["approval"]],
        )
        assert key and len(key) == 64
        call = SimpleNamespace(id="call_1")
        _attach_idempotency_key(call, key)
        assert idempotency_key_for(call) == key
        assert idempotency_key_for(SimpleNamespace(id="call_2")) is None


@pytest.mark.asyncio
async def test_mcp_client_and_server_sharing_one_store(setup, monkeypatch):
    """The client authorizes before sending and the server enforces; with one
    store between them, only the server consumes, so the first call runs."""
    pytest.importorskip("mcp")
    from types import SimpleNamespace

    from tenuo import Authorizer
    from tenuo.decorators import key_scope, warrant_scope
    from tenuo.mcp.client import SecureMCPClient
    from tenuo.mcp.server import MCPVerifier

    enable_default_consumption_store()
    monkeypatch.setattr("tenuo.config.resolve_trusted_roots", lambda explicit=None: [setup["issuer"].public_key])
    monkeypatch.setattr("tenuo.mcp.client.is_configured", lambda: True)
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[setup["issuer"].public_key]))
    outcomes = []

    class InProcessSession:
        async def call_tool(self, name, arguments, meta=None):
            result = verifier.verify(name, arguments, meta=meta)
            outcomes.append(result.allowed)
            return SimpleNamespace(content=[], isError=not result.allowed, structuredContent=None)

    client = SecureMCPClient("python", [], inject_warrant=True)
    client.session = InProcessSession()
    with warrant_scope(setup["warrant"]), key_scope(setup["holder"]):
        await client.call_tool("transfer", dict(setup["args"]), approvals=[setup["approval"]])
    assert outcomes == [True]


@pytest.mark.asyncio
async def test_mcp_client_without_injection_is_the_enforcement_point(setup, monkeypatch):
    """Without the warrant sent, the server may not run Tenuo at all, so the
    client's own check consumes: a second call on the same approval is denied."""
    pytest.importorskip("mcp")
    from types import SimpleNamespace

    from tenuo.decorators import key_scope, warrant_scope
    from tenuo.mcp.client import SecureMCPClient

    enable_default_consumption_store()
    monkeypatch.setattr("tenuo.config.resolve_trusted_roots", lambda explicit=None: [setup["issuer"].public_key])
    monkeypatch.setattr("tenuo.mcp.client.is_configured", lambda: True)
    executed = []

    class PlainSession:
        async def call_tool(self, name, arguments, meta=None):
            executed.append(name)
            return SimpleNamespace(content=[], isError=False, structuredContent=None)

    client = SecureMCPClient("python", [], inject_warrant=False)
    client.session = PlainSession()
    with warrant_scope(setup["warrant"]), key_scope(setup["holder"]):
        await client.call_tool("transfer", dict(setup["args"]), approvals=[setup["approval"]])
        with pytest.raises(Exception):
            await client.call_tool("transfer", dict(setup["args"]), approvals=[setup["approval"]])
    assert executed == ["transfer"]


class TestOpenAIReleasesUnusedReservations:
    """The guarded OpenAI client verifies a response; it does not run tools.
    A response or call it rejects must leave its approvals usable."""

    @staticmethod
    def _response(calls):
        from types import SimpleNamespace as NS

        tool_calls = [
            NS(id=f"call_{i}", type="function", function=NS(name=name, arguments=raw))
            for i, (name, raw) in enumerate(calls)
        ]
        message = NS(role="assistant", content=None, tool_calls=tool_calls, function_call=None)
        return NS(id="resp", model="m", choices=[NS(index=0, message=message, finish_reason="tool_calls")])

    def _guarded(self, setup, monkeypatch, response, **kw):
        pytest.importorskip("openai")
        from unittest.mock import Mock

        from tenuo.openai import GuardBuilder

        monkeypatch.setattr("tenuo.openai.resolve_trusted_roots", lambda explicit=None: [setup["issuer"].public_key])
        client = Mock()
        client.chat.completions.create.return_value = response
        builder = GuardBuilder(client).with_warrant(setup["warrant"], setup["holder"]).with_approvals([setup["approval"]])
        for name in kw.get("deny", []):
            builder = builder.deny(name)
        return builder.on_denial("raise").build()

    def test_rejected_response_releases_earlier_calls(self, setup, monkeypatch):
        import json

        store = enable_default_consumption_store()
        bad = self._response([("transfer", json.dumps(setup["args"])), ("transfer", "{not json")])
        with pytest.raises(Exception):
            self._guarded(setup, monkeypatch, bad).chat.completions.create(model="m", messages=[])
        assert len(store) == 0

        good = self._response([("transfer", json.dumps(setup["args"]))])
        self._guarded(setup, monkeypatch, good).chat.completions.create(model="m", messages=[])
        assert len(store) == 1

    def test_tier1_denial_does_not_reserve_or_publish_a_key(self, setup, monkeypatch):
        from tenuo.openai import ToolDenied, verify_tool_call

        pytest.importorskip("openai")
        store = enable_default_consumption_store()
        roots = [setup["issuer"].public_key]
        with pytest.raises(ToolDenied):
            verify_tool_call(
                "transfer", setup["args"], None, ["transfer"], None,
                setup["warrant"], setup["holder"], roots, None, [setup["approval"]],
            )
        assert len(store) == 0
        assert current_idempotency_key() is None
        assert verify_tool_call(
            "transfer", setup["args"], None, None, None,
            setup["warrant"], setup["holder"], roots, None, [setup["approval"]],
        )

    @pytest.mark.asyncio
    async def test_async_tier1_denial_clears_the_prior_key(self, setup):
        pytest.importorskip("openai")
        from tenuo.openai import ToolDenied, verify_tool_call_async

        store = enable_default_consumption_store()
        first = await enforce_tool_call_async(
            "transfer", setup["args"], setup["bound"],
            trusted_roots=[setup["issuer"].public_key], approvals=[setup["approval"]],
        )
        assert current_idempotency_key() is not None
        first.approval_reservation.release()
        with pytest.raises(ToolDenied):
            await verify_tool_call_async(
                "transfer", setup["args"], None, ["transfer"], None,
                setup["warrant"], setup["holder"], [setup["issuer"].public_key],
                None, [setup["approval"]],
            )
        assert len(store) == 0
        assert current_idempotency_key() is None


class TestSecondReviewFollowUps:
    def test_duplicate_approver_selection_is_independent_of_order(self, setup):
        first = setup["approval"]
        second = _approval(setup["warrant"], "transfer", setup["args"], setup["holder"], setup["approver"])
        a = _call(setup, [first], consumption_store=False)
        b = _call(setup, [second], consumption_store=False)
        ab = _call(setup, [first, second], consumption_store=False)
        ba = _call(setup, [second, first], consumption_store=False)
        assert ab.allowed and ba.allowed
        assert len(ab.chain_result.verified_approvals) == 1
        assert ab.idempotency_key == ba.idempotency_key
        assert bytes(ab.chain_result.verified_approvals[0].nonce) == min(
            bytes(a.chain_result.verified_approvals[0].nonce),
            bytes(b.chain_result.verified_approvals[0].nonce),
        )

    @staticmethod
    def _chain(*keys):
        from types import SimpleNamespace

        return SimpleNamespace(verified_approvals=[
            SimpleNamespace(consumption_key=key, expires_at=int(time.time()) + 300)
            for key in keys
        ])

    def test_lost_release_response_cannot_release_a_new_owner(self):
        from tenuo.consumption import InMemoryConsumptionBackend

        class LostReply(InMemoryConsumptionBackend):
            lose_reply = True

            def release(self, key, *, owner_token):
                super().release(key, owner_token=owner_token)
                if self.lose_reply:
                    self.lose_reply = False
                    raise ConnectionError("release succeeded but response was lost")

        store = ApprovalConsumptionStore(backend=LostReply())
        chain = self._chain("aa:01")
        first, _ = store.reserve(chain, "same-authorization")
        with pytest.raises(ConnectionError):
            first.release()
        second, denial = store.reserve(chain, "same-authorization")
        assert second is not None and denial is None
        first.release()
        assert first.done
        third, denial = store.reserve(chain, "same-authorization")
        assert third is None and denial.state == "in_flight"
        second.commit()
        assert store.reserve(chain)[1].state == "consumed"

    def test_lost_reserve_response_rolls_back_that_acquisition(self):
        from tenuo.consumption import InMemoryConsumptionBackend

        class LostReply(InMemoryConsumptionBackend):
            lose_reply = True

            def reserve(self, key, ttl_seconds, idempotency_key=None, *, owner_token):
                result = super().reserve(key, ttl_seconds, idempotency_key, owner_token=owner_token)
                if key == "bb:02" and self.lose_reply:
                    self.lose_reply = False
                    raise ConnectionError("reserve succeeded but response was lost")
                return result

        store = ApprovalConsumptionStore(backend=LostReply())
        chain = self._chain("aa:01", "bb:02")
        with pytest.raises(ConnectionError):
            store.reserve(chain)
        assert len(store) == 0
        reservation, denial = store.reserve(chain)
        assert reservation is not None and denial is None

    def test_old_commit_cannot_commit_a_new_acquisition(self, monkeypatch):
        from tenuo.consumption import ApprovalReservation, InMemoryConsumptionBackend

        now = [100.0]
        monkeypatch.setattr("tenuo.consumption.time.monotonic", lambda: now[0])
        backend = InMemoryConsumptionBackend()
        backend.reserve("aa:01", 1, owner_token="first")
        old = ApprovalReservation(backend, ["aa:01"], owner_token="first")
        now[0] += 2
        assert backend.reserve("aa:01", 60, owner_token="second") is None
        old.commit()
        assert backend.reserve("aa:01", 60, owner_token="third").state == "in_flight"

    def test_old_expiry_does_not_evict_a_reacquired_approval(self, monkeypatch):
        from tenuo.consumption import InMemoryConsumptionBackend

        now = [100.0]
        monkeypatch.setattr("tenuo.consumption.time.monotonic", lambda: now[0])
        backend = InMemoryConsumptionBackend()
        backend.reserve("aa:01", 1, owner_token="first")
        backend.release("aa:01", owner_token="first")
        assert backend.reserve("aa:01", 60, owner_token="second") is None
        now[0] += 2
        assert len(backend) == 1
        assert backend.reserve("aa:01", 60, owner_token="third").state == "in_flight"
        now[0] += 60
        assert len(backend) == 0

    def test_only_one_concurrent_reservation_succeeds(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier

        store = ApprovalConsumptionStore()
        chain = self._chain("aa:01")
        ready = Barrier(8)

        def reserve(_):
            ready.wait()
            return store.reserve(chain)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(reserve, range(8)))
        assert sum(reservation is not None for reservation, _ in results) == 1
        assert sum(denial is not None for _, denial in results) == 7

    @pytest.mark.parametrize("margin", [-1, 0.5, float("nan")])
    def test_expiry_margin_cannot_shorten_approval_retention(self, margin):
        with pytest.raises(ValueError, match="non-negative integer"):
            ApprovalConsumptionStore(margin_seconds=margin)

    def test_reuse_denial_returns_the_original_key_after_a_surplus_expires(self, monkeypatch):
        issuer, holder = SigningKey.generate(), SigningKey.generate()
        a, b = SigningKey.generate(), SigningKey.generate()
        warrant = _gated_warrant(issuer, holder, [a, b], min_approvals=1)
        bound, args = warrant.bind(holder), {"amount": 9}
        t0 = int(time.time())
        short = _approval(warrant, "transfer", args, holder, a, ttl=2)
        long = _approval(warrant, "transfer", args, holder, b, ttl=300)
        store = ApprovalConsumptionStore()
        kw = dict(trusted_roots=[issuer.public_key], consumption_store=store)

        first = enforce_tool_call("transfer", args, bound, approvals=[short, long], **kw)
        assert first.allowed and len(first.approval_reservation.keys) == 2

        # Wait for the short approval to expire (the core checks real time).
        time.sleep(max(0.0, t0 + 2.05 - time.time()))
        _next_pop_window(monkeypatch)
        retry = enforce_tool_call("transfer", args, bound, approvals=[short, long], **kw)
        assert retry.error_type == "approval_consumed"
        # Only the long-lived approval verifies now, so the key for this
        # attempt alone would differ; the denial names the first use instead.
        alone = enforce_tool_call(
            "transfer", args, bound, approvals=[long], trusted_roots=[issuer.public_key], consumption_store=False
        )
        assert alone.allowed and alone.idempotency_key != first.idempotency_key
        # ...but the denial names the authorization that used it.
        assert retry.idempotency_key == first.idempotency_key

    def test_failed_release_can_be_retried(self):
        from tenuo.consumption import ApprovalReservation, InMemoryConsumptionBackend

        class FlakyRelease(InMemoryConsumptionBackend):
            failures = 1

            def release(self, key, *, owner_token):
                if key == "bb:02" and self.failures:
                    self.failures -= 1
                    raise ConnectionError("backend down")
                super().release(key, owner_token=owner_token)

        backend = FlakyRelease()
        for k in ("aa:01", "bb:02", "cc:03"):
            backend.reserve(k, 60, owner_token="first")
        reservation = ApprovalReservation(backend, ["aa:01", "bb:02", "cc:03"], owner_token="first")
        with pytest.raises(ConnectionError):
            reservation.release()
        # Keys that succeeded are released; the failed one is still pending.
        assert not reservation.done and len(backend) == 1
        reservation.commit()  # the outcome is already release; ignored
        assert len(backend) == 1
        reservation.release()
        assert reservation.done and len(backend) == 0

    def test_failed_commit_can_be_retried(self):
        from tenuo.consumption import ApprovalReservation, InMemoryConsumptionBackend

        class FlakyCommit(InMemoryConsumptionBackend):
            failures = 1

            def commit(self, key, *, owner_token):
                if self.failures:
                    self.failures -= 1
                    raise ConnectionError("backend down")
                super().commit(key, owner_token=owner_token)

        backend = FlakyCommit()
        backend.reserve("aa:01", 60, owner_token="first")
        reservation = ApprovalReservation(backend, ["aa:01"], owner_token="first")
        with pytest.raises(ConnectionError):
            reservation.commit()
        assert backend.reserve("aa:01", 60, owner_token="second").state == "in_flight"
        reservation.commit()
        assert reservation.done and backend.reserve("aa:01", 60, owner_token="second").state == "consumed"

    @staticmethod
    def _fastapi_headers(setup, tool, args):
        import base64
        import json

        from tenuo.fastapi import X_TENUO_APPROVALS, X_TENUO_POP, X_TENUO_WARRANT

        pop = setup["warrant"].sign(setup["holder"], tool, args, int(time.time()))
        approvals = [base64.b64encode(setup["approval"].to_bytes()).decode()]
        return {
            X_TENUO_WARRANT: setup["warrant"].to_base64(),
            X_TENUO_POP: base64.b64encode(pop).decode(),
            X_TENUO_APPROVALS: base64.b64encode(json.dumps(approvals).encode()).decode(),
        }

    def test_fastapi_async_endpoint_gets_the_key_from_the_context(self, setup, monkeypatch):
        pytest.importorskip("fastapi")
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient

        from tenuo.fastapi import SecurityContext, TenuoGuard, configure_tenuo

        app = FastAPI()
        configure_tenuo(app, trusted_issuers=[setup["issuer"].public_key])
        seen = {}

        @app.post("/transfer")
        async def transfer(amount: int, ctx: SecurityContext = Depends(TenuoGuard("transfer"))):
            seen["ctx"] = ctx.idempotency_key
            seen["var"] = current_idempotency_key()
            return {"ok": True}

        store = enable_default_consumption_store()
        headers = self._fastapi_headers(setup, "transfer", setup["args"])
        r = TestClient(app).post("/transfer?amount=100", headers=headers)
        assert r.status_code == 200, r.text
        assert seen["ctx"] and len(seen["ctx"]) == 64
        assert len(store) == 1

    def test_openai_stream_deltas_carry_the_key(self, setup, monkeypatch):
        pytest.importorskip("openai")
        import json
        from types import SimpleNamespace as NS
        from unittest.mock import Mock

        from tenuo.openai import GuardBuilder, idempotency_key_for

        monkeypatch.setattr("tenuo.openai.resolve_trusted_roots", lambda explicit=None: [setup["issuer"].public_key])
        raw = json.dumps(setup["args"])

        def chunk(tc=None, finish=None):
            delta = NS(content=None, tool_calls=[tc] if tc else None, function_call=None, role="assistant")
            return NS(choices=[NS(index=0, delta=delta, finish_reason=finish)])

        chunks = [
            chunk(NS(index=0, id="call_0", type="function", function=NS(name="transfer", arguments=raw[:5]))),
            chunk(NS(index=0, id=None, type=None, function=NS(name=None, arguments=raw[5:]))),
            chunk(finish="tool_calls"),
        ]
        client = Mock()
        client.chat.completions.create.return_value = iter(chunks)
        guarded = (
            GuardBuilder(client).with_warrant(setup["warrant"], setup["holder"])
            .with_approvals([setup["approval"]]).on_denial("raise").build()
        )
        out = list(guarded.chat.completions.create(model="m", messages=[], stream=True))
        first_tc = out[0].choices[0].delta.tool_calls[0]
        key = idempotency_key_for(first_tc)
        assert key and len(key) == 64
        assert idempotency_key_for(out[1].choices[0].delta.tool_calls[0]) == key

    def test_openai_response_tool_calls_carry_their_keys(self, setup, monkeypatch):
        import json

        from tenuo.openai import idempotency_key_for

        enable_default_consumption_store()
        resp = TestOpenAIReleasesUnusedReservations._response([("transfer", json.dumps(setup["args"]))])
        out = TestOpenAIReleasesUnusedReservations()._guarded(setup, monkeypatch, resp).chat.completions.create(
            model="m", messages=[]
        )
        key = idempotency_key_for(out.choices[0].message.tool_calls[0])
        assert key and len(key) == 64
