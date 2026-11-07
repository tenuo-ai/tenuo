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
        assert 290 <= ttl <= 300

    def test_backend_protocol(self):
        from tenuo.consumption import ConsumptionBackend, InMemoryConsumptionBackend

        b = InMemoryConsumptionBackend()
        assert isinstance(b, ConsumptionBackend)
        assert b.reserve("k", 60) is None
        assert b.reserve("k", 60) == "in_flight"
        b.commit("k")
        assert b.reserve("k", 60) == "consumed"
        b.release("k")
        assert b.reserve("k", 60) == "consumed"


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
