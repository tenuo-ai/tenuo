"""
Tests for :mod:`tenuo.mcp.tasks`: binding SEP-2663 task ids to the creating
warrant and authorizing ``tasks/*`` requests with PoP.

Framework-free; the FastMCP wiring is covered in
``test_mcp_fastmcp_tasks_e2e.py``.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

import pytest
from tenuo_core import Authorizer, SigningKey, Warrant

from tenuo import Pattern
from tenuo.mcp.tasks import (
    InMemoryTaskBindingStore,
    TaskBinding,
    binding_for_created_task,
    sign_task_request,
    verify_task_request,
)
from tenuo.mcp.server import MCPVerifier
from tenuo.nonce import NonceStore

TASK_ID = "task-abc"


@pytest.fixture
def issuer_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def agent_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def authorizer(issuer_key: SigningKey) -> Authorizer:
    return Authorizer(trusted_roots=[issuer_key.public_key])


@pytest.fixture
def warrant(issuer_key: SigningKey, agent_key: SigningKey) -> Warrant:
    return Warrant.issue(
        issuer_key,
        capabilities={"crunch": {"dataset": Pattern("d*")}},
        holder=agent_key.public_key,
        ttl_seconds=600,
    )


@pytest.fixture
def store(warrant: Warrant) -> InMemoryTaskBindingStore:
    s = InMemoryTaskBindingStore()
    s.put(binding_for_created_task(TASK_ID, warrant))
    return s


def _request(
    chain: List[Warrant],
    key: SigningKey,
    method: str,
    params: Dict[str, Any],
    *,
    signed_params: Dict[str, Any] | None = None,
    signed_method: str | None = None,
) -> Dict[str, Any]:
    envelope = sign_task_request(
        chain, key, signed_method or method, signed_params if signed_params is not None else params
    )
    return {**params, "_meta": {"tenuo": envelope}}


def _verify(method: str, params: Dict[str, Any], store, authorizer, **kw: Any):
    return verify_task_request(method, params, store=store, authorizer=authorizer, **kw)


@pytest.mark.parametrize("method", ["tasks/get", "tasks/cancel"])
def test_creating_warrant_is_allowed(method, warrant, agent_key, store, authorizer) -> None:
    params = _request([warrant], agent_key, method, {"taskId": TASK_ID})
    result = _verify(method, params, store, authorizer)
    assert result.allowed, result.denial_reason
    assert result.warrant_id == warrant.id


def test_update_covers_input_responses(warrant, agent_key, store, authorizer) -> None:
    body = {"taskId": TASK_ID, "inputResponses": {"k1": {"action": "accept", "content": {"name": "x"}}}}
    params = _request([warrant], agent_key, "tasks/update", body)
    assert _verify("tasks/update", params, store, authorizer).allowed

    tampered = {**params, "inputResponses": {"k1": {"action": "accept", "content": {"name": "y"}}}}
    result = _verify("tasks/update", tampered, store, authorizer)
    assert not result.allowed
    assert result.error_type == "invalid_pop"


def test_missing_envelope_is_denied(store, authorizer) -> None:
    result = _verify("tasks/get", {"taskId": TASK_ID}, store, authorizer)
    assert not result.allowed
    assert result.error_type == "missing_signature"
    assert result.jsonrpc_error_code == -32001


def test_missing_task_id_is_invalid_params(warrant, agent_key, store, authorizer) -> None:
    params = _request([warrant], agent_key, "tasks/get", {})
    result = _verify("tasks/get", params, store, authorizer)
    assert result.jsonrpc_error_code == -32602


def test_pop_for_another_task_is_denied(warrant, agent_key, store, authorizer) -> None:
    params = _request(
        [warrant], agent_key, "tasks/get", {"taskId": TASK_ID}, signed_params={"taskId": "other"}
    )
    result = _verify("tasks/get", params, store, authorizer)
    assert result.error_type == "invalid_pop"


def test_pop_for_get_cannot_cancel(warrant, agent_key, store, authorizer) -> None:
    params = _request(
        [warrant], agent_key, "tasks/cancel", {"taskId": TASK_ID}, signed_method="tasks/get"
    )
    result = _verify("tasks/cancel", params, store, authorizer)
    assert result.error_type == "invalid_pop"


def test_signature_by_non_holder_is_denied(warrant, store, authorizer) -> None:
    params = _request([warrant], SigningKey.generate(), "tasks/get", {"taskId": TASK_ID})
    assert _verify("tasks/get", params, store, authorizer).error_type == "invalid_pop"


def test_untrusted_issuer_is_denied(agent_key, store) -> None:
    rogue = Warrant.issue(
        SigningKey.generate(), capabilities={"crunch": {}}, holder=agent_key.public_key
    )
    params = _request([rogue], agent_key, "tasks/get", {"taskId": TASK_ID})
    authorizer = Authorizer(trusted_roots=[SigningKey.generate().public_key])
    result = _verify("tasks/get", params, store, authorizer)
    assert result.error_type == "invalid_warrant"


def test_other_valid_warrant_cannot_reach_task(issuer_key, store, authorizer) -> None:
    """A different caller with its own valid warrant learns nothing about the task."""
    other_key = SigningKey.generate()
    other = Warrant.issue(issuer_key, capabilities={"crunch": {}}, holder=other_key.public_key)
    params = _request([other], other_key, "tasks/get", {"taskId": TASK_ID})
    denied = _verify("tasks/get", params, store, authorizer)

    unknown = _request([other], other_key, "tasks/get", {"taskId": "no-such-task"})
    missing = _verify("tasks/get", unknown, store, authorizer)

    assert denied.error_type == missing.error_type == "task_not_accessible"
    assert denied.denial_reason == missing.denial_reason


def test_same_holder_new_warrant_cannot_reach_task(issuer_key, agent_key, store, authorizer) -> None:
    """Binding is to the warrant id, not only the key."""
    renewed = Warrant.issue(issuer_key, capabilities={"crunch": {}}, holder=agent_key.public_key)
    params = _request([renewed], agent_key, "tasks/get", {"taskId": TASK_ID})
    assert _verify("tasks/get", params, store, authorizer).error_type == "task_not_accessible"


def test_replay_is_denied(warrant, agent_key, store, authorizer) -> None:
    nonce_store = NonceStore()
    params = _request([warrant], agent_key, "tasks/cancel", {"taskId": TASK_ID})
    assert _verify("tasks/cancel", params, store, authorizer, nonce_store=nonce_store).allowed
    again = _verify("tasks/cancel", params, store, authorizer, nonce_store=nonce_store)
    assert again.error_type == "replay"


class TestDelegatedChain:
    @pytest.fixture
    def worker_key(self) -> SigningKey:
        return SigningKey.generate()

    @pytest.fixture
    def root(self, issuer_key, agent_key) -> Warrant:
        return (
            Warrant.mint_builder()
            .capability("crunch")
            .holder(agent_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

    @pytest.fixture
    def child(self, root, agent_key, worker_key) -> Warrant:
        return (
            root.grant_builder()
            .capability("crunch")
            .holder(worker_key.public_key)
            .ttl(1800)
            .grant(agent_key)
        )

    def test_worker_reaches_task_it_created(self, root, child, worker_key, authorizer) -> None:
        store = InMemoryTaskBindingStore()
        store.put(binding_for_created_task(TASK_ID, child))
        params = _request([root, child], worker_key, "tasks/get", {"taskId": TASK_ID})
        assert _verify("tasks/get", params, store, authorizer).allowed

    def test_parent_holder_cannot_reach_worker_task(self, root, child, agent_key, authorizer) -> None:
        store = InMemoryTaskBindingStore()
        store.put(binding_for_created_task(TASK_ID, child))
        params = _request([root], agent_key, "tasks/get", {"taskId": TASK_ID})
        assert _verify("tasks/get", params, store, authorizer).error_type == "task_not_accessible"

    def test_worker_cannot_reach_parent_task(self, root, child, worker_key, authorizer) -> None:
        """The creating warrant is in the worker's chain, but the holder differs."""
        store = InMemoryTaskBindingStore()
        store.put(binding_for_created_task(TASK_ID, root))
        params = _request([root, child], worker_key, "tasks/get", {"taskId": TASK_ID})
        assert _verify("tasks/get", params, store, authorizer).error_type == "task_not_accessible"


def test_binding_records_creating_warrant(warrant, agent_key) -> None:
    binding = binding_for_created_task(TASK_ID, warrant)
    assert binding.warrant_id == warrant.id
    assert bytes(binding.holder.to_bytes()) == bytes(agent_key.public_key.to_bytes())
    assert time.time() < binding.expires_at <= time.time() + 601


def test_store_drops_expired_bindings(agent_key) -> None:
    store = InMemoryTaskBindingStore()
    holder = agent_key.public_key
    store.put(TaskBinding("old", "w", holder, int(time.time()) - 1))
    store.put(TaskBinding("live", "w", holder, int(time.time()) + 60))
    assert store.get("old") is None
    assert store.get("live") is not None
    assert len(store) == 1


def test_binding_round_trips_through_storage_fields(warrant) -> None:
    from tenuo_core import PublicKey

    binding = binding_for_created_task(TASK_ID, warrant)
    rebuilt = TaskBinding(
        binding.task_id,
        binding.warrant_id,
        PublicKey.from_bytes(bytes(binding.holder.to_bytes())),
        binding.expires_at,
    )
    assert rebuilt == binding


class _RecordingControlPlane:
    def __init__(self) -> None:
        self.events: List[Any] = []

    def emit_for_enforcement(self, result: Any, chain_result: Any = None, **_: Any) -> None:
        self.events.append(result)


class TestVerifierAudit:
    def test_allow_and_deny_are_emitted(self, warrant, agent_key, store, authorizer) -> None:
        control_plane = _RecordingControlPlane()
        verifier = MCPVerifier(authorizer=authorizer, control_plane=control_plane)

        ok = _request([warrant], agent_key, "tasks/get", {"taskId": TASK_ID})
        assert verifier.verify_task_request("tasks/get", ok, bindings=store).allowed
        denied = verifier.verify_task_request("tasks/cancel", {"taskId": TASK_ID}, bindings=store)
        assert not denied.allowed

        allow_event, deny_event = control_plane.events
        assert (allow_event.allowed, allow_event.tool, allow_event.warrant_id) == (
            True,
            "tasks/get",
            warrant.id,
        )
        assert (deny_event.allowed, deny_event.tool, deny_event.error_type) == (
            False,
            "tasks/cancel",
            "missing_signature",
        )

    def test_audit_view_leaves_out_input_responses(self, warrant, agent_key, store, authorizer) -> None:
        control_plane = _RecordingControlPlane()
        verifier = MCPVerifier(authorizer=authorizer, control_plane=control_plane)
        body = {"taskId": TASK_ID, "inputResponses": {"k": {"action": "accept", "content": {"ssn": "x"}}}}
        verifier.verify_task_request(
            "tasks/update", _request([warrant], agent_key, "tasks/update", body), bindings=store
        )
        assert control_plane.events[0].arguments == {"taskId": TASK_ID}

    def test_unbound_task_without_envelope_passes_only_in_rollout(self, authorizer) -> None:
        store = InMemoryTaskBindingStore()
        params = {"taskId": "unbound"}
        strict = MCPVerifier(authorizer=authorizer, control_plane=_RecordingControlPlane())
        rollout = MCPVerifier(
            authorizer=authorizer, require_warrant=False, control_plane=_RecordingControlPlane()
        )
        assert not strict.verify_task_request("tasks/get", params, bindings=store).allowed
        assert rollout.verify_task_request("tasks/get", params, bindings=store).allowed

    def test_bound_task_needs_warrant_even_in_rollout(self, store, authorizer) -> None:
        rollout = MCPVerifier(
            authorizer=authorizer, require_warrant=False, control_plane=_RecordingControlPlane()
        )
        result = rollout.verify_task_request("tasks/get", {"taskId": TASK_ID}, bindings=store)
        assert result.error_type == "missing_signature"
