"""``warrant_chain=`` takes one convention across the Temporal integration.

Every helper accepts the parents (root-first) or the full chain ending with the
leaf, and both shapes produce identical headers. The leaf anywhere but last is
still rejected.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("temporalio")

from temporalio import workflow  # noqa: E402

import tenuo  # noqa: F401, E402 - installs Warrant builders
from tenuo_core import SigningKey, Warrant, decode_warrant_stack_base64  # noqa: E402
from tenuo.temporal._config import TenuoPluginConfig  # noqa: E402
from tenuo.temporal._constants import TENUO_CHAIN_HEADER  # noqa: E402
from tenuo.temporal._headers import tenuo_headers  # noqa: E402
from tenuo.temporal._state import _activity_warrant_override, _store_lock, _workflow_config_store  # noqa: E402
from tenuo.temporal.exceptions import TenuoContextError  # noqa: E402


def _chain():
    """Return ``(root, mid, leaf, leaf_key)`` for a three-level delegation."""
    root_key, mid_key, leaf_key = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    root = Warrant.mint_builder().holder(mid_key.public_key).capability("echo").ttl(3600).mint(root_key)
    mid = root.grant_builder().holder(leaf_key.public_key).capability("echo").ttl(1800).grant(mid_key)
    leaf = mid.grant_builder().holder(leaf_key.public_key).capability("echo").ttl(900).grant(leaf_key)
    return root, mid, leaf, leaf_key


def _chain_bytes(raw: bytes) -> list:
    return [bytes(w.to_bytes()) for w in decode_warrant_stack_base64(raw.decode("utf-8"))]


def _malformed(root, mid, leaf):
    """Chains that put the leaf somewhere other than last."""
    return [[leaf, root, mid], [root, leaf, mid], [root, leaf, mid, leaf], [root, mid, leaf, leaf]]


# ── Start helpers ─────────────────────────────────────────────────────────


def test_tenuo_headers_accepts_parents_or_full_chain():
    root, mid, leaf, _ = _chain()
    from_parents = tenuo_headers(leaf, "agent1", compress=False, warrant_chain=[root, mid])
    from_full = tenuo_headers(leaf, "agent1", compress=False, warrant_chain=[root, mid, leaf])

    assert from_parents == from_full
    assert _chain_bytes(from_full[TENUO_CHAIN_HEADER]) == [bytes(w.to_bytes()) for w in (root, mid, leaf)]


def test_tenuo_headers_rejects_leaf_before_end_of_chain():
    root, mid, leaf, _ = _chain()
    for malformed in _malformed(root, mid, leaf):
        with pytest.raises(TenuoContextError, match="before its end"):
            tenuo_headers(leaf, "agent1", warrant_chain=malformed)


def test_whole_chain_as_warrant_matches_explicit_chain():
    from tenuo_core import encode_warrant_stack

    root, mid, leaf, _ = _chain()
    expected = tenuo_headers(leaf, "agent1", compress=False, warrant_chain=[root, mid])
    assert tenuo_headers([root, mid, leaf], "agent1", compress=False) == expected
    assert tenuo_headers([root, mid, leaf], "agent1", compress=False, warrant_chain=[]) == expected
    stack = encode_warrant_stack([root, mid, leaf])
    assert tenuo_headers(stack, "agent1", compress=False) == expected


def test_whole_chain_as_warrant_rejects_duplicate_leaf():
    """A whole chain already had its leaf split off; a second copy is malformed.

    Stripping it as if it were an explicit ``warrant_chain`` ending with the
    leaf silently accepted ``[root, leaf, leaf]``.
    """
    from tenuo_core import encode_warrant_stack

    root, mid, leaf, _ = _chain()
    for malformed in ([root, mid, leaf, leaf], [leaf, leaf], [root, leaf, mid, leaf]):
        for chain_arg in (None, []):
            with pytest.raises(TenuoContextError, match="before its end"):
                tenuo_headers(malformed, "agent1", warrant_chain=chain_arg)
        with pytest.raises(TenuoContextError, match="before its end"):
            tenuo_headers(encode_warrant_stack(malformed), "agent1")


def test_chain_of_only_the_leaf_sends_the_leaf_alone():
    _root, _mid, leaf, _ = _chain()
    assert TENUO_CHAIN_HEADER not in tenuo_headers(leaf, "agent1", warrant_chain=[leaf])


@pytest.mark.asyncio
async def test_execute_workflow_authorized_accepts_both_shapes():
    from tenuo.temporal._client import TenuoClientInterceptor
    from tenuo.temporal._workflow import execute_workflow_authorized

    root, mid, leaf, _ = _chain()
    bound = []
    for shape in ([root, mid], [root, mid, leaf]):
        ci = TenuoClientInterceptor()
        client = MagicMock()
        client.execute_workflow = AsyncMock(return_value="done")
        await execute_workflow_authorized(
            client=client,
            client_interceptor=ci,
            workflow_run_fn="wf",
            workflow_id="wf-shape",
            warrant=leaf,
            key_id="agent1",
            compress=False,
            warrant_chain=shape,
        )
        bound.append(ci._headers_by_workflow_id["wf-shape"][0])
    assert bound[0] == bound[1]
    assert TENUO_CHAIN_HEADER in bound[0]


@pytest.mark.asyncio
async def test_tenuo_warrant_context_accepts_both_shapes():
    from tenuo.temporal._client import TenuoWarrantContextPropagator, tenuo_warrant_context

    root, mid, leaf, _ = _chain()
    seen = []
    for shape in ([root, mid], [root, mid, leaf]):
        async with tenuo_warrant_context(leaf, "agent1", warrant_chain=shape) as active:
            assert bytes(active.to_bytes()) == bytes(leaf.to_bytes())
            presented, key_id = TenuoWarrantContextPropagator().get()
            seen.append(tenuo_headers(presented, key_id, compress=False))
    assert seen[0] == seen[1]

    with pytest.raises(TenuoContextError, match="before its end"):
        async with tenuo_warrant_context(leaf, "agent1", warrant_chain=[leaf, root, mid]):
            pass


# ── Activity helper ───────────────────────────────────────────────────────


async def _activity_override_headers(warrant, warrant_chain):
    from tenuo.temporal._workflow import tenuo_execute_activity

    captured = {}

    async def fake_execute_activity(activity, **kwargs):
        captured["headers"] = _activity_warrant_override.get()
        return "ok"

    def echo():
        return None

    with (
        patch.object(workflow, "info", return_value=MagicMock(run_id="run-chain-shape")),
        patch.object(workflow, "execute_activity", side_effect=fake_execute_activity),
    ):
        await tenuo_execute_activity(
            echo,
            warrant=warrant,
            key_id="agent1",
            warrant_chain=warrant_chain,
            compress=False,
            start_to_close_timeout=1,
        )
    return captured["headers"]


@pytest.mark.asyncio
async def test_execute_activity_accepts_both_shapes_and_matches_start_headers():
    root, mid, leaf, _ = _chain()
    from_parents = await _activity_override_headers(leaf, [root, mid])
    from_full = await _activity_override_headers(leaf, [root, mid, leaf])

    assert from_parents == from_full
    # Same list passed to a start helper yields the same Tenuo headers.
    assert from_full == tenuo_headers(leaf, "agent1", compress=False, warrant_chain=[root, mid, leaf])
    assert from_full == tenuo_headers(leaf, "agent1", compress=False, warrant_chain=[root, mid])


@pytest.mark.asyncio
async def test_execute_activity_rejects_leaf_before_end_of_chain():
    root, mid, leaf, _ = _chain()
    for malformed in _malformed(root, mid, leaf):
        with pytest.raises(TenuoContextError, match="before its end"):
            await _activity_override_headers(leaf, malformed)


# ── Nexus helpers ─────────────────────────────────────────────────────────


def _nexus_headers(warrant, signer, warrant_chain):
    pytest.importorskip("nexusrpc")
    from tenuo.temporal._nexus import tenuo_nexus_headers

    return tenuo_nexus_headers(
        warrant,
        "agent1",
        signer,
        endpoint="billing",
        service="Billing",
        operation="echo",
        input={"value": 1},
        warrant_chain=warrant_chain,
        compress=False,
        timestamp=1_700_000_000,
    )


def test_nexus_headers_accept_both_shapes_and_match_start_headers():
    import base64

    root, mid, leaf, leaf_key = _chain()
    from_parents = _nexus_headers(leaf, leaf_key, [root, mid])
    from_full = _nexus_headers(leaf, leaf_key, [root, mid, leaf])

    assert from_parents == from_full
    start = tenuo_headers(leaf, "agent1", compress=False, warrant_chain=[root, mid])
    assert base64.b64decode(from_full[TENUO_CHAIN_HEADER]) == start[TENUO_CHAIN_HEADER]


def test_nexus_headers_reject_leaf_before_end_of_chain():
    root, mid, leaf, leaf_key = _chain()
    for malformed in _malformed(root, mid, leaf):
        with pytest.raises(TenuoContextError, match="before its end"):
            _nexus_headers(leaf, leaf_key, malformed)


def test_nexus_workflow_envelope_accepts_both_shapes():
    pytest.importorskip("nexusrpc")
    from tenuo.temporal._nexus import tenuo_create_nexus_workflow_envelope

    root, mid, leaf, _ = _chain()
    envelopes = [
        tenuo_create_nexus_workflow_envelope(
            leaf, "agent1", workflow_id="wf-env", warrant_chain=shape, compress=False
        ).headers
        for shape in ([root, mid], [root, mid, leaf])
    ]
    assert envelopes[0] == envelopes[1]
    assert TENUO_CHAIN_HEADER in envelopes[0]

    with pytest.raises(TenuoContextError, match="before its end"):
        tenuo_create_nexus_workflow_envelope(leaf, "agent1", workflow_id="wf-env", warrant_chain=[root, leaf, mid])


def test_nexus_operation_authority_accepts_both_shapes():
    pytest.importorskip("nexusrpc")
    from tenuo.temporal._nexus import _resolve_workflow_nexus_authority

    root, mid, leaf, leaf_key = _chain()
    resolver = MagicMock()
    resolver.resolve_sync.return_value = leaf_key
    config = SimpleNamespace(key_resolver=resolver)
    run_id = "run-nexus-shape"
    with _store_lock:
        _workflow_config_store[run_id] = config
    try:
        with patch.object(workflow, "info", return_value=MagicMock(run_id=run_id)):
            chains = [
                _resolve_workflow_nexus_authority(warrant=leaf, key_id="agent1", warrant_chain=shape)[2]
                for shape in ([root, mid], [root, mid, leaf])
            ]
            with pytest.raises(TenuoContextError, match="before its end"):
                _resolve_workflow_nexus_authority(warrant=leaf, key_id="agent1", warrant_chain=[leaf, root, mid])
    finally:
        with _store_lock:
            _workflow_config_store.pop(run_id, None)

    expected = [bytes(w.to_bytes()) for w in (root, mid, leaf)]
    for chain in chains:
        assert [bytes(w.to_bytes()) for w in chain] == expected


# ── Async activity completion ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_completion_accepts_both_shapes():
    from tenuo.temporal import tenuo_complete_async_activity
    from tenuo.temporal._state import _clear_worker_config, _set_worker_config

    root_key, leaf_key = SigningKey.generate(), SigningKey.generate()
    root = Warrant.issue(root_key, capabilities={"external_job": {}}, holder=root_key.public_key)
    leaf = root.attenuate(signing_key=root_key, holder=leaf_key.public_key, capabilities={"external_job": {}})
    _set_worker_config(
        TenuoPluginConfig(key_resolver=AsyncMock(), trusted_roots=[root_key.public_key]),
        task_queue="async-completion-shape",
    )
    try:
        for shape in ([root], [root, leaf]):
            handle = AsyncMock()
            await tenuo_complete_async_activity(
                handle, "result", leaf, task_queue="async-completion-shape", warrant_chain=shape
            )
            handle.complete.assert_awaited_once_with("result")

        handle = AsyncMock()
        with pytest.raises(TenuoContextError, match="before its end"):
            await tenuo_complete_async_activity(
                handle, "result", leaf, task_queue="async-completion-shape", warrant_chain=[leaf, root]
            )
        handle.complete.assert_not_awaited()
    finally:
        _clear_worker_config("async-completion-shape")
