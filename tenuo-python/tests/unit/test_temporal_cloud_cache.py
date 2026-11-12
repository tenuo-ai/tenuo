"""Cloud signing caches must work without threads or I/O in workflows."""
import time
from unittest.mock import AsyncMock, patch

import pytest

pytest.importorskip("temporalio")

from tenuo import SigningKey
from tenuo.temporal._resolvers import (
    AWSSecretsManagerKeyResolver,
    GCPSecretManagerKeyResolver,
    VaultKeyResolver,
)
from tenuo.temporal.exceptions import KeyResolutionError


@pytest.fixture(params=[VaultKeyResolver, AWSSecretsManagerKeyResolver, GCPSecretManagerKeyResolver])
def resolver(request):
    cls = request.param
    kwargs = {VaultKeyResolver: {"url": "https://vault.example"},
              AWSSecretsManagerKeyResolver: {}, GCPSecretManagerKeyResolver: {"project_id": "test"}}
    return cls(**kwargs[cls])


def test_warm_sync_read_never_starts_thread_or_fetches(resolver):
    key = SigningKey.generate()
    resolver._cache["agent"] = (key, time.time())
    with patch("concurrent.futures.ThreadPoolExecutor", side_effect=AssertionError("thread")), \
         patch.object(resolver, "resolve", side_effect=AssertionError("fetch")):
        assert resolver.resolve_sync("agent") is key


@pytest.mark.parametrize("age", [None, 300, 301])
def test_workflow_cache_miss_and_expiry_fail_closed(resolver, age):
    if age is not None:
        resolver._cache["agent"] = (SigningKey.generate(), 1000 - age)
    with patch("tenuo.temporal._resolvers.time.time", return_value=1000), \
         patch("temporalio.workflow.in_workflow", return_value=True), \
         patch.object(resolver, "resolve", side_effect=AssertionError("fetch")):
        with pytest.raises(KeyResolutionError):
            resolver.resolve_sync("agent")


def test_host_cache_miss_retains_sync_fetch(resolver):
    key = SigningKey.generate()
    with patch.object(resolver, "resolve", new=AsyncMock(return_value=key)) as fetch:
        assert resolver.resolve_sync("agent") is key
        fetch.assert_awaited_once_with("agent")


@pytest.mark.asyncio
async def test_preload_and_refresh_outside_workflow(resolver):
    old, new = SigningKey.generate(), SigningKey.generate()

    async def fetch(key_id):
        resolver._cache[key_id] = (new, time.time())
        return new

    with patch.object(resolver, "_fetch_key", side_effect=fetch):
        await resolver.preload_keys(["agent"])
        assert resolver.resolve_sync("agent") is new
        resolver._cache["agent"] = (old, time.time())
        await resolver.refresh_keys(["agent"])
        assert resolver.resolve_sync("agent") is new
    with patch.object(resolver, "_fetch_key", side_effect=KeyResolutionError(key_id="agent")):
        with pytest.raises(KeyResolutionError):
            await resolver.refresh_keys(["agent"])
    assert "agent" not in resolver._cache


@pytest.mark.asyncio
async def test_workflow_cannot_preload_or_refresh(resolver):
    with patch("temporalio.workflow.in_workflow", return_value=True), \
         patch.object(resolver, "resolve", side_effect=AssertionError("fetch")):
        for method in [resolver.preload_keys, resolver.refresh_keys]:
            with pytest.raises(KeyResolutionError):
                await method(["agent"])


@pytest.mark.asyncio
async def test_cached_reads_under_real_temporal_sandbox_restrictions(resolver):
    from temporalio.worker.workflow_sandbox import SandboxRestrictions
    from temporalio.worker.workflow_sandbox._importer import Importer
    from temporalio.worker.workflow_sandbox._restrictions import (
        RestrictedWorkflowAccessError,
        RestrictionContext,
    )

    from tenuo.temporal._resolvers import KeyResolver

    key = SigningKey.generate()
    resolver._cache["agent"] = (key, time.time())
    context = RestrictionContext()
    context.is_runtime = True
    importer = Importer(
        SandboxRestrictions.default.with_passthrough_modules("tenuo", "tenuo_core"), context,
    )
    with importer.applied():
        assert resolver.resolve_sync("agent") is key
        # The old inherited bridge fails under these same real restrictions.
        with pytest.raises(RestrictedWorkflowAccessError):
            KeyResolver.resolve_sync(resolver, "agent")


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_refresh_keeps_unexpired_key_until_fetch_finishes(resolver, fails):
    import asyncio

    old, new = SigningKey.generate(), SigningKey.generate()
    resolver._cache["agent"] = (old, time.time())
    started, finish = asyncio.Event(), asyncio.Event()

    async def fetch(key_id):
        started.set()
        await finish.wait()
        if fails:
            raise KeyResolutionError(key_id=key_id)
        return new

    with patch.object(resolver, "_fetch_key", side_effect=fetch):
        refresh = asyncio.create_task(resolver.refresh_keys(["agent"]))
        await started.wait()
        with patch("temporalio.workflow.in_workflow", return_value=True):
            assert resolver.resolve_sync("agent") is old
        finish.set()
        if fails:
            with pytest.raises(KeyResolutionError):
                await refresh
            assert "agent" not in resolver._cache
        else:
            await refresh
            assert resolver.resolve_sync("agent") is new
