"""A presented PoP is admitted once when the inbound replay check is on."""

import time

import pytest

pytest.importorskip("tenuo_core")

from tenuo_core import Authorizer  # noqa: E402

from tenuo import SigningKey, Subpath, Warrant  # noqa: E402
from tenuo._enforcement import verify_inbound_call  # noqa: E402
from tenuo.nonce import NonceStore, disable_default_nonce_store, enable_default_nonce_store  # noqa: E402


@pytest.fixture(autouse=True)
def no_default_store():
    disable_default_nonce_store()
    yield
    disable_default_nonce_store()


@pytest.fixture
def call():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Subpath("/data"))
        .holder(holder.public_key)
        .ttl(300)
        .mint(issuer)
    )
    authorizer = Authorizer(trusted_roots=[issuer.public_key])

    def verify(path="/data/x", signature=None, timestamp=None, **kwargs):
        args = {"path": path}
        if signature is None:
            signature = bytes(warrant.sign(holder, "read_file", args, timestamp or int(time.time())))
        result = verify_inbound_call(
            tool_name="read_file",
            tool_args=args,
            warrant=warrant,
            pop_signature=signature,
            authorizer=authorizer,
            **kwargs,
        )
        return result, signature

    return verify


def test_replayed_pop_is_denied_with_an_explicit_store(call):
    store = NonceStore(ttl_seconds=150)
    first, signature = call(check_replay=True, nonce_store=store)
    assert first.allowed
    replay, _ = call(signature=signature, check_replay=True, nonce_store=store)
    assert not replay.allowed
    assert replay.error_type == "invalid_pop"


def test_replayed_pop_is_denied_with_the_process_wide_store(call):
    enable_default_nonce_store()
    first, signature = call(check_replay=True)
    assert first.allowed
    assert not call(signature=signature, check_replay=True)[0].allowed
    # A different request under the same warrant is a different signature.
    assert call(path="/data/y", check_replay=True)[0].allowed


def test_a_denied_request_does_not_use_up_its_signature(call):
    store = NonceStore(ttl_seconds=150)
    denied, signature = call(path="/etc/x", check_replay=True, nonce_store=store)
    assert not denied.allowed
    assert not store.is_replay(signature)
    assert call(check_replay=True, nonce_store=store)[0].allowed


def test_replay_check_is_off_unless_requested(call):
    enable_default_nonce_store()
    first, signature = call()
    assert first.allowed
    assert call(signature=signature)[0].allowed
    assert call(signature=signature, check_replay=True)[0].allowed
    assert not call(signature=signature, check_replay=True)[0].allowed


def test_no_store_means_no_replay_check(call):
    first, signature = call(check_replay=True)
    assert first.allowed
    assert call(signature=signature, check_replay=True)[0].allowed


@pytest.mark.parametrize("window, count", [(30, 5), (60, 9), (30, 4)])
def test_retention_covers_the_verifiers_full_acceptance_interval(monkeypatch, window, count):
    from tenuo.nonce import _admit_verified_pop

    now = [1000.0]
    monkeypatch.setattr("tenuo.nonce.time.monotonic", lambda: now[0])
    authorizer = Authorizer(pop_window_secs=window, pop_max_windows=count)
    store = NonceStore(ttl_seconds=window * count, pop_window_secs=window)
    assert _admit_verified_pop(store, b"signature", authorizer)
    now[0] += window * count - 0.001
    assert not _admit_verified_pop(store, b"signature", authorizer)


def test_future_window_pop_remains_recorded_past_120_seconds(call, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("tenuo.nonce.time.monotonic", lambda: now[0])
    store = NonceStore(ttl_seconds=150)
    first, signature = call(timestamp=int(time.time()) + 60, check_replay=True, nonce_store=store)
    assert first.allowed
    now[0] += 121
    assert not call(signature=signature, check_replay=True, nonce_store=store)[0].allowed


def test_concurrent_admission_is_an_atomic_check_and_insert():
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from tenuo.nonce import _InMemoryBackend

    class InterleavedBackend(_InMemoryBackend):
        barrier = threading.Barrier(2)

        def seen(self, key):
            result = super().seen(key)
            self.barrier.wait(timeout=5)
            return result

    backend = InterleavedBackend()
    stores = [NonceStore(backend=backend), NonceStore(backend=backend)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda store: store.check_and_record(b"same-pop"), stores))
    assert sorted(results) == [False, True]


def test_shared_backend_must_provide_atomic_admission():
    class LegacyBackend:
        def seen(self, key):
            return False

        def record(self, key, ttl):
            pass

    with pytest.raises(TypeError, match="atomic check_and_record"):
        NonceStore(backend=LegacyBackend())


def test_multiple_fastapi_guards_reuse_admission_only_within_the_request():
    import base64

    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from tenuo.fastapi import SecureAPIRouter, TenuoGuard, configure_tenuo

    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().capability("ping").holder(holder.public_key).ttl(300).mint(issuer)
    app, router = FastAPI(), SecureAPIRouter()
    configure_tenuo(app, trusted_issuers=[issuer.public_key])

    @router.get("/ping", tool="ping")
    def ping(ctx=Depends(TenuoGuard("ping"))):
        return {"tool": ctx.tool}

    app.include_router(router)
    enable_default_nonce_store()
    headers = {
        "X-Tenuo-Warrant": warrant.to_base64(),
        "X-Tenuo-PoP": base64.b64encode(bytes(warrant.sign(holder, "ping", {}, int(time.time())))).decode(),
    }
    with TestClient(app) as client:
        first = client.get("/ping", headers=headers)
        assert first.status_code == 200, first.text
        assert client.get("/ping", headers=headers).status_code == 403


@pytest.mark.asyncio
async def test_a2a_local_denial_does_not_consume_the_process_nonce_store():
    from tenuo.a2a.errors import ConstraintViolationError, PopVerificationError
    from tenuo.a2a.server import A2AServer

    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().capability("read_file", path=Subpath("/data")).holder(holder.public_key).ttl(300).mint(issuer)
    args = {"path": "/data/x"}
    signature = bytes(warrant.sign(holder, "read_file", args, int(time.time())))
    store = enable_default_nonce_store()
    server = A2AServer(name="agent", url="https://agent.test", public_key=issuer.public_key,
                       trusted_issuers=[issuer.public_key], check_replay=False)

    @server.skill("read_file", constraints={"path": Subpath("/private")})
    async def read_file(path: str):
        return path

    with pytest.raises(ConstraintViolationError):
        await server.validate_warrant(warrant.to_base64(), "read_file", args, pop_signature=signature)
    assert not store.is_replay(signature)
    server._skills["read_file"].constraints = {"path": Subpath("/data")}
    assert await server.validate_warrant(warrant.to_base64(), "read_file", args, pop_signature=signature)
    with pytest.raises(PopVerificationError):
        await server.validate_warrant(warrant.to_base64(), "read_file", args, pop_signature=signature)


def test_shared_backend_rejects_wider_verifiers_until_the_floor_is_configured(monkeypatch):
    from tenuo.exceptions import ConfigurationError
    from tenuo.nonce import _InMemoryBackend, _admit_verified_pop

    now = [1000.0]
    monkeypatch.setattr("tenuo.nonce.time.monotonic", lambda: now[0])
    narrow, wide = Authorizer(pop_max_windows=5), Authorizer(pop_max_windows=9)
    backend = _InMemoryBackend(retention_seconds=150)
    first, second = NonceStore(backend=backend), NonceStore(backend=backend)
    assert _admit_verified_pop(first, b"same-pop", narrow)
    now[0] += 151
    with pytest.raises(ConfigurationError, match="every shared verifier"):
        _admit_verified_pop(second, b"same-pop", wide)
    with pytest.raises(ValueError, match="shared backend retention floor"):
        NonceStore(ttl_seconds=270, backend=backend)

    # Every admission uses the namespace floor, including the narrow verifier.
    backend = _InMemoryBackend(retention_seconds=270)
    first, second = NonceStore(backend=backend), NonceStore(ttl_seconds=270, backend=backend)
    assert _admit_verified_pop(first, b"same-pop", narrow)
    now[0] += 151
    assert not _admit_verified_pop(second, b"same-pop", wide)


def test_short_retention_is_denied_without_recording_a_signature(call):
    store = NonceStore(ttl_seconds=120)
    denied, signature = call(check_replay=True, nonce_store=store)
    assert not denied.allowed
    assert "retention floor" in denied.denial_reason
    assert not store.is_replay(signature)


@pytest.mark.asyncio
async def test_a2a_nonce_replay_observes_the_configured_mode(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock

    from tenuo.a2a.errors import PopVerificationError
    from tenuo.a2a.server import A2AServer
    from tenuo.config import configure, reset_config

    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().capability("ping").holder(holder.public_key).ttl(300).mint(issuer)
    signature = bytes(warrant.sign(holder, "ping", {}, int(time.time())))
    server = A2AServer(name="agent", url="https://agent.test", public_key=issuer.public_key,
                       trusted_issuers=[issuer.public_key], check_replay=False)
    audit = AsyncMock()
    monkeypatch.setattr(server, "_audit", audit)
    cp = MagicMock()
    monkeypatch.setattr(server, "_control_plane", cp)
    enable_default_nonce_store()
    try:
        configure(mode="observe", trusted_roots=[issuer.public_key])
        assert await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
        assert await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
        result = cp.emit_for_enforcement.call_args.args[0]
        assert result.allowed and result.observed
        assert result.error_type == "invalid_pop"
        assert result.chain_result is None
        assert [item.id for item in result.presented_chain] == [warrant.id]
        assert result.verified_pop == signature
        assert result.pop_auth_args == {}
        assert "replay" in result.denial_reason.lower()
        assert audit.call_args.args[0].outcome == "denied"
        configure(mode="enforce", trusted_roots=[issuer.public_key])
        audit.reset_mock()
        cp.reset_mock()
        with pytest.raises(PopVerificationError):
            await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
        assert audit.call_args.args[0].outcome == "denied"
        assert "replay" in audit.call_args.args[0].reason.lower()
        assert not cp.emit_for_enforcement.call_args.args[0].allowed
    finally:
        reset_config()


@pytest.mark.asyncio
@pytest.mark.parametrize("observe", [False, True])
async def test_a2a_nonce_denial_produces_a_signed_runtime_receipt(observe):
    import io
    import json
    from tenuo import HolderIdentity, Runtime
    from tenuo.a2a.errors import PopVerificationError
    from tenuo.a2a.server import A2AServer
    from tenuo.config import configure, reset_config
    from tenuo_core import verify_receipt

    issuer, holder = SigningKey.generate(), HolderIdentity.generate()
    warrant = Warrant.mint_builder().capability("ping").holder(holder.public_key).ttl(300).mint(issuer)
    signature = bytes(warrant.sign(holder.signing_key, "ping", {}, int(time.time())))
    runtime = Runtime(identity=holder, trusted_roots=[issuer.public_key], receipts="collect")
    audit = io.StringIO()
    server = A2AServer(name="receipts", url="https://agent.test", public_key=holder.public_key,
                       trusted_issuers=[issuer.public_key], check_replay=False,
                       require_audience=False, audit_log=audit, runtime=runtime)
    enable_default_nonce_store()
    try:
        configure(mode="observe" if observe else "enforce", trusted_roots=[issuer.public_key])
        assert await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
        if observe:
            assert await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
        else:
            with pytest.raises(PopVerificationError):
                await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
        assert [verify_receipt(receipt).outcome for receipt in runtime.peek_receipts()] == ["allow", "deny"]
        events = [json.loads(line) for line in audit.getvalue().splitlines()]
        assert events[-1]["outcome"] == "denied"
        assert "replay" in events[-1]["reason"].lower()
    finally:
        reset_config()


def test_mixed_bucket_sizes_cannot_share_a_nonce_namespace():
    from tenuo.nonce import _admit_verified_pop
    from tenuo.exceptions import ConfigurationError
    store = NonceStore(ttl_seconds=270, pop_window_secs=30)
    assert _admit_verified_pop(store, b"pop", Authorizer(pop_window_secs=30, pop_max_windows=9))
    with pytest.raises(ConfigurationError, match="window size"):
        _admit_verified_pop(store, b"pop", Authorizer(pop_window_secs=60, pop_max_windows=4))


def test_nonce_release_does_not_remove_a_replacement_owner(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("tenuo.nonce.time.monotonic", lambda: now[0])
    store = NonceStore()
    first = store.reserve(b"pop")
    assert first is not None
    now[0] += 151
    second = store.reserve(b"pop")
    assert second is not None
    first.release()
    assert store.reserve(b"pop") is None
    second.release()
    final = store.reserve(b"pop")
    assert final is not None
    final.commit()
    final.release()
    assert store.is_replay(b"pop")


@pytest.mark.asyncio
async def test_a2a_jti_backend_failure_releases_only_its_nonce_reservation():
    from tenuo.a2a.server import A2AServer
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().capability("ping").holder(holder.public_key).ttl(300).mint(issuer)
    signature = bytes(warrant.sign(holder, "ping", {}, int(time.time())))
    class RecoveringCache:
        failed = True
        async def check_and_add(self, jti, ttl):
            if self.failed:
                raise RuntimeError("JTI cache unavailable")
            return True
    cache = RecoveringCache()
    server = A2AServer(name="agent", url="https://agent.test", public_key=issuer.public_key,
                       trusted_issuers=[issuer.public_key], check_replay=True, replay_backend=cache)
    store = enable_default_nonce_store()
    with pytest.raises(RuntimeError, match="JTI cache unavailable"):
        await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
    assert not store.is_replay(signature)
    cache.failed = False
    assert await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
    assert store.is_replay(signature)


@pytest.mark.asyncio
async def test_a2a_lost_nonce_reservation_reply_can_retry_after_recovery():
    from tenuo.a2a.server import A2AServer
    from tenuo.nonce import _InMemoryBackend
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().capability("ping").holder(holder.public_key).ttl(300).mint(issuer)
    signature = bytes(warrant.sign(holder, "ping", {}, int(time.time())))
    class LostReply(_InMemoryBackend):
        failed = True
        def reserve(self, nonce, ttl, owner):
            admitted = super().reserve(nonce, ttl, owner)
            if self.failed:
                raise RuntimeError("nonce response lost")
            return admitted
    backend = LostReply()
    store = enable_default_nonce_store(backend=backend)
    server = A2AServer(name="agent", url="https://agent.test", public_key=issuer.public_key,
                       trusted_issuers=[issuer.public_key], check_replay=True)
    with pytest.raises(RuntimeError, match="nonce response lost"):
        await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
    assert not store.is_replay(signature)
    backend.failed = False
    assert await server.validate_warrant(warrant.to_base64(), "ping", {}, pop_signature=signature)
    assert store.is_replay(signature)
