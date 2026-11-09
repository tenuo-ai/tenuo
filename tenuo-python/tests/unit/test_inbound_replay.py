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
    store = NonceStore(ttl_seconds=120)
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
    store = NonceStore(ttl_seconds=120)
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
    store = NonceStore(ttl_seconds=1)
    assert _admit_verified_pop(store, b"signature", authorizer)
    now[0] += window * count - 0.001
    assert not _admit_verified_pop(store, b"signature", authorizer)


def test_future_window_pop_remains_recorded_past_120_seconds(call, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("tenuo.nonce.time.monotonic", lambda: now[0])
    store = NonceStore(ttl_seconds=120)
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
