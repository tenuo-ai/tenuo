"""FastAPI strict mode refuses to start while a route has no TenuoGuard."""

import pytest

pytest.importorskip("fastapi")

from fastapi import APIRouter, Depends, FastAPI  # noqa: E402
from fastapi.responses import PlainTextResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tenuo import SigningKey  # noqa: E402
from tenuo.exceptions import ConfigurationError, TenuoError  # noqa: E402
from tenuo.fastapi import SecureAPIRouter, SecurityContext, TenuoGuard, configure_tenuo, require_warrant  # noqa: E402


def _app(**kwargs):
    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[SigningKey.generate().public_key], **kwargs)
    return app


def _start(app):
    with TestClient(app) as client:
        return client


def _guarded(app, path="/search"):
    @app.get(path)
    def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
        return {}


def test_unguarded_route_fails_startup_and_is_listed():
    app = _app(strict=True)
    _guarded(app)

    @app.post("/open")
    def open_route():
        return {}

    with pytest.raises(ConfigurationError) as exc:
        _start(app)
    assert "POST /open" in str(exc.value)
    assert "/search" not in str(exc.value)


def test_all_guarded_starts():
    app = _app(strict=True)
    _guarded(app)
    _start(app)


def test_docs_routes_exempt_by_default():
    app = _app(strict=True)
    _guarded(app)
    client = _start(app)
    assert client is not None


def test_exempt_path_is_skipped():
    app = _app(strict=True, exempt=["/health"])
    _guarded(app)

    @app.get("/health")
    def health():
        return {"ok": True}

    _start(app)


def test_require_warrant_does_not_count():
    app = _app(strict=True)

    @app.get("/items")
    def items(w=Depends(require_warrant)):
        return {}

    with pytest.raises(ConfigurationError, match="GET /items"):
        _start(app)


def test_included_router_routes_are_checked_with_prefix():
    app = _app(strict=True)
    router = APIRouter()

    @router.get("/users")
    def users():
        return {}

    app.include_router(router, prefix="/v1")
    with pytest.raises(ConfigurationError, match="GET /v1/users"):
        _start(app)


def test_router_level_guard_and_secure_router_count():
    app = _app(strict=True)
    router = APIRouter(dependencies=[Depends(TenuoGuard("admin"))])

    @router.get("/admin")
    def admin():
        return {}

    secure = SecureAPIRouter()

    @secure.get("/reports")
    def reports():
        return {}

    app.include_router(router)
    app.include_router(secure)
    _start(app)


def test_route_added_after_configure_is_checked():
    app = _app(strict=True)

    @app.get("/late")
    def late():
        return {}

    with pytest.raises(ConfigurationError, match="GET /late"):
        _start(app)


def test_strict_false_unchanged():
    app = _app()

    @app.get("/open")
    def open_route():
        return {"ok": True}

    with TestClient(app) as client:
        assert client.get("/open").json() == {"ok": True}


def test_user_lifespan_still_runs():
    events = []

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app):
        events.append("start")
        yield
        events.append("stop")

    app = FastAPI(lifespan=lifespan)
    configure_tenuo(app, trusted_issuers=[SigningKey.generate().public_key], strict=True)
    _guarded(app)
    _start(app)
    assert events == ["start", "stop"]


class _Boom(TenuoError):
    pass


def _raising_app(**kwargs):
    app = _app(**kwargs)

    @app.get("/boom")
    def boom():
        raise _Boom("nope")

    return app


def test_error_handler_response_is_used():
    seen = []

    def handler(exc):
        seen.append(exc)
        return PlainTextResponse("custom", status_code=418)

    resp = TestClient(_raising_app(error_handler=handler)).get("/boom")
    assert (resp.status_code, resp.text) == (418, "custom")
    assert isinstance(seen[0], _Boom)


def test_async_error_handler_supported():
    async def handler(exc):
        return PlainTextResponse("async", status_code=418)

    resp = TestClient(_raising_app(error_handler=handler)).get("/boom")
    assert (resp.status_code, resp.text) == (418, "async")


def test_error_handler_returning_none_falls_back_to_default():
    seen = []
    resp = TestClient(_raising_app(error_handler=seen.append)).get("/boom")
    assert len(seen) == 1
    assert resp.headers["content-type"].startswith("application/json")
    assert "error" in resp.json()


def test_mount_fails_unless_exempt():
    app = _app(strict=True)
    _guarded(app)
    app.mount("/static", FastAPI())
    with pytest.raises(ConfigurationError, match="MOUNT /static"):
        _start(app)

    app = _app(strict=True, exempt=["/static"])
    _guarded(app)
    app.mount("/static", FastAPI())
    _start(app)
