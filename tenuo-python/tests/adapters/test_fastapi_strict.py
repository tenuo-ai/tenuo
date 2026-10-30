"""FastAPI strict mode refuses to start while a route has no TenuoGuard."""

import pytest

pytest.importorskip("fastapi")

from fastapi import APIRouter, Depends, FastAPI, WebSocket  # noqa: E402
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


@pytest.mark.parametrize("docs_url", ["/docs", "/custom-docs"])
def test_custom_route_at_docs_path_is_not_implicitly_public(docs_url):
    app = FastAPI(docs_url=docs_url)
    configure_tenuo(app, strict=True)

    @app.post(docs_url)
    def custom_action():
        return {"executed": True}

    with pytest.raises(ConfigurationError, match=f"POST {docs_url}"):
        _start(app)


def test_disabled_docs_do_not_exempt_application_route():
    app = FastAPI(openapi_url=None)
    configure_tenuo(app, strict=True)

    @app.get("/docs")
    def custom_docs():
        return {}

    with pytest.raises(ConfigurationError, match="GET /docs"):
        _start(app)


def test_plain_route_at_docs_path_is_not_implicitly_public():
    app = FastAPI(openapi_url=None)
    configure_tenuo(app, strict=True)
    app.add_route("/docs", lambda request: PlainTextResponse("custom"), name="swagger_ui_html")
    with pytest.raises(ConfigurationError, match="GET /docs"):
        _start(app)


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


def test_reconfiguration_updates_exemptions_without_duplicate_middleware():
    app = _app(strict=True)

    @app.get("/health")
    def health():
        return {"ok": True}

    configure_tenuo(app, strict=True, exempt=["/health"])
    assert len(app.user_middleware) == 1
    with TestClient(app) as client:
        assert client.get("/health").json() == {"ok": True}


def test_explicitly_disabling_strict_mode_before_startup():
    app = _app(strict=True)
    configure_tenuo(app, strict=False)

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


def test_route_added_during_lifespan_is_checked_and_cleanup_runs():
    from contextlib import asynccontextmanager

    events = []

    @asynccontextmanager
    async def lifespan(app):
        @app.get("/startup-route")
        def startup_route():
            return {}

        events.append("start")
        try:
            yield {"ready": True}
        finally:
            events.append("stop")

    app = FastAPI(lifespan=lifespan)
    configure_tenuo(app, strict=True)
    with pytest.raises(ConfigurationError, match="GET /startup-route"):
        _start(app)
    assert events == ["start", "stop"]


def test_guarded_route_added_during_startup_is_allowed():
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app):
        _guarded(app)
        yield {"ready": True}

    app = FastAPI(lifespan=lifespan)
    configure_tenuo(app, strict=True)
    with TestClient(app) as client:
        assert client.app_state["ready"] is True
        assert client.get("/search").status_code == 401


def test_included_router_lifespan_cannot_add_an_unchecked_route():
    from contextlib import asynccontextmanager

    import fastapi.routing

    if not hasattr(fastapi.routing, "_merge_lifespan_context"):
        pytest.skip("This FastAPI version does not run included-router lifespans")

    events = []

    @asynccontextmanager
    async def lifespan(app):
        @router.get("/late")
        def late():
            return {}

        # Older FastAPI copies included routes, so register directly too.
        @app.get("/router-startup")
        def router_startup():
            return {}

        events.append("start")
        try:
            yield
        finally:
            events.append("stop")

    app = _app(strict=True)
    router = APIRouter(lifespan=lifespan)
    app.include_router(router, prefix="/v1")
    with pytest.raises(ConfigurationError, match="/router-startup"):
        _start(app)
    assert events == ["start", "stop"]


def test_legacy_router_startup_hook_routes_are_checked():
    app = _app(strict=True)

    def startup():
        app.add_api_route("/startup-hook", lambda: {})

    router = APIRouter(on_startup=[startup])
    app.include_router(router)
    with pytest.raises(ConfigurationError, match="GET /startup-hook"):
        _start(app)


def _raising_app(**kwargs):
    app = _app(**kwargs)

    @app.get("/boom")
    def boom():
        raise TenuoError("nope")

    return app


def test_error_handler_response_is_used():
    seen = []

    def handler(exc):
        seen.append(exc)
        return PlainTextResponse("custom", status_code=418)

    resp = TestClient(_raising_app(error_handler=handler)).get("/boom")
    assert (resp.status_code, resp.text) == (418, "custom")
    assert isinstance(seen[0], TenuoError)


def test_async_error_handler_supported():
    async def handler(exc):
        return PlainTextResponse("async", status_code=418)

    resp = TestClient(_raising_app(error_handler=handler)).get("/boom")
    assert (resp.status_code, resp.text) == (418, "async")


def test_sync_error_handler_runs_without_blocking_the_event_loop():
    import asyncio

    def handler(exc):
        with pytest.raises(RuntimeError):
            asyncio.get_running_loop()
        return PlainTextResponse("worker", status_code=418)

    resp = TestClient(_raising_app(error_handler=handler)).get("/boom")
    assert (resp.status_code, resp.text) == (418, "worker")


def test_async_callable_error_handler_supported():
    import asyncio

    class Handler:
        async def __call__(self, exc):
            assert asyncio.get_running_loop().is_running()
            return PlainTextResponse("async callable", status_code=418)

    resp = TestClient(_raising_app(error_handler=Handler())).get("/boom")
    assert (resp.status_code, resp.text) == (418, "async callable")


def test_sync_error_handler_returning_awaitable_is_awaited():
    import asyncio

    async def response():
        assert asyncio.get_running_loop().is_running()
        return PlainTextResponse("awaited", status_code=418)

    def handler(exc):
        return response()

    resp = TestClient(_raising_app(error_handler=handler)).get("/boom")
    assert (resp.status_code, resp.text) == (418, "awaited")


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


@pytest.mark.parametrize("kind", ["subapp", "static"])
@pytest.mark.parametrize("exemption", [None, "/", ""])
def test_root_mount_requires_and_accepts_an_explicit_exemption(kind, exemption, tmp_path):
    from starlette.staticfiles import StaticFiles

    app = _app(strict=True, exempt=[] if exemption is None else [exemption])
    mounted = FastAPI() if kind == "subapp" else StaticFiles(directory=tmp_path)
    app.mount("/", mounted)
    if exemption is None:
        with pytest.raises(ConfigurationError, match=r"MOUNT /$"):
            _start(app)
    else:
        _start(app)


@pytest.mark.parametrize("kind", ["fastapi", "starlette"])
def test_websocket_without_guard_fails_startup(kind):
    app = _app(strict=True)

    async def websocket(ws: WebSocket):
        await ws.accept()

    if kind == "fastapi":
        app.add_api_websocket_route("/ws", websocket)
    else:
        from starlette.routing import WebSocketRoute

        app.router.routes.append(WebSocketRoute("/ws", websocket))

    with pytest.raises(ConfigurationError, match="WEBSOCKET /ws"):
        _start(app)


def test_plain_starlette_route_without_guard_fails_startup():
    app = _app(strict=True)
    app.add_route("/plain", lambda request: PlainTextResponse("open"))
    with pytest.raises(ConfigurationError, match="GET /plain"):
        _start(app)


def test_app_level_transitive_guard_counts_and_still_authorizes():
    def protected(ctx=Depends(TenuoGuard("search"))):
        return ctx

    app = FastAPI(dependencies=[Depends(protected)])
    configure_tenuo(app, strict=True)

    @app.get("/search")
    def search():
        return {}

    with TestClient(app) as client:
        assert client.get("/search").status_code == 401
