"""SecureAPIRouter guards every HTTP route it serves.

Routes added with ``add_api_route()`` and the routes of routers passed to
``include_router()`` used to run with no warrant at all. These tests drive
real requests through the ASGI app and record which handlers executed.
"""

import asyncio
import base64
import time
from typing import Any, Dict, List

import pytest

from tenuo import Exact, SigningKey, Warrant
from tenuo.exceptions import ConfigurationError

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi import APIRouter, Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.responses import PlainTextResponse  # noqa: E402

from tenuo.fastapi import SecureAPIRouter, SecurityContext, TenuoGuard, configure_tenuo  # noqa: E402
from tenuo.fastapi import _lazy_include_supported  # noqa: E402

ISSUER = SigningKey.generate()
AGENT = SigningKey.generate()


def _headers(tool: str, args: Dict[str, Any], **constraints: Any) -> Dict[str, str]:
    # Signed by hand: Warrant.headers() refuses to sign a call it would deny.
    warrant = Warrant.mint_builder().capability(tool, **constraints).holder(AGENT.public_key).ttl(300).mint(ISSUER)
    pop = bytes(warrant.sign(AGENT, tool, args, int(time.time())))
    return {"X-Tenuo-Warrant": warrant.to_base64(), "X-Tenuo-PoP": base64.b64encode(pop).decode()}


def _call(app: Any, method: str, path: str, headers: Any = None) -> int:
    async def go() -> int:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            return (await client.request(method, path, headers=headers or {})).status_code

    return asyncio.run(go())


def _app(router: Any) -> Any:
    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[ISSUER.public_key])
    app.include_router(router)
    return app


def test_add_api_route_is_guarded() -> None:
    ran: List[str] = []
    router = SecureAPIRouter(tool_prefix="api")

    async def wipe() -> Dict[str, bool]:
        ran.append("wipe")
        return {"ok": True}

    router.add_api_route("/wipe", wipe, methods=["POST"])
    app = _app(router)

    assert _call(app, "POST", "/wipe") == 401
    assert _call(app, "POST", "/wipe", _headers("api_other_create", {})) == 403
    assert ran == []
    assert _call(app, "POST", "/wipe", _headers("api_wipe_create", {})) == 200
    assert ran == ["wipe"]


def test_add_api_route_with_explicit_tool() -> None:
    ran: List[str] = []
    router = SecureAPIRouter()

    async def wipe() -> Dict[str, bool]:
        ran.append("wipe")
        return {}

    router.add_api_route("/wipe", wipe, methods=["POST"], tool="wipe_all")
    app = _app(router)

    assert _call(app, "POST", "/wipe", _headers("wipe_create", {})) == 403
    assert _call(app, "POST", "/wipe", _headers("wipe_all", {})) == 200
    assert ran == ["wipe"]


def test_included_plain_router_routes_are_guarded() -> None:
    ran: List[str] = []
    router = SecureAPIRouter(tool_prefix="api")
    sub = APIRouter()

    @sub.post("/reset")
    async def reset() -> Dict[str, bool]:
        ran.append("reset")
        return {}

    @sub.get("/items/{item_id}")
    async def item(item_id: str) -> Dict[str, str]:
        ran.append(f"item:{item_id}")
        return {}

    router.include_router(sub, prefix="/sub")
    app = _app(router)

    assert _call(app, "POST", "/sub/reset") == 401
    assert _call(app, "POST", "/sub/reset", _headers("api_sub_items_item_id_read", {})) == 403
    assert _call(app, "GET", "/sub/items/7", _headers("api_sub_items_item_id_read", {"item_id": "8"}, item_id=Exact("8"))) == 403
    assert ran == []
    assert _call(app, "POST", "/sub/reset", _headers("api_sub_reset_create", {})) == 200
    assert _call(app, "GET", "/sub/items/7", _headers("api_sub_items_item_id_read", {"item_id": "7"}, item_id=Exact("7"))) == 200
    assert ran == ["reset", "item:7"]


def test_route_added_to_included_router_later_is_guarded() -> None:
    if not _lazy_include_supported():
        pytest.skip("FastAPI copies routes at include time; later routes are not served")
    ran: List[str] = []
    router = SecureAPIRouter(tool_prefix="api")
    sub = APIRouter()
    router.include_router(sub)

    @sub.post("/late")
    async def late() -> Dict[str, bool]:
        ran.append("late")
        return {}

    app = _app(router)
    assert _call(app, "POST", "/late") == 401
    assert ran == []
    assert _call(app, "POST", "/late", _headers("api_late_create", {})) == 200
    assert ran == ["late"]


@pytest.mark.parametrize("kind", ["plain", "mount"])
def test_late_non_api_route_cannot_bypass_included_guard(kind: str) -> None:
    if not _lazy_include_supported():
        pytest.skip("Older FastAPI copies included routes")
    ran: List[str] = []
    router = SecureAPIRouter()
    sub = APIRouter()

    @sub.get("/safe")
    async def safe() -> Dict[str, bool]:
        return {}

    router.include_router(sub)
    app = _app(router)
    assert _call(app, "GET", "/safe", _headers("safe_read", {})) == 200

    async def plain(request: Any) -> Any:
        ran.append("unprotected")
        return PlainTextResponse("open")

    if kind == "plain":
        sub.add_route("/late", plain, methods=["GET"])
    else:
        mounted = FastAPI()
        mounted.add_route("/", plain, methods=["GET"])
        sub.mount("/late", mounted)
        # Some FastAPI versions do not invalidate lazy caches for mount()
        # alone; another normal registration makes that mount dispatchable.
        sub.add_api_route("/refresh", safe, methods=["GET"])

    path = "/late" if kind == "plain" else "/late/"
    assert _call(app, "GET", path) == 403
    assert ran == []


def test_unchanged_lazy_graph_is_not_revalidated_on_every_request() -> None:
    if not _lazy_include_supported():
        pytest.skip("Tests lazy inclusion graph invalidation")
    from unittest.mock import patch

    router = SecureAPIRouter()
    if not callable(getattr(router, "_get_routes_version", None)):
        pytest.skip("Framework has no graph invalidation hook; conservative fallback rescans")
    sub = APIRouter()

    async def action() -> Dict[str, bool]:
        return {}

    sub.add_api_route("/x", action, methods=["GET"])
    router.include_router(sub)
    app = _app(router)
    guard = router._included_guards[0]
    with patch.object(guard, "refresh", wraps=guard.refresh) as refresh:
        assert _call(app, "GET", "/x", _headers("x_read", {})) == 200
        assert _call(app, "GET", "/x", _headers("x_read", {})) == 200
        assert refresh.call_count == 1
        sub.add_api_route("/y", action, methods=["GET"])
        assert _call(app, "GET", "/y", _headers("y_read", {})) == 200
        assert refresh.call_count == 2


@pytest.mark.parametrize("kind", ["fastapi", "starlette"])
def test_late_websocket_route_is_closed_before_its_body(kind: str) -> None:
    if not _lazy_include_supported():
        pytest.skip("Older FastAPI copies included routes")
    from starlette.websockets import WebSocketDisconnect

    ran: List[str] = []
    router = SecureAPIRouter()
    sub = APIRouter()
    router.include_router(sub)
    app = _app(router)

    async def websocket(ws: Any) -> None:
        ran.append("websocket")
        await ws.accept()

    if kind == "fastapi":
        sub.add_api_websocket_route("/ws", websocket)
    else:
        sub.add_websocket_route("/ws", websocket)
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/ws"):
                pytest.fail("Unsafe websocket route was accepted")
    assert exc.value.code == 1008
    assert ran == []


def test_aliased_route_requires_explicit_guard_instead_of_sharing_inferred_authority() -> None:
    if not _lazy_include_supported():
        pytest.skip("Older FastAPI copies routes into distinct objects")
    sub = APIRouter()

    @sub.get("/x")
    async def x() -> Dict[str, bool]:
        return {}

    aliases = APIRouter()
    aliases.include_router(sub, prefix="/a")
    aliases.include_router(sub, prefix="/b")
    router = SecureAPIRouter()
    with pytest.raises(ConfigurationError, match="explicit TenuoGuard"):
        router.include_router(aliases)


def test_late_alias_cannot_reuse_cached_inferred_permission() -> None:
    if not _lazy_include_supported():
        pytest.skip("Older FastAPI copies included routes")
    ran: List[str] = []
    sub = APIRouter()

    @sub.get("/x")
    async def x() -> Dict[str, bool]:
        ran.append("x")
        return {}

    aliases = APIRouter()
    aliases.include_router(sub, prefix="/a")
    router = SecureAPIRouter()
    router.include_router(aliases)
    app = _app(router)
    assert _call(app, "GET", "/a/x", _headers("a_x_read", {})) == 200
    aliases.include_router(sub, prefix="/b")
    assert _call(app, "GET", "/b/x", _headers("a_x_read", {})) == 403
    assert ran == ["x"]


def test_nested_secure_router_with_lazy_plain_child_preserves_its_guard() -> None:
    if not _lazy_include_supported():
        pytest.skip("Tests lazy inclusion dependency contexts")
    ran: List[str] = []
    inner = SecureAPIRouter(tool_prefix="inner")
    sub = APIRouter()

    @sub.get("/x")
    async def x() -> Dict[str, bool]:
        ran.append("x")
        return {}

    inner.include_router(sub)
    outer = SecureAPIRouter(tool_prefix="outer")
    outer.include_router(inner, prefix="/p")
    app = _app(outer)
    assert _call(app, "GET", "/p/x") == 401
    assert _call(app, "GET", "/p/x", _headers("outer_p_x_read", {})) == 403
    assert ran == []
    assert _call(app, "GET", "/p/x", _headers("inner_x_read", {})) == 200
    assert ran == ["x"]


def test_inclusion_dependencies_preserve_explicit_authority_per_alias() -> None:
    ran: List[str] = []
    sub = APIRouter()

    @sub.get("/x")
    async def x() -> Dict[str, bool]:
        ran.append("x")
        return {}

    aliases = APIRouter()
    aliases.include_router(sub, prefix="/a", dependencies=[Depends(TenuoGuard("a"))])
    aliases.include_router(sub, prefix="/b", dependencies=[Depends(TenuoGuard("b"))])
    router = SecureAPIRouter()
    router.include_router(aliases)
    app = _app(router)
    assert _call(app, "GET", "/a/x", _headers("b", {})) == 403
    assert ran == []
    assert _call(app, "GET", "/a/x", _headers("a", {})) == 200
    assert _call(app, "GET", "/b/x", _headers("b", {})) == 200
    assert ran == ["x", "x"]


@pytest.mark.parametrize("guard_location", ["router", "include"])
def test_secure_router_inclusion_preserves_its_explicit_guard(guard_location: str) -> None:
    ran: List[str] = []
    dependencies = [Depends(TenuoGuard("action"))]
    router = SecureAPIRouter(dependencies=dependencies if guard_location == "router" else None)
    sub = APIRouter()

    @sub.api_route("/x", methods=["GET", "POST"])
    async def x() -> Dict[str, bool]:
        ran.append("x")
        return {}

    router.include_router(sub, dependencies=dependencies if guard_location == "include" else None)
    app = _app(router)
    assert _call(app, "POST", "/x") == 401
    assert _call(app, "POST", "/x", _headers("x_create", {})) == 403
    assert ran == []
    assert _call(app, "POST", "/x", _headers("action", {})) == 200
    assert ran == ["x"]


def test_nested_plain_routers_are_guarded() -> None:
    ran: List[str] = []
    router = SecureAPIRouter()
    outer = APIRouter()
    inner = APIRouter()

    @inner.delete("/thing")
    async def thing() -> Dict[str, bool]:
        ran.append("thing")
        return {}

    outer.include_router(inner, prefix="/in")
    router.include_router(outer, prefix="/out")
    app = _app(router)

    assert _call(app, "DELETE", "/out/in/thing") == 401
    assert ran == []
    assert _call(app, "DELETE", "/out/in/thing", _headers("out_in_thing_delete", {})) == 200
    assert ran == ["thing"]


@pytest.mark.parametrize("extractor_kind", ["sync", "async"])
def test_included_route_keeps_its_own_guard(extractor_kind: str) -> None:
    ran: List[str] = []
    router = SecureAPIRouter()
    sub = APIRouter()

    async def extract(request: Any) -> Dict[str, Any]:
        return {}

    guard = TenuoGuard("search", extract_args=extract if extractor_kind == "async" else None)

    @sub.get("/search")
    async def search(ctx: SecurityContext = Depends(guard)) -> Dict[str, bool]:
        ran.append("search")
        return {}

    router.include_router(sub)
    app = _app(router)

    assert _call(app, "GET", "/search") == 401
    assert _call(app, "GET", "/search", _headers("search_read", {})) == 403
    assert _call(app, "GET", "/search", _headers("search", {})) == 200
    assert ran == ["search"]


def test_included_secure_router_keeps_its_tool_names() -> None:
    ran: List[str] = []
    router = SecureAPIRouter(tool_prefix="outer")
    sub = SecureAPIRouter(tool_prefix="inner")

    @sub.get("/x")
    async def x() -> Dict[str, bool]:
        ran.append("x")
        return {}

    router.include_router(sub, prefix="/p")
    app = _app(router)

    assert _call(app, "GET", "/p/x") == 401
    assert _call(app, "GET", "/p/x", _headers("inner_x_read", {})) == 200
    assert ran == ["x"]


def test_routes_that_cannot_carry_a_guard_are_refused() -> None:
    router = SecureAPIRouter()

    async def ws(websocket: Any) -> None:  # pragma: no cover - never registered
        pass

    async def plain(request: Any) -> Any:  # pragma: no cover - never registered
        return PlainTextResponse("x")

    with pytest.raises(ConfigurationError):
        router.add_api_websocket_route("/ws", ws)
    with pytest.raises(ConfigurationError):
        router.add_route("/plain", plain)
    with pytest.raises(ConfigurationError):
        router.mount("/static", FastAPI())
    with pytest.raises(ConfigurationError):

        @router.websocket("/ws2")
        async def ws2(websocket: Any) -> None:  # pragma: no cover
            pass

    sub = APIRouter()
    sub.add_api_websocket_route("/ws", ws)
    with pytest.raises(ConfigurationError):
        router.include_router(sub)
    assert router.routes == []


def test_inferred_tool_name_collision_is_refused() -> None:
    router = SecureAPIRouter(tool_prefix="api")

    @router.get("/admin_users")
    async def a() -> None:  # pragma: no cover
        pass

    with pytest.raises(ConfigurationError, match="api_admin_users_read"):

        @router.get("/admin/users")
        async def b() -> None:  # pragma: no cover
            pass

    async def c() -> None:  # pragma: no cover
        pass

    with pytest.raises(ConfigurationError):
        router.add_api_route("/admin/users", c, methods=["GET"])

    sub = APIRouter()
    sub.add_api_route("/users", c, methods=["GET"])
    with pytest.raises(ConfigurationError):
        router.include_router(sub, prefix="/admin")

    # An explicit tool name resolves it.
    router.add_api_route("/admin/users", c, methods=["GET"], tool="admin_users_list")


def test_put_and_patch_on_one_path_share_a_name() -> None:
    router = SecureAPIRouter()

    @router.put("/users/{uid}")
    async def put(uid: str) -> None:  # pragma: no cover
        pass

    @router.patch("/users/{uid}")
    async def patch(uid: str) -> None:  # pragma: no cover
        pass


def test_multi_method_route_needs_one_name() -> None:
    router = SecureAPIRouter()

    async def h() -> None:  # pragma: no cover
        pass

    with pytest.raises(ConfigurationError, match="tool="):
        router.add_api_route("/h", h, methods=["GET", "POST"])
    router.add_api_route("/h", h, methods=["GET", "HEAD"])
    router.add_api_route("/h2", h, methods=["GET", "POST"], tool="h2")


@pytest.mark.parametrize("methods", [["GET", "OPTIONS"], ["POST", "HEAD"]])
def test_non_get_head_method_groups_require_explicit_authority(methods: List[str]) -> None:
    router = SecureAPIRouter()

    async def action() -> Dict[str, bool]:
        return {}

    with pytest.raises(ConfigurationError, match="tool="):
        router.add_api_route("/action", action, methods=methods)
    router.add_api_route("/action", action, methods=methods, tool="explicit_action")


def test_direct_registration_name_metadata_does_not_change_inferred_authority() -> None:
    router = SecureAPIRouter()
    ran: List[str] = []

    async def action() -> Dict[str, bool]:
        ran.append("action")
        return {}

    router.add_api_route("/action", action, name="operation", methods=["GET"])
    app = _app(router)
    assert _call(app, "GET", "/action", _headers("operation", {})) == 403
    assert ran == []
    assert _call(app, "GET", "/action", _headers("action_read", {})) == 200
    assert ran == ["action"]


def test_strict_app_accepts_secure_router_with_included_routes() -> None:
    ran: List[str] = []
    router = SecureAPIRouter()
    sub = APIRouter()

    @sub.post("/reset")
    async def reset() -> Dict[str, bool]:
        ran.append("reset")
        return {}

    router.include_router(sub)
    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[ISSUER.public_key], strict=True)
    app.include_router(router)

    with TestClient(app) as client:
        assert client.post("/reset").status_code == 401
    assert ran == []


def test_documented_path_param_pattern_with_subpath() -> None:
    """docs/fastapi.md: {path:path} has no leading slash; the extractor restores it."""
    from tenuo import Subpath

    ran: List[str] = []
    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[ISSUER.public_key])

    def file_args(request: Any) -> Dict[str, str]:
        return {"path": "/" + request.path_params["path"]}

    @app.get("/files/{path:path}")
    async def read_file(path: str, ctx: SecurityContext = Depends(TenuoGuard("read_file", extract_args=file_args))) -> Dict[str, str]:
        ran.append(ctx.args["path"])
        return {}

    def h(path: str) -> Dict[str, str]:
        return _headers("read_file", {"path": path}, path=Subpath("/data"))

    assert _call(app, "GET", "/files/data/a.txt", h("/data/a.txt")) == 200
    assert _call(app, "GET", "/files/etc/passwd", h("/etc/passwd")) == 403
    traversal = "/data/../../etc/passwd"
    assert _call(app, "GET", "/files/data/%2e%2e/%2e%2e/etc/passwd", h(traversal)) == 403
    assert ran == ["/data/a.txt"]
