import base64
import time
from typing import Any, Dict

import pytest

from tenuo import (
    SigningKey,
    Warrant,
)

# Import FastAPI components with fallback for when not installed
FASTAPI_AVAILABLE = False
FastAPI: Any = None
Depends: Any = None
Request: Any = None
TestClient: Any = None
configure_tenuo: Any = None
TenuoGuard: Any = None
SecurityContext: Any = None
X_TENUO_WARRANT = ""
X_TENUO_POP = ""

try:
    from fastapi import Depends, FastAPI, Request  # type: ignore[no-redef]
    from fastapi.testclient import TestClient  # type: ignore[no-redef]

    from tenuo.fastapi import (  # type: ignore[no-redef]
        FASTAPI_AVAILABLE,
        X_TENUO_APPROVALS,
        X_TENUO_POP,
        X_TENUO_WARRANT,
        SecurityContext,
        TenuoGuard,
        configure_tenuo,
    )
except ImportError:
    pass  # Use fallback values defined above


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestFastAPIIntegration:
    @pytest.fixture
    def key(self):
        return SigningKey.generate()

    @pytest.fixture
    def app(self, key):
        app = FastAPI()
        configure_tenuo(app, trusted_issuers=[key.public_key])
        return app

    @pytest.fixture
    def client(self, app):
        return TestClient(app)

    def test_missing_headers_returns_401(self, app, client):
        @app.get("/search")
        def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            return {"status": "ok"}

        # No headers
        resp = client.get("/search?query=test")
        assert resp.status_code == 401
        assert "Missing X-Tenuo-Warrant" in resp.json()["detail"]["message"]

        # Missing PoP
        warrant = Warrant.mint_builder().tool("search").mint(SigningKey.generate())
        resp = client.get("/search?query=test", headers={X_TENUO_WARRANT: warrant.to_base64()})
        assert resp.status_code == 401
        assert "Missing X-Tenuo-PoP" in resp.json()["detail"]["message"]

    def test_valid_request_allows_access(self, app, client, key):
        @app.get("/search")
        def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            return {"query": ctx.args.get("query"), "issuer": ctx.issuer}

        warrant = Warrant.mint_builder().tool("search").mint(key)

        # Sign PoP
        # Args matched by default logic: query params + path params
        args = {"query": "test"}
        pop_sig = warrant.sign(key, "search", args, int(time.time()))
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")

        headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64}

        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["query"] == "test"

    def test_malformed_approvals_header_returns_400(self, app, client, key):
        """Malformed X-Tenuo-Approvals must fail closed with 400, not be ignored."""
        @app.get("/search")
        def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            return {"status": "ok"}

        warrant = Warrant.mint_builder().tool("search").mint(key)
        args = {"query": "test"}
        pop_sig = warrant.sign(key, "search", args, int(time.time()))
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")
        bad_approvals = base64.b64encode(b"not-json").decode("ascii")

        headers = {
            X_TENUO_WARRANT: warrant.to_base64(),
            X_TENUO_POP: pop_b64,
            X_TENUO_APPROVALS: bad_approvals,
        }
        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_approval"

    def test_invalid_pop_signature_returns_403(self, app, client, key):
        @app.get("/search")
        def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            pass

        warrant = Warrant.mint_builder().tool("search").mint(key)

        # Sign for WRONG args
        args = {"query": "malicious"}
        pop_sig = warrant.sign(key, "search", args, int(time.time()))
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")

        headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64}

        # Request for "test" but signed "malicious"
        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 403
        assert "denied" in resp.json()["detail"]["message"]

    def test_unauthorized_tool_returns_403(self, app, client, key):
        @app.get("/admin")
        def admin(ctx: SecurityContext = Depends(TenuoGuard("admin"))):
            pass

        # Warrant only allows "search"
        warrant = Warrant.mint_builder().tool("search").mint(key)

        args = {}
        pop_sig = warrant.sign(key, "admin", args, int(time.time()))
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")

        headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64}

        resp = client.get("/admin", headers=headers)
        assert resp.status_code == 403
        # Error should be opaque (no constraint details exposed)
        detail = resp.json()["detail"]
        assert detail["error"] == "authorization_denied"
        assert detail["message"] == "Authorization denied"
        # Should have request_id for log correlation
        assert "request_id" in detail
        # Should NOT expose authorized_tools (information leakage)
        assert "authorized_tools" not in detail

    def test_custom_arg_extraction(self, app, client, key):
        def extract_custom(request: Request) -> Dict[str, Any]:
            # Extract from custom header 'X-Query'
            return {"query": request.headers.get("X-Query")}

        @app.get("/custom")
        def custom(ctx: SecurityContext = Depends(TenuoGuard("custom", extract_args=extract_custom))):
            return {"ok": True}

        warrant = Warrant.mint_builder().tool("custom").mint(key)

        # Sign for custom arg
        args = {"query": "secret"}
        pop_sig = warrant.sign(key, "custom", args, int(time.time()))
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")

        headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64, "X-Query": "secret"}

        resp = client.get("/custom", headers=headers)
        assert resp.status_code == 200

    def _transfer_app(self, app, key, extract_args):
        """POST /transfer guarded by a warrant constraining body field `amount` <= 100."""
        from tenuo import Range

        @app.post("/transfer")
        async def transfer(ctx: SecurityContext = Depends(TenuoGuard("transfer", extract_args=extract_args))):
            return {"args": ctx.args}

        return Warrant.mint_builder().capability("transfer", amount=Range.max_value(100)).mint(key)

    def _post_transfer(self, client, key, warrant, body):
        pop_sig = warrant.sign(key, "transfer", body, int(time.time()))
        headers = {
            X_TENUO_WARRANT: warrant.to_base64(),
            X_TENUO_POP: base64.b64encode(pop_sig).decode("ascii"),
        }
        return client.post("/transfer", json=body, headers=headers)

    def test_async_extractor_enforces_body_constraint(self, app, client, key):
        """An async extract_args reading the JSON body is awaited and its fields enforced."""

        async def extract_body(request: Request) -> Dict[str, Any]:
            return await request.json()

        warrant = self._transfer_app(app, key, extract_body)

        resp = self._post_transfer(client, key, warrant, {"amount": 50})
        assert resp.status_code == 200
        assert resp.json()["args"] == {"amount": 50}

        resp = self._post_transfer(client, key, warrant, {"amount": 5000})
        assert resp.status_code == 403
        assert resp.json()["detail"]["error"] == "authorization_denied"

    def test_extract_body_args_helper_works_as_extractor(self, app, client, key):
        """The documented extract_body_args helper can be passed directly."""
        from tenuo.fastapi import extract_body_args

        warrant = self._transfer_app(app, key, extract_body_args)

        assert self._post_transfer(client, key, warrant, {"amount": 100}).status_code == 200
        assert self._post_transfer(client, key, warrant, {"amount": 101}).status_code == 403

    def test_async_extractor_still_checks_headers_first(self, app, client, key):
        """Missing credentials are rejected with 401 before the body extractor runs."""
        called = []

        async def extract_body(request: Request) -> Dict[str, Any]:
            called.append(True)
            return await request.json()

        self._transfer_app(app, key, extract_body)
        resp = client.post("/transfer", json={"amount": 1})
        assert resp.status_code == 401
        assert called == []

    def test_sync_extractor_returning_awaitable_fails_closed(self, app, client, key):
        """A sync callable that returns a coroutine must not be authorized against."""

        async def _read(request: Request) -> Dict[str, Any]:
            return await request.json()

        warrant = self._transfer_app(app, key, lambda request: _read(request))
        resp = self._post_transfer(client, key, warrant, {"amount": 50})
        assert resp.status_code == 500
        assert resp.json()["detail"]["error"] == "configuration_error"

    def test_sync_extractor_guard_stays_directly_callable(self):
        """Guards with sync extractors keep a sync __call__ (no coroutine returned)."""
        import inspect as _inspect

        sync_guard = TenuoGuard("search", extract_args=lambda r: {})
        assert isinstance(sync_guard, TenuoGuard)
        assert not _inspect.iscoroutinefunction(type(sync_guard).__call__)
        assert not _inspect.iscoroutinefunction(type(TenuoGuard("search")).__call__)

        async def extract(request: Request) -> Dict[str, Any]:
            return {}

        async_guard = TenuoGuard("search", extract_args=extract)
        assert isinstance(async_guard, TenuoGuard)
        assert _inspect.iscoroutinefunction(type(async_guard).__call__)

    # -- Default extraction: values typed from the endpoint signature ----------

    def _headers(self, key, warrant, tool, args):
        pop_sig = warrant.sign(key, tool, args, int(time.time()))
        return {
            X_TENUO_WARRANT: warrant.to_base64(),
            X_TENUO_POP: base64.b64encode(pop_sig).decode("ascii"),
        }

    def _limit_app(self, app, key):
        from tenuo import Range

        @app.get("/items")
        def items(limit: int, ctx: SecurityContext = Depends(TenuoGuard("list_items"))):
            return {"limit": limit, "args": ctx.args}

        return Warrant.mint_builder().capability("list_items", limit=Range.max_value(100)).mint(key)

    def test_declared_int_query_param_is_typed(self, app, client, key):
        """`limit: int` + Range(max=100): ?limit=5 is checked as int 5, not "5"."""
        warrant = self._limit_app(app, key)

        resp = client.get("/items?limit=5", headers=self._headers(key, warrant, "list_items", {"limit": 5}))
        assert resp.status_code == 200, resp.json()
        assert resp.json() == {"limit": 5, "args": {"limit": 5}}

        resp = client.get("/items?limit=500", headers=self._headers(key, warrant, "list_items", {"limit": 500}))
        assert resp.status_code == 403

    def test_declared_int_query_param_rejects_string_signature(self, app, client, key):
        """The client must sign the typed value: a PoP over "5" no longer matches."""
        warrant = self._limit_app(app, key)
        resp = client.get("/items?limit=5", headers=self._headers(key, warrant, "list_items", {"limit": "5"}))
        assert resp.status_code == 403

    def test_uncoercible_value_is_never_authorized(self, app, client, key):
        """?limit=abc for `limit: int` is not guessed into a number."""
        warrant = self._limit_app(app, key)
        for signed in ({"limit": "abc"}, {"limit": 0}):
            resp = client.get("/items?limit=abc", headers=self._headers(key, warrant, "list_items", signed))
            assert resp.status_code in (403, 422), resp.json()

    def test_declared_int_path_param_is_typed(self, app, client, key):
        from tenuo import Range

        @app.get("/items/{item_id}")
        def item(item_id: int, ctx: SecurityContext = Depends(TenuoGuard("get_item"))):
            return {"args": ctx.args}

        warrant = Warrant.mint_builder().capability("get_item", item_id=Range.max_value(10)).mint(key)

        resp = client.get("/items/7", headers=self._headers(key, warrant, "get_item", {"item_id": 7}))
        assert resp.status_code == 200, resp.json()
        assert resp.json()["args"] == {"item_id": 7}

        resp = client.get("/items/11", headers=self._headers(key, warrant, "get_item", {"item_id": 11}))
        assert resp.status_code == 403

    def test_typed_float_bool_and_list_params(self, app, client, key):
        from typing import List

        from fastapi import Query

        @app.get("/search")
        def search(
            price: float,
            enabled: bool,
            tag: List[str] = Query([]),
            ctx: SecurityContext = Depends(TenuoGuard("search")),
        ):
            return {"args": ctx.args}

        warrant = Warrant.mint_builder().tool("search").mint(key)
        args = {"price": 2.5, "enabled": True, "tag": ["a", "b"], "extra": "x"}
        resp = client.get(
            "/search?price=2.5&enabled=true&tag=a&tag=b&extra=x",
            headers=self._headers(key, warrant, "search", args),
        )
        assert resp.status_code == 200, resp.json()
        assert resp.json()["args"] == args

    def test_undeclared_query_param_stays_string(self, app, client, key):
        @app.get("/search")
        def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            return {"args": ctx.args}

        warrant = Warrant.mint_builder().tool("search").mint(key)
        resp = client.get("/search?page=3", headers=self._headers(key, warrant, "search", {"page": "3"}))
        assert resp.status_code == 200, resp.json()
        assert resp.json()["args"] == {"page": "3"}

    def test_secure_router_numeric_constraint(self, app, client, key):
        from tenuo import Range
        from tenuo.fastapi import SecureAPIRouter

        router = SecureAPIRouter()

        @router.get("/orders", tool="list_orders")
        def orders(limit: int):
            return {"limit": limit}

        app.include_router(router)
        warrant = Warrant.mint_builder().capability("list_orders", limit=Range.max_value(100)).mint(key)

        resp = client.get("/orders?limit=5", headers=self._headers(key, warrant, "list_orders", {"limit": 5}))
        assert resp.status_code == 200, resp.json()
        resp = client.get("/orders?limit=500", headers=self._headers(key, warrant, "list_orders", {"limit": 500}))
        assert resp.status_code == 403

    def test_custom_extractors_are_not_coerced(self, app, client, key):
        """Custom sync and async extract_args return exactly what they produce."""

        def sync_extract(request: Request) -> Dict[str, Any]:
            return dict(request.query_params)

        async def async_extract(request: Request) -> Dict[str, Any]:
            return dict(request.query_params)

        @app.get("/sync")
        def sync_route(limit: int, ctx: SecurityContext = Depends(TenuoGuard("q", extract_args=sync_extract))):
            return {"args": ctx.args}

        @app.get("/async")
        async def async_route(limit: int, ctx: SecurityContext = Depends(TenuoGuard("q", extract_args=async_extract))):
            return {"args": ctx.args}

        warrant = Warrant.mint_builder().tool("q").mint(key)
        for path in ("/sync", "/async"):
            resp = client.get(f"{path}?limit=5", headers=self._headers(key, warrant, "q", {"limit": "5"}))
            assert resp.status_code == 200, resp.json()
            assert resp.json()["args"] == {"limit": "5"}

    def test_expired_warrant_returns_401(self, app, client, key):
        @app.get("/search")
        def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            pass

        # Create warrant that expires in 1 second
        warrant = Warrant.mint_builder().tool("search").ttl(1).mint(key)

        # Wait for it to expire (add buffer for CI timing)
        import time

        time.sleep(2.0)  # Increased from 1.1 to 2.0 for CI reliability

        # Verify it's actually expired
        assert warrant.is_expired(), "Warrant should be expired after 2 second sleep"

        args = {"query": "test"}
        # PoP signing works even on expired warrants (signing doesn't check expiry)
        pop_sig = warrant.sign(key, "search", args, int(time.time()))
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")

        headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64}

        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 401, f"Expected 401 for expired warrant, got {resp.status_code}: {resp.json()}"
        assert resp.json()["detail"]["error"] == "warrant_expired"

    def test_self_signed_warrant_rejected_without_trusted_issuers(self):
        """Attacker mints self-signed warrant; server has no trusted_issuers configured."""
        from tenuo import reset_config

        reset_config()  # isolate from global trusted_roots set by earlier tests
        app = FastAPI()
        configure_tenuo(app)  # no trusted_issuers

        @app.get("/admin")
        def admin(ctx: SecurityContext = Depends(TenuoGuard("admin"))):
            return {"status": "ok"}

        client = TestClient(app)

        attacker_key = SigningKey.generate()
        forged = Warrant.mint_builder().tool("admin").holder(attacker_key.public_key).ttl(3600).mint(attacker_key)

        args = {}
        pop_sig = forged.sign(attacker_key, "admin", args, int(time.time()))
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")

        headers = {X_TENUO_WARRANT: forged.to_base64(), X_TENUO_POP: pop_b64}
        resp = client.get("/admin", headers=headers)
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.json()}"
        detail = resp.json()["detail"]
        assert detail.get("error") == "configuration_error"
        assert "trusted_issuers" in detail["message"].lower()

    def test_global_config_trusted_roots_bridged(self, key):
        """tenuo.configure(trusted_roots=[...]) is respected by TenuoGuard."""
        from tenuo import configure as tenuo_configure, reset_config

        try:
            tenuo_configure(trusted_roots=[key.public_key])
            app = FastAPI()
            configure_tenuo(app)  # no trusted_issuers — should fall back to global

            @app.get("/search")
            def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
                return {"status": "ok"}

            client = TestClient(app)

            warrant = Warrant.mint_builder().tool("search").holder(key.public_key).ttl(3600).mint(key)
            args = {"query": "test"}
            pop_sig = warrant.sign(key, "search", args, int(time.time()))
            pop_b64 = base64.b64encode(pop_sig).decode("ascii")

            headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64}
            resp = client.get("/search?query=test", headers=headers)
            assert resp.status_code == 200
        finally:
            reset_config()
