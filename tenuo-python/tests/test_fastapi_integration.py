import pytest
import base64
from typing import Any, Dict

from tenuo import (
    Warrant,
    SigningKey,
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
    from fastapi import FastAPI, Depends, Request  # type: ignore[no-redef]
    from fastapi.testclient import TestClient  # type: ignore[no-redef]
    from tenuo.fastapi import (  # type: ignore[no-redef]
        configure_tenuo,
        TenuoGuard,
        SecurityContext,
        X_TENUO_WARRANT,
        X_TENUO_POP,
        FASTAPI_AVAILABLE,
    )
except ImportError:
    pass  # Use fallback values defined above


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestFastAPIIntegration:
    @pytest.fixture
    def app(self):
        app = FastAPI()
        configure_tenuo(app)
        return app

    @pytest.fixture
    def client(self, app):
        return TestClient(app)

    @pytest.fixture
    def key(self):
        return SigningKey.generate()

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
        pop_sig = warrant.sign(key, "search", args)
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")

        headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64}

        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["query"] == "test"

    def test_invalid_pop_signature_returns_403(self, app, client, key):
        @app.get("/search")
        def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            pass

        warrant = Warrant.mint_builder().tool("search").mint(key)

        # Sign for WRONG args
        args = {"query": "malicious"}
        pop_sig = warrant.sign(key, "search", args)
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
        pop_sig = warrant.sign(key, "admin", args)
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
        pop_sig = warrant.sign(key, "custom", args)
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")

        headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64, "X-Query": "secret"}

        resp = client.get("/custom", headers=headers)
        assert resp.status_code == 200

    def test_expired_warrant_returns_401(self, app, client, key):
        @app.get("/search")
        def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            pass

        # Expired warrant (TTL=0 is not instantly expired in some impls, using -1 or sleep if needed)
        # But Warrant.mint(ttl=) usually sets expiry.
        # Tenuo Core enforces expiry.
        # Let's assume TTL=0 makes it expire immediately or quickly.
        # However, `sign()` might fail if expired? No, PoP is signature.

        import time

        try:
            warrant = Warrant.mint_builder().tool("search").ttl(0).mint(key)
            # Wait a bit
            time.sleep(0.01)
        except Exception:
            # Fallback if TTL=0 invalid
            warrant = Warrant.mint_builder().tool("search").ttl(1).mint(key)
            time.sleep(1.1)

        args = {"query": "test"}
        # PoP signing doesn't care about expiry usually
        pop_sig = warrant.sign(key, "search", args)
        pop_b64 = base64.b64encode(pop_sig).decode("ascii")

        headers = {X_TENUO_WARRANT: warrant.to_base64(), X_TENUO_POP: pop_b64}

        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 401
        assert resp.json()["detail"]["error"] == "warrant_expired"
