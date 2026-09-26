"""SecureAPIRouter must survive ``include_router`` on every supported FastAPI.

FastAPI 0.120+ includes routers lazily, by reference, and reads router
internals when the app builds its route table. The original SecureAPIRouter
was a delegating wrapper around an inner ``APIRouter``, which that path could
not see through: ``app.include_router(router)`` registered nothing and every
protected route returned 404. These tests pin the documented usage.
"""

from typing import Any

import pytest

from tenuo import Exact, SigningKey, Warrant

FASTAPI_AVAILABLE = False
APIRouter: Any = None
FastAPI: Any = None
TestClient: Any = None
SecureAPIRouter: Any = None
configure_tenuo: Any = None

try:
    from fastapi import APIRouter, FastAPI  # type: ignore[no-redef]
    from fastapi.testclient import TestClient  # type: ignore[no-redef]

    from tenuo.fastapi import (  # type: ignore[no-redef]
        FASTAPI_AVAILABLE,
        SecureAPIRouter,
        configure_tenuo,
    )
except ImportError:
    pass


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestSecureAPIRouterInclusion:
    @pytest.fixture
    def issuer(self):
        return SigningKey.generate()

    @pytest.fixture
    def agent(self):
        return SigningKey.generate()

    @pytest.fixture
    def router(self):
        router = SecureAPIRouter(tool_prefix="api")

        @router.get("/users/{user_id}")
        async def get_user(user_id: str):
            return {"user_id": user_id}

        @router.post("/users", tool="create_user")
        async def create_user():
            return {"created": True}

        return router

    def _app(self, issuer):
        app = FastAPI()
        configure_tenuo(app, trusted_issuers=[issuer.public_key])
        return app

    def _headers(self, issuer, agent, user_id="42"):
        warrant = (
            Warrant.mint_builder()
            .capability("api_users_user_id_read", user_id=Exact(user_id))
            .holder(agent.public_key)
            .ttl(300)
            .mint(issuer)
        )
        return warrant.headers(agent, "api_users_user_id_read", {"user_id": user_id})

    def test_is_an_apirouter(self, router):
        assert isinstance(router, APIRouter)

    def test_included_routes_are_registered(self, issuer, router):
        app = self._app(issuer)
        app.include_router(router)
        client = TestClient(app)

        # 401 (not 404) proves the route exists and the guard runs.
        assert client.get("/users/42").status_code == 401
        assert client.post("/users").status_code == 401

    def test_valid_warrant_is_allowed(self, issuer, agent, router):
        app = self._app(issuer)
        app.include_router(router)
        client = TestClient(app)

        assert client.get("/users/42", headers=self._headers(issuer, agent)).status_code == 200

    def test_warrant_is_scoped_to_its_arguments(self, issuer, agent, router):
        app = self._app(issuer)
        app.include_router(router)
        client = TestClient(app)

        # Headers signed for user 42 must not open user 43.
        assert client.get("/users/43", headers=self._headers(issuer, agent)).status_code == 403

    def test_nested_include_keeps_protection(self, issuer, agent, router):
        app = self._app(issuer)
        outer = APIRouter(prefix="/v1")
        outer.include_router(router)
        app.include_router(outer)
        client = TestClient(app)

        assert client.get("/v1/users/42").status_code == 401
        assert client.get("/v1/users/42", headers=self._headers(issuer, agent)).status_code == 200

    def test_legacy_inner_router_access(self, issuer, agent, router):
        # Callers who worked around the bug with ``router._router`` keep working.
        app = self._app(issuer)
        app.include_router(router._router)
        client = TestClient(app)

        assert client.get("/users/42", headers=self._headers(issuer, agent)).status_code == 200
