"""
Tests for FastAPI delegation support (WarrantStack in X-Tenuo-Warrant header).

Covers:
- WarrantStack header decoded and chain verified
- Single root warrant backward compatibility
- Orphaned child warrant rejected
- Attenuated tool denied
"""

import base64
import time
from typing import Any

import pytest

from tenuo import SigningKey, Warrant, encode_warrant_stack

FASTAPI_AVAILABLE = False
FastAPI: Any = None
Depends: Any = None
TestClient: Any = None
configure_tenuo: Any = None
TenuoGuard: Any = None
SecurityContext: Any = None
X_TENUO_WARRANT = ""
X_TENUO_POP = ""

try:
    from fastapi import Depends, FastAPI  # type: ignore[no-redef]
    from fastapi.testclient import TestClient  # type: ignore[no-redef]

    from tenuo.fastapi import (  # type: ignore[no-redef]
        FASTAPI_AVAILABLE,
        X_TENUO_POP,
        X_TENUO_WARRANT,
        SecurityContext,
        TenuoGuard,
        configure_tenuo,
    )
except ImportError:
    pass

pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")


@pytest.fixture
def issuer_key():
    return SigningKey.generate()


@pytest.fixture
def orch_key():
    return SigningKey.generate()


@pytest.fixture
def worker_key():
    return SigningKey.generate()


@pytest.fixture
def root_warrant(issuer_key, orch_key):
    return (
        Warrant.mint_builder()
        .capability("search")
        .capability("read_file")
        .capability("delete_file")
        .holder(orch_key.public_key)
        .ttl(3600)
        .mint(issuer_key)
    )


@pytest.fixture
def child_warrant(root_warrant, orch_key, worker_key):
    return (
        root_warrant.grant_builder()
        .capability("search")
        .holder(worker_key.public_key)
        .ttl(1800)
        .grant(orch_key)
    )


def _make_headers(warrant_b64, warrant, signing_key, tool, args):
    pop = warrant.sign(signing_key, tool, args, int(time.time()))
    return {
        X_TENUO_WARRANT: warrant_b64,
        X_TENUO_POP: base64.b64encode(bytes(pop)).decode(),
    }


@pytest.fixture
def app(issuer_key):
    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[issuer_key.public_key])
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


class TestFastAPIDelegation:
    def test_warrant_stack_chain_allowed(self, app, client, root_warrant, child_warrant, worker_key):
        @app.get("/search")
        def do_search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            return {"status": "ok"}

        stack_b64 = encode_warrant_stack([root_warrant, child_warrant])
        headers = _make_headers(stack_b64, child_warrant, worker_key, "search", {})
        resp = client.get("/search", headers=headers)
        assert resp.status_code == 200

    def test_warrant_stack_dropped_tool_denied(self, app, client, root_warrant, child_warrant, worker_key):
        @app.get("/delete")
        def do_delete(ctx: SecurityContext = Depends(TenuoGuard("delete_file"))):
            return {"status": "ok"}

        stack_b64 = encode_warrant_stack([root_warrant, child_warrant])
        headers = _make_headers(stack_b64, child_warrant, worker_key, "delete_file", {})
        resp = client.get("/delete", headers=headers)
        assert resp.status_code in (401, 403)

    def test_single_root_warrant_allowed(self, app, client, issuer_key, orch_key):
        @app.get("/search2")
        def do_search2(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            return {"status": "ok"}

        root = (
            Warrant.mint_builder()
            .capability("search")
            .holder(orch_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )
        headers = _make_headers(root.to_base64(), root, orch_key, "search", {})
        resp = client.get("/search2", headers=headers)
        assert resp.status_code == 200

    def test_orphaned_child_rejected(self, app, client, child_warrant, worker_key):
        @app.get("/search3")
        def do_search3(ctx: SecurityContext = Depends(TenuoGuard("search"))):
            return {"status": "ok"}

        headers = _make_headers(child_warrant.to_base64(), child_warrant, worker_key, "search", {})
        resp = client.get("/search3", headers=headers)
        assert resp.status_code in (401, 403)
