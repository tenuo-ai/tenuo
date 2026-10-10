"""Outbound headers carry the full root-to-leaf chain for delegated warrants.

A verifier that trusts only the root can check a delegated warrant only when
its parents travel with it. ``Warrant.headers`` and ``BoundWarrant.headers``
send them as a WarrantStack, from ``warrant_chain=`` or, for a delegated
warrant, from the ambient ``chain_scope()``.
"""

import base64
import json
from typing import Any

import pytest

from tenuo import SigningKey, Warrant, chain_scope

FASTAPI_AVAILABLE = False
TestClient: Any = None
try:
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient  # type: ignore[no-redef]

    from tenuo.fastapi import (
        FASTAPI_AVAILABLE,
        X_TENUO_APPROVALS,
        SecurityContext,
        TenuoGuard,
        configure_tenuo,
    )
except ImportError:
    pass


@pytest.fixture
def keys():
    return SigningKey.generate(), SigningKey.generate(), SigningKey.generate()


@pytest.fixture
def chain(keys):
    """root (issued by root_key, held by worker) -> child (held by leaf_key)."""
    root_key, worker_key, leaf_key = keys
    root = Warrant.mint_builder().tool("search").holder(worker_key.public_key).ttl(300).mint(root_key)
    child = root.grant(to=leaf_key.public_key, allow="search", ttl=60, key=worker_key)
    return root, child


@pytest.fixture
def client(keys):
    root_key, _, _ = keys
    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[root_key.public_key])

    @app.get("/search")
    def search(ctx: SecurityContext = Depends(TenuoGuard("search"))):
        return {"query": ctx.args.get("query")}

    return TestClient(app)


ARGS = {"query": "test"}


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestWarrantHeadersChain:
    def test_leaf_alone_is_denied_by_root_only_server(self, keys, chain, client):
        _, _, leaf_key = keys
        _, child = chain
        resp = client.get("/search?query=test", headers=child.headers(leaf_key, "search", ARGS))
        assert resp.status_code == 403

    def test_explicit_warrant_chain_is_accepted(self, keys, chain, client):
        _, _, leaf_key = keys
        root, child = chain
        headers = child.headers(leaf_key, "search", ARGS, warrant_chain=[root])
        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 200, resp.json()

    def test_ambient_chain_scope_is_used_for_delegated_warrant(self, keys, chain, client):
        _, _, leaf_key = keys
        root, child = chain
        with chain_scope([root]):
            headers = child.headers(leaf_key, "search", ARGS)
        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 200, resp.json()

    def test_explicit_chain_beats_ambient(self, keys, chain, client):
        _, worker_key, leaf_key = keys
        root, child = chain
        unrelated = Warrant.mint_builder().tool("search").mint(SigningKey.generate())
        with chain_scope([unrelated]):
            headers = child.headers(leaf_key, "search", ARGS, warrant_chain=[root])
        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 200, resp.json()

    def test_bound_warrant_uses_ambient_chain(self, keys, chain, client):
        root_key, _, leaf_key = keys
        root, child = chain
        with chain_scope([root]):
            headers = child.bind(leaf_key).headers("search", ARGS, trusted_roots=[root_key.public_key])
        resp = client.get("/search?query=test", headers=headers)
        assert resp.status_code == 200, resp.json()


class TestDepthZeroUnchanged:
    def test_root_warrant_ignores_ambient_chain(self, keys, chain):
        root_key, _, _ = keys
        root, _ = chain
        own = Warrant.mint_builder().tool("search").mint(root_key)
        assert own.depth == 0
        with chain_scope([root]):
            headers = own.headers(root_key, "search", ARGS)
        assert headers["X-Tenuo-Warrant"] == own.to_base64()

    def test_bound_root_warrant_ignores_ambient_chain(self, keys, chain):
        root_key, _, _ = keys
        root, _ = chain
        own = Warrant.mint_builder().tool("search").mint(root_key)
        with chain_scope([root]):
            headers = own.bind(root_key).headers("search", ARGS, trusted_roots=[root_key.public_key])
        assert headers["X-Tenuo-Warrant"] == own.to_base64()


class _FakeApproval:
    def __init__(self, raw: bytes):
        self._raw = raw

    def to_bytes(self) -> bytes:
        return self._raw


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestApprovalsHeader:
    def test_no_approvals_no_header(self, keys):
        root_key, _, _ = keys
        own = Warrant.mint_builder().tool("search").mint(root_key)
        headers = own.bind(root_key).headers("search", ARGS, trusted_roots=[root_key.public_key])
        assert X_TENUO_APPROVALS not in headers

    def test_approvals_sent_in_the_format_fastapi_decodes(self, keys):
        from tenuo.bound_warrant import _encode_approvals_header

        approvals = [_FakeApproval(b"first"), _FakeApproval(b"second")]
        encoded = _encode_approvals_header(approvals)
        # Same decoding as TenuoGuard: base64 -> JSON list -> base64 CBOR items.
        decoded = [base64.b64decode(i) for i in json.loads(base64.b64decode(encoded))]
        assert decoded == [b"first", b"second"]

    def test_bound_headers_emit_approvals(self, keys, monkeypatch):
        from tenuo import bound_warrant as bw_mod

        root_key, _, _ = keys
        own = Warrant.mint_builder().tool("search").mint(root_key)
        bound = own.bind(root_key)
        # The pre-flight is covered elsewhere; here we only check the header is emitted.
        monkeypatch.setattr(type(bound), "validate", lambda self, *a, **k: True)
        headers = bound.headers("search", ARGS, approvals=[_FakeApproval(b"x")])
        assert headers[X_TENUO_APPROVALS] == bw_mod._encode_approvals_header([_FakeApproval(b"x")])
