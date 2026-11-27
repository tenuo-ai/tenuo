"""OAuth trust boundaries, task compilation, persistent replay and HTTP issuance."""

# ruff: noqa: E402
import asyncio
import base64
import json
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

jwt = pytest.importorskip("jwt")
httpx = pytest.importorskip("httpx")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from tenuo import Authorizer, SigningKey
from tenuo._issuance_http import _request_body
from tenuo.oauth import (
    ExactFrom,
    MaximumFrom,
    OAuthAccessTokens,
    OAuthError,
    OAuthUnavailable,
    OAuthWarrantIssuer,
    OAuthWarrantIssuerApp,
    SQLiteReplayStore,
    TaskTemplate,
    sign_oauth_holder_proof,
)


@pytest.fixture
def provider():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="one", alg="RS256", use="sig")
    state = {"keys": [jwk], "status": 200, "calls": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["calls"] += 1
            self.send_response(state["status"])
            self.end_headers()
            self.wfile.write(json.dumps({"keys": state["keys"]}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    issuer = f"http://127.0.0.1:{server.server_port}"

    def token(headers=None, **changes):
        claims = dict(
            iss=issuer,
            sub="alice",
            aud="authority",
            azp="support",
            typ="Bearer",
            jti="fixture-token-id",
            tenant_id="acme",
            scope="refunds:write",
            iat=int(time.time()),
            exp=int(time.time()) + 300,
        )
        claims.update(changes)
        return jwt.encode(claims, key, algorithm="RS256", headers=headers or {"kid": "one", "typ": "JWT"})

    state.update(token=token, issuer=issuer, key=key)
    yield state
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture
def validator(provider):
    instance = OAuthAccessTokens(
        issuer=provider["issuer"],
        audience="authority",
        jwks_url=provider["issuer"] + "/keys",
        allowed_clients=frozenset({"support"}),
        profile="keycloak",
        allow_loopback_http=True,
        refresh_interval=0.01,
    )
    yield instance
    instance.close()


@pytest.fixture
def setup(provider, validator, tmp_path):
    template = TaskTemplate(
        tool="refund",
        arguments={"payment_id": ExactFrom("payment"), "amount_cents": MaximumFrom("limit")},
        required_scopes=frozenset({"refunds:write"}),
        max_depth=1,
    )
    task = dict(
        task_id="t1",
        issuer=provider["issuer"],
        subject="alice",
        tenant_id="acme",
        status="approved",
        expires_at=int(time.time()) + 180,
        payment="p1",
        limit=5000,
    )
    audits = []
    root, holder = SigningKey.generate(), SigningKey.generate()
    store = SQLiteReplayStore(str(tmp_path / "replay.db"))
    issuer = OAuthWarrantIssuer(
        credentials=validator,
        signing_key=root,
        replay_store=store,
        policy=lambda caller, task_id: template.compile(caller, task_id, task),
        audit=audits.append,
    )
    return issuer, holder, root, task, audits, template, store


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "elsewhere"},
        {"iss": "https://attacker.test"},
        {"exp": 1},
        {"azp": "other"},
        {"tenant_id": None},
        {"typ": "ID"},
        {"cnf": {}},
        {"act": {"sub": "someone"}},
        {"exp": True},
        {"iat": 1.5},
        {"scope": ["refunds:write"]},
        {"sub": ""},
    ],
)
def test_reject_invalid_credentials(provider, validator, changes):
    with pytest.raises(OAuthError):
        validator.authenticate(provider["token"](**changes))


def test_rfc9068_is_a_separate_profile(provider):
    with pytest.raises(ValueError):
        OAuthAccessTokens(
            issuer=provider["issuer"],
            audience="authority",
            jwks_url=provider["issuer"],
            allowed_clients=frozenset({"support"}),
        )
    instance = OAuthAccessTokens(
        issuer=provider["issuer"],
        audience="authority",
        jwks_url=provider["issuer"],
        allowed_clients=frozenset({"support"}),
        allow_loopback_http=True,
    )
    try:
        with pytest.raises(OAuthError):
            instance.authenticate(provider["token"]())
        caller = instance.authenticate(provider["token"](headers={"kid": "one", "typ": "at+jwt"}, client_id="support"))
        assert caller.subject == "alice"
    finally:
        instance.close()


def test_key_rotation_withdrawal_and_outage(provider, validator):
    token = provider["token"]()
    assert validator.authenticate(token).subject == "alice"
    provider["status"] = 503
    assert validator.authenticate(token).subject == "alice"  # bounded, unexpired cache
    validator._loaded -= validator.cache_seconds + 1
    time.sleep(0.02)
    with pytest.raises(OAuthError):
        validator.authenticate(token)
    provider["status"] = 200
    provider["keys"] = []
    validator.refresh()
    with pytest.raises(OAuthError):
        validator.authenticate(token)


def test_unknown_key_refresh_is_bounded(provider, validator):
    validator.refresh()
    validator.refresh_interval = 60
    for _ in range(10):
        with pytest.raises(OAuthError):
            validator.authenticate(provider["token"](headers={"kid": "random", "typ": "JWT"}))
    assert provider["calls"] == 1


def test_duplicate_jwks_kid_fails_closed(provider, validator):
    provider["keys"] *= 2
    with pytest.raises(OAuthError):
        validator.authenticate(provider["token"]())


def test_duplicate_jwt_claims_and_unsigned_token(provider, validator):
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    token = provider["token"]()
    header, payload, signature = token.split(".")
    duplicate = encode(b'{"sub":"alice","sub":"bob"}')
    with pytest.raises(OAuthError):
        validator.authenticate(f"{header}.{duplicate}.{signature}")
    with pytest.raises(OAuthError):
        validator.authenticate(jwt.encode({"sub": "alice"}, key=None, algorithm="none"))


def test_issue_bound_to_holder_task_and_source_expiry(provider, setup):
    issuer, holder, root, task, audits, _, _ = setup
    token = provider["token"](exp=int(time.time()) + 20)
    proof = sign_oauth_holder_proof(token, holder, audience="authority", task_id="t1")
    warrant = issuer.issue(token, holder.public_key, "t1", proof)
    assert warrant.authorized_holder == holder.public_key
    Authorizer(trusted_roots=[root.public_key]).verify(warrant)
    assert len(audits) == 1
    assert audits[0].caller.subject == "alice"
    assert (
        datetime.fromisoformat(warrant.expires_at()).timestamp()
        <= jwt.decode(token, options={"verify_signature": False})["exp"]
    )
    with pytest.raises(OAuthError, match="already used"):
        issuer.issue(token, holder.public_key, "t1", proof)
    assert warrant.check_constraints("refund", {"payment_id": "p1", "amount_cents": 4000}) is None
    assert warrant.check_constraints("refund", {"payment_id": "p2", "amount_cents": 4000}) is not None
    assert warrant.check_constraints("refund", {"payment_id": "p1", "amount_cents": 6000}) is not None
    assert warrant.check_constraints("refund", {"payment_id": "p1", "amount_cents": 4000, "bypass": True}) is not None


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject", "bob"),
        ("tenant_id", "other"),
        ("issuer", "other"),
        ("status", "pending"),
        ("expires_at", 1),
        ("limit", True),
    ],
)
def test_template_denies_untrusted_or_invalid_task(provider, setup, field, value):
    issuer, holder, _, task, audits, _, _ = setup
    task[field] = value
    token = provider["token"]()
    proof = sign_oauth_holder_proof(token, holder, audience="authority", task_id="t1")
    with pytest.raises(OAuthError):
        issuer.issue(token, holder.public_key, "t1", proof)
    assert audits == []


@pytest.mark.parametrize("change", ["task", "holder", "token", "audience", "expired"])
def test_proof_is_bound_to_request(provider, setup, change):
    issuer, holder, _, _, audits, _, _ = setup
    token = provider["token"]()
    proof = sign_oauth_holder_proof(
        token, holder, audience="other" if change == "audience" else "authority", task_id="t1"
    )
    if change == "expired":
        proof = replace(proof, timestamp=1)
    with pytest.raises(OAuthError):
        issuer.issue(
            provider["token"](scope="different") if change == "token" else token,
            SigningKey.generate().public_key if change == "holder" else holder.public_key,
            "t2" if change == "task" else "t1",
            proof,
        )
    assert audits == []


def test_replay_across_process_connections_and_restart(tmp_path):
    path = str(tmp_path / "proofs.db")
    stores = [SQLiteReplayStore(path) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda store: store.claim("same", time.time() + 60), stores))
    assert results.count(True) == 1
    assert not SQLiteReplayStore(path).claim("same", time.time() + 60)


def test_audit_failure_releases_no_warrant_and_consumes_proof(provider, setup):
    issuer, holder, *_ = setup

    def fail(_):
        raise RuntimeError("audit offline")

    issuer.audit = fail
    token = provider["token"]()
    proof = sign_oauth_holder_proof(token, holder, audience="authority", task_id="t1")
    with pytest.raises(RuntimeError):
        issuer.issue(token, holder.public_key, "t1", proof)
    with pytest.raises(OAuthError, match="already used"):
        issuer.issue(token, holder.public_key, "t1", proof)


def test_http_contract_and_duplicate_json(provider, setup):
    issuer, holder, *_ = setup
    app = OAuthWarrantIssuerApp(issuer)

    async def run():
        token = provider["token"]()
        proof = sign_oauth_holder_proof(token, holder, audience="authority", task_id="t1")
        body = _request_body(holder, "t1", proof)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            response = await client.post("/warrants", content=body, headers=headers)
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert (await client.post("/warrants", content=body, headers=headers)).status_code == 403
            assert (await client.post("/warrants", content=b'{"v":1,"v":1}', headers=headers)).status_code == 400
            headers["Authorization"] = "Bearer bad"
            assert (await client.post("/warrants", content=body, headers=headers)).status_code == 401

    try:
        asyncio.run(run())
    finally:
        app.close()


def test_es256_and_algorithm_confusion(provider, validator):
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="ec", alg="ES256")
    provider["keys"] = [jwk]
    claims = jwt.decode(provider["token"](), options={"verify_signature": False})
    token = jwt.encode(claims, key, algorithm="ES256", headers={"kid": "ec", "typ": "JWT"})
    assert validator.authenticate(token).subject == "alice"
    with pytest.raises(OAuthError):
        validator.authenticate(provider["token"](headers={"kid": "ec", "typ": "JWT"}))


def test_missing_fields_scope_and_expiry_cap(provider, setup):
    issuer, holder, _, task, _, template, _ = setup
    caller = issuer.credentials.authenticate(provider["token"]())
    with pytest.raises(OAuthError):
        template.compile(replace(caller, scopes=frozenset()), "t1", task)
    missing = dict(task)
    del missing["payment"]
    with pytest.raises(OAuthError):
        template.compile(caller, "t1", missing)
    task["expires_at"] = int(time.time()) + 8
    token = provider["token"]()
    proof = sign_oauth_holder_proof(token, holder, audience="authority", task_id="t1")
    warrant = issuer.issue(token, holder.public_key, "t1", proof)
    assert datetime.fromisoformat(warrant.expires_at()).timestamp() <= task["expires_at"]


def test_store_full_expiration_and_dependency_failure(tmp_path):
    store = SQLiteReplayStore(str(tmp_path / "proofs.db"), capacity=1)
    assert store.claim("expired", time.time() - 1)
    assert store.claim("live", time.time() + 100)
    with pytest.raises(OAuthUnavailable):
        store.claim("another", time.time() + 100)


def test_dependency_failures_are_503(provider, setup):
    issuer, holder, _, _, audits, _, _ = setup
    app = OAuthWarrantIssuerApp(issuer)
    token = provider["token"]()

    async def request():
        proof = sign_oauth_holder_proof(token, holder, audience="authority", task_id="t1")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
            return await client.post(
                "/warrants",
                content=_request_body(holder, "t1", proof),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )

    try:
        provider["status"] = 503
        assert asyncio.run(request()).status_code == 503
        provider["status"] = 200
        issuer.credentials.refresh()

        def unavailable(*_):
            raise RuntimeError("task database unavailable")

        issuer.policy = unavailable
        response = asyncio.run(request())
        assert response.status_code == 503 and "warrant" not in response.json()
        assert audits == []
    finally:
        app.close()
