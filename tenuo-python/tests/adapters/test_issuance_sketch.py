"""SKETCH: what the shared issuer in ``tenuo.issuance`` is meant to show. See that module's docstring."""

# ruff: noqa: E402
import asyncio
import json
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

jwt = pytest.importorskip("jwt")
pytest.importorskip("httpx")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric import rsa

from tenuo import Authorizer, Exact, Range, SigningKey
from tenuo._spiffe_http import _request_body
from tenuo.issuance import (
    GITHUB_ACTIONS,
    KEYCLOAK,
    RFC9068,
    Grant,
    JWTCredential,
    SQLiteProofStore,
    Trust,
    WarrantIssuer,
    WarrantIssuerApp,
    sign_holder_proof,
)
from tenuo.oauth import OAuthError, OAuthUnavailable

AUDIENCE = "tenuo-authority"
REFUND = {"refund": {"payment_id": Exact("p1"), "amount_cents": Range(1, 5000)}}
DEPLOY = {"deploy": {"service": Exact("backend"), "environment": Exact("staging")}}


@pytest.fixture
def provider():
    """One signing key behind one key endpoint, standing in for three identity providers."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="one", alg="RS256", use="sig")
    state = {"delay": 0.0, "calls": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["calls"] += 1
            time.sleep(state["delay"])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"keys": [jwk]}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def token(issuer, header_type="at+jwt", kid="one", **claims):
        now = int(time.time())
        payload = {"iss": f"{base}/{issuer}", "aud": AUDIENCE, "iat": now, "exp": now + 300, **claims}
        return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid, "typ": header_type})

    state.update(base=base, token=token)
    yield state
    server.shutdown()
    server.server_close()
    thread.join()


def keycloak_token(provider, **changes):
    claims = dict(sub="alice", azp="support-app", typ="Bearer", scope="refunds:write", tenant_id="acme")
    return provider["token"]("keycloak", header_type="JWT", **{**claims, **changes})


def service_token(provider, **changes):
    claims = dict(sub="billing-agent", client_id="billing-agent", jti="token-1", scope="refunds:write")
    return provider["token"]("standard", **{**claims, **changes})


def workflow_token(provider, **changes):
    claims = dict(
        sub="repo:acme/backend:ref:refs/heads/main",
        repository="acme/backend",
        repository_owner="acme",
        ref="refs/heads/main",
        workflow="deploy",
    )
    return provider["token"]("github", header_type="JWT", **{**claims, **changes})


@pytest.fixture
def setup(provider, tmp_path):
    def trust(issuer, shape, **options):
        return JWTCredential(
            Trust(f"{provider['base']}/{issuer}", AUDIENCE, provider["base"] + "/keys", shape, **options),
            allow_loopback_http=True,
            refresh_interval=0.01,
        )

    credentials = [
        # A person, through an app: Keycloak's token shape, only from the support app.
        trust("keycloak", replace(KEYCLOAK, tenant="tenant_id"), where={"azp": "support-app"}),
        # A service of our own: a standard access token from one of two named clients.
        trust("standard", RFC9068, where={"client_id": frozenset({"billing-agent", "support-agent"})}),
        # A CI run: no client, no scopes. Trusted by repository and branch.
        trust("github", GITHUB_ACTIONS, where={"repository": "acme/backend", "ref": "refs/heads/main"}),
    ]
    approved = {("alice", "refund-1"), ("billing-agent", "refund-1")}
    seen, audits = [], []

    def policy(identity, task_id):
        seen.append((identity.subject, identity.client, identity.tenant, task_id))
        if identity.claims.get("repository") == "acme/backend" and task_id == "deploy-42":
            return Grant(DEPLOY, ttl_seconds=60)
        if (identity.subject, task_id) in approved and "refunds:write" in identity.scopes:
            return Grant(REFUND, ttl_seconds=60, max_depth=1)
        return None

    root, holder = SigningKey.generate(), SigningKey.generate()
    proofs = SQLiteProofStore(str(tmp_path / "proofs.db"), capacity=8, per_owner=2)
    issuer = WarrantIssuer(credentials=credentials, signing_key=root, policy=policy, proofs=proofs, audit=audits.append)
    yield issuer, root, holder, seen, audits, proofs
    for credential in credentials:
        credential.close()


def ask(issuer, token, holder, task):
    return issuer.issue(
        token, holder.public_key, task, sign_holder_proof(token, holder, audience=AUDIENCE, task_id=task)
    )


def allowed(root, warrant, holder, tool, args):
    signature = warrant.sign(holder, tool, args, int(time.time()))
    try:
        Authorizer(trusted_roots=[root.public_key]).authorize(warrant, tool, args, signature)
    except Exception:
        return False
    return True


def test_one_issuer_serves_a_person_a_service_and_a_ci_run(provider, setup):
    """Three providers, three token shapes, one issuer and one policy. A new provider is data."""
    issuer, root, holder, seen, audits, _ = setup
    person = ask(issuer, keycloak_token(provider), holder, "refund-1")
    service = ask(issuer, service_token(provider), holder, "refund-1")
    workflow = ask(issuer, workflow_token(provider), holder, "deploy-42")

    assert seen == [
        ("alice", "support-app", "acme", "refund-1"),
        ("billing-agent", "billing-agent", None, "refund-1"),
        ("repo:acme/backend:ref:refs/heads/main", None, None, "deploy-42"),
    ]
    for warrant in (person, service):
        assert allowed(root, warrant, holder, "refund", {"payment_id": "p1", "amount_cents": 4000})
        assert not allowed(root, warrant, holder, "refund", {"payment_id": "p1", "amount_cents": 9000})
        assert not allowed(root, warrant, holder, "deploy", {"service": "backend", "environment": "staging"})
    assert allowed(root, workflow, holder, "deploy", {"service": "backend", "environment": "staging"})
    assert not allowed(root, workflow, holder, "deploy", {"service": "backend", "environment": "production"})
    assert [record.task_id for record in audits] == ["refund-1", "refund-1", "deploy-42"]
    assert all(warrant.authorized_holder == holder.public_key for warrant in (person, service, workflow))


@pytest.mark.parametrize(
    "make",
    [
        lambda p: workflow_token(p, repository="someone/fork"),  # Another repository.
        lambda p: workflow_token(p, ref="refs/heads/feature"),  # Another branch.
        lambda p: p["token"](
            "github", header_type="JWT", sub="repo:acme/backend:ref:refs/heads/main"
        ),  # No repository claim.
        lambda p: keycloak_token(p, azp="another-app"),
        lambda p: keycloak_token(p, typ="ID"),
        lambda p: keycloak_token(p, tenant_id=None),
        lambda p: service_token(p, client_id="unlisted"),
        lambda p: service_token(p, jti=None),
        lambda p: p["token"](
            "standard", header_type="JWT", sub="x", client_id="billing-agent", jti="t"
        ),  # Wrong shape for its issuer.
        lambda p: p["token"]("unknown-issuer", sub="alice"),
        lambda p: service_token(p, aud="another-api"),
        lambda p: service_token(p, exp=int(time.time()) - 60),
        lambda p: p["token"]("standard", kid="other", sub="x", client_id="billing-agent", jti="t"),
        lambda p: service_token(p, cnf={"jkt": "x"}),
    ],
)
def test_a_token_that_does_not_meet_its_trust_is_refused(provider, setup, make):
    issuer, _, holder, seen, audits, proofs = setup
    with pytest.raises(OAuthError):
        ask(issuer, make(provider), holder, "refund-1")
    assert not seen and not audits  # The policy never heard of it.


def test_one_caller_cannot_fill_the_proof_store_and_a_denial_leaves_nothing(provider, setup):
    issuer, _, holder, _, _, proofs = setup
    busy = service_token(provider)
    for _ in range(4):  # Denied requests keep no proof, so they do not count.
        with pytest.raises(OAuthError, match="Not authorized"):
            ask(issuer, busy, holder, "not-approved")
    assert ask(issuer, busy, holder, "refund-1").id and ask(issuer, busy, holder, "refund-1").id
    with pytest.raises(OAuthUnavailable, match="This caller is at its limit"):
        ask(issuer, busy, holder, "refund-1")
    assert ask(issuer, keycloak_token(provider), holder, "refund-1").id  # Someone else is still served.
    # The same signed request twice is one warrant.
    token = keycloak_token(provider)
    proof = sign_holder_proof(token, holder, audience=AUDIENCE, task_id="refund-1")
    assert issuer.issue(token, holder.public_key, "refund-1", proof).id
    with pytest.raises(OAuthError, match="already used"):
        issuer.issue(token, holder.public_key, "refund-1", proof)


def test_a_slow_key_fetch_does_not_hold_up_tokens_from_known_keys(provider, setup):
    issuer, _, holder, *_ = setup
    assert ask(issuer, service_token(provider), holder, "refund-1").id  # The key is now cached.
    provider["delay"] = 1.5
    unknown = threading.Thread(
        target=lambda: pytest.raises(
            OAuthError, ask, issuer, service_token(provider, kid="rotated"), holder, "refund-1"
        )
    )
    unknown.start()  # Sends the validator to fetch keys, slowly.
    time.sleep(0.2)
    began = time.monotonic()
    credential, identity = issuer.authenticate(service_token(provider))
    waited = time.monotonic() - began
    unknown.join()
    provider["delay"] = 0.0
    assert identity.subject == "billing-agent" and waited < 0.5


def _post(application, token, body, receive=None):
    async def run():
        sent, asked = [], []

        async def whole():
            asked.append(1)
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/warrants",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
        }
        await application(scope, receive or whole, send)
        return sent[0]["status"], json.loads(sent[1]["body"]), bool(asked)

    return asyncio.run(run())


def test_endpoint_checks_the_token_before_the_request_takes_a_place(provider, setup):
    issuer, root, holder, *_ = setup
    application = WarrantIssuerApp(issuer, max_concurrent=2)
    try:
        good = service_token(provider)
        body = _request_body(holder, "refund-1", sign_holder_proof(good, holder, audience=AUDIENCE, task_id="refund-1"))
        for bad in (
            service_token(provider, client_id="unlisted"),
            workflow_token(provider, ref="refs/heads/x"),
            "a.b.c",
        ):
            status, reply, body_read = _post(application, bad, body)
            assert (status, reply["message"], body_read) == (401, "Access token not accepted", False)
        assert application._in_progress == 0 and application._places.checking == 0
        status, reply, _ = _post(application, good, body)
        assert status == 200 and reply["warrant"]
    finally:
        application.close()


def test_endpoint_keeps_a_policy_failure_to_itself(provider, setup, caplog):
    issuer, _, holder, *_ = setup

    def broken(identity, task_id):
        raise OAuthError("task database detail")

    issuer._policy = broken
    application = WarrantIssuerApp(issuer)
    try:
        token = service_token(provider)
        body = _request_body(
            holder, "refund-1", sign_holder_proof(token, holder, audience=AUDIENCE, task_id="refund-1")
        )
        with caplog.at_level("INFO", logger="tenuo.spiffe"):
            status, reply, _ = _post(application, token, body)
        assert (status, reply) == (503, {"error": "unavailable", "message": "Issuer error"})
        assert [record for record in caplog.records if record.levelname == "ERROR"]
    finally:
        application.close()
