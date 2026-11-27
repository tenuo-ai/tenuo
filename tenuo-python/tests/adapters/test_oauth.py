"""OAuth trust policies, task compilation, proof memory, and both HTTP request shapes."""

# ruff: noqa: E402
import asyncio
import base64
import json
import socket
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from tenuo import Authorizer, Exact, SigningKey
from tenuo._issuance_http import _request_body
from tenuo.oauth import (
    GITHUB_ACTIONS,
    KEYCLOAK,
    RFC9068,
    ClaimMap,
    ExactFrom,
    MaximumFrom,
    OAuthError,
    OAuthTokens,
    OAuthUnavailable,
    OAuthWarrantIssuer,
    OAuthWarrantIssuerApp,
    SQLiteProofStore,
    TaskGrant,
    TaskTemplate,
    Trust,
    request_warrant_oauth,
    sign_oauth_holder_proof,
)

AUDIENCE = "authority"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
WARRANT = "urn:tenuo:params:oauth:token-type:warrant"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
JSON = [("Content-Type", "application/json")]
FORM = [("Content-Type", "application/x-www-form-urlencoded")]


@pytest.fixture
def provider():
    """One signing key behind one key endpoint. Tests name the issuer each token claims."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="one", alg="RS256", use="sig")
    state = {"keys": [jwk], "status": 200, "calls": 0, "delay": 0.0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["calls"] += 1
            time.sleep(state["delay"])
            self.send_response(state["status"])
            self.end_headers()
            self.wfile.write(json.dumps({"keys": state["keys"]}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    issuer = f"http://127.0.0.1:{server.server_port}"

    def token(headers=None, **changes):
        """A Keycloak-shaped access token for alice, through the support client."""
        claims = dict(
            iss=issuer,
            sub="alice",
            aud=AUDIENCE,
            azp="support",
            typ="Bearer",
            jti="fixture-token-id",
            tenant_id="acme",
            scope="refunds:write",
            iat=int(time.time()),
            exp=int(time.time()) + 300,
        )
        claims.update(changes)
        claims = {name: value for name, value in claims.items() if value is not ...}
        return jwt.encode(claims, key, algorithm="RS256", headers=headers or {"kid": "one", "typ": "JWT"})

    state.update(token=token, issuer=issuer, key=key)
    yield state
    server.shutdown()
    server.server_close()
    thread.join()


def tokens(provider, issuer=None, **options):
    options.setdefault("claims", KEYCLOAK)
    if options["claims"].has_clients:
        options.setdefault("clients", frozenset({"support"}))
    issuer = issuer or provider["issuer"]
    return OAuthTokens(
        Trust(issuer, AUDIENCE, provider["issuer"] + "/keys", **options),
        allow_loopback_http=True,
        refresh_interval=0.01,
    )


@pytest.fixture
def validator(provider):
    return tokens(provider, tenant_claim="tenant_id")


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
    store = SQLiteProofStore(str(tmp_path / "proofs.db"))
    issuer = OAuthWarrantIssuer(
        credentials=validator,
        signing_key=root,
        proof_store=store,
        policy=lambda identity, task_id: template.compile(identity, task_id, task if task_id == "t1" else None),
        audit=audits.append,
    )
    return issuer, holder, root, task, audits, template, store


def ask(issuer, token, holder, task="t1"):
    proof = sign_oauth_holder_proof(token, holder, audience=AUDIENCE, task_id=task)
    return issuer.issue(token, holder.public_key, task, proof)


def allowed(root, warrant, holder, tool, args):
    signature = warrant.sign(holder, tool, args, int(time.time()))
    try:
        Authorizer(trusted_roots=[root.public_key]).authorize(warrant, tool, args, signature)
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# Whose tokens are accepted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "elsewhere"},
        {"iss": "https://attacker.test"},
        {"exp": 1},
        {"azp": "other"},
        {"azp": ...},
        {"tenant_id": ...},
        {"tenant_id": 7},
        {"typ": "ID"},
        {"cnf": {}},
        {"act": {"sub": "someone"}},
        {"may_act": {"sub": "someone"}},
        {"exp": True},
        {"iat": 1.5},
        {"scope": {"refunds:write": True}},
        {"scope": 5},
        {"scope": ["refunds:write", 5]},
        {"sub": ""},
        {"sub": ...},
    ],
)
def test_reject_invalid_credentials(provider, validator, changes):
    with pytest.raises(OAuthError):
        validator.authenticate(provider["token"](**changes))


def test_identity_is_what_the_token_said(provider, validator):
    identity = validator.authenticate(provider["token"](scope=["refunds:write", "mail:send"], email="a@acme.test"))
    assert (identity.issuer, identity.subject, identity.client_id, identity.tenant_id) == (
        provider["issuer"],
        "alice",
        "support",
        "acme",
    )
    assert identity.scopes == {"refunds:write", "mail:send"}  # A list of scopes reads like a string of them.
    assert identity.claims["email"] == "a@acme.test"
    assert identity.key == f"{provider['issuer']} support alice"
    with pytest.raises(TypeError):
        identity.claims["email"] = "someone else"


def test_each_provider_shape_is_refused_by_the_others(provider):
    standard = dict(headers={"kid": "one", "typ": "at+jwt"}, client_id="support")
    for shape, good, bad in (
        (RFC9068, standard, {}),
        (RFC9068, standard, {**standard, "jti": ...}),
        (KEYCLOAK, {}, standard),
    ):
        instance = tokens(provider, claims=shape)
        assert instance.authenticate(provider["token"](**good)).client_id == "support"
        with pytest.raises(OAuthError):
            instance.authenticate(provider["token"](**bad))


def test_a_workflow_run_is_trusted_by_its_claims_not_by_a_client(provider):
    issuer = provider["issuer"] + "/github"

    def run(**changes):
        claims = dict(
            iss=issuer,
            sub="repo:acme/backend:ref:refs/heads/main",
            repository="acme/backend",
            ref="refs/heads/main",
            azp=...,
            typ=...,
            scope=...,
            tenant_id=...,
        )
        return provider["token"](headers={"kid": "one", "typ": "JWT", "x5t": "thumb"}, **{**claims, **changes})

    where = {"repository": "acme/backend", "ref": frozenset({"refs/heads/main", "refs/heads/release"})}
    instance = tokens(provider, issuer, claims=GITHUB_ACTIONS, where=where)
    identity = instance.authenticate(run())
    assert (identity.client_id, identity.scopes, identity.claims["repository"]) == (None, frozenset(), "acme/backend")
    assert instance.authenticate(run(ref="refs/heads/release")).subject
    for changes in ({"repository": "someone/fork"}, {"ref": "refs/heads/feature"}, {"ref": ...}, {"ref": ["x"]}):
        with pytest.raises(OAuthError):
            instance.authenticate(run(**changes))


def test_a_trust_must_say_who_is_trusted(provider):
    for options in (
        dict(claims=KEYCLOAK, clients=frozenset()),  # No client named.
        dict(claims=KEYCLOAK, clients="support"),  # A string is not a set of names.
        dict(claims=GITHUB_ACTIONS),  # No client to name, and no claim required either.
        dict(claims=GITHUB_ACTIONS, clients=frozenset({"x"}), where={"repository": "acme/backend"}),
        dict(leeway_seconds=600),
    ):
        with pytest.raises(ValueError):
            tokens(provider, **options)
    for url in ("http://idp.example", "https://user:secret@idp.example", "https://idp.example/keys?x=1"):
        with pytest.raises(ValueError):
            OAuthTokens(Trust(url, AUDIENCE, url, KEYCLOAK, clients=frozenset({"support"})))
    with pytest.raises(ValueError):  # Plain HTTP to this host is refused unless it is asked for.
        OAuthTokens(Trust(provider["issuer"], AUDIENCE, provider["issuer"], KEYCLOAK, clients=frozenset({"support"})))


def test_another_provider_is_a_claim_map(provider):
    """A provider outside the tested presets is described, not coded for."""
    shape = ClaimMap(client=("cid", "azp"), scopes=("scp", "permissions"), header_type="JWT")
    instance = tokens(provider, claims=shape, required_scopes=frozenset({"refunds:write"}))
    identity = instance.authenticate(provider["token"](cid="support", azp="ignored", scp=["refunds:write"], scope=...))
    assert identity.client_id == "support" and identity.scopes == {"refunds:write"}
    with pytest.raises(OAuthError):  # The scope every caller must hold is missing.
        instance.authenticate(provider["token"](cid="support", scp=["mail:send"], scope=...))


def test_key_rotation_withdrawal_and_outage(provider, validator):
    token = provider["token"]()
    assert validator.authenticate(token).subject == "alice"
    provider["status"] = 503
    assert validator.authenticate(token).subject == "alice"  # Keys already fetched are used for a bounded time.
    validator._loaded -= validator._cache_seconds + 1
    time.sleep(0.02)
    with pytest.raises(OAuthUnavailable):
        validator.authenticate(token)
    provider["status"] = 200
    provider["keys"] = []
    validator.refresh()
    with pytest.raises(OAuthError):
        validator.authenticate(token)


def test_unknown_key_refresh_is_bounded(provider, validator):
    validator.refresh()
    validator._refresh_interval = 60
    for _ in range(10):
        with pytest.raises(OAuthError):
            validator.authenticate(provider["token"](headers={"kid": "random", "typ": "JWT"}))
    assert provider["calls"] == 1


def test_a_slow_key_fetch_does_not_hold_up_tokens_from_known_keys(provider, validator):
    token = provider["token"]()
    assert validator.authenticate(token).subject == "alice"  # The key is now known.
    provider["delay"] = 1.5
    rotated = provider["token"](headers={"kid": "rotated", "typ": "JWT"})
    with ThreadPoolExecutor(max_workers=1) as pool:
        unknown = pool.submit(validator.authenticate, rotated)  # Sends one caller to fetch, slowly.
        time.sleep(0.3)
        began = time.monotonic()
        assert validator.authenticate(token).subject == "alice"
        waited = time.monotonic() - began
        with pytest.raises(OAuthError):
            unknown.result()
    assert waited < 0.5


@pytest.mark.parametrize(
    "keys",
    [
        lambda jwk: [jwk, jwk],  # One key ID twice.
        lambda jwk: [{**jwk, "d": "AQAB"}],  # A private key published by mistake.
        lambda jwk: {"not": "a list"},
    ],
)
def test_an_unusable_key_set_is_refused_whole(provider, validator, keys):
    provider["keys"] = keys(provider["keys"][0])
    with pytest.raises(OAuthUnavailable):
        validator.authenticate(provider["token"]())


def test_duplicate_jwt_claims_and_unsigned_token(provider, validator):
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    token = provider["token"]()
    header, payload, signature = token.split(".")
    duplicate = encode(b'{"sub":"alice","sub":"bob"}')
    for bad in (
        f"{header}.{duplicate}.{signature}",
        jwt.encode({"sub": "alice"}, key=None, algorithm="none"),
        f"{header}.{payload}.{signature}=",  # One spelling per token.
        f"{header}.{payload}",
        token + "\n",
    ):
        with pytest.raises(OAuthError):
            validator.authenticate(bad)


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


# ---------------------------------------------------------------------------
# Issuing
# ---------------------------------------------------------------------------


def test_issue_bound_to_holder_task_and_source_expiry(provider, setup):
    issuer, holder, root, task, audits, _, _ = setup
    token = provider["token"](exp=int(time.time()) + 20)
    proof = sign_oauth_holder_proof(token, holder, audience=AUDIENCE, task_id="t1")
    warrant = issuer.issue(token, holder.public_key, "t1", proof)
    assert warrant.authorized_holder == holder.public_key
    Authorizer(trusted_roots=[root.public_key]).verify(warrant)
    assert len(audits) == 1
    assert (audits[0].identity.subject, audits[0].task_id, audits[0].warrant_id) == ("alice", "t1", warrant.id)
    assert (
        datetime.fromisoformat(warrant.expires_at()).timestamp()
        <= jwt.decode(token, options={"verify_signature": False})["exp"]
    )
    with pytest.raises(OAuthError, match="already used"):
        issuer.issue(token, holder.public_key, "t1", proof)
    assert allowed(root, warrant, holder, "refund", {"payment_id": "p1", "amount_cents": 4000})
    assert not allowed(root, warrant, holder, "refund", {"payment_id": "p2", "amount_cents": 4000})
    assert not allowed(root, warrant, holder, "refund", {"payment_id": "p1", "amount_cents": 6000})
    assert not allowed(root, warrant, holder, "refund", {"payment_id": "p1", "amount_cents": 4000, "bypass": True})
    assert not allowed(root, warrant, SigningKey.generate(), "refund", {"payment_id": "p1", "amount_cents": 4000})


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject", "bob"),
        ("tenant_id", "other"),
        ("issuer", "other"),
        ("status", "pending"),
        ("expires_at", 1),
        ("limit", True),
        ("payment", 1.5),
    ],
)
def test_template_denies_untrusted_or_invalid_task(provider, setup, field, value):
    issuer, holder, _, task, audits, _, _ = setup
    task[field] = value
    with pytest.raises(OAuthError):
        ask(issuer, provider["token"](), holder)
    assert audits == []


def test_a_task_may_belong_to_a_service_instead_of_a_person(provider, setup):
    issuer, holder, _, task, *_ = setup
    identity = issuer.authenticate(provider["token"](sub="service-account-support"))
    record = dict(task, client_id="support")
    del record["subject"], record["tenant_id"]
    service = TaskTemplate(tool="refund", arguments={"payment_id": ExactFrom("payment")}, owner=("issuer", "client_id"))
    assert service.compile(identity, "t1", record).capabilities["refund"]
    assert service.compile(replace(identity, client_id="another"), "t1", record) is None
    assert service.compile(replace(identity, client_id=None), "t1", dict(record, client_id=None)) is None
    for owner in ((), ("subject",), ("issuer", "email")):
        with pytest.raises(ValueError):
            TaskTemplate(tool="refund", arguments={"payment_id": ExactFrom("payment")}, owner=owner)


def test_missing_fields_scope_and_expiry_cap(provider, setup):
    issuer, holder, _, task, _, template, _ = setup
    identity = issuer.authenticate(provider["token"]())
    assert template.compile(replace(identity, scopes=frozenset()), "t1", task) is None
    assert template.compile(identity, "t1", None) is None
    assert template.compile(identity, "t2", task) is None
    missing = dict(task)
    del missing["payment"]
    with pytest.raises(OAuthError):  # A fault in the record, not a denial.
        template.compile(identity, "t1", missing)
    task["expires_at"] = int(time.time()) + 8
    warrant = ask(issuer, provider["token"](), holder)
    assert datetime.fromisoformat(warrant.expires_at()).timestamp() <= task["expires_at"]


@pytest.mark.parametrize(
    "grant",
    [
        {"refund": {"payment_id": Exact("p1")}},  # Not a TaskGrant.
        TaskGrant({}),
        TaskGrant({"refund": {}}),  # A tool with no argument constraints would allow any call.
        TaskGrant({"refund": {"payment_id": Exact("p1")}}, ttl_seconds=0),
        TaskGrant({"refund": {"payment_id": Exact("p1")}}, max_depth=99),
    ],
)
def test_what_a_policy_returns_is_checked(provider, setup, grant):
    issuer, holder, _, _, audits, *_ = setup
    issuer.policy = lambda identity, task_id: grant
    with pytest.raises(OAuthError):
        ask(issuer, provider["token"](), holder)
    assert audits == []


@pytest.mark.parametrize("change", ["task", "holder", "token", "audience", "expired", "future"])
def test_proof_is_bound_to_request(provider, setup, change):
    issuer, holder, _, _, audits, _, _ = setup
    token = provider["token"]()
    proof = sign_oauth_holder_proof(token, holder, audience="other" if change == "audience" else AUDIENCE, task_id="t1")
    if change == "expired":
        proof = replace(proof, timestamp=1)
    if change == "future":
        proof = replace(proof, timestamp=int(time.time()) + 600)
    with pytest.raises(OAuthError):
        issuer.issue(
            provider["token"](scope="different") if change == "token" else token,
            SigningKey.generate().public_key if change == "holder" else holder.public_key,
            "t2" if change == "task" else "t1",
            proof,
        )
    assert audits == []


def test_one_issuer_serves_several_providers(provider, tmp_path):
    """A person through an app, a service of our own and a CI run: one issuer, one policy."""
    base = provider["issuer"]
    sources = [
        tokens(provider, base + "/keycloak", tenant_claim="tenant_id"),
        tokens(provider, base + "/standard", claims=RFC9068, clients=frozenset({"billing"})),
        tokens(provider, base + "/github", claims=GITHUB_ACTIONS, where={"repository": "acme/backend"}),
    ]
    seen = []

    def policy(identity, task_id):
        seen.append((identity.issuer.rsplit("/", 1)[1], identity.subject, identity.client_id, identity.tenant_id))
        if identity.claims.get("repository") == "acme/backend" and task_id == "deploy-42":
            return TaskGrant({"deploy": {"environment": Exact("staging")}}, ttl_seconds=60)
        if task_id == "t1" and "refunds:write" in identity.scopes:
            return TaskGrant({"refund": {"payment_id": Exact("p1")}}, ttl_seconds=60)
        return None

    root, holder = SigningKey.generate(), SigningKey.generate()
    issuer = OAuthWarrantIssuer(credentials=sources, signing_key=root, policy=policy, audit=lambda record: None)
    person = provider["token"](iss=base + "/keycloak")
    service = provider["token"](
        headers={"kid": "one", "typ": "at+jwt"}, iss=base + "/standard", sub="billing", client_id="billing"
    )
    run = provider["token"](iss=base + "/github", sub="repo:acme/backend", repository="acme/backend", azp=...)
    assert allowed(root, ask(issuer, person, holder), holder, "refund", {"payment_id": "p1"})
    assert allowed(root, ask(issuer, service, holder), holder, "refund", {"payment_id": "p1"})
    deploy = ask(issuer, run, holder, "deploy-42")
    assert allowed(root, deploy, holder, "deploy", {"environment": "staging"})
    assert not allowed(root, deploy, holder, "deploy", {"environment": "production"})
    assert seen == [
        ("keycloak", "alice", "support", "acme"),
        ("standard", "billing", "billing", None),
        ("github", "repo:acme/backend", None, None),
    ]
    # A token is judged by the trust for the issuer it names, and by no other.
    for wrong in (
        provider["token"](iss=base + "/standard"),  # Keycloak's shape, claiming the standard issuer.
        provider["token"](iss=base + "/github", repository="someone/fork", azp=...),
        provider["token"](iss=base + "/unknown"),
        provider["token"](),
    ):
        with pytest.raises(OAuthError):
            ask(issuer, wrong, holder)
    assert len(seen) == 3
    with pytest.raises(ValueError, match="once"):
        OAuthWarrantIssuer(
            credentials=[sources[0], sources[0]], signing_key=root, policy=policy, audit=lambda record: None
        )


# ---------------------------------------------------------------------------
# Remembering proofs
# ---------------------------------------------------------------------------


def test_replay_across_process_connections_and_restart(tmp_path):
    path = str(tmp_path / "proofs.db")
    stores = [SQLiteProofStore(path) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda store: store.claim("same", time.time() + 60, "alice"), stores))
    assert sorted(results) == ["claimed"] + ["used"] * 7
    assert SQLiteProofStore(path).claim("same", time.time() + 60, "alice") == "used"


def test_store_limits_and_expiry(tmp_path):
    store = SQLiteProofStore(str(tmp_path / "proofs.db"), capacity=2, per_owner=1)
    assert store.claim("past", time.time() - 1, "alice") == "too old"
    assert store.claim("a1", time.time() + 100, "alice") == "claimed"
    assert store.claim("a2", time.time() + 100, "alice") == "owner full"
    assert store.claim("b1", time.time() + 100, "bob") == "claimed"
    assert store.claim("c1", time.time() + 100, "carol") == "full"
    store.release("a1")
    assert store.claim("c1", time.time() + 100, "carol") == "claimed"


def test_one_caller_cannot_fill_the_proof_memory_and_a_denial_leaves_nothing(provider, validator, tmp_path):
    holder = SigningKey.generate()
    issuer = OAuthWarrantIssuer(
        credentials=validator,
        signing_key=SigningKey.generate(),
        proof_store=SQLiteProofStore(str(tmp_path / "proofs.db"), capacity=8, per_owner=2),
        policy=lambda identity, task_id: (
            TaskGrant({"refund": {"payment_id": Exact("p1")}}) if task_id == "t1" else None
        ),
        audit=lambda record: None,
    )
    alice = provider["token"]()
    for _ in range(4):  # Denied requests keep no proof, so they do not count.
        with pytest.raises(OAuthError, match="not authorized"):
            ask(issuer, alice, holder, "not-approved")
    assert ask(issuer, alice, holder).id and ask(issuer, alice, holder).id
    with pytest.raises(OAuthUnavailable, match="This caller is at its limit"):
        ask(issuer, alice, holder)
    assert ask(issuer, provider["token"](sub="bob"), holder).id  # Someone else is still served.


def test_a_failed_audit_releases_no_warrant_and_the_request_can_be_retried(provider, setup):
    issuer, holder, _, _, audits, *_ = setup

    def fail(_):
        raise RuntimeError("audit offline")

    issuer.audit = fail
    token = provider["token"]()
    proof = sign_oauth_holder_proof(token, holder, audience=AUDIENCE, task_id="t1")
    with pytest.raises(RuntimeError):
        issuer.issue(token, holder.public_key, "t1", proof)
    issuer.audit = audits.append
    assert issuer.issue(token, holder.public_key, "t1", proof).id  # Nothing was issued, so nothing was used.
    with pytest.raises(OAuthError, match="already used"):
        issuer.issue(token, holder.public_key, "t1", proof)
    assert len(audits) == 1


# ---------------------------------------------------------------------------
# The endpoint
# ---------------------------------------------------------------------------


def call_app(app, *, headers=(), body=b"", method="POST", path="/warrants", receive=None):
    """Drive the ASGI app directly: (status, headers, reply, whether the body was asked for)."""

    async def run():
        sent, asked = [], []

        async def whole():
            asked.append(1)
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [(name.lower().encode(), value.encode()) for name, value in headers],
        }
        await app(scope, receive or whole, send)
        await asyncio.sleep(0.01)  # Let worker completions land.
        return sent[0]["status"], dict(sent[0]["headers"]), json.loads(sent[1]["body"]), bool(asked)

    return asyncio.run(run())


def bearer(token, content=JSON):
    return [("Authorization", f"Bearer {token}"), *content]


def compact(token, holder, task="t1"):
    return _request_body(holder, task, sign_oauth_holder_proof(token, holder, audience=AUDIENCE, task_id=task))


@pytest.fixture
def app(setup):
    application = OAuthWarrantIssuerApp(setup[0], max_concurrent=4)
    yield application
    application.close()


def test_http_contract_and_duplicate_json(provider, setup, app):
    _, holder, root, *_ = setup
    token = provider["token"]()
    body = compact(token, holder)
    status, headers, reply, _ = call_app(app, headers=bearer(token), body=body)
    assert status == 200 and headers[b"cache-control"] == b"no-store" and set(reply) == {"warrant"}
    status, _, reply, _ = call_app(app, headers=bearer(token), body=body)
    assert (status, reply["error"]) == (403, "refused") and "already used" in reply["message"]
    assert call_app(app, headers=bearer(token), body=b'{"v":1,"v":1}')[0] == 400
    assert call_app(app, headers=bearer(token), body=compact(token, holder, "unknown"))[0] == 403
    assert call_app(app, headers=bearer(token), method="GET")[0] == 405
    assert call_app(app, headers=bearer(token), path="/elsewhere")[0] == 404


def test_endpoint_checks_the_token_before_the_request_takes_a_place(provider, setup, app):
    _, holder, *_ = setup
    good = provider["token"]()
    body = compact(good, holder)
    for bad in (provider["token"](azp="other"), provider["token"](exp=1), "aaaa.bbbb.cccc", "x" * 20000):
        status, headers, reply, body_read = call_app(app, headers=bearer(bad), body=body)
        assert (status, body_read) == (401, False), reply
        assert headers[b"www-authenticate"] == b"Bearer"
        assert bad not in json.dumps(reply)
    for headers in ([("Authorization", f"Bearer {good}")], bearer(good, [("Content-Type", "text/plain")])):
        assert call_app(app, headers=headers, body=body)[::3] == (415, False)
    for headers in (
        JSON,
        [("Authorization", f"Basic {good}"), *JSON],
        [("Authorization", f"Bearer {good}"), *bearer(good)],
    ):
        assert call_app(app, headers=headers, body=body)[::3] == (401, False)
    assert app._in_progress == 0 and app._places.checking == 0
    assert call_app(app, headers=bearer(good), body=body)[0] == 200


def test_dependency_failures_are_503(provider, setup, app):
    issuer, holder, _, _, audits, *_ = setup
    token = provider["token"]()
    provider["status"] = 503
    status, _, reply, body_read = call_app(app, headers=bearer(token), body=compact(token, holder))
    assert (status, reply["error"], body_read) == (503, "unavailable", False)
    provider["status"] = 200
    issuer.credentials[0].refresh()

    def unavailable(*_):
        raise OAuthError("task database detail")  # Whatever a callback raises is the issuer failing.

    issuer.policy = unavailable
    status, _, reply, _ = call_app(app, headers=bearer(token), body=compact(token, holder))
    assert (status, reply) == (503, {"error": "unavailable", "message": "Issuer error"})
    assert audits == []


def test_one_identity_cannot_take_every_place(provider, setup):
    issuer, holder, *_ = setup
    application = OAuthWarrantIssuerApp(issuer, max_concurrent=8, max_per_identity=1)
    alice, bob = provider["token"](), provider["token"](sub="bob")

    async def run():
        waiting = asyncio.Event()

        async def never():
            await waiting.wait()
            return {"type": "http.disconnect"}

        async def post(token, receive=None):
            sent = []

            async def whole():
                return {"type": "http.request", "body": compact(token, holder), "more_body": False}

            async def send(message):
                sent.append(message)

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/warrants",
                "headers": [(n.lower().encode(), v.encode()) for n, v in bearer(token)],
            }
            await application(scope, receive or whole, send)
            return sent[0]["status"], json.loads(sent[1]["body"])

        slow = asyncio.ensure_future(post(alice, never))  # Alice holds a place while her body does not arrive.
        for _ in range(100):
            await asyncio.sleep(0.01)
            if application._in_progress:
                break
        second = await post(alice)
        other = await post(bob)
        waiting.set()
        await slow
        return second, other

    try:
        second, other = asyncio.run(run())
    finally:
        application.close()
    assert second[0] == 503 and "this caller" in second[1]["message"]
    assert other[0] == 403  # Bob was admitted; the task is not his.


# ---------------------------------------------------------------------------
# The token-exchange request shape (RFC 8693)
# ---------------------------------------------------------------------------


def exchange(token, holder, task="t1", detail=None, **fields):
    proof = sign_oauth_holder_proof(token, holder, audience=AUDIENCE, task_id=task)
    task_detail = {
        "type": "tenuo_task",
        "task": task,
        "holder": base64.b64encode(bytes(holder.public_key.to_bytes())).decode(),
        "timestamp": proof.timestamp,
        "nonce": base64.b64encode(proof.nonce).decode(),
        "signature": base64.b64encode(proof.signature).decode(),
    }
    task_detail.update(detail or {})
    request = {
        "grant_type": EXCHANGE,
        "subject_token": token,
        "subject_token_type": ACCESS_TOKEN,
        "requested_token_type": WARRANT,
        "authorization_details": json.dumps([task_detail]),
    }
    request.update(fields)
    return urllib.parse.urlencode({name: value for name, value in request.items() if value is not ...}).encode()


def test_token_exchange_returns_the_warrant_as_a_token_response(provider, setup, app):
    _, holder, root, _, audits, *_ = setup
    token = provider["token"]()
    body = exchange(token, holder)
    status, headers, reply, _ = call_app(app, headers=FORM, body=body)
    assert status == 200 and headers[b"cache-control"] == b"no-store"
    assert set(reply) == {"access_token", "issued_token_type", "token_type", "expires_in"}
    assert (reply["issued_token_type"], reply["token_type"]) == (WARRANT, "N_A")
    assert 0 < reply["expires_in"] <= 120
    from tenuo import Warrant

    warrant = Warrant.from_base64(reply["access_token"])
    assert warrant.authorized_holder == holder.public_key
    assert allowed(root, warrant, holder, "refund", {"payment_id": "p1", "amount_cents": 4000})
    assert [record.warrant_id for record in audits] == [warrant.id]
    # The same signed request again, in either shape, is refused: one proof is one warrant.
    status, _, reply, _ = call_app(app, headers=FORM, body=body)
    assert (status, reply["error"]) == (400, "invalid_authorization_details")
    assert "already used" in reply["error_description"]
    form = dict(urllib.parse.parse_qsl(body.decode()))
    detail = json.loads(form["authorization_details"])[0]
    again = json.dumps({"v": 1, **{name: value for name, value in detail.items() if name != "type"}}).encode()
    assert call_app(app, headers=bearer(token), body=again)[0] == 403
    # The content type may carry a charset, and the subject token may be called a JWT.
    jwt_type = "urn:ietf:params:oauth:token-type:jwt"
    status, _, reply, _ = call_app(
        app,
        headers=[("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")],
        body=exchange(token, holder, subject_token_type=jwt_type),
    )
    assert status == 200 and reply["access_token"]


def test_token_exchange_refusals_use_token_endpoint_errors(provider, setup, app):
    issuer, holder, *_ = setup
    token = provider["token"]()
    for bad in (provider["token"](azp="other"), provider["token"](exp=1), "aaaa.bbbb.cccc", ""):
        status, headers, reply, _ = call_app(app, headers=FORM, body=exchange(token, holder, subject_token=bad))
        assert (status, reply["error"]) == (400, "invalid_grant"), reply
        assert set(reply) == {"error", "error_description"} and b"www-authenticate" not in headers
    status, _, reply, _ = call_app(app, headers=FORM, body=exchange(token, holder, "unknown"))
    assert (status, reply["error"]) == (400, "invalid_authorization_details")
    provider["status"] = 503
    issuer.credentials[0]._loaded = float("-inf")
    status, _, reply, _ = call_app(app, headers=FORM, body=exchange(token, holder))
    assert (status, reply["error"]) == (503, "temporarily_unavailable")
    assert app._in_progress == 0 and app._places.unverified == 0 and app._places.checking == 0


@pytest.mark.parametrize(
    "fields,detail",
    [
        ({"grant_type": "client_credentials"}, None),
        ({"requested_token_type": ACCESS_TOKEN}, None),
        ({"subject_token_type": "urn:ietf:params:oauth:token-type:id_token"}, None),
        ({"scope": "refunds:write"}, None),  # Nothing is accepted and then ignored.
        ({"actor_token": "x"}, None),
        ({"subject_token": ...}, None),
        ({"authorization_details": "{}"}, None),
        ({"authorization_details": "[]"}, None),
        ({"authorization_details": '[{"type":"tenuo_task"},{"type":"tenuo_task"}]'}, None),
        ({"authorization_details": "not json"}, None),
        ({}, {"type": "payment_initiation"}),
        ({}, {"actions": ["refund"]}),  # The request names a task. It does not ask for permissions.
        ({}, {"nonce": "not base64!"}),
        ({}, {"holder": "AAAA"}),
        ({}, {"timestamp": "1"}),
    ],
)
def test_token_exchange_requests_are_read_strictly(provider, setup, app, fields, detail):
    _, holder, _, _, audits, *_ = setup
    body = exchange(provider["token"](), holder, detail=detail, **fields)
    status, _, reply, _ = call_app(app, headers=FORM, body=body)
    assert status in (400, 403) and reply["error"] in ("invalid_request", "invalid_authorization_details"), reply
    assert audits == []


def test_token_exchange_duplicate_fields_and_bad_encoding(provider, setup, app):
    _, holder, *_ = setup
    body = exchange(provider["token"](), holder)
    for bad in (body + b"&subject_token=another", body + b"&", b"\xff" + body, b"", b"a" * 70000):
        status, _, reply, _ = call_app(app, headers=FORM, body=bad)
        assert (status, reply["error"]) == (400 if len(bad) < 70000 else 413, "invalid_request"), reply


def test_requests_without_a_checked_token_have_only_a_share_of_the_places(provider, setup, app):
    """A token-exchange body is read before its token is known. Such requests cannot crowd out the rest."""
    _, holder, *_ = setup
    token = provider["token"]()

    async def run():
        waiting = asyncio.Event()

        async def never():
            await waiting.wait()
            return {"type": "http.disconnect"}

        async def post(headers, body, receive=None):
            sent = []

            async def whole():
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(message):
                sent.append(message)

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/warrants",
                "headers": [(n.lower().encode(), v.encode()) for n, v in headers],
            }
            await app(scope, receive or whole, send)
            return sent[0]["status"], json.loads(sent[1]["body"])

        slow = asyncio.ensure_future(post(FORM, b"", never))  # Holds the one place open to unknown callers.
        for _ in range(100):
            await asyncio.sleep(0.01)
            if app._places.unverified:
                break
        refused = await post(FORM, exchange(token, holder))
        served = await post(bearer(token), compact(token, holder))
        waiting.set()
        return refused, served, await slow

    refused, served, slow = asyncio.run(run())
    assert refused == (503, {"error": "temporarily_unavailable", "error_description": "Issuer is busy; retry shortly"})
    assert served[0] == 200
    assert slow[0] == 400 and app._places.unverified == 0


# ---------------------------------------------------------------------------
# The agent's side
# ---------------------------------------------------------------------------


def test_client_and_endpoint_over_http(provider, setup, app):
    uvicorn = pytest.importorskip("uvicorn")
    _, holder, root, *_ = setup
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        url = f"http://127.0.0.1:{port}/warrants"
        options = dict(audience=AUDIENCE, issuer_key=root.public_key, holder_key=holder, allow_loopback_http=True)
        token = provider["token"]()
        warrant = request_warrant_oauth(url, token=token, task_id="t1", **options)
        assert warrant.authorized_holder == holder.public_key
        with pytest.raises(OAuthError, match=r"HTTP 403.*not authorized"):
            request_warrant_oauth(url, token=token, task_id="unknown", **options)
        with pytest.raises(OAuthError, match=r"HTTP 401"):
            request_warrant_oauth(url, token=provider["token"](azp="other"), task_id="t1", **options)
        with pytest.raises(OAuthError, match="failed verification"):  # A warrant from a key the agent does not trust.
            request_warrant_oauth(
                url, token=token, task_id="t1", **{**options, "issuer_key": SigningKey.generate().public_key}
            )
        with pytest.raises(ValueError):  # The token is not sent over plain HTTP unless that was asked for.
            request_warrant_oauth(url, token=token, task_id="t1", **{**options, "allow_loopback_http": False})
        with pytest.raises(ValueError):
            request_warrant_oauth("http://issuer.example/warrants", token=token, task_id="t1", **options)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
