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
    MemoryProofStore,
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
        {"iat": []},  # Claims of the wrong JSON type are a refusal like any other, with a reason.
        {"iat": {"a": 1}},
        {"exp": []},
        {"exp": "soon"},
        {"nbf": []},
        {"nbf": {}},
        {"aud": {"a": 1}},
        {"aud": 7},
        {"sub": []},
        {"sub": 7},
        {"azp": []},
        {"scope": None},
        {"jti": []},
        {"scope": {"refunds:write": True}},
        {"scope": 5},
        {"scope": ["refunds:write", 5]},
        {"sub": ""},
        {"sub": ...},
    ],
)
def test_reject_invalid_credentials(provider, validator, changes):
    with pytest.raises(OAuthError) as refused:
        validator.authenticate(provider["token"](**changes))
    assert refused.value.reason and not isinstance(refused.value, OAuthUnavailable)


@pytest.mark.parametrize(
    "changes,options,says",
    [
        ({"aud": "account"}, {}, "audience: the token is for 'account' and Trust.audience is 'authority'"),
        ({"azp": "other-app"}, {}, "client 'other-app' is not in Trust.clients"),
        ({}, {"claims": RFC9068}, "the header's typ is 'JWT' and this trust's claim map expects 'at+jwt'"),
        ({"typ": "ID"}, {}, "this looks like an ID token, not an access token"),
        ({"scope": "mail:send"}, {"required_scopes": frozenset({"refunds:write"})}, "Trust.required_scopes also needs"),
        ({"tenant_id": ...}, {"tenant_claim": "tenant_id"}, "no 'tenant_id' claim to read the tenant from"),
        ({"exp": 1}, {}, "the token has expired"),
        ({"iss": "https://elsewhere.example"}, {}, "issuer: the token says 'https://elsewhere.example'"),
        (
            {"repository": "someone/fork"},
            {"where": {"repository": "acme/backend"}},
            "Trust.where expects 'acme/backend'",
        ),
        ({"cnf": {"jkt": "x"}}, {}, "sender-constrained"),
        ({"headers": {"kid": "rotated", "typ": "JWT"}}, {}, "which is not among the 1 usable keys"),
    ],
)
def test_the_operator_is_told_which_check_failed_and_the_caller_is_not(provider, caplog, changes, options, says):
    instance = tokens(provider, **options)
    token = provider["token"](**changes)
    with caplog.at_level("INFO", logger="tenuo.oauth"):
        with pytest.raises(OAuthError) as refused:
            instance.authenticate(token)
    assert says in refused.value.reason
    assert says in caplog.text and token not in caplog.text and token not in refused.value.reason
    assert says not in str(refused.value)  # What a caller is shown stays the same for every refusal.


def test_a_wrong_key_url_is_named_in_the_log_and_not_called_a_bad_token(provider, caplog):
    instance = tokens(provider)
    provider["status"] = 404
    with caplog.at_level("INFO", logger="tenuo.oauth"):
        with pytest.raises(OAuthUnavailable) as refused:
            instance.authenticate(provider["token"]())
    assert "could not fetch signing keys from" in refused.value.reason and "HTTP 404" in refused.value.reason
    assert "check Trust.jwks_url" in caplog.text


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
    assert json.loads(identity.key) == [provider["issuer"], "support", "alice"]
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
        lambda jwk: [jwk, {**jwk, "kid": "two", "use": "enc", "d": "AQAB"}],  # Whatever use it claims.
        lambda jwk: [jwk, {**jwk, "kid": "two", "key_ops": ["sign"], "d": "AQAB"}],
        lambda jwk: {"not": "a list"},
    ],
)
def test_an_unusable_key_set_is_refused_whole(provider, validator, keys):
    provider["keys"] = keys(provider["keys"][0])
    with pytest.raises(OAuthUnavailable):
        validator.authenticate(provider["token"]())


@pytest.mark.parametrize("kid", ["one\n", "o\x00ne", "\ud800", "k" * 2000])
def test_a_key_id_must_be_plain_text_even_if_the_provider_publishes_it(provider, validator, kid):
    provider["keys"] = [{**provider["keys"][0], "kid": kid}, provider["keys"][0]]
    assert validator.authenticate(provider["token"]()).subject == "alice"  # The well-named key still works.
    assert kid not in validator._keys
    token = provider["token"](headers={"kid": kid, "typ": "JWT"})
    with pytest.raises(OAuthError) as refused:
        validator.authenticate(token)
    assert refused.value.reason == "the header has no usable key ID (kid)"


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


def test_a_refresh_is_not_undone_by_a_fetch_that_began_before_it(provider, validator, monkeypatch):
    token = provider["token"]()
    real = validator._fetch
    with_the_key = real()
    began, release = threading.Event(), threading.Event()

    def older_fetch():  # Read the key set while the key was still published, and is slow to come back.
        began.set()
        release.wait(10)
        return with_the_key

    monkeypatch.setattr(validator, "_fetch", older_fetch)
    with ThreadPoolExecutor(max_workers=1) as pool:
        older = pool.submit(validator.authenticate, token)  # No keys yet, so this caller fetches.
        assert began.wait(5)
        monkeypatch.setattr(validator, "_fetch", real)
        provider["keys"] = []
        validator.refresh()  # The operator withdrew the key and refreshed.
        assert validator._keys == {}
        release.set()
        with pytest.raises(OAuthUnavailable):  # Overtaken: what it fetched is not used, and it is told to retry.
            older.result()
    assert validator._keys == {}  # What the older fetch brought back did not replace the refreshed set.
    validator._refresh_interval = 60  # Judge the token by the keys in use, without another fetch.
    with pytest.raises(OAuthError) as refused:
        validator.authenticate(token)
    assert not isinstance(refused.value, OAuthUnavailable)


def test_nobody_waits_for_another_callers_fetch(provider, validator):
    """With no keys yet, one caller fetches. The others are told to try again, at once."""
    provider["delay"] = 0.5
    token = provider["token"]()
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(validator.authenticate, token)
        for _ in range(200):
            if validator._under_way:
                break
            time.sleep(0.005)
        began = time.monotonic()
        for _ in range(3):
            with pytest.raises(OAuthUnavailable):
                validator.authenticate(token)
        assert time.monotonic() - began < 0.3
        assert first.result().subject == "alice"
    assert validator.authenticate(token).subject == "alice" and provider["calls"] == 1


def test_known_keys_are_fetched_again_in_the_background_before_they_age_out(provider, validator):
    token = provider["token"]()
    assert validator.authenticate(token).subject == "alice"
    validator._loaded -= validator._cache_seconds * 0.6  # Past half their life.
    time.sleep(0.02)
    provider["delay"] = 0.3
    began = time.monotonic()
    assert validator.authenticate(token).subject == "alice"  # Answered from the keys in hand.
    assert time.monotonic() - began < 0.2
    provider["delay"] = 0.0
    for _ in range(200):
        if provider["calls"] == 2 and not validator._under_way:
            break
        time.sleep(0.01)
    assert provider["calls"] == 2 and time.monotonic() - validator._loaded < 5


def test_a_fetch_that_ends_badly_does_not_stop_later_ones(provider, validator, monkeypatch):
    real = validator._fetch
    monkeypatch.setattr(validator, "_fetch", lambda: (_ for _ in ()).throw(SystemExit()))
    with pytest.raises(OAuthUnavailable):
        validator.authenticate(provider["token"]())
    monkeypatch.setattr(validator, "_fetch", real)
    assert validator._under_way == 0
    time.sleep(0.02)
    assert validator.authenticate(provider["token"]()).subject == "alice"


def test_a_fetch_that_hangs_holds_its_caller_only_to_the_deadline(provider, monkeypatch):
    """A step that cannot be interrupted (a name lookup) must not hold a caller, nor be joined by more fetches."""
    instance = tokens(provider, tenant_claim="tenant_id")
    instance._timeout, instance._refresh_interval = 0.2, 0.01
    release, started = threading.Event(), []
    real = instance._fetch

    def hang():
        started.append(1)
        release.wait(10)
        return real()

    monkeypatch.setattr(instance, "_fetch", hang)
    token = provider["token"]()
    began = time.monotonic()
    with pytest.raises(OAuthUnavailable):
        instance.authenticate(token)
    assert 1 < time.monotonic() - began < 2  # One second past the deadline, and no longer.
    for _ in range(5):  # While it hangs, others are answered at once and start nothing.
        time.sleep(0.02)
        began = time.monotonic()
        with pytest.raises(OAuthUnavailable):
            instance.authenticate(token)
        assert time.monotonic() - began < 0.1
    assert started == [1] and instance._under_way == 1
    release.set()
    for _ in range(200):
        if not instance._under_way:
            break
        time.sleep(0.01)
    assert instance.authenticate(token).subject == "alice"  # What it fetched in the end is used.


def test_a_new_key_that_cannot_be_fetched_is_unavailable_not_invalid(provider, validator):
    assert validator.authenticate(provider["token"]()).subject == "alice"
    provider["status"] = 503
    time.sleep(0.02)
    rotated = provider["token"](headers={"kid": "rotated", "typ": "JWT"})
    for _ in range(3):  # The caller that fetched, and those after it who may not fetch again yet.
        with pytest.raises(OAuthUnavailable):
            validator.authenticate(rotated)
        validator._refresh_interval = 60
    assert provider["calls"] == 2
    assert validator.authenticate(provider["token"]()).subject == "alice"  # Known keys are unaffected.
    provider["status"] = 200
    validator.refresh()
    with pytest.raises(OAuthError) as refused:  # Fetched, and not there: now it is simply not accepted.
        validator.authenticate(rotated)
    assert not isinstance(refused.value, OAuthUnavailable)


def test_entries_this_adapter_does_not_use_are_passed_over(provider, validator):
    other = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(ec.generate_private_key(ec.SECP384R1()).public_key()))
    weak = json.loads(
        jwt.algorithms.RSAAlgorithm.to_jwk(rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key())
    )
    provider["keys"] = [
        {**other, "kid": "p384"},  # No alg, and not the curve this adapter uses.
        {k: v for k, v in provider["keys"][0].items() if k != "kid"},  # No key ID: no token can name it.
        {**weak, "kid": "weak", "alg": "RS256"},
        {"kty": "RSA", "kid": "broken", "alg": "RS256", "n": "!", "e": "AQAB"},
        {"kty": "OKP", "kid": "okp", "crv": "Ed25519", "x": "AAAA"},
        *provider["keys"],
    ]
    assert validator.authenticate(provider["token"]()).subject == "alice"
    assert set(validator._keys) == {"one"}


def test_the_fetch_timeout_bounds_a_provider_that_answers_a_little_at_a_time(provider):
    slow = socket.socket()
    slow.bind(("127.0.0.1", 0))
    slow.listen(1)

    def drip():
        connection, _ = slow.accept()
        with connection:
            connection.recv(4096)
            for piece in [b"HTTP/1.1 200 OK\r\n"] + [b"X-Wait: 1\r\n"] * 40:
                try:
                    connection.sendall(piece)
                except OSError:
                    return
                time.sleep(0.1)

    threading.Thread(target=drip, daemon=True).start()
    url = f"http://127.0.0.1:{slow.getsockname()[1]}"
    instance = OAuthTokens(
        Trust(url, AUDIENCE, url + "/keys", KEYCLOAK, clients=frozenset({"support"})),
        allow_loopback_http=True,
        timeout=0.5,
    )
    began = time.monotonic()
    with pytest.raises(OAuthUnavailable):
        instance.refresh()
    slow.close()
    assert time.monotonic() - began < 2


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


@pytest.mark.parametrize(
    "change,says",
    [
        (None, "there is no record for it"),
        ({"subject": "bob"}, "the record's 'subject' is not this caller's"),
        ({"tenant_id": "other"}, "the record's 'tenant_id' is not this caller's"),
        ({"status": "pending"}, "the record's status is not 'approved'"),
        ({"expires_at": 1}, "the approval has expired"),
        ({"task_id": "t2"}, "the record's task_id is not the one asked for"),
    ],
)
def test_the_operator_is_told_why_a_task_was_not_granted(provider, setup, caplog, change, says):
    issuer, _, _, task, _, template, _ = setup
    identity = issuer.authenticate(provider["token"]())
    with caplog.at_level("INFO", logger="tenuo.oauth"):
        assert template.compile(identity, "t1", None if change is None else {**task, **change}) is None
    assert "Task 't1' is not granted" in caplog.text and says in caplog.text
    with caplog.at_level("INFO", logger="tenuo.oauth"):
        assert template.compile(replace(identity, scopes=frozenset()), "t1", task) is None
    assert "lacks the scope ['refunds:write']" in caplog.text


def test_a_task_may_belong_to_a_service_instead_of_a_person(provider, setup):
    issuer, holder, _, task, *_ = setup
    identity = issuer.authenticate(provider["token"](sub="service-account-support"))
    record = dict(task, client_id="support")
    del record["subject"], record["tenant_id"]
    service = TaskTemplate(tool="refund", arguments={"payment_id": ExactFrom("payment")}, owner=("issuer", "client_id"))
    assert service.compile(identity, "t1", record).capabilities["refund"]
    assert service.compile(replace(identity, client_id="another"), "t1", record) is None
    assert service.compile(replace(identity, client_id=None), "t1", dict(record, client_id=None)) is None
    for owner in ((), ("subject",), ("issuer", "email"), "issuer"):
        with pytest.raises(ValueError):
            TaskTemplate(tool="refund", arguments={"payment_id": ExactFrom("payment")}, owner=owner)
    with pytest.raises(ValueError):
        TaskTemplate(tool="refund", arguments={"payment_id": ExactFrom("payment")}, required_scopes="refunds:write")


def test_a_person_owns_their_task_with_or_without_tenants(provider, setup):
    issuer, _, _, task, _, template, _ = setup
    identity = issuer.authenticate(provider["token"]())
    assert template.compile(identity, "t1", task) is not None
    assert template.compile(identity, "t1", dict(task, tenant_id="other")) is None  # The identity has a tenant.
    without = replace(identity, tenant_id=None)  # A trust with no tenant_claim.
    record = {name: value for name, value in task.items() if name != "tenant_id"}
    assert template.compile(without, "t1", record) is not None
    assert template.compile(replace(without, subject="bob"), "t1", record) is None


def test_missing_fields_scope_and_expiry_cap(provider, setup):
    issuer, holder, _, task, _, template, _ = setup
    identity = issuer.authenticate(provider["token"]())
    assert template.compile(replace(identity, scopes=frozenset()), "t1", task) is None
    assert template.compile(identity, "t1", None) is None
    assert template.compile(identity, "t2", task) is None
    missing = dict(task)
    del missing["payment"]
    with pytest.raises(OAuthError, match="no 'payment' field, which argument 'payment_id' is bound to"):
        template.compile(identity, "t1", missing)  # A fault in the record, not a denial: it names the field.
    task["expires_at"] = int(time.time()) + 8
    warrant = ask(issuer, provider["token"](), holder)
    assert datetime.fromisoformat(warrant.expires_at()).timestamp() <= task["expires_at"]


@pytest.mark.parametrize(
    "grant",
    [
        {"refund": {"payment_id": Exact("p1")}},  # Not a TaskGrant.
        TaskGrant({}),
        TaskGrant({"refund": {}}),  # A tool with no argument constraints would allow any call.
        TaskGrant({"refund": {"_allow_unknown": True}}),  # A setting, not a constraint: the same thing.
        TaskGrant({"refund": {"payment_id": Exact("p1")}}, ttl_seconds=0),
        TaskGrant({"refund": {"payment_id": Exact("p1")}}, max_depth=99),
        TaskGrant(
            {"refund": {"payment_id": Exact("p1")}}, expires_at=0
        ),  # An approval that ended, not one without an end.
        TaskGrant({"refund": {"payment_id": Exact("p1")}}, expires_at=1.5),
    ],
)
def test_what_a_policy_returns_is_checked(provider, setup, grant):
    issuer, holder, _, _, audits, *_ = setup
    issuer.policy = lambda identity, task_id: grant
    with pytest.raises(OAuthError):
        ask(issuer, provider["token"](), holder)
    assert audits == []


def test_unlisted_arguments_are_refused_unless_the_grant_says_otherwise(provider, setup):
    issuer, holder, root, *_ = setup
    listed = {"payment_id": Exact("p1")}
    for constraints, unlisted_allowed in ((listed, False), ({**listed, "_allow_unknown": True}, True)):
        issuer.policy = lambda identity, task_id, constraints=constraints: TaskGrant({"refund": constraints})
        warrant = ask(issuer, provider["token"](), holder)
        assert allowed(root, warrant, holder, "refund", {"payment_id": "p1"})
        assert allowed(root, warrant, holder, "refund", {"payment_id": "p1", "note": "x"}) is unlisted_allowed
        assert not allowed(root, warrant, holder, "refund", {"payment_id": "p2", "note": "x"})


def test_a_grant_is_copied_when_it_is_checked(provider, setup):
    """A policy may return mappings it keeps and changes. What was checked is what is minted."""
    from collections.abc import Mapping

    from tenuo.oauth import _validated

    shared = {"refund": {"payment_id": Exact("p1")}}
    checked = _validated(TaskGrant(shared))
    shared["refund"].clear()
    shared["transfer"] = {}
    assert {tool: set(constraints) for tool, constraints in checked.capabilities.items()} == {"refund": {"payment_id"}}
    with pytest.raises(TypeError):
        checked.capabilities["refund"]["amount_cents"] = Exact(1)

    class Changing(Mapping):
        """Says it has a constraint when asked its size, and has none by the time it is read."""

        def __len__(self):
            return 1

        def __iter__(self):
            return iter(())

        def __getitem__(self, name):
            raise KeyError(name)

    issuer, holder, _, _, audits, *_ = setup
    issuer.policy = lambda identity, task_id: TaskGrant({"refund": Changing()})
    with pytest.raises(OAuthError, match="explicit argument constraints"):
        ask(issuer, provider["token"](), holder)
    assert audits == []


def test_callbacks_that_would_need_awaiting_do_not_count_as_having_run(provider, setup):
    issuer, holder, _, _, audits, *_ = setup

    async def later(record):
        audits.append(record)

    for callbacks in (dict(policy=later, audit=audits.append), dict(policy=lambda *_: None, audit=later)):
        with pytest.raises(ValueError, match="plain functions"):
            OAuthWarrantIssuer(credentials=issuer.credentials, signing_key=SigningKey.generate(), **callbacks)
    # One that is not declared async and still hands back something to await.
    written = issuer.audit
    issuer.audit = lambda record: later(record)
    token = provider["token"]()
    proof = sign_oauth_holder_proof(token, holder, audience=AUDIENCE, task_id="t1")
    with pytest.raises(TypeError, match="plain functions"):
        issuer.issue(token, holder.public_key, "t1", proof)
    assert audits == []  # No audit record, so no warrant.
    issuer.audit = written
    assert issuer.issue(token, holder.public_key, "t1", proof).id and len(audits) == 1


def test_only_a_store_that_says_the_proof_is_new_lets_issuance_go_on(provider, validator):
    answers = [True, None, "ok", 1]

    class Other:
        """A store written to some other contract."""

        def claim(self, key, keep_until, owner):
            return answers[0]

        def release(self, key):
            pass

    audits = []
    issuer = OAuthWarrantIssuer(
        credentials=validator,
        signing_key=SigningKey.generate(),
        proof_store=Other(),
        policy=lambda identity, task_id: TaskGrant({"refund": {"payment_id": Exact("p1")}}),
        audit=audits.append,
    )
    while answers:
        with pytest.raises(OAuthUnavailable, match="cannot record holder proofs"):
            ask(issuer, provider["token"](), SigningKey.generate())
        answers.pop(0)
    assert audits == []


def test_a_proof_store_that_looks_empty_is_still_the_one_used(provider, validator):
    class Counting(MemoryProofStore):
        claims = 0

        def __len__(self):
            return 0  # Falsy.

        def claim(self, key, keep_until, owner):
            Counting.claims += 1
            return super().claim(key, keep_until, owner)

    issuer = OAuthWarrantIssuer(
        credentials=validator,
        signing_key=SigningKey.generate(),
        proof_store=Counting(),
        policy=lambda identity, task_id: TaskGrant({"refund": {"payment_id": Exact("p1")}}),
        audit=lambda record: None,
    )
    assert ask(issuer, provider["token"](), SigningKey.generate()).id and Counting.claims == 1


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


def test_sqlite_store_finds_expired_proofs_by_index(tmp_path):
    import sqlite3

    path = str(tmp_path / "proofs.db")
    SQLiteProofStore(path)
    db = sqlite3.connect(path)
    try:
        plan = " ".join(row[-1] for row in db.execute("EXPLAIN QUERY PLAN DELETE FROM proofs WHERE expires <= 1"))
    finally:
        db.close()
    assert "proofs_expires" in plan and "SCAN" not in plan


def test_sqlite_store_closes_what_it_opens(tmp_path, recwarn):
    import gc
    import warnings

    warnings.simplefilter("always", ResourceWarning)
    store = SQLiteProofStore(str(tmp_path / "proofs.db"))
    store.claim("a", time.time() + 100, "alice")
    store.release("a")
    gc.collect()
    # Only this store's connections: something else in the process may be collected here too.
    assert not [
        warning
        for warning in recwarn
        if issubclass(warning.category, ResourceWarning) and "sqlite3" in str(warning.message)
    ]


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

    # So is a grant it returned that cannot be used: the caller can do nothing about either.
    for policy in (unavailable, lambda *_: {"refund": {}}, lambda *_: TaskGrant({"refund": {}})):
        issuer.policy = policy
        status, _, reply, _ = call_app(app, headers=bearer(token), body=compact(token, holder))
        assert (status, reply) == (503, {"error": "unavailable", "message": "Issuer error"})
    assert audits == []


@pytest.mark.parametrize("shape", ["compact", "exchange"])
def test_a_task_id_no_statement_can_carry_is_the_callers_mistake(provider, setup, app, shape):
    _, holder, *_ = setup
    token = provider["token"]()
    surrogate = json.dumps("\ud800")  # Valid JSON, and not text that can be signed.
    if shape == "compact":
        body = compact(token, holder).replace(b'"t1"', surrogate.encode())
        status, _, reply, _ = call_app(app, headers=bearer(token), body=body)
    else:
        form = dict(urllib.parse.parse_qsl(exchange(token, holder).decode()))
        form["authorization_details"] = form["authorization_details"].replace('"t1"', surrogate)
        status, _, reply, _ = call_app(app, headers=FORM, body=urllib.parse.urlencode(form).encode())
    assert status in (400, 403), reply


def test_unreachable_providers_do_not_hold_up_callers_of_another(provider, validator):
    """Tokens that only name a provider whose key endpoint does not answer cost one check thread for each such provider."""
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(64)  # Accepts connections and never answers.
    base = f"http://127.0.0.1:{silent.getsockname()[1]}"
    downs = [
        OAuthTokens(
            Trust(f"{base}/{n}", AUDIENCE, base + "/keys", KEYCLOAK, clients=frozenset({"support"})),
            allow_loopback_http=True,
            timeout=1,
        )
        for n in range(5)
    ]
    holder = SigningKey.generate()
    issuer = OAuthWarrantIssuer(
        credentials=[validator, *downs],
        signing_key=SigningKey.generate(),
        policy=lambda identity, task_id: TaskGrant({"refund": {"payment_id": Exact("p1")}}),
        audit=lambda record: None,
    )
    application = OAuthWarrantIssuerApp(issuer)
    assert application._check_pool._max_workers == 4 + 6  # The usual four, and one for each provider's fetch.
    good = provider["token"]()
    assert validator.authenticate(good).subject == "alice"
    # Each names one silent provider. Nothing about a token is checked before its provider's keys.
    forged = [provider["token"](iss=down.trust.issuer) for down in downs]

    async def post(token):
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
        await application(scope, whole, send)
        return sent[0]["status"]

    async def run():
        others = [asyncio.ensure_future(post(token)) for token in forged * 3]
        for _ in range(200):
            await asyncio.sleep(0.005)
            if all(down._under_way for down in downs):
                break
        began = time.monotonic()
        status = await asyncio.wait_for(post(good), 2)
        waited = time.monotonic() - began
        return status, waited, await asyncio.gather(*others)

    try:
        status, waited, others = asyncio.run(run())
    finally:
        application.close()
        silent.close()
    assert status == 200 and waited < 1.5  # Their fetches take longer than this to give up.
    assert set(others) == {503}


def test_keys_are_fetched_before_the_server_takes_requests(provider, setup, app):
    """A server sends requests only after start-up completes, so the first one finds the keys there."""
    _, holder, *_ = setup
    provider["delay"] = 0.3
    token = provider["token"]()
    seen = {}

    async def run():
        events = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
        go_on = asyncio.Event()

        async def receive():
            if len(events) == 1:
                await go_on.wait()
            return events.pop(0)

        async def send(message):
            if message["type"] == "lifespan.startup.complete":
                seen["calls_at_start"] = provider["calls"]
                go_on.set()

        await app({"type": "lifespan"}, receive, send)

    asyncio.run(run())
    assert seen["calls_at_start"] == 1

    # A provider that cannot be reached delays the start by its deadline at most, and does not stop it.
    provider["status"], provider["delay"] = 503, 0.0
    application = OAuthWarrantIssuerApp(setup[0])
    setup[0].credentials[0]._loaded = float("-inf")
    try:
        asyncio.run(application._started())
        status, _, reply, _ = call_app(application, headers=bearer(token), body=compact(token, holder))
        assert (status, reply["error"]) == (503, "unavailable")
    finally:
        application.close()


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
        ({"audience": "payments-api"}, None),
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


def test_token_exchange_with_an_authorization_header_needs_the_same_token_in_both(provider, setup, app):
    """Through a gateway the request carries a bearer header too. It is never accepted and then ignored."""
    _, holder, *_ = setup
    token = provider["token"]()
    for header in (
        f"Bearer {provider['token'](sub='bob')}",  # Another valid token.
        "Bearer aaaa.bbbb.cccc",
        "Basic dXNlcjpwYXNz",
        "Bearer",
    ):
        status, _, reply, _ = call_app(app, headers=[("Authorization", header), *FORM], body=exchange(token, holder))
        assert (status, reply["error"]) == (400, "invalid_request"), reply
    status, _, reply, _ = call_app(
        app, headers=[("Authorization", f"Bearer {token}"), *FORM], body=exchange(token, holder)
    )
    assert status == 200 and reply["access_token"]


def test_token_exchange_names_a_parameter_it_does_not_support(provider, setup, app):
    _, holder, *_ = setup
    for name in ("scope", "audience", "client_id"):
        body = exchange(provider["token"](), holder, **{name: "x"})
        status, _, reply, _ = call_app(app, headers=FORM, body=body)
        assert (status, reply["error"]) == (400, "invalid_request")
        assert reply["error_description"] == f"Unsupported token-exchange parameter: {name}"
    status, _, reply, _ = call_app(app, headers=FORM, body=exchange(provider["token"](), holder, **{"<b>" * 30: "x"}))
    assert reply["error_description"] == "Malformed token-exchange request"  # Not echoed.


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


def test_a_token_exchange_holds_its_share_until_its_token_is_checked(provider, setup, app, monkeypatch):
    """Not only while its body is read: a slow check of one such request must not let more of them in."""
    issuer, holder, *_ = setup
    slow, other = provider["token"](), provider["token"](jti="another")
    checking, release = threading.Event(), threading.Event()
    real = issuer.authenticate

    def authenticate(token):
        if token == slow and not release.is_set():
            checking.set()
            release.wait(10)
        return real(token)

    monkeypatch.setattr(issuer, "authenticate", authenticate)
    assert real(slow).subject == "alice"  # The keys are known: the checks below are slow only where made so.

    async def post(headers, body):
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
        await app(scope, whole, send)
        return sent[0]["status"], json.loads(sent[1]["body"])

    async def run():
        first = asyncio.ensure_future(post(FORM, exchange(slow, holder)))
        for _ in range(400):
            await asyncio.sleep(0.005)
            if checking.is_set():
                break
        held = app._places.unverified
        second = await post(FORM, exchange(other, holder))  # The fixture's endpoint has one such place.
        compact_request = await post(bearer(other), compact(other, holder))
        release.set()
        return held, second, compact_request, await first

    held, second, compact_request, first = asyncio.run(run())
    assert held == 1
    assert second == (503, {"error": "temporarily_unavailable", "error_description": "Issuer is busy; retry shortly"})
    assert compact_request[0] == 200 and first[0] == 200
    assert app._places.unverified == 0 and app._places.checking == 0


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
        for bad in ("http://issuer.example/warrants", "https://127.0.0.1:99999/warrants", "ftp://127.0.0.1/warrants"):
            with pytest.raises(OAuthError):  # Every failure of the client is this one type.
                request_warrant_oauth(bad, token=token, task_id="t1", **options)
        for changed in ({"task_id": "\ud800"}, {"token": "\ud800"}, {"audience": "\ud800"}):
            with pytest.raises(OAuthError):  # Text that cannot be signed.
                request_warrant_oauth(url, **{"token": token, "task_id": "t1", **options, **changed})
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_the_quickstart_runs_as_printed():
    """The one-file example the guide starts from, with a stand-in provider and no Docker."""
    pytest.importorskip("uvicorn")
    import os
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    done = subprocess.run(
        [sys.executable, str(root / "examples" / "oauth" / "quickstart.py")],
        env={**os.environ, "PYTHONPATH": str(root)},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    for line in (
        "refunded 4000 cents on payment-789",
        "REFUSED at the tool: Constraint 'amount_cents' not satisfied",
        "REFUSED at the tool: Constraint 'payment_id' not satisfied",
        "Issuer refused (HTTP 403): Task is not authorized for this caller",
        "client 'reporting-agent' is not in Trust.clients",
        "All as expected.",
    ):
        assert line in done.stdout, line
    assert done.stdout.count("refunded 4000 cents") == 1  # The approved refund is made once.
