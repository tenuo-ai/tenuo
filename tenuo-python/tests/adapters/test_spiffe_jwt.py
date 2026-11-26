"""JWT-SVID validation, the single-request issuance exchange, and its HTTP endpoint."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")
pyjwt = pytest.importorskip("jwt")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from tenuo import Authorizer, Exact, Range, SigningKey  # noqa: E402
from tenuo.exceptions import AuthorizationError  # noqa: E402
from tenuo.spiffe import (  # noqa: E402
    SpiffeError,
    SpiffeGrant,
    SpiffeIssuerServer,
    SpiffeJWTProof,
    SpiffeWarrantIssuer,
)
from tenuo.spiffe_jwt import (  # noqa: E402
    SpiffeJWT,
    SpiffeJWTIssuerApp,
    fetch_jwt_svid,
    request_warrant_jwt,
    sign_jwt_holder_proof,
)

from .test_spiffe import (  # noqa: E402
    AGENT,
    DOMAIN,
    REFUND,
    SERVER,
    _field,
    eventually,
    workload_api,  # noqa: F401  (fixture)
)

AUDIENCE = SERVER


class JWTAuthority:
    """A trust domain's JWT-SVID signing key."""

    def __init__(self, kind="EC", kid=None, bits=2048, curve=None):
        if kind == "EC":
            self.key = ec.generate_private_key(curve or ec.SECP256R1())
            self.algorithm = {"secp256r1": "ES256", "secp384r1": "ES384", "secp521r1": "ES512"}[self.key.curve.name]
            exported = pyjwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key())
        else:
            self.key = rsa.generate_private_key(65537, bits)
            self.algorithm = "RS256"
            exported = pyjwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key())
        self.kid = kid or "kid-" + secrets.token_hex(4)
        self.jwk = {
            **(json.loads(exported) if isinstance(exported, str) else exported),
            "kid": self.kid,
            "use": "jwt-svid",
        }

    def token(self, sub=AGENT, aud=AUDIENCE, *, exp=300, algorithm=None, headers=None, drop=(), **claims):
        now = int(time.time())
        payload = {"sub": sub, "aud": aud, "exp": now + exp, "iat": now, **claims}
        for name in drop:
            payload.pop(name)
        return pyjwt.encode(
            payload, self.key, algorithm=algorithm or self.algorithm, headers={"kid": self.kid, **(headers or {})}
        )


def jwks(*authorities, extra=()):
    return json.dumps({"keys": [a.jwk for a in authorities] + list(extra)}).encode()


@pytest.fixture
def authority():
    return JWTAuthority()


@pytest.fixture
def validator(authority, tmp_path):
    path = tmp_path / "jwt_bundle.json"
    path.write_bytes(jwks(authority))
    return SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))


# -- token validation ---------------------------------------------------------


@pytest.mark.parametrize(
    "kind, options, algorithm",
    [
        ("EC", {}, "ES256"),
        ("EC", {"curve": ec.SECP384R1()}, "ES384"),
        ("EC", {"curve": ec.SECP521R1()}, "ES512"),
        ("RSA", {}, "RS256"),
        ("RSA", {}, "RS512"),
        ("RSA", {}, "PS256"),
        ("RSA", {}, "PS384"),
    ],
)
def test_valid_tokens_for_each_algorithm(tmp_path, kind, options, algorithm):
    authority = JWTAuthority(kind, **options)
    path = tmp_path / "bundle.json"
    path.write_bytes(jwks(authority))
    validator = SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
    token = authority.token(algorithm=algorithm)
    identity = validator.authenticate(token)
    assert (identity.spiffe_id, identity.svid_type) == (AGENT, "jwt")
    assert identity.certificate_sha256 == hashlib.sha256(token.encode()).hexdigest()
    assert 290 < identity.expires_at - time.time() <= 300


def test_audience_list_and_optional_typ(validator, authority):
    assert validator.authenticate(authority.token(aud=["other", AUDIENCE])).spiffe_id == AGENT
    assert validator.authenticate(authority.token(headers={"typ": "JOSE"})).spiffe_id == AGENT


def _unsigned(header, payload):
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{encode(header)}.{encode(payload)}."


@pytest.mark.parametrize(
    "build, message",
    [
        (lambda a: a.token(exp=-30), "expired"),
        (lambda a: a.token(aud="spiffe://example.test/someone-else"), "not for this issuer's audience"),
        (lambda a: a.token(aud=[]), "Invalid JWT-SVID|not for this issuer"),
        (lambda a: a.token(drop=("aud",)), "Invalid JWT-SVID"),
        (lambda a: a.token(drop=("exp",)), "Invalid JWT-SVID"),
        (lambda a: a.token(drop=("sub",)), "Invalid JWT-SVID"),
        (lambda a: a.token(sub="spiffe://other.test/agent"), "different trust domain"),
        (lambda a: a.token(sub="spiffe://example.test"), "Invalid workload SPIFFE ID"),
        (lambda a: a.token(sub="agent"), "Invalid workload SPIFFE ID"),
        (lambda a: a.token(sub=123), "Invalid JWT-SVID"),
        (lambda a: a.token(nbf=int(time.time()) + 600), "Invalid JWT-SVID"),
        (lambda a: a.token(headers={"kid": "unknown"}), "not in the trust bundle"),
        (
            lambda a: pyjwt.encode(
                {"sub": AGENT, "aud": AUDIENCE, "exp": int(time.time()) + 60}, a.key, algorithm=a.algorithm
            ),
            "names no signing key",
        ),
        (lambda a: a.token(headers={"typ": "at+jwt"}), "Malformed"),
        (lambda a: JWTAuthority(kid=a.kid).token(), "Invalid JWT-SVID"),  # Right key ID, wrong key.
        (lambda a: a.token()[:-4] + "AAAA", "Invalid JWT-SVID"),
        (lambda a: a.token() + ".extra", "Malformed"),
        (lambda a: "not-a-token", "Malformed"),
        (lambda a: "", "Malformed"),
        (lambda a: None, "Malformed"),
        (lambda a: a.token(padding="x" * 20000), "Malformed"),
        (
            lambda a: _unsigned(
                {"alg": "none", "kid": a.kid}, {"sub": AGENT, "aud": AUDIENCE, "exp": time.time() + 60}
            ),
            "Malformed",  # An empty signature segment is not a JWS this adapter accepts.
        ),
        (
            lambda a: (
                _unsigned({"alg": "none", "kid": a.kid}, {"sub": AGENT, "aud": AUDIENCE, "exp": time.time() + 60})
                + "AAAA"
            ),
            "algorithm its signing key does not support",
        ),
        (
            # A symmetric signature made with the public key as the secret.
            lambda a: pyjwt.encode(
                {"sub": AGENT, "aud": AUDIENCE, "exp": int(time.time()) + 60},
                hashlib.sha256(json.dumps(a.jwk, sort_keys=True).encode()).digest(),
                algorithm="HS256",
                headers={"kid": a.kid},
            ),
            "algorithm its signing key does not support",
        ),
    ],
    ids=[
        "expired",
        "other-audience",
        "empty-audience",
        "no-aud",
        "no-exp",
        "no-sub",
        "other-domain",
        "trust-domain-id",
        "not-a-spiffe-id",
        "numeric-sub",
        "not-yet-valid",
        "unknown-kid",
        "no-kid",
        "bad-typ",
        "same-kid-other-key",
        "bad-signature",
        "four-parts",
        "garbage",
        "empty",
        "none",
        "oversized",
        "alg-none",
        "alg-none-with-signature",
        "hmac-with-public-key",
    ],
)
def test_rejected_tokens(validator, authority, build, message):
    with pytest.raises(SpiffeError, match=message):
        validator.authenticate(build(authority))


def test_only_standard_headers_are_accepted(validator, authority):
    """The JWT-SVID standard forbids headers beyond alg, kid and typ."""
    for extra in (
        {"jku": "https://attacker.example/keys.json"},
        {"jwk": authority.jwk},
        {"x5u": "https://attacker.example/cert.pem"},
        {"crit": ["exp"]},
        {"cty": "JWT"},
        {"custom": 1},
    ):
        with pytest.raises(SpiffeError, match="Malformed JWT-SVID"):
            validator.authenticate(authority.token(headers=extra))
    assert validator.authenticate(authority.token(headers={"typ": "JWT"})).spiffe_id == AGENT


def test_algorithm_must_match_the_key_type(tmp_path):
    rsa_authority, ec_authority = JWTAuthority("RSA"), JWTAuthority("EC")
    # The EC authority's token names the RSA key's ID, and the reverse.
    path = tmp_path / "bundle.json"
    path.write_bytes(jwks(rsa_authority, ec_authority))
    validator = SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
    for forged in (
        ec_authority.token(headers={"kid": rsa_authority.kid}),
        rsa_authority.token(headers={"kid": ec_authority.kid}),
        JWTAuthority("EC", curve=ec.SECP384R1(), kid=ec_authority.kid).token(),
    ):
        with pytest.raises(SpiffeError, match="does not support"):
            validator.authenticate(forged)


# -- bundle sources -----------------------------------------------------------


def test_bundle_file_formats(authority, tmp_path):
    x509_entry = {"kty": "EC", "use": "x509-svid", "crv": "P-256", "x": "AA", "y": "AA", "x5c": ["AA"]}
    helper_name = {DOMAIN: base64.b64encode(jwks(authority)).decode(), "other.test": "AAAA"}
    helper_uri = {f"spiffe://{DOMAIN}": base64.b64encode(jwks(authority)).decode()}
    no_use = {key: value for key, value in authority.jwk.items() if key != "use"}
    path = tmp_path / "bundle.json"
    for document in (
        jwks(authority),
        jwks(authority, extra=[x509_entry]),
        json.dumps({"keys": [no_use]}).encode(),
        json.dumps(helper_name).encode(),
        json.dumps(helper_uri).encode(),
    ):
        path.write_bytes(document)
        validator = SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
        assert validator.authenticate(authority.token()).spiffe_id == AGENT


def test_only_marked_keys_count_in_a_spiffe_format_bundle(authority, tmp_path):
    """In a bundle that also holds X.509 authorities, an unmarked key is not a JWT signing key."""
    unmarked, x509_authority = JWTAuthority(), JWTAuthority()
    plain = {key: value for key, value in unmarked.jwk.items() if key != "use"}
    with_chain = {**{k: v for k, v in x509_authority.jwk.items() if k != "use"}, "x5c": ["AAAA"]}
    path = tmp_path / "bundle.json"
    # As `spire-server bundle show -format spiffe` writes it: every key carries a use.
    path.write_bytes(
        json.dumps(
            {
                "spiffe_sequence": 3,
                "keys": [authority.jwk, plain, {**x509_authority.jwk, "use": "x509-svid", "x5c": ["AAAA"]}],
            }
        ).encode()
    )
    validator = SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
    assert list(validator._keys) == [authority.kid]
    assert validator.authenticate(authority.token()).spiffe_id == AGENT
    for forged in (unmarked.token(), x509_authority.token()):
        with pytest.raises(SpiffeError, match="not in the trust bundle"):
            validator.authenticate(forged)
    # A key that carries a certificate chain is an X.509 authority in any document.
    path.write_bytes(json.dumps({"keys": [plain, with_chain]}).encode())
    validator = SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
    assert list(validator._keys) == [unmarked.kid]
    # A sequence number alone marks the SPIFFE format: nothing unmarked is accepted.
    path.write_bytes(json.dumps({"spiffe_sequence": 1, "keys": [plain]}).encode())
    with pytest.raises(SpiffeError, match="no usable JWT-SVID signing keys"):
        SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))


def test_unusable_bundles_are_refused(authority, tmp_path):
    small = JWTAuthority("RSA", bits=1024)
    private = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(authority.key))
    private = {**(private if isinstance(private, dict) else json.loads(private)), "kid": "private", "use": "jwt-svid"}
    unusable = [
        small.jwk,
        private,
        {**authority.jwk, "kid": ""},
        {"kty": "oct", "k": "AAAA", "kid": "sym", "use": "jwt-svid"},
        {"kty": "OKP", "crv": "Ed25519", "x": "AAAA", "kid": "okp", "use": "jwt-svid"},
        {"kty": "AKP", "alg": "ML-DSA-44", "pub": "AAAA", "kid": "pq", "use": "jwt-svid"},
        {"kty": "EC", "crv": "P-256", "kid": "bad-point", "x": "!", "y": "!"},
        {"kty": "RSA", "kid": "bad-rsa", "n": 5, "e": "AQAB"},
        {"kty": "RSA", "kid": "even-exponent", "n": "AQAB" * 86, "e": "Ag"},
        "not an object",
    ]
    path = tmp_path / "bundle.json"
    for document, message in (
        (b"not json", "not a JWKS document"),
        (b"[]", "not a JWKS document"),
        (b'{"keys": "x"}', "not a JWKS document"),
        (json.dumps({"other.test": "AAAA"}).encode(), "no usable JWT-SVID signing keys"),
        (json.dumps({DOMAIN: 5}).encode(), "not a JWKS document"),
        (json.dumps({DOMAIN: "!!"}).encode(), "not a JWKS document"),
        (jwks(), "no usable JWT-SVID signing keys"),
        (jwks(authority, authority), "must be unique"),
        *[(json.dumps({"keys": [entry]}).encode(), "no usable JWT-SVID signing keys") for entry in unusable],
    ):
        path.write_bytes(document)
        with pytest.raises(SpiffeError, match=message):
            SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
    # Unusable keys beside a good one are skipped, not fatal.
    path.write_bytes(jwks(authority, extra=unusable))
    validator = SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
    assert list(validator._keys) == [authority.kid]
    assert validator.authenticate(authority.token()).spiffe_id == AGENT


def test_rotation_that_adds_an_unsupported_key_still_retires_the_old_one(authority, tmp_path, monkeypatch):
    monkeypatch.setattr("tenuo.spiffe_jwt._FILE_CHECK_SECONDS", 0.0)
    retired = JWTAuthority()
    path = tmp_path / "bundle.json"
    path.write_bytes(jwks(authority, retired))
    validator = SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
    assert validator.authenticate(retired.token()).spiffe_id == AGENT
    time.sleep(0.01)
    post_quantum = {"kty": "AKP", "alg": "ML-DSA-44", "pub": "AAAA", "kid": "pq", "use": "jwt-svid"}
    path.write_bytes(jwks(authority, extra=[post_quantum]))
    assert validator.authenticate(authority.token()).spiffe_id == AGENT
    with pytest.raises(SpiffeError, match="not in the trust bundle"):
        validator.authenticate(retired.token())


def test_one_token_has_one_spelling(validator, authority):
    """Padding or junk after a valid token must not validate as a second identity."""
    token = authority.token()
    assert validator.authenticate(token).spiffe_id == AGENT
    nested = base64.urlsafe_b64encode(b"[" * 30000).rstrip(b"=").decode()
    for variant in (
        token + "==",
        token + "=",
        token + "!!!!",
        token + " ",
        " " + token,
        token + "\n",
        token + "é",
        token.replace(".", "..", 1),
        f"{nested}.{token.split('.')[1]}.{token.split('.')[2]}",
        f"{token.split('.')[0]}.{nested}.{token.split('.')[2]}",
        f"{base64.urlsafe_b64encode(b'[1]').rstrip(b'=').decode()}.e30.AAAA",
    ):
        with pytest.raises(SpiffeError, match="Malformed JWT-SVID|Invalid JWT-SVID"):
            validator.authenticate(variant)
    with pytest.raises(SpiffeError, match="Malformed JWT-SVID"):
        sign_jwt_holder_proof(token + "==", SigningKey.generate(), audience=AUDIENCE, task_id="t")
    with pytest.raises(SpiffeError, match="Invalid JWT-SVID"):
        validator.authenticate(authority.token(exp=10**400))


def test_bundle_file_rotation(authority, tmp_path, monkeypatch):
    monkeypatch.setattr("tenuo.spiffe_jwt._FILE_CHECK_SECONDS", 0.0)
    path = tmp_path / "bundle.json"
    path.write_bytes(jwks(authority))
    validator = SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
    successor = JWTAuthority()
    with pytest.raises(SpiffeError, match="not in the trust bundle"):
        validator.authenticate(successor.token())
    time.sleep(0.01)
    path.write_bytes(b"half-written")
    assert validator.authenticate(authority.token()).spiffe_id == AGENT  # Bad file: keys are kept.
    path.write_bytes(jwks(successor))
    assert validator.authenticate(successor.token()).spiffe_id == AGENT
    with pytest.raises(SpiffeError, match="not in the trust bundle"):
        validator.authenticate(authority.token())  # The retired key is gone.


def bundles_response(**by_domain):
    return b"".join(
        _field(1, _field(1, domain.encode()) + _field(2, document)) for domain, document in by_domain.items()
    )


def test_workload_api_bundle_source(authority, workload_api):  # noqa: F811
    foreign = JWTAuthority()
    api = workload_api()
    own = f"spiffe://{DOMAIN}"
    api.publish_jwt_bundles(bundles_response(**{"spiffe://foreign.test": jwks(foreign), own: jwks(authority)}))
    validator = SpiffeJWT.from_workload_api(trust_domain=DOMAIN, audience=AUDIENCE, socket_path=api.address, timeout=5)
    try:
        assert validator.authenticate(authority.token()).spiffe_id == AGENT
        with pytest.raises(SpiffeError, match="not in the trust bundle"):
            validator.authenticate(foreign.token())  # Another domain's key is never trusted.
        successor = JWTAuthority()
        api.publish_jwt_bundles(bundles_response(**{own: b"garbage"}))  # Ignored.
        api.publish_jwt_bundles(bundles_response(**{own: jwks(authority, successor)}))
        assert eventually(lambda: successor.kid in validator._keys)
        assert validator.authenticate(successor.token()).spiffe_id == AGENT
        assert validator.authenticate(authority.token()).spiffe_id == AGENT
        api.drop_streams()
        api.publish_jwt_bundles(bundles_response(**{own: jwks(successor)}))
        assert eventually(lambda: authority.kid not in validator._keys)
    finally:
        validator.close()

    lonely = workload_api()
    lonely.publish_jwt_bundles(bundles_response(**{"spiffe://foreign.test": jwks(foreign)}))
    with pytest.raises(SpiffeError, match=f"no JWT bundle for {DOMAIN}"):
        SpiffeJWT.from_workload_api(trust_domain=DOMAIN, audience=AUDIENCE, socket_path=lonely.address, timeout=0.5)


def test_withdrawn_file_keys_are_no_longer_trusted(authority, tmp_path, monkeypatch):
    monkeypatch.setattr("tenuo.spiffe_jwt._FILE_CHECK_SECONDS", 0.0)
    path = tmp_path / "bundle.json"
    path.write_bytes(jwks(authority))
    validator = SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path))
    token = authority.token()
    unsupported = {"kty": "AKP", "alg": "ML-DSA-44", "pub": "AAAA", "kid": "pq", "use": "jwt-svid"}
    other_domain_only = json.dumps({"other.test": base64.b64encode(jwks(JWTAuthority())).decode()}).encode()
    for withdrawal in (jwks(), jwks(extra=[unsupported]), other_domain_only, b"{}"):
        time.sleep(0.01)
        path.write_bytes(withdrawal)  # A well-formed bundle that no longer lists the key.
        with pytest.raises(SpiffeError, match="not in the trust bundle"):
            validator.authenticate(token)
        time.sleep(0.01)
        path.write_bytes(jwks(authority))
        assert validator.authenticate(token).spiffe_id == AGENT
    empty = tmp_path / "empty.json"
    empty.write_bytes(jwks())
    with pytest.raises(SpiffeError, match="no usable JWT-SVID signing keys"):
        SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(empty))  # Never usable to start with.


def test_workload_api_withdrawals_stop_trust_at_once(authority, workload_api):  # noqa: F811
    grpc = pytest.importorskip("grpc")
    own, token = f"spiffe://{DOMAIN}", authority.token()
    good = bundles_response(**{own: jwks(authority)})
    api = workload_api()
    api.publish_jwt_bundles(good)
    validator = SpiffeJWT.from_workload_api(trust_domain=DOMAIN, audience=AUDIENCE, socket_path=api.address, timeout=5)

    def refused():
        try:
            validator.authenticate(token)
        except SpiffeError:
            return True
        return False

    try:
        assert not refused()
        for withdrawal in (
            bundles_response(**{own: jwks()}),  # The domain now has no JWT keys.
            bundles_response(**{"spiffe://foreign.test": jwks(JWTAuthority())}),  # The domain is gone.
            b"",
        ):
            api.publish_jwt_bundles(withdrawal)
            assert eventually(refused)
            api.publish_jwt_bundles(good)
            assert eventually(lambda: not refused())
        # A malformed update is not a withdrawal: the keys in use are kept.
        api.publish_jwt_bundles(bundles_response(**{own: b"garbage"}))
        api.publish_jwt_bundles(b"\xff\xff not protobuf")
        time.sleep(0.3)
        assert not refused()
        # SPIRE stops issuing this workload an identity.
        api.refuse = grpc.StatusCode.PERMISSION_DENIED
        api.drop_streams()
        assert eventually(refused)
        api.publish_jwt_bundles(good)  # What a reconnecting stream is sent first.
        api.refuse = None
        assert eventually(lambda: not refused())
    finally:
        validator.close()


def test_workload_api_outage_is_tolerated_for_a_bounded_time(authority, workload_api):  # noqa: F811
    grpc = pytest.importorskip("grpc")
    token = authority.token()
    api = workload_api()
    api.publish_jwt_bundles(bundles_response(**{f"spiffe://{DOMAIN}": jwks(authority)}))
    validator = SpiffeJWT.from_workload_api(
        trust_domain=DOMAIN, audience=AUDIENCE, socket_path=api.address, timeout=5, max_stale_seconds=1.0
    )

    def accepted():
        try:
            return validator.authenticate(token).spiffe_id == AGENT
        except SpiffeError:
            return False

    try:
        api.refuse = grpc.StatusCode.UNAVAILABLE  # The SPIRE agent is restarting.
        api.drop_streams()
        assert eventually(lambda: validator._lost_since is not None)
        assert accepted()  # Still served during a short outage.
        time.sleep(1.2)
        with pytest.raises(SpiffeError, match="SPIRE agent is unreachable"):
            validator.authenticate(token)
        api.refuse = None
        assert eventually(accepted)
    finally:
        validator.close()


def test_request_during_recovery_cannot_discard_the_recovered_keys(authority, workload_api):  # noqa: F811
    """A request that saw the outage as too long must not undo a bundle installed meanwhile."""
    token = authority.token()
    api = workload_api()
    api.publish_jwt_bundles(bundles_response(**{f"spiffe://{DOMAIN}": jwks(authority)}))
    validator = SpiffeJWT.from_workload_api(
        trust_domain=DOMAIN, audience=AUDIENCE, socket_path=api.address, timeout=5, max_stale_seconds=1.0
    )
    try:
        keys = validator._keys
        validator._lost_since = time.monotonic() - 60  # The outage timer has long expired.
        with pytest.raises(SpiffeError, match="SPIRE agent is unreachable"):
            validator.authenticate(token)
        assert validator._keys is keys  # Refused, but nothing shared was cleared.
        validator._lost_since = None  # The watcher reconnects; SPIRE has nothing new to send.
        assert validator.authenticate(token).spiffe_id == AGENT

        # The same interleaving, with the stale read racing a real recovery many times.
        outcomes = []

        def hammer():
            for _ in range(300):
                try:
                    validator.authenticate(token)
                    outcomes.append(True)
                except SpiffeError:
                    outcomes.append(False)

        workers = [threading.Thread(target=hammer) for _ in range(4)]
        for worker in workers:
            worker.start()
        for _ in range(200):
            validator._lost_since = time.monotonic() - 60
            validator._lost_since = None
        for worker in workers:
            worker.join()
        assert validator._keys is keys and validator.authenticate(token).spiffe_id == AGENT
    finally:
        validator.close()


def test_malformed_home_bundle_is_consumed_once(authority, workload_api, monkeypatch):  # noqa: F811
    """A response with an unreadable home bundle must not be replayed as if SPIRE had sent it again."""
    grpc = pytest.importorskip("grpc")
    monkeypatch.setattr("tenuo.spiffe._PENDING_RETRY", (0.1, 0.2))
    partner = JWTAuthority()
    own, theirs = f"spiffe://{DOMAIN}", f"spiffe://{PARTNER}"
    api = workload_api()
    api.publish_jwt_bundles(bundles_response(**{own: jwks(authority), theirs: jwks(partner)}))
    validator = SpiffeJWT.from_workload_api(
        trust_domain=DOMAIN,
        audience=AUDIENCE,
        socket_path=api.address,
        timeout=5,
        max_stale_seconds=1.0,
        federates_with=[PARTNER],
    )
    token, partner_token = authority.token(), partner.token(sub=PARTNER_AGENT)
    try:
        api.publish_jwt_bundles(bundles_response(**{own: b"garbage", theirs: jwks(partner)}))
        time.sleep(0.4)
        assert validator._watcher._pending is None  # Nothing is left to deliver again.
        assert validator.authenticate(token).spiffe_id == AGENT  # The home keys are kept.
        assert validator.authenticate(partner_token).trust_domain == PARTNER

        # An outage is still timed from when the stream was lost, whatever retries run meanwhile.
        api.refuse = grpc.StatusCode.UNAVAILABLE
        api.drop_streams()
        assert eventually(lambda: validator._lost_since is not None)
        time.sleep(1.4)
        with pytest.raises(SpiffeError, match="SPIRE agent is unreachable"):
            validator.authenticate(token)

        # Keys withdrawn because SPIRE refused this workload stay withdrawn.
        api.refuse = grpc.StatusCode.PERMISSION_DENIED
        assert eventually(lambda: validator._keys == {} and validator._federated_keys == {})
        time.sleep(0.6)
        assert validator._keys == {} and validator._federated_keys == {}
    finally:
        validator.close()


def test_workload_api_startup_needs_usable_keys(workload_api):  # noqa: F811
    api = workload_api()
    api.publish_jwt_bundles(bundles_response(**{f"spiffe://{DOMAIN}": jwks()}))
    with pytest.raises(SpiffeError, match="no usable JWT-SVID signing keys"):
        SpiffeJWT.from_workload_api(trust_domain=DOMAIN, audience=AUDIENCE, socket_path=api.address, timeout=0.5)


# -- federation ---------------------------------------------------------------

PARTNER = "partner.test"
PARTNER_AGENT = f"spiffe://{PARTNER}/agent"


@pytest.fixture
def federated(authority, tmp_path):
    """A validator for example.test that also accepts partner.test tokens."""
    partner = JWTAuthority()
    own_file, partner_file = tmp_path / "own.json", tmp_path / "partner.json"
    own_file.write_bytes(jwks(authority))
    partner_file.write_bytes(jwks(partner))
    validator = SpiffeJWT(
        trust_domain=DOMAIN,
        audience=AUDIENCE,
        bundle_file=str(own_file),
        federated_bundle_files={PARTNER: str(partner_file)},
    )
    return validator, partner, partner_file


def test_federated_tokens_are_accepted_for_their_own_domain(federated, authority):
    validator, partner, _ = federated
    identity = validator.authenticate(partner.token(sub=PARTNER_AGENT))
    assert (identity.spiffe_id, identity.trust_domain, identity.svid_type) == (PARTNER_AGENT, PARTNER, "jwt")
    assert validator.authenticate(authority.token()).trust_domain == DOMAIN


def test_one_domains_keys_cannot_sign_for_another(federated, authority):
    validator, partner, _ = federated
    with pytest.raises(SpiffeError, match="not signed by its own trust domain's keys"):
        validator.authenticate(partner.token(sub=AGENT))  # The partner's key names an example.test workload.
    with pytest.raises(SpiffeError, match="not signed by its own trust domain's keys"):
        validator.authenticate(authority.token(sub=PARTNER_AGENT))
    with pytest.raises(SpiffeError, match="different trust domain"):
        validator.authenticate(partner.token(sub="spiffe://other.test/agent"))


def test_key_ids_shared_between_domains_stay_separate(tmp_path):
    own, partner = JWTAuthority(kid="shared"), JWTAuthority(kid="shared")
    own_file, partner_file = tmp_path / "own.json", tmp_path / "partner.json"
    own_file.write_bytes(jwks(own))
    partner_file.write_bytes(jwks(partner))
    validator = SpiffeJWT(
        trust_domain=DOMAIN,
        audience=AUDIENCE,
        bundle_file=str(own_file),
        federated_bundle_files={PARTNER: str(partner_file)},
    )
    assert validator.authenticate(own.token()).spiffe_id == AGENT
    assert validator.authenticate(partner.token(sub=PARTNER_AGENT)).spiffe_id == PARTNER_AGENT
    for forged in (partner.token(sub=AGENT), own.token(sub=PARTNER_AGENT)):
        with pytest.raises(SpiffeError):
            validator.authenticate(forged)


def test_federated_keys_from_one_helper_file_and_their_withdrawal(authority, tmp_path, monkeypatch):
    monkeypatch.setattr("tenuo.spiffe_jwt._FILE_CHECK_SECONDS", 0.0)
    partner = JWTAuthority()
    helper = tmp_path / "jwt_bundle.json"

    def write(**domains):
        time.sleep(0.01)
        helper.write_bytes(json.dumps({d: base64.b64encode(doc).decode() for d, doc in domains.items()}).encode())

    write(**{DOMAIN: jwks(authority), PARTNER: jwks(partner)})
    validator = SpiffeJWT(
        trust_domain=DOMAIN,
        audience=AUDIENCE,
        bundle_file=str(helper),
        federated_bundle_files={PARTNER: str(helper)},
    )
    token = partner.token(sub=PARTNER_AGENT)
    assert validator.authenticate(token).trust_domain == PARTNER
    write(**{DOMAIN: jwks(authority)})  # The helper no longer lists the partner.
    with pytest.raises(SpiffeError, match="not in the trust bundle"):
        validator.authenticate(token)
    assert validator.authenticate(authority.token()).spiffe_id == AGENT  # The home domain is unaffected.
    write(**{DOMAIN: jwks(authority), PARTNER: jwks(partner)})
    assert validator.authenticate(token).trust_domain == PARTNER


def test_damaged_federated_file_does_not_pin_home_keys(federated, authority, tmp_path, monkeypatch):
    monkeypatch.setattr("tenuo.spiffe_jwt._FILE_CHECK_SECONDS", 0.0)
    validator, partner, partner_file = federated
    own_file = tmp_path / "own.json"
    successor = JWTAuthority()
    time.sleep(0.01)
    partner_file.write_bytes(b"half-written")
    own_file.write_bytes(jwks(successor))  # The home domain rotated its key at the same time.
    assert validator.authenticate(successor.token()).spiffe_id == AGENT
    with pytest.raises(SpiffeError, match="not in the trust bundle"):
        validator.authenticate(authority.token())  # The retired home key is gone.
    with pytest.raises(SpiffeError, match="not in the trust bundle"):
        validator.authenticate(partner.token(sub=PARTNER_AGENT))
    # A damaged home file keeps the home keys, and a partner change still applies.
    time.sleep(0.01)
    partner_file.write_bytes(jwks(partner))
    own_file.write_bytes(b"half-written")
    assert validator.authenticate(partner.token(sub=PARTNER_AGENT)).trust_domain == PARTNER
    assert validator.authenticate(successor.token()).spiffe_id == AGENT
    partner_file.unlink()
    with pytest.raises(SpiffeError, match="not in the trust bundle"):
        validator.authenticate(partner.token(sub=PARTNER_AGENT))


def test_domains_sharing_a_signing_key_are_not_federated(authority, tmp_path, caplog):
    own_file, partner_file = tmp_path / "own.json", tmp_path / "partner.json"
    own_file.write_bytes(jwks(authority))
    partner_file.write_bytes(jwks(authority))  # The same key set for both domains.
    with caplog.at_level("WARNING", logger="tenuo.spiffe"):
        validator = SpiffeJWT(
            trust_domain=DOMAIN,
            audience=AUDIENCE,
            bundle_file=str(own_file),
            federated_bundle_files={PARTNER: str(partner_file)},
        )
    assert "shares a signing key with another domain" in caplog.text
    assert validator._federated_keys == {}
    assert validator.authenticate(authority.token()).spiffe_id == AGENT
    with pytest.raises(SpiffeError):
        validator.authenticate(authority.token(sub=PARTNER_AGENT))


def test_duplicate_key_id_reports_the_specific_refusal(tmp_path):
    own, partner = JWTAuthority(kid="shared"), JWTAuthority(kid="shared")
    own_file, partner_file = tmp_path / "own.json", tmp_path / "partner.json"
    own_file.write_bytes(jwks(own))
    partner_file.write_bytes(jwks(partner))
    validator = SpiffeJWT(
        trust_domain=DOMAIN,
        audience=AUDIENCE,
        bundle_file=str(own_file),
        federated_bundle_files={PARTNER: str(partner_file)},
    )
    with pytest.raises(SpiffeError, match="has expired"):
        validator.authenticate(partner.token(sub=PARTNER_AGENT, exp=-60))


def test_federation_configuration_is_validated(authority, tmp_path):
    path = tmp_path / "bundle.json"
    path.write_bytes(jwks(authority))
    for bad in ({DOMAIN: str(path)}, {"Partner.Test": str(path)}):
        with pytest.raises(ValueError):
            SpiffeJWT(trust_domain=DOMAIN, audience=AUDIENCE, bundle_file=str(path), federated_bundle_files=bad)


def test_workload_api_federated_jwt_bundles(authority, workload_api):  # noqa: F811
    grpc = pytest.importorskip("grpc")
    partner, foreign = JWTAuthority(), JWTAuthority()
    own, theirs = f"spiffe://{DOMAIN}", f"spiffe://{PARTNER}"
    full = bundles_response(**{own: jwks(authority), theirs: jwks(partner), "spiffe://foreign.test": jwks(foreign)})
    api = workload_api()
    api.publish_jwt_bundles(full)
    validator = SpiffeJWT.from_workload_api(
        trust_domain=DOMAIN, audience=AUDIENCE, socket_path=api.address, timeout=5, federates_with=[PARTNER]
    )
    token = partner.token(sub=PARTNER_AGENT)

    def accepted():
        try:
            return validator.authenticate(token).trust_domain == PARTNER
        except SpiffeError:
            return False

    try:
        assert accepted()
        with pytest.raises(SpiffeError, match="not in the trust bundle"):
            validator.authenticate(foreign.token(sub="spiffe://foreign.test/agent"))  # Not asked for.
        with pytest.raises(SpiffeError, match="its own trust domain's keys"):
            validator.authenticate(partner.token(sub=AGENT))
        # A malformed bundle for the partner costs only the partner; the home domain still updates.
        successor = JWTAuthority()
        api.publish_jwt_bundles(bundles_response(**{own: jwks(authority, successor), theirs: b"garbage"}))
        assert eventually(lambda: successor.kid in validator._keys)
        assert not accepted()
        api.publish_jwt_bundles(full)
        assert eventually(accepted)
        # A malformed home bundle keeps the home keys, and the partner's withdrawal still applies.
        api.publish_jwt_bundles(bundles_response(**{own: b"garbage"}))
        assert eventually(lambda: not accepted())
        assert validator.authenticate(authority.token()).spiffe_id == AGENT
        api.publish_jwt_bundles(full)
        assert eventually(accepted)
        # SPIRE stops offering the partner's bundle: its tokens are refused, the home domain's are not.
        api.publish_jwt_bundles(bundles_response(**{own: jwks(authority)}))
        assert eventually(lambda: not accepted())
        assert validator.authenticate(authority.token()).spiffe_id == AGENT
        api.publish_jwt_bundles(full)
        assert eventually(accepted)
        # Losing this workload's own identity withdraws every domain's keys.
        api.refuse = grpc.StatusCode.PERMISSION_DENIED
        api.drop_streams()
        assert eventually(lambda: not accepted())
        assert validator._federated_keys == {}
    finally:
        validator.close()
    with pytest.raises(ValueError, match="list of names"):
        SpiffeJWT.from_workload_api(
            trust_domain=DOMAIN, audience=AUDIENCE, socket_path=api.address, timeout=1, federates_with=PARTNER
        )


def test_jwt_issuance_across_trust_domains(federated):
    validator, partner, _ = federated
    seen = []

    def policy(identity, task_id):
        seen.append((identity.trust_domain, identity.svid_type))
        return SpiffeGrant(REFUND) if identity.trust_domain == PARTNER else None

    issuer = SpiffeWarrantIssuer(signing_key=SigningKey.generate(), policy=policy, jwt=validator)
    holder = SigningKey.generate()
    warrant = issue(issuer, partner.token(sub=PARTNER_AGENT), holder)
    assert seen == [(PARTNER, "jwt")] and warrant.authorized_holder == holder.public_key


def svids_response(*pairs):
    return b"".join(_field(1, _field(1, identity.encode()) + _field(2, token.encode())) for identity, token in pairs)


def test_fetch_jwt_svid_from_workload_api(authority, workload_api):  # noqa: F811
    grpc = pytest.importorskip("grpc")
    api = workload_api()
    agent_token, server_token = authority.token(), authority.token(sub=SERVER)
    api.jwt_svid_response = svids_response((AGENT, agent_token), (SERVER, server_token))
    assert fetch_jwt_svid(AUDIENCE, socket_path=api.address) == agent_token
    assert fetch_jwt_svid(AUDIENCE, socket_path=api.address, spiffe_id=SERVER) == server_token
    assert api.saw_header == ["true", "true"]
    # The request carries the audience (field 1) and the requested SPIFFE ID (field 2).
    assert api.jwt_svid_requests == [
        _field(1, AUDIENCE.encode()),
        _field(1, AUDIENCE.encode()) + _field(2, SERVER.encode()),
    ]
    with pytest.raises(SpiffeError, match="returned no JWT-SVID for"):
        fetch_jwt_svid(AUDIENCE, socket_path=api.address, spiffe_id=f"spiffe://{DOMAIN}/absent")
    api.jwt_svid_response = b""
    with pytest.raises(SpiffeError, match="returned no JWT-SVID"):
        fetch_jwt_svid(AUDIENCE, socket_path=api.address)
    api.refuse = grpc.StatusCode.PERMISSION_DENIED
    with pytest.raises(SpiffeError, match="PERMISSION_DENIED: no identity issued"):
        fetch_jwt_svid(AUDIENCE, socket_path=api.address)
    with pytest.raises(ValueError):
        fetch_jwt_svid("", socket_path=api.address)


# -- issuance -----------------------------------------------------------------


@pytest.fixture
def jwt_issuer(validator):
    root = SigningKey.generate()
    seen, records = [], []

    def policy(identity, task_id):
        seen.append((identity.spiffe_id, identity.svid_type, task_id))
        if identity.spiffe_id == AGENT and task_id == "task-123":
            return SpiffeGrant(REFUND, ttl_seconds=120, max_depth=1)
        return None

    issuer = SpiffeWarrantIssuer(signing_key=root, policy=policy, jwt=validator, audit=records.append)
    return issuer, root, seen, records


def issue(issuer, token, holder, task="task-123", **proof):
    signed = sign_jwt_holder_proof(
        proof.pop("signed_token", token),
        holder,
        audience=proof.pop("audience", AUDIENCE),
        task_id=proof.pop("signed_task", task),
        **proof,
    )
    return issuer.issue_jwt(token, holder.public_key, task, signed)


def test_jwt_issuance_and_tool_enforcement(jwt_issuer, authority):
    issuer, root, seen, records = jwt_issuer
    holder = SigningKey.generate()
    token = authority.token()
    warrant = issue(issuer, token, holder)
    assert seen == [(AGENT, "jwt", "task-123")]
    assert records[0].identity.svid_type == "jwt" and records[0].warrant_id == warrant.id
    authorizer = Authorizer(trusted_roots=[root.public_key])
    args = {"customer": "123", "cents": 4000}
    authorizer.authorize(warrant, "refund", args, warrant.sign(holder, "refund", args, int(time.time())))
    bad = {"customer": "999", "cents": 4000}
    with pytest.raises(AuthorizationError):
        authorizer.authorize(warrant, "refund", bad, warrant.sign(holder, "refund", bad, int(time.time())))


def test_warrant_never_outlives_the_token(jwt_issuer, authority):
    issuer, *_ = jwt_issuer
    warrant = issue(issuer, authority.token(exp=20), SigningKey.generate())
    assert datetime.fromisoformat(warrant.expires_at()).timestamp() <= time.time() + 20
    with pytest.raises(SpiffeError, match="expires too soon"):
        issue(issuer, authority.token(exp=1), SigningKey.generate())


def test_holder_proof_is_bound_to_token_audience_task_and_key(jwt_issuer, authority):
    issuer, *_ = jwt_issuer
    holder, token = SigningKey.generate(), authority.token()
    for changes in (
        {"signed_token": authority.token(exp=301)},
        {"audience": "spiffe://example.test/other-issuer"},
        {"signed_task": "task-999"},
    ):
        with pytest.raises(SpiffeError, match="Invalid holder proof"):
            issue(issuer, token, holder, **changes)
    other = sign_jwt_holder_proof(token, SigningKey.generate(), audience=AUDIENCE, task_id="task-123")
    good = sign_jwt_holder_proof(token, holder, audience=AUDIENCE, task_id="task-123")
    for bad in (
        other,
        SpiffeJWTProof(good.timestamp, good.nonce, b"short"),
        SpiffeJWTProof(good.timestamp, good.nonce, "text"),
        SpiffeJWTProof(good.timestamp, b"short", good.signature),
        SpiffeJWTProof(good.timestamp, bytes(16), good.signature),  # A different nonce than was signed.
        SpiffeJWTProof(good.timestamp + 1, good.nonce, good.signature),
        (good.timestamp, good.nonce, good.signature),
        None,
    ):
        with pytest.raises(SpiffeError, match="Invalid holder proof"):
            issuer.issue_jwt(token, holder.public_key, "task-123", bad)
    with pytest.raises(SpiffeError, match="PublicKey"):
        issuer.issue_jwt(token, bytes(holder.public_key.to_bytes()), "task-123", good)
    assert issuer.issue_jwt(token, holder.public_key, "task-123", good).id


def test_holder_proof_layout_matches_the_documented_bytes(jwt_issuer, authority):
    """Rebuild the signed statement from the wire-protocol description alone."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    issuer, *_ = jwt_issuer
    issuer._policy = lambda *_: SpiffeGrant(REFUND)
    holder, token = SigningKey.generate(), authority.token()
    task = "tâche-é 🎟 refund"  # Not ASCII: nothing may depend on JSON escaping.
    proof = sign_jwt_holder_proof(token, holder, audience=AUDIENCE, task_id=task)
    public = bytes(holder.public_key.to_bytes())
    statement = (
        b"tenuo.spiffe.jwt-holder-binding.v1\x00"
        + hashlib.sha256(token.encode()).digest()
        + public
        + proof.timestamp.to_bytes(8, "big")
        + proof.nonce
        + hashlib.sha256(AUDIENCE.encode()).digest()
        + hashlib.sha256(task.encode()).digest()
    )
    assert len(statement) == 35 + 32 + 32 + 8 + 16 + 32 + 32 and len(proof.nonce) == 16
    Ed25519PublicKey.from_public_bytes(public).verify(proof.signature, statement)
    assert issuer.issue_jwt(token, holder.public_key, task, proof).id
    assert sign_jwt_holder_proof(token, holder, audience=AUDIENCE, task_id=task).signature != proof.signature


def test_holder_proof_freshness_and_replay(jwt_issuer, authority):
    issuer, _, seen, _ = jwt_issuer
    holder, token = SigningKey.generate(), authority.token()
    for offset in (-120, 120):
        with pytest.raises(SpiffeError, match="too old or from the future"):
            issue(issuer, token, holder, timestamp=int(time.time()) + offset)
    for bad in (True, "now", 1.5, None, -5, 10**400):
        with pytest.raises(SpiffeError, match="too old or from the future"):
            issuer.issue_jwt(token, holder.public_key, "task-123", SpiffeJWTProof(bad, bytes(16), bytes(64)))
    assert seen == []  # Policy is not consulted for a request without a valid proof.
    proof = sign_jwt_holder_proof(token, holder, audience=AUDIENCE, task_id="task-123")
    issuer.issue_jwt(token, holder.public_key, "task-123", proof)
    with pytest.raises(SpiffeError, match="already used"):
        issuer.issue_jwt(token, holder.public_key, "task-123", proof)
    issue(issuer, token, holder)  # A new proof for the same token, even in the same second, is fine.


def test_failed_requests_can_be_retried_and_leave_no_proof_behind(jwt_issuer, authority):
    issuer, *_ = jwt_issuer
    holder, token = SigningKey.generate(), authority.token()
    approve = issuer._policy

    def broken(*_):
        raise RuntimeError("database down")

    proof = sign_jwt_holder_proof(token, holder, audience=AUDIENCE, task_id="task-123")
    issuer._policy = broken
    with pytest.raises(RuntimeError):
        issuer.issue_jwt(token, holder.public_key, "task-123", proof)
    issuer._policy = approve
    assert issuer._proofs == {}
    assert issuer.issue_jwt(token, holder.public_key, "task-123", proof).id  # The very same request, retried.
    # Denied requests do not occupy the replay memory, so they cannot push real entries out.
    kept = dict(issuer._proofs)
    for _ in range(50):
        with pytest.raises(SpiffeError, match="not authorized"):
            issue(issuer, token, holder, task="unknown")
    assert issuer._proofs == kept and len(kept) == 1


def test_full_proof_memory_refuses_new_requests_and_never_forgets_a_live_proof(validator, authority, monkeypatch):
    root = SigningKey.generate()
    issuer = SpiffeWarrantIssuer(
        signing_key=root,
        policy=lambda identity, task: SpiffeGrant(REFUND) if task == "task-123" else None,
        jwt=validator,
        max_jwt_proofs=4,
    )
    holder, token = SigningKey.generate(), authority.token()
    first = sign_jwt_holder_proof(token, holder, audience=AUDIENCE, task_id="task-123")
    issuer.issue_jwt(token, holder.public_key, "task-123", first)
    for _ in range(3):
        issue(issuer, token, holder)
    # Full: new requests are asked to retry, whether or not policy would approve them.
    for task in ("task-123", "unknown"):
        with pytest.raises(SpiffeError, match="retry shortly"):
            issue(issuer, token, holder, task=task)
    # Nothing was dropped to make room, so the earliest request still cannot be replayed.
    with pytest.raises(SpiffeError, match="already used"):
        issuer.issue_jwt(token, holder.public_key, "task-123", first)
    assert len(issuer._proofs) == 4
    # Entries expire once their timestamps are no longer acceptable, and admissions resume.
    later = time.monotonic() + 62
    monkeypatch.setattr("tenuo.spiffe.time.monotonic", lambda: later)
    assert issue(issuer, token, holder).id
    assert len(issuer._proofs) == 1
    with pytest.raises(ValueError):
        SpiffeWarrantIssuer(signing_key=root, policy=lambda *_: None, jwt=validator, max_jwt_proofs=0)


def test_full_proof_memory_answers_503(validator, authority):
    issuer = SpiffeWarrantIssuer(
        signing_key=SigningKey.generate(), policy=lambda *_: SpiffeGrant(REFUND), jwt=validator, max_jwt_proofs=1
    )
    application = SpiffeJWTIssuerApp(issuer)
    holder, token = SigningKey.generate(), authority.token()
    try:
        statuses = [
            call_app(application, headers=[("Authorization", f"Bearer {token}")], body=request_body(token, holder))[0]
            for _ in range(2)
        ]
    finally:
        application.close()
    assert statuses == [200, 503]


def test_jwt_policy_denials_and_invalid_grants(jwt_issuer, authority):
    issuer, *_ = jwt_issuer
    with pytest.raises(SpiffeError, match="not authorized"):
        issue(issuer, authority.token(), SigningKey.generate(), task="unknown")
    with pytest.raises(SpiffeError, match="not authorized"):
        issue(issuer, authority.token(sub=SERVER), SigningKey.generate())
    with pytest.raises(SpiffeError, match="task_id must contain"):
        issuer.issue_jwt(authority.token(), SigningKey.generate().public_key, "", None)
    issuer._policy = lambda *_: SpiffeGrant({"refund": {}})
    with pytest.raises(SpiffeError, match="Empty constraints"):
        issue(issuer, authority.token(), SigningKey.generate())


def test_issuer_modes_are_explicit(validator, authority):
    root = SigningKey.generate()
    with pytest.raises(ValueError, match="tls .* jwt"):
        SpiffeWarrantIssuer(signing_key=root, policy=lambda *_: None)
    jwt_only = SpiffeWarrantIssuer(signing_key=root, policy=lambda *_: SpiffeGrant(REFUND), jwt=validator)
    with pytest.raises(SpiffeError, match="does not accept X.509-SVIDs"):
        jwt_only.challenge(object(), root.public_key, "task-123")
    with pytest.raises(ValueError, match="SpiffeJWTIssuerApp"):
        SpiffeIssuerServer(jwt_only, host="127.0.0.1", port=0)


def test_jwt_endpoint_needs_a_jwt_issuer(tmp_path):
    from .test_spiffe import CA, _tls

    mtls_only = SpiffeWarrantIssuer(
        tls=_tls(CA(tmp_path).files("mtls-only", SERVER), True),
        signing_key=SigningKey.generate(),
        policy=lambda *_: None,
    )
    with pytest.raises(ValueError, match="jwt=SpiffeJWT"):
        SpiffeJWTIssuerApp(mtls_only)
    with pytest.raises(SpiffeError, match="does not accept JWT-SVIDs"):
        mtls_only.issue_jwt("a.b.c", SigningKey.generate().public_key, "task-123", None)


# -- HTTP endpoint ------------------------------------------------------------


def request_body(token, holder_key, task="task-123", **overrides):
    proof = sign_jwt_holder_proof(token, holder_key, audience=AUDIENCE, task_id=task)
    body = {
        "v": 1,
        "holder": base64.b64encode(bytes(holder_key.public_key.to_bytes())).decode(),
        "task": task,
        "timestamp": proof.timestamp,
        "nonce": base64.b64encode(proof.nonce).decode(),
        "signature": base64.b64encode(proof.signature).decode(),
    }
    body.update(overrides)
    return json.dumps(body).encode()


def call_app(app, *, method="POST", path="/warrants", headers=None, body=b"", chunks=None, root_path=""):
    """Drive the ASGI app directly and return (status, headers, json)."""

    async def run():
        pieces = list(chunks) if chunks is not None else [body]
        sent = []

        async def receive():
            piece = pieces.pop(0) if pieces else b""
            return {"type": "http.request", "body": piece, "more_body": bool(pieces)}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "method": method,
            "path": root_path + path,
            "root_path": root_path,
            "headers": [(name.lower().encode(), value.encode()) for name, value in (headers or [])],
        }
        await app(scope, receive, send)
        await asyncio.sleep(0.01)  # Let worker completions land.
        start, reply = sent[0], sent[1]
        return start["status"], dict(start["headers"]), json.loads(reply["body"])

    return asyncio.run(run())


@pytest.fixture
def app(jwt_issuer):
    issuer, root, *_ = jwt_issuer
    application = SpiffeJWTIssuerApp(issuer)
    yield application, issuer, root
    application.close()


def test_endpoint_issues_a_warrant(app, authority):
    application, _, root = app
    holder, token = SigningKey.generate(), authority.token()
    status, headers, reply = call_app(
        application, headers=[("Authorization", f"Bearer {token}")], body=request_body(token, holder)
    )
    assert status == 200 and headers[b"cache-control"] == b"no-store"
    from tenuo import Warrant

    warrant = Warrant.from_base64(reply["warrant"])
    assert warrant.authorized_holder == holder.public_key and warrant.issuer == root.public_key
    # Split bodies, a lower-case scheme, and a mount prefix all work.
    token = authority.token(exp=299)
    body = request_body(token, holder)
    status, _, _ = call_app(
        application,
        headers=[("authorization", f"bearer {token}")],
        chunks=[body[:10], body[10:]],
        root_path="/tenuo",
    )
    assert status == 200


def test_endpoint_refusals(app, authority):
    application, issuer, _ = app
    holder, token = SigningKey.generate(), authority.token()
    good = [("Authorization", f"Bearer {token}")]
    body = request_body(token, holder)

    def status_of(**kwargs):
        status, headers, reply = call_app(application, **kwargs)
        assert set(reply) == {"error", "message"} and "warrant" not in reply
        return status, headers, reply["message"]

    assert status_of(path="/other", headers=good, body=body)[0] == 404
    assert status_of(method="GET", headers=good, body=body)[0] == 405
    for headers in ([], [("Authorization", "Basic abc")], good + good, [("Authorization", "Bearer ")]):
        status, reply_headers, _ = status_of(headers=headers, body=body)
        assert status == 401 and reply_headers[b"www-authenticate"] == b"Bearer"
    expired = authority.token(exp=-60)
    status, _, message = status_of(headers=[("Authorization", f"Bearer {expired}")], body=request_body(expired, holder))
    assert (status, message) == (401, "JWT-SVID has expired")
    assert status_of(headers=good, body=b"x" * (70 * 1024))[0] == 413
    for malformed in (
        b"",
        b"not json",
        b"[]",
        b"[" * 5000,
        request_body(token, holder, extra=1),
        request_body(token, holder, v=2),
        request_body(token, holder, holder="!!"),
        request_body(token, holder, holder="AAAA"),
        request_body(token, holder, signature=5),
    ):
        assert status_of(headers=good, body=malformed)[0] == 400
    status, _, message = status_of(headers=good, body=request_body(token, holder, task="unknown"))
    assert (status, message) == (403, "Workload is not authorized for this task")
    status, _, message = status_of(headers=good, body=request_body(token, holder, timestamp=int(time.time()) - 600))
    assert status == 403 and "too old" in message
    assert issuer._proofs == {} or len(issuer._proofs) <= 1


def test_endpoint_reports_callback_failures_and_stays_bounded(app, authority):
    application, issuer, _ = app
    holder = SigningKey.generate()

    def broken(*_):
        raise RuntimeError("database down")

    issuer._policy = broken
    token = authority.token()
    status, _, reply = call_app(
        application, headers=[("Authorization", f"Bearer {token}")], body=request_body(token, holder)
    )
    assert (status, reply) == (503, {"error": "unavailable", "message": "Issuer error"})

    gate = threading.Event()

    def slow(*_):
        gate.wait(5)
        return SpiffeGrant(REFUND)

    issuer._policy = slow
    limited = SpiffeJWTIssuerApp(issuer, max_concurrent=1, max_workers=1)

    async def scenario():
        async def one():
            token = authority.token(exp=300 + secrets.randbelow(1000))
            sent = []

            async def receive():
                return {"type": "http.request", "body": request_body(token, holder), "more_body": False}

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/warrants",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            }
            await limited(scope, receive, lambda message: _collect(sent, message))
            return sent[0]["status"]

        first = asyncio.ensure_future(one())
        await asyncio.sleep(0.2)
        second = await one()  # The only slot is taken.
        gate.set()
        return await first, second

    try:
        assert asyncio.run(scenario()) == (200, 503)
    finally:
        gate.set()
        limited.close()


async def _collect(sent, message):
    sent.append(message)


def test_endpoint_bounds_and_times_out_body_reads(jwt_issuer, authority):
    issuer, *_ = jwt_issuer
    application = SpiffeJWTIssuerApp(issuer, max_concurrent=2, body_timeout=0.3)
    token = authority.token()
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/warrants",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
    }

    async def scenario():
        async def never():
            await asyncio.sleep(30)

        async def one(receive):
            sent = []
            await application(scope, receive, lambda message: _collect(sent, message))
            return sent[0]["status"]

        stalled = [asyncio.ensure_future(one(never)) for _ in range(2)]
        await asyncio.sleep(0.05)
        refused = await one(never)  # Both read slots are taken by senders that never finish.
        return refused, await asyncio.gather(*stalled), application._reading

    try:
        assert asyncio.run(scenario()) == (503, [408, 408], 0)
    finally:
        application.close()


def test_endpoint_refuses_absurd_numbers_without_failing(app, authority):
    application, *_ = app
    holder, token = SigningKey.generate(), authority.token()
    for timestamp in (10**400, -1, 1.5, "soon", None, True):
        status, _, reply = call_app(
            application,
            headers=[("Authorization", f"Bearer {token}")],
            body=request_body(token, holder, timestamp=timestamp),
        )
        assert status == 403 and "too old or from the future" in reply["message"]
    for nonce in ("", "AAAA", 5, None):
        status, _, _ = call_app(
            application, headers=[("Authorization", f"Bearer {token}")], body=request_body(token, holder, nonce=nonce)
        )
        assert status in (400, 403)


def test_endpoint_lifespan(app):
    application, *_ = app

    async def run():
        events = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
        sent = []

        async def receive():
            return events.pop(0)

        await application({"type": "lifespan"}, receive, lambda message: _collect(sent, message))
        return [message["type"] for message in sent]

    assert asyncio.run(run()) == ["lifespan.startup.complete", "lifespan.shutdown.complete"]


# -- over real HTTP -----------------------------------------------------------


def tls_server_files(directory):
    """A CA and a localhost server certificate, as a load balancer or ASGI server would present."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test web CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(True, None), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    import ipaddress

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            False,
        )
        .add_extension(x509.BasicConstraints(False, None), True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    paths = {name: directory / f"web-{name}.pem" for name in ("ca", "cert", "key")}
    paths["ca"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    paths["cert"].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    paths["key"].write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return paths


@pytest.fixture
def serve():
    uvicorn = pytest.importorskip("uvicorn")
    running = []

    def start(application, **tls):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        config = uvicorn.Config(application, host="127.0.0.1", port=port, log_level="warning", **tls)
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        assert eventually(lambda: server.started, seconds=10)
        running.append((server, thread))
        return port

    yield start
    for server, thread in running:
        server.should_exit = True
        thread.join(timeout=10)


def test_client_and_endpoint_over_http_and_https(app, authority, serve, tmp_path):
    application, issuer, root = app
    holder = SigningKey.generate()
    options = dict(audience=AUDIENCE, issuer_key=root.public_key, holder_key=holder, task_id="task-123")
    port = serve(application)
    warrant = request_warrant_jwt(f"http://127.0.0.1:{port}/warrants", token=authority.token(), **options)
    assert warrant.authorized_holder == holder.public_key

    web = tls_server_files(tmp_path)
    secure = serve(application, ssl_certfile=str(web["cert"]), ssl_keyfile=str(web["key"]))
    url = f"https://localhost:{secure}/warrants"
    calls = []

    def token():
        calls.append(1)
        return authority.token(exp=300 + len(calls)) + "\n"  # As read from a file.

    assert request_warrant_jwt(url, token=token, ca_file=str(web["ca"]), **options).id != warrant.id
    assert calls == [1]

    # Refusals reach the caller as SpiffeError with the issuer's reason.
    with pytest.raises(SpiffeError, match=r"Issuer refused \(HTTP 403\): Workload is not authorized"):
        request_warrant_jwt(url, token=authority.token(), ca_file=str(web["ca"]), **{**options, "task_id": "unknown"})
    with pytest.raises(SpiffeError, match=r"Issuer refused \(HTTP 401\): JWT-SVID has expired"):
        request_warrant_jwt(url, token=authority.token(exp=-60), ca_file=str(web["ca"]), **options)
    with pytest.raises(SpiffeError, match=r"HTTP 401.*not for this issuer's audience"):
        request_warrant_jwt(url, token=authority.token(aud="other"), ca_file=str(web["ca"]), **options)
    with pytest.raises(SpiffeError, match=r"HTTP 404"):
        request_warrant_jwt(
            f"https://localhost:{secure}/elsewhere", token=authority.token(), ca_file=str(web["ca"]), **options
        )
    # The server's certificate must verify: no CA configured means the system roots, which do not know it.
    with pytest.raises(SpiffeError, match="was not accepted"):
        request_warrant_jwt(url, token=authority.token(), **options)
    # A warrant from a key the agent does not trust is not returned.
    with pytest.raises(SpiffeError, match="failed verification"):
        request_warrant_jwt(
            url,
            token=authority.token(),
            ca_file=str(web["ca"]),
            **{**options, "issuer_key": SigningKey.generate().public_key},
        )
    assert request_warrant_jwt(
        url,
        token=authority.token(exp=250),
        ca_file=str(web["ca"]),
        **{**options, "issuer_key": [SigningKey.generate().public_key, root.public_key]},
    ).id


def test_client_never_sends_the_token_in_the_clear():
    holder = SigningKey.generate()
    options = dict(token="a.b.c", audience=AUDIENCE, issuer_key=holder.public_key, holder_key=holder, task_id="t")
    for url in (
        "http://issuer.acme.internal/warrants",
        "http://10.0.0.5:8080/warrants",
        "ftp://localhost/warrants",
        "https://user:secret@localhost/warrants",
        "https://localhost/warrants#fragment",
        "localhost:8443/warrants",
    ):
        with pytest.raises(ValueError):
            request_warrant_jwt(url, **options)
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    with pytest.raises(SpiffeError, match="Could not complete the exchange"):
        request_warrant_jwt(f"http://127.0.0.1:{port}/warrants", timeout=2, **options)


def test_client_addresses_ipv6_hosts_correctly(authority, monkeypatch):
    """A bare IPv6 host must not have its last group read as the port."""
    import http.client

    seen = []

    class Recorder:
        def __init__(self, host, port=None, **_):
            seen.append((host, port))

        def request(self, *_, **__):
            raise OSError("stop here")

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", Recorder)
    monkeypatch.setattr(http.client, "HTTPSConnection", Recorder)
    holder = SigningKey.generate()
    options = dict(
        token=authority.token(), audience=AUDIENCE, issuer_key=holder.public_key, holder_key=holder, task_id="t"
    )
    for url, expected in (
        ("http://[::1]/warrants", ("::1", 80)),
        ("http://[::1]:9000/warrants", ("::1", 9000)),
        ("https://[fd00::1:8443]/warrants", ("fd00::1:8443", 443)),
        ("https://issuer.acme.internal/warrants", ("issuer.acme.internal", 443)),
        ("https://issuer.acme.internal:8443/warrants", ("issuer.acme.internal", 8443)),
    ):
        with pytest.raises(SpiffeError, match="Could not complete the exchange"):
            request_warrant_jwt(url, **options)
        assert seen[-1] == expected
    for bad in ("https://issuer.acme.internal:port/warrants", "https://[::1/warrants", "http://[::ffff:10.0.0.1]/w"):
        with pytest.raises(ValueError):
            request_warrant_jwt(bad, **options)


def test_client_does_not_follow_redirects(authority):
    """A redirect must not carry the bearer token to another host."""
    received = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def answer():
        connection, _ = listener.accept()
        with connection:
            received.append(connection.recv(65536))
            connection.sendall(
                b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/steal\r\nContent-Length: 0\r\n\r\n"
            )

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    holder = SigningKey.generate()
    try:
        with pytest.raises(SpiffeError, match="HTTP 307 without a warrant"):
            request_warrant_jwt(
                f"http://127.0.0.1:{port}/warrants",
                token=authority.token(),
                audience=AUDIENCE,
                issuer_key=holder.public_key,
                holder_key=holder,
                task_id="task-123",
            )
    finally:
        thread.join(timeout=5)
        listener.close()
    assert len(received) == 1 and b"Authorization: Bearer " in received[0]


def test_mtls_and_jwt_on_one_issuer(validator, authority, tmp_path):
    """One issuer, one policy and one audit log can serve both kinds of SVID."""
    from .test_spiffe import CA, _tls, connect
    from tenuo.spiffe import sign_holder_challenge

    ca = CA(tmp_path)
    server = _tls(ca.files("both-server", SERVER), True)
    client = _tls(ca.files("both-agent", AGENT), False)
    root, kinds = SigningKey.generate(), []

    def policy(identity, task_id):
        kinds.append(identity.svid_type)
        cents = 5000 if identity.svid_type == "x509" else 500  # Less for bearer tokens.
        return SpiffeGrant({"refund": {"customer": Exact("123"), "cents": Range(1, cents)}})

    issuer = SpiffeWarrantIssuer(tls=server, signing_key=root, policy=policy, jwt=validator)
    holder = SigningKey.generate()
    connection, _ = connect(server, client)
    challenge = issuer.challenge(connection, holder.public_key, "task-123")
    over_mtls = issuer.issue(connection, challenge, sign_holder_challenge(challenge, holder, task_id="task-123"))
    over_jwt = issue(issuer, authority.token(), holder)
    assert kinds == ["x509", "jwt"]
    authorizer = Authorizer(trusted_roots=[root.public_key])
    args = {"customer": "123", "cents": 4000}
    authorizer.authorize(over_mtls, "refund", args, over_mtls.sign(holder, "refund", args, int(time.time())))
    with pytest.raises(AuthorizationError):
        authorizer.authorize(over_jwt, "refund", args, over_jwt.sign(holder, "refund", args, int(time.time())))
    # A JWT identity cannot be passed off on the mTLS path, or the reverse.
    with pytest.raises(SpiffeError):
        issuer._issue_jwt(server.authenticate(connection), holder.public_key, "task-123", None)


def test_guide_jwt_code_runs(tmp_path, monkeypatch, authority, workload_api, serve):  # noqa: F811
    """Execute the guide's JWT issuer and agent blocks against a fake SPIRE agent."""
    from .test_spiffe import _guide_blocks

    blocks = _guide_blocks()
    acme, refund_agent = "acme.test", "spiffe://acme.test/agents/refund"
    issuer_api, agent_api = workload_api(), workload_api()
    issuer_api.publish_jwt_bundles(bundles_response(**{f"spiffe://{acme}": jwks(authority)}))
    audiences = []

    def mint(request):
        audiences.append(request)
        return svids_response((refund_agent, authority.token(sub=refund_agent, aud="spiffe://acme.test/issuer")))

    agent_api.jwt_svid_response = mint

    def localize(code, api):
        assert code.count('"/run/spire/sockets/agent.sock"') == 1
        code = code.replace('"/run/spire/sockets/agent.sock"', repr(api.address))
        code = code.replace("/run/secrets/tenuo-issuer.pem", (tmp_path / "tenuo-issuer.pem").as_posix()).replace(
            "/etc/tenuo/tenuo-issuer.pub", (tmp_path / "tenuo-issuer.pub").as_posix()
        )
        assert "/run/" not in code and "/etc/" not in code
        return code

    monkeypatch.chdir(tmp_path)
    exec(blocks["make_issuer_key.py"], {})
    issuer_scope: dict = {}
    agent_scope: dict = {}
    try:
        exec(localize(blocks["jwt_issuer.py"], issuer_api), issuer_scope)
        port = serve(issuer_scope["app"])
        agent_code = localize(blocks["jwt_agent.py"], agent_api)
        assert agent_code.count('"https://issuer.acme.internal/warrants"') == 1
        exec(
            agent_code.replace('"https://issuer.acme.internal/warrants"', repr(f"http://127.0.0.1:{port}/warrants")),
            agent_scope,
        )
    finally:
        if "tokens" in issuer_scope:
            issuer_scope["tokens"].close()
        if "app" in issuer_scope:
            issuer_scope["app"].close()
    assert audiences == [_field(1, b"spiffe://acme.test/issuer")]  # The agent asked SPIRE for the issuer's audience.

    warrant, holder = agent_scope["warrant"], agent_scope["holder_key"]
    tool_scope: dict = {}
    exec(
        blocks["tool.py"].replace("/etc/tenuo/tenuo-issuer.pub", (tmp_path / "tenuo-issuer.pub").as_posix()), tool_scope
    )

    def call(args):
        proof = warrant.sign(holder, "refund", args, int(time.time()))
        return {"chain": [warrant.to_base64()], "args": args, "proof": base64.b64encode(proof).decode()}

    refund = tool_scope["refund"]
    assert refund(call({"customer": "123", "cents": 2000})) == "refunded 2000 cents to customer 123"
    # The guide's policy grants a bearer token less than an mTLS peer.
    assert refund(call({"customer": "123", "cents": 4000})).startswith("denied: ")
    assert refund(call({"customer": "999", "cents": 100})).startswith("denied: ")
