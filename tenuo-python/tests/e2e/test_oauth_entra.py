"""A real Microsoft Entra ID access token, exchanged for a task-scoped warrant.

Runs inside a GitHub Actions job with ``permissions: id-token: write``. The job
holds no secret: it presents its own GitHub OIDC token to Entra as the client
assertion (workload identity federation), receives an Entra access token for a
test API, and exchanges that for a warrant. Entra signs the token and
publishes the keys it is checked against.

Three identifiers say which tenant and applications to use. They are not
secrets. Without them the test is skipped, unless ``TENUO_REQUIRE_ENTRA=1``.
"""

# ruff: noqa: E402
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

jwt = pytest.importorskip("jwt")
uvicorn = pytest.importorskip("uvicorn")

from tenuo import Authorizer, Exact, SigningKey
from tenuo.oauth import (
    ENTRA_ID,
    GITHUB_ACTIONS,
    ClaimMap,
    OAuthError,
    OAuthTokens,
    OAuthWarrantIssuer,
    OAuthWarrantIssuerApp,
    TaskGrant,
    Trust,
    request_warrant_oauth,
)

TENANT = os.environ.get("TENUO_ENTRA_TENANT_ID")
API = os.environ.get("TENUO_ENTRA_API_CLIENT_ID")  # The application that stands for the warrant issuer.
CLIENT = os.environ.get("TENUO_ENTRA_CLIENT_ID")  # The application the CI job acts as.
ROLE = os.environ.get("TENUO_ENTRA_APP_ROLE", "Warrants.Request")
REQUEST_URL = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
REQUEST_TOKEN = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
REQUIRED = os.environ.get("TENUO_REQUIRE_ENTRA") == "1"

pytestmark = pytest.mark.skipif(
    not (TENANT and API and CLIENT and REQUEST_URL and REQUEST_TOKEN) and not REQUIRED,
    reason="Needs an Entra tenant set up for this repository and a job with permissions: id-token: write",
)


def github_token(audience):
    request = urllib.request.Request(
        f"{REQUEST_URL}&audience={urllib.parse.quote(audience, safe='')}",
        headers={"Authorization": f"Bearer {REQUEST_TOKEN}"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)["value"]


def entra_token():
    """Client credentials with this run's GitHub token as the client assertion. No secret is involved."""
    form = {
        "grant_type": "client_credentials",
        "client_id": CLIENT,
        "scope": f"api://{API}/.default",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": github_token("api://AzureADTokenExchange"),
    }
    request = urllib.request.Request(
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token", data=urllib.parse.urlencode(form).encode()
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)["access_token"]
    except urllib.error.HTTPError as error:
        reply = json.loads(error.read() or b"{}")
        # Entra says which part of the set-up is missing. The description holds no credential.
        pytest.fail(f"Entra refused the token request: {reply.get('error')}: {reply.get('error_description')}")


def trust(**changes):
    base = f"https://login.microsoftonline.com/{TENANT}"
    options = dict(
        issuer=base + "/v2.0",
        audience=API,
        jwks_url=base + "/discovery/v2.0/keys",
        claims=ENTRA_ID,
        clients=frozenset({CLIENT}),
        where={"tid": TENANT},
        required_scopes=frozenset({ROLE}),
    )
    options.update(changes)
    return OAuthTokens(Trust(**options))


def test_an_entra_application_gets_a_warrant_for_its_task():
    assert TENANT and API and CLIENT and REQUEST_URL and REQUEST_TOKEN, (
        "Entra identifiers or id-token permission missing"
    )
    token = entra_token()
    header = jwt.get_unverified_header(token)
    print("Entra access token header fields:", sorted(header), "typ:", header.get("typ"))
    print("Entra access token claims:", sorted(jwt.decode(token, options={"verify_signature": False})))

    identity = trust().authenticate(token)
    assert identity.issuer.endswith(f"/{TENANT}/v2.0") and identity.client_id == CLIENT
    assert ROLE in identity.scopes and identity.claims["tid"] == TENANT

    for refused in (
        trust(audience="api://some-other-api"),
        trust(clients=frozenset({"00000000-0000-0000-0000-000000000000"})),
        trust(required_scopes=frozenset({"A.Role.Nobody.Granted"})),
        trust(where={"tid": "00000000-0000-0000-0000-000000000000"}),
        trust(claims=ClaimMap(client=("azp",), scopes=("roles",), header_type="at+jwt")),
    ):
        with pytest.raises(OAuthError):
            refused.authenticate(token)
    # The GitHub token that was traded for it is not an Entra token, and the Entra token is not a GitHub one.
    with pytest.raises(OAuthError):
        trust().authenticate(github_token("api://AzureADTokenExchange"))
    github = OAuthTokens(
        Trust(
            "https://token.actions.githubusercontent.com",
            API,
            "https://token.actions.githubusercontent.com/.well-known/jwks",
            GITHUB_ACTIONS,
            where={"repository": os.environ["GITHUB_REPOSITORY"]},
        )
    )
    with pytest.raises(OAuthError):
        github.authenticate(token)

    def policy(identity, task_id):
        if task_id != "rotate-staging-key" or ROLE not in identity.scopes:
            return None
        return TaskGrant({"rotate_key": {"environment": Exact("staging")}}, ttl_seconds=60)

    root, holder, audits = SigningKey.generate(), SigningKey.generate(), []
    app = OAuthWarrantIssuerApp(
        OAuthWarrantIssuer(credentials=trust(), signing_key=root, policy=policy, audit=audits.append)
    )
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
        options = dict(
            token=token, audience=API, issuer_key=root.public_key, holder_key=holder, allow_loopback_http=True
        )
        url = f"http://127.0.0.1:{port}/warrants"
        warrant = request_warrant_oauth(url, task_id="rotate-staging-key", **options)
        with pytest.raises(OAuthError, match="HTTP 403"):
            request_warrant_oauth(url, task_id="rotate-production-key", **options)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        app.close()

    assert [record.identity.client_id for record in audits] == [CLIENT]
    authorizer = Authorizer(trusted_roots=[root.public_key])
    for arguments, expected in (({"environment": "staging"}, True), ({"environment": "production"}, False)):
        signature = warrant.sign(holder, "rotate_key", arguments, int(time.time()))
        try:
            authorizer.authorize(warrant, "rotate_key", arguments, signature)
            granted = True
        except Exception:
            granted = False
        assert granted is expected, arguments
