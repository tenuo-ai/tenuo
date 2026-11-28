"""A real GitHub Actions workflow token, exchanged for a task-scoped warrant.

Runs inside a workflow job that has ``permissions: id-token: write``. The
token is minted by GitHub for this run and checked against GitHub's published
keys: nothing here is a generated stand-in. Elsewhere the test is skipped,
unless ``TENUO_REQUIRE_GITHUB_OIDC=1`` says it must run.
"""

# ruff: noqa: E402
import json
import os
import socket
import threading
import time
import urllib.request

import pytest

pytest.importorskip("jwt")
uvicorn = pytest.importorskip("uvicorn")

from tenuo import Authorizer, Exact, SigningKey
from tenuo.oauth import (
    GITHUB_ACTIONS,
    OAuthError,
    OAuthTokens,
    OAuthWarrantIssuer,
    OAuthWarrantIssuerApp,
    TaskGrant,
    Trust,
    request_warrant_oauth,
)

GITHUB = "https://token.actions.githubusercontent.com"
AUDIENCE = "tenuo-authority"
REQUEST_URL = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
REQUEST_TOKEN = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
REQUIRED = os.environ.get("TENUO_REQUIRE_GITHUB_OIDC") == "1"

pytestmark = pytest.mark.skipif(
    not (REQUEST_URL and REQUEST_TOKEN) and not REQUIRED,
    reason="Needs a GitHub Actions job with permissions: id-token: write",
)


def workflow_token(audience=AUDIENCE):
    assert REQUEST_URL and REQUEST_TOKEN, "This job has no id-token permission"
    request = urllib.request.Request(
        f"{REQUEST_URL}&audience={audience}", headers={"Authorization": f"Bearer {REQUEST_TOKEN}"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)["value"]


def trust(**where):
    return OAuthTokens(Trust(GITHUB, AUDIENCE, GITHUB + "/.well-known/jwks", GITHUB_ACTIONS, where=where))


def test_a_workflow_run_gets_a_warrant_for_its_own_repository_only():
    repository = os.environ["GITHUB_REPOSITORY"]
    token = workflow_token()
    identity = trust(repository=repository).authenticate(token)
    assert identity.issuer == GITHUB and identity.client_id is None and identity.scopes == frozenset()
    assert identity.subject.startswith(f"repo:{repository}:")
    assert identity.claims["repository"] == repository and identity.claims["run_id"] == os.environ["GITHUB_RUN_ID"]

    for refused in (
        trust(repository="someone-else/" + repository.split("/")[1]),  # Another owner's repository.
        trust(repository=repository, ref="refs/heads/a-branch-that-does-not-exist"),
        trust(repository=repository, environment="production"),  # This job runs in no environment.
    ):
        with pytest.raises(OAuthError):
            refused.authenticate(token)
    with pytest.raises(OAuthError):  # A token GitHub minted for another audience.
        trust(repository=repository).authenticate(workflow_token("another-service"))

    seen = []

    def policy(identity, task_id):
        seen.append((identity.claims["repository"], identity.claims["workflow"], task_id))
        if task_id != "deploy-staging":
            return None
        return TaskGrant(
            {"deploy": {"repository": Exact(identity.claims["repository"]), "environment": Exact("staging")}},
            ttl_seconds=60,
        )

    root, holder = SigningKey.generate(), SigningKey.generate()
    audits = []
    issuer = OAuthWarrantIssuer(
        credentials=trust(repository=repository), signing_key=root, policy=policy, audit=audits.append
    )
    app = OAuthWarrantIssuerApp(issuer)
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
            token=token, audience=AUDIENCE, issuer_key=root.public_key, holder_key=holder, allow_loopback_http=True
        )
        url = f"http://127.0.0.1:{port}/warrants"
        warrant = request_warrant_oauth(url, task_id="deploy-staging", **options)
        with pytest.raises(OAuthError, match="HTTP 403"):
            request_warrant_oauth(url, task_id="deploy-production", **options)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        app.close()

    assert [record.identity.subject for record in audits] == [identity.subject]
    assert seen[0][0] == repository and seen[0][2] == "deploy-staging"
    authorizer = Authorizer(trusted_roots=[root.public_key])
    for arguments, expected in (
        ({"repository": repository, "environment": "staging"}, True),
        ({"repository": repository, "environment": "production"}, False),
        ({"repository": "someone-else/project", "environment": "staging"}, False),
    ):
        signature = warrant.sign(holder, "deploy", arguments, int(time.time()))
        try:
            authorizer.authorize(warrant, "deploy", arguments, signature)
            granted = True
        except Exception:
            granted = False
        assert granted is expected, arguments
