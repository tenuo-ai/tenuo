"""Independent RFC 9068 provider: actual browser PKCE, refresh, issuance and tools.

The provider is pinned node-oidc-provider. Its development login UI is a fixture,
not production user authentication. Tokens/JWKS/code/refresh handling are real.
"""

import asyncio
import base64
import hashlib
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
from playwright.sync_api import sync_playwright
from tenuo import SigningKey
from tenuo.oauth import (
    RFC9068,
    OAuthError,
    OAuthTokens,
    OAuthWarrantIssuer,
    OAuthWarrantIssuerApp,
    SQLiteProofStore,
    Trust,
    request_warrant_oauth,
)

from email_smoke import exercise_email
from refund_policy import policy_for
from smoke import callback_server, check, exercise_mcp, issuer_server

HERE = Path(__file__).resolve().parent
RESOURCE = "https://tenuo.example.test/authority"


def login(
    browser,
    http,
    discovery,
    callback,
    *,
    user="alice",
    client="support",
    resource=RESOURCE,
    bad_verifier=False,
    replay_code=False,
):
    verifier, state, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    scope = "mail:send" if client == "mail-support" else "refunds:write"
    query = urlencode(
        dict(
            client_id=client,
            response_type="code",
            redirect_uri=callback,
            scope="openid offline_access " + scope,
            resource=resource,
            state=state,
            nonce=nonce,
            prompt="consent",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    )
    with browser.new_context() as context:
        # The provider's development stylesheet references external fonts. Keep the test local.
        context.route(
            "**/*",
            lambda route: route.continue_() if urlsplit(route.request.url).hostname == "127.0.0.1" else route.abort(),
        )
        page = context.new_page()
        page.goto(discovery["authorization_endpoint"] + "?" + query)
        page.locator('input[name="login"]').fill(user)
        page.locator('input[name="password"]').fill("local-fixture-password")
        page.get_by_role("button", name="Sign-in", exact=True).click()
        page.get_by_role("button", name="Continue", exact=True).click()
        page.wait_for_url(callback + "?**", timeout=20000)
        params = parse_qs(urlsplit(page.url).query)
        check(
            params.get("state") == [state] and params.get("iss") == [discovery["issuer"]],
            "independent provider state and response issuer checked",
        )
    data = dict(
        grant_type="authorization_code",
        client_id=client,
        redirect_uri=callback,
        code=params["code"][0],
        code_verifier="wrong-verifier" if bad_verifier else verifier,
        resource=resource,
    )
    response = http.post(discovery["token_endpoint"], data=data)
    if bad_verifier:
        check(response.status_code == 400, "independent provider rejects wrong PKCE verifier")
        return None
    response.raise_for_status()
    tokens = response.json()
    keys = http.get(discovery["jwks_uri"]).json()["keys"]
    header = jwt.get_unverified_header(tokens["id_token"])
    key = jwt.PyJWK.from_dict(next(k for k in keys if k["kid"] == header["kid"])).key
    claims = jwt.decode(tokens["id_token"], key, algorithms=["RS256"], audience=client, issuer=discovery["issuer"])
    check(
        claims["nonce"] == nonce and claims["sub"] == user, "independent provider ID token signature and nonce checked"
    )
    if replay_code:
        check(
            http.post(discovery["token_endpoint"], data=data).status_code == 400,
            "independent provider authorization code is single-use",
        )
        # Code reuse can revoke its entire grant. Never reuse this session in success tests.
        response = http.post(
            discovery["token_endpoint"],
            data=dict(
                grant_type="refresh_token", client_id=client, refresh_token=tokens["refresh_token"], resource=resource
            ),
        )
        check(response.status_code == 400, "code replay invalidates the associated refresh grant")
    return tokens


def exercise(directory, http, discovery, tokens):
    credentials = OAuthTokens(
        Trust(
            issuer=discovery["issuer"],
            audience="tenuo-authority",
            jwks_url=discovery["jwks_uri"],
            claims=RFC9068,
            clients=frozenset({"support", "mail-support", "no-tenant", "opaque"}),
            tenant_claim="tenant_id",
        ),
        allow_loopback_http=True,
    )
    root, holder = SigningKey.generate(), SigningKey.generate()
    app = None
    try:
        alice = credentials.authenticate(tokens["alice"]["access_token"])
        check(
            alice.subject == "alice" and alice.tenant_id == "acme" and alice.client_id == "support",
            "unmodified RFC 9068 adapter accepts independent provider JWT",
        )
        check(
            jwt.get_unverified_header(tokens["alice"]["access_token"])["typ"] == "at+jwt",
            "provider emits at+jwt access tokens",
        )
        for token, reason in (
            (tokens["wrong"]["access_token"], "wrong resource audience"),
            (tokens["alice"]["id_token"], "ID token used as access token"),
            (tokens["no-tenant"]["access_token"], "missing administrator tenant claim"),
            (tokens["opaque"]["access_token"], "opaque access token"),
        ):
            try:
                credentials.authenticate(token)
            except OAuthError:
                check(True, "independent provider " + reason + " refused")
            else:
                raise AssertionError(reason + " accepted")
        response = http.post(
            discovery["token_endpoint"],
            data=dict(
                grant_type="refresh_token",
                client_id="support",
                refresh_token=tokens["alice"]["refresh_token"],
                resource=RESOURCE,
            ),
        )
        response.raise_for_status()
        refreshed = response.json()
        check(
            credentials.authenticate(refreshed["access_token"]).subject == alice.subject,
            "real refresh grant produces a valid replacement access token",
        )
        records = {}
        for task, payment in (("refund-123", "payment-789"), ("refund-456", "payment-456")):
            records[("acme", task)] = dict(
                task_id=task,
                issuer=alice.issuer,
                subject=alice.subject,
                tenant_id="acme",
                status="approved",
                expires_at=int(time.time()) + 300,
                payment_id=payment,
                currency="USD",
                max_amount_cents=5000,
            )
        audit = []
        app = OAuthWarrantIssuerApp(
            OAuthWarrantIssuer(
                credentials=credentials,
                signing_key=root,
                policy=policy_for(records),
                proof_store=SQLiteProofStore(str(directory / "proofs.db")),
                audit=audit.append,
            )
        )
        with issuer_server(app) as endpoint:

            def request(token, task="refund-123"):
                return request_warrant_oauth(
                    endpoint,
                    token=token,
                    audience="tenuo-authority",
                    issuer_key=root.public_key,
                    holder_key=holder,
                    task_id=task,
                    allow_loopback_http=True,
                )

            for token, reason in (
                (tokens["bob"]["access_token"], "cross-tenant refund"),
                (tokens["mail"]["access_token"], "mail-only scope for refund"),
            ):
                try:
                    request(token)
                except OAuthError:
                    check(True, "independent provider " + reason + " refused")
                else:
                    raise AssertionError(reason + " accepted")
            warrant = request(refreshed["access_token"])
            delegated = request(tokens["alice"]["access_token"], "refund-456")
            check(len(audit) == 2, "independent provider issuance recorded in audit")
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(lambda: asyncio.run(exercise_mcp(directory, root, holder, warrant, delegated))).result(
                    timeout=90
                )
        exercise_email(
            directory,
            credentials,
            root,
            holder,
            tokens["mail"]["access_token"],
            tokens["alice"]["access_token"],
            tokens["bob-mail"]["access_token"],
            issuer_server,
        )
        replay = http.post(
            discovery["token_endpoint"],
            data=dict(
                grant_type="refresh_token",
                client_id="support",
                refresh_token=tokens["alice"]["refresh_token"],
                resource=RESOURCE,
            ),
        )
        check(replay.status_code == 400, "provider rejects reused rotated refresh token")
    finally:
        if app:
            app.close()
        credentials.close()


def run():
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Install Node.js 22+ and npm ci in oidc-provider-fixture first")
    with tempfile.TemporaryDirectory(prefix="tenuo-oidc-") as temp, callback_server() as callback:
        directory = Path(temp)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            issuer = f"http://127.0.0.1:{reservation.getsockname()[1]}"
        with (directory / "provider.log").open("w+") as log:
            process = subprocess.Popen(
                [node, str(HERE / "oidc-provider-fixture/server.mjs")],
                env={**os.environ, "OIDC_SMOKE_ISSUER": issuer, "OIDC_SMOKE_CALLBACK": callback},
                stdout=log,
                stderr=log,
            )
            try:
                with httpx.Client(timeout=5, trust_env=False, follow_redirects=False) as http:
                    deadline = time.monotonic() + 20
                    while True:
                        try:
                            response = http.get(issuer + "/.well-known/openid-configuration")
                            if response.status_code == 200:
                                discovery = response.json()
                                break
                        except httpx.HTTPError:
                            pass
                        if process.poll() is not None or time.monotonic() > deadline:
                            log.seek(0)
                            raise RuntimeError("Provider failed to start: " + log.read())
                        time.sleep(0.1)
                    check(
                        discovery["issuer"] == issuer and discovery["jwks_uri"] == issuer + "/jwks",
                        "discovery matches pinned local provider endpoints",
                    )
                    with sync_playwright() as playwright:
                        browser = playwright.chromium.launch()
                        try:
                            login(browser, http, discovery, callback, bad_verifier=True)
                            login(browser, http, discovery, callback, replay_code=True)
                            tokens = {}
                            for name, options in (
                                ("alice", {}),
                                ("bob", {"user": "bob"}),
                                ("mail", {"client": "mail-support"}),
                                ("bob-mail", {"user": "bob", "client": "mail-support"}),
                                ("wrong", {"resource": "https://other.example.test/api"}),
                                ("no-tenant", {"client": "no-tenant"}),
                                ("opaque", {"client": "opaque"}),
                            ):
                                tokens[name] = login(browser, http, discovery, callback, **options)
                            exercise(directory, http, discovery, tokens)
                        finally:
                            browser.close()
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    run()
