"""Real Keycloak + browser authorization code/PKCE + HTTP issuance + MCP tests.

Run from the checkout with PYTHONPATH=tenuo-python. Creates and removes only
its own Docker container, browser contexts, local servers, and temporary state.
Credentials are throwaway fixtures. HTTP is permitted only on loopback.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import uvicorn
from playwright.sync_api import sync_playwright

from tenuo import Exact, Range, SigningKey, Warrant
from tenuo._issuance_http import _request_body
from tenuo.mcp import SecureMCPClient
from tenuo.mcp._compat import call_tool_result_is_error
from tenuo.oauth import (
    KEYCLOAK,
    OAuthError,
    OAuthTokens,
    OAuthWarrantIssuer,
    OAuthWarrantIssuerApp,
    SQLiteProofStore,
    Trust,
    request_warrant_oauth,
    sign_oauth_holder_proof,
)
from tenuo_core import sign_meta

from refund_policy import policy_for
from email_smoke import exercise_email

HERE = Path(__file__).resolve().parent
IMAGE = "quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3"
AUDIENCE = "tenuo-authority"
ALICE = "11111111-1111-4111-8111-111111111111"


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS", message, flush=True)


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


@contextmanager
def callback_server():
    class Callback(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login complete. Return to the smoke test.")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Callback)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/callback"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@contextmanager
def issuer_server(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("Issuer did not start")
            time.sleep(0.02)
        yield f"http://127.0.0.1:{sock.getsockname()[1]}/warrants"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


def login(browser, http, base, callback, user="alice", client="support", bad_verifier=False):
    verifier, state, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    endpoint = base + "/realms/tenuo-smoke/protocol/openid-connect"
    query = urlencode(
        dict(
            client_id=client,
            response_type="code",
            redirect_uri=callback,
            scope="openid",
            state=state,
            nonce=nonce,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    )
    with browser.new_context() as context:
        page = context.new_page()
        page.goto(endpoint + "/auth?" + query)
        page.locator("#username").fill(user)
        page.locator("#password").fill("local-smoke-password")
        page.locator("#kc-login").click()
        page.wait_for_url(callback + "?**", timeout=20000)
        params = parse_qs(urlsplit(page.url).query)
        check(params.get("state") == [state], f"OAuth state checked ({user}/{client})")
    data = dict(
        grant_type="authorization_code",
        client_id=client,
        redirect_uri=callback,
        code=params["code"][0],
        code_verifier="incorrect-verifier" if bad_verifier else verifier,
    )
    response = http.post(endpoint + "/token", data=data)
    if bad_verifier:
        check(response.status_code == 400, "PKCE rejects an incorrect verifier")
        return None
    response.raise_for_status()
    tokens = response.json()
    # This is an OIDC login too: check the ID token and nonce at the client,
    # but never use this ID token as an API access credential.
    jwks = http.get(endpoint + "/certs").json()["keys"]
    header = jwt.get_unverified_header(tokens["id_token"])
    key = jwt.PyJWK.from_dict(next(k for k in jwks if k["kid"] == header["kid"])).key
    claims = jwt.decode(
        tokens["id_token"], key, algorithms=["RS256"], audience=client, issuer=base + "/realms/tenuo-smoke"
    )
    check(claims["nonce"] == nonce, "OIDC ID token and nonce checked at client")
    check(http.post(endpoint + "/token", data=data).status_code == 400, "authorization code is single-use")
    return tokens


async def exercise_mcp(directory, root, holder, warrant, delegated_root):
    ledger = directory / "ledger.db"
    env = {
        **os.environ,
        "OAUTH_DEMO_ROOT": bytes(root.public_key.to_bytes()).hex(),
        "OAUTH_DEMO_LEDGER": str(ledger),
        "PYTHONPATH": str(HERE.parents[1]),
    }
    async with SecureMCPClient(command=sys.executable, args=[str(HERE / "payments_server.py")], env=env) as client:
        args = dict(operation_id="refund-123", payment_id="payment-789", currency="USD", amount_cents=4000)

        def counts():
            with sqlite3.connect(ledger) as db:
                return tuple(
                    db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("refunds", "calls")
                )

        async def call(arguments, chain=None, key=None, meta=None):
            if meta is None:
                meta = sign_meta(
                    chain or [warrant], key or holder, "refund", json.dumps(arguments), int(time.time()), None
                )
            return await client.session.call_tool("refund", arguments, meta={"tenuo": meta})

        good_meta = sign_meta([warrant], holder, "refund", json.dumps(args), int(time.time()), None)
        result = await call(args, meta=good_meta)
        check(not call_tool_result_is_error(result) and counts()[0] == 1, "authorized refund reaches ledger")
        for changed in ({**args, "payment_id": "other"}, {**args, "amount_cents": 6000}, {**args, "currency": "EUR"}):
            before = counts()
            result = await call(changed)
            check(call_tool_result_is_error(result) and counts() == before, "denied arguments never enter tool body")
        before = counts()
        result = await call(args, key=SigningKey.generate())
        check(call_tool_result_is_error(result) and counts() == before, "copied warrant fails with another holder key")
        result = await client.session.call_tool("refund", args)
        check(call_tool_result_is_error(result) and counts() == before, "missing warrant fails before execution")
        await call(args, meta=good_meta)
        check(counts()[0] == 1, "captured invocation cannot duplicate the business operation")
        await call(args)  # a fresh proof must not bypass business idempotency either
        check(counts()[0] == 1, "fresh valid retry cannot duplicate the business operation")
        worker = SigningKey.generate()
        child = (
            delegated_root.grant_builder()
            .holder(worker.public_key)
            .ttl(30)
            .capability(
                "refund",
                {
                    "operation_id": Exact("refund-456"),
                    "payment_id": Exact("payment-456"),
                    "currency": Exact("USD"),
                    "amount_cents": Range(1, 1000),
                },
            )
            .grant(holder)
        )
        child_args = dict(operation_id="refund-456", payment_id="payment-456", currency="USD", amount_cents=800)
        result = await call(child_args, chain=[delegated_root, child], key=worker)
        check(not call_tool_result_is_error(result) and counts()[0] == 2, "narrowed delegated refund succeeds")
        try:
            (
                delegated_root.grant_builder()
                .holder(worker.public_key)
                .ttl(30)
                .capability("refund", {"amount_cents": Range(1, 6000)})
                .grant(holder)
            )
        except Exception:
            pass
        else:
            raise AssertionError("Broader delegation was allowed")
        check(True, "broader delegation rejected")


def run():
    name = "tenuo-oauth-smoke-" + secrets.token_hex(5)
    password = secrets.token_urlsafe(24)
    started = False
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "-p",
                "127.0.0.1::8080",
                "-e",
                "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
                "-e",
                "KC_BOOTSTRAP_ADMIN_PASSWORD",
                IMAGE,
                "start-dev",
            ],
            env={**os.environ, "KC_BOOTSTRAP_ADMIN_PASSWORD": password},
            check=True,
            stdout=subprocess.DEVNULL,
        )
        started = True
        port = docker("port", name, "8080/tcp").split(":")[-1]
        base = "http://127.0.0.1:" + port
        with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as http, callback_server() as callback:
            deadline = time.monotonic() + 120
            while True:
                try:
                    ready = http.get(base + "/realms/master/.well-known/openid-configuration").status_code == 200
                except httpx.HTTPError:
                    ready = False
                if ready:
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError("Keycloak failed to start")
                time.sleep(1)
            # Password grant is used ONLY for disposable server administration.
            # Every application credential below comes from browser code + PKCE.
            response = http.post(
                base + "/realms/master/protocol/openid-connect/token",
                data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": password},
            )
            response.raise_for_status()
            admin = {"Authorization": "Bearer " + response.json()["access_token"]}
            realm = json.loads((HERE / "keycloak-realm.json").read_text())
            realm["clients"][0]["redirectUris"] = [callback]
            for client_id in ("wrong-audience", "short-support", "no-scope", "mail-support"):
                client = copy.deepcopy(realm["clients"][0])
                client["clientId"] = client_id
                if client_id == "wrong-audience":
                    client["protocolMappers"][0]["config"]["included.custom.audience"] = "another-api"
                if client_id == "short-support":
                    client["attributes"]["access.token.lifespan"] = "3"
                if client_id == "mail-support":
                    client["defaultClientScopes"] = ["basic", "mail:send"]
                if client_id == "no-scope":
                    client["defaultClientScopes"] = ["basic"]
                realm["clients"].append(client)
            http.post(base + "/admin/realms", headers=admin, json=realm).raise_for_status()
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                try:
                    login(browser, http, base, callback, bad_verifier=True)
                    alice = login(browser, http, base, callback)
                    bob = login(browser, http, base, callback, user="bob")
                    wrong = login(browser, http, base, callback, client="wrong-audience")
                    short = login(browser, http, base, callback, client="short-support")
                    no_scope = login(browser, http, base, callback, client="no-scope")
                    mail = login(browser, http, base, callback, client="mail-support")
                    bob_mail = login(browser, http, base, callback, user="bob", client="mail-support")
                    with tempfile.TemporaryDirectory(prefix="tenuo-oauth-") as temp:
                        exercise_issuance(
                            Path(temp),
                            http,
                            browser,
                            base,
                            callback,
                            admin,
                            alice,
                            bob,
                            wrong,
                            short,
                            no_scope,
                            name,
                            mail,
                            bob_mail,
                        )
                finally:
                    browser.close()
    finally:
        if started:
            subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL)


def exercise_issuance(
    directory, http, browser, base, callback, admin, alice, bob, wrong, short, no_scope, container, mail, bob_mail
):
    issuer_url = base + "/realms/tenuo-smoke"
    credentials = OAuthTokens(
        Trust(
            issuer=issuer_url,
            audience=AUDIENCE,
            jwks_url=issuer_url + "/protocol/openid-connect/certs",
            claims=KEYCLOAK,
            clients=frozenset({"support", "wrong-audience", "short-support", "no-scope", "mail-support"}),
            tenant_claim="tenant_id",
        ),
        allow_loopback_http=True,
        timeout=2,
        refresh_interval=0.1,
    )
    root, holder = SigningKey.generate(), SigningKey.generate()
    records = {}
    for task, payment, status in (
        ("refund-123", "payment-789", "approved"),
        ("refund-456", "payment-456", "approved"),
        ("pending", "payment-x", "pending"),
    ):
        records[("acme", task)] = dict(
            task_id=task,
            issuer=issuer_url,
            subject=ALICE,
            tenant_id="acme",
            status=status,
            expires_at=int(time.time()) + 600,
            payment_id=payment,
            currency="USD",
            max_amount_cents=5000,
        )
    audit = []
    authority = OAuthWarrantIssuer(
        credentials=credentials,
        signing_key=root,
        policy=policy_for(records),
        proof_store=SQLiteProofStore(str(directory / "proofs.db")),
        audit=audit.append,
    )
    app = OAuthWarrantIssuerApp(authority)
    try:
        credentials.authenticate(alice["access_token"])
        with issuer_server(app) as endpoint:

            def request(token, task="refund-123"):
                return request_warrant_oauth(
                    endpoint,
                    token=token,
                    audience=AUDIENCE,
                    issuer_key=root.public_key,
                    holder_key=holder,
                    task_id=task,
                    allow_loopback_http=True,
                )

            warrant = request(alice["access_token"])
            delegated_root = request(alice["access_token"], "refund-456")
            check(len(audit) == 2, "trusted task template issues audited holder-bound warrants")
            # Wait for the genuinely issued short-lived credential, not a forged exp claim.
            expiry = jwt.decode(short["access_token"], options={"verify_signature": False})["exp"]
            time.sleep(max(0, expiry - time.time() + 0.1))
            for token, task, reason in (
                (bob["access_token"], "refund-123", "cross-tenant task"),
                (alice["access_token"], "pending", "unapproved task"),
                (alice["access_token"], "unknown", "unknown task"),
                (wrong["access_token"], "refund-123", "wrong audience"),
                (alice["id_token"], "refund-123", "ID token used as access token"),
                (short["access_token"], "refund-123", "expired access token"),
                (no_scope["access_token"], "refund-123", "missing task scope"),
            ):
                try:
                    request(token, task)
                except OAuthError:
                    check(True, reason + " refused")
                else:
                    raise AssertionError(reason + " accepted")
            proof = sign_oauth_holder_proof(alice["access_token"], holder, audience=AUDIENCE, task_id="refund-123")
            body = _request_body(holder, "refund-123", proof)
            headers = {"Authorization": "Bearer " + alice["access_token"], "Content-Type": "application/json"}
            check(
                http.post(endpoint, content=body, headers=headers).status_code == 200, "fresh issuance proof accepted"
            )
            check(
                http.post(endpoint, content=body, headers=headers).status_code == 403, "issuance proof replay refused"
            )
            # The same request as OAuth 2.0 Token Exchange (RFC 8693), with Keycloak's own token as the subject token.
            fresh = sign_oauth_holder_proof(alice["access_token"], holder, audience=AUDIENCE, task_id="refund-123")
            detail = {"type": "tenuo_task", **json.loads(_request_body(holder, "refund-123", fresh))}
            del detail["v"]
            form = {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": alice["access_token"],
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:tenuo:params:oauth:token-type:warrant",
                "authorization_details": json.dumps([detail]),
            }
            exchanged = http.post(endpoint, data=form)
            reply = exchanged.json()
            check(
                exchanged.status_code == 200
                and reply["issued_token_type"] == form["requested_token_type"]
                and Warrant.from_base64(reply["access_token"]).authorized_holder == holder.public_key,
                "token exchange returns a holder-bound warrant",
            )
            refused = http.post(endpoint, data={**form, "subject_token": alice["id_token"]})
            check(
                refused.status_code == 400 and refused.json()["error"] == "invalid_grant",
                "token exchange refuses an ID token as invalid_grant",
            )
            # Playwright's sync driver owns an event loop on this thread.
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(lambda: asyncio.run(exercise_mcp(directory, root, holder, warrant, delegated_root))).result(
                    timeout=90
                )
            exercise_email(
                directory,
                credentials,
                root,
                holder,
                mail["access_token"],
                alice["access_token"],
                bob_mail["access_token"],
                issuer_server,
            )
            # Rotate the real authorization server's active signing key.
            realm = http.get(base + "/admin/realms/tenuo-smoke", headers=admin).json()
            response = http.post(
                base + "/admin/realms/tenuo-smoke/components",
                headers=admin,
                json={
                    "name": "rotated-rsa",
                    "providerId": "rsa-generated",
                    "providerType": "org.keycloak.keys.KeyProvider",
                    "parentId": realm["id"],
                    "config": {
                        "priority": ["200"],
                        "enabled": ["true"],
                        "active": ["true"],
                        "algorithm": ["RS256"],
                        "keySize": ["2048"],
                    },
                },
            )
            response.raise_for_status()
            rotated = login(browser, http, base, callback)
            check(
                jwt.get_unverified_header(rotated["access_token"])["kid"]
                != jwt.get_unverified_header(alice["access_token"])["kid"],
                "Keycloak rotated its real signing key",
            )
            request(rotated["access_token"])
            check(True, "new signing key discovered and accepted")
            docker("pause", container)
            try:
                request(rotated["access_token"])
                check(True, "unexpired JWKS cache tolerates provider outage")
                credentials._loaded -= credentials._cache_seconds + 1
                time.sleep(0.11)
                try:
                    request(rotated["access_token"])
                except OAuthError:
                    check(True, "expired JWKS cache fails closed during outage")
                else:
                    raise AssertionError("Expired JWKS cache was trusted")
            finally:
                docker("unpause", container)
            credentials.refresh()
            request(rotated["access_token"])
            check(True, "issuance recovers after provider returns")
    finally:
        app.close()
        credentials.close()


if __name__ == "__main__":
    run()
