"""Run the gateway recipe and check what it claims.

Starts Keycloak, Envoy, the Tenuo authorizer and a stand-in payments backend
with Docker Compose, runs the warrant issuer in this process, and then acts as
two agents with real Keycloak tokens. Everything it started is removed on exit.

    PYTHONPATH=tenuo-python python tenuo-python/examples/oauth/gateway/check.py
    ... check.py --keep     # leave it running, to try requests by hand
"""

import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import uvicorn

from tenuo import SigningKey
from tenuo.oauth import OAuthError, request_warrant_oauth

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from issuer import AUDIENCE, REALM, build  # noqa: E402

GATEWAY = "http://127.0.0.1:18180"
ISSUER_PORT = 18181
COMPOSE = ["docker", "compose", "-f", str(HERE / "docker-compose.yaml")]
SECRETS = {"support-agent": "local-recipe-secret-support", "reports-agent": "local-recipe-secret-reports"}
REFUND = {"payment_id": "payment-789", "currency": "USD", "amount_cents": 4000}


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS", message, flush=True)


def http(method, url, *, headers=None, body=None, form=None):
    """One request: (status, headers, body text). No redirects are expected and none are followed."""
    data = urllib.parse.urlencode(form).encode() if form else body
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as response:
            return response.status, dict(response.headers), response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode()
    except OSError:
        return 0, {}, ""


def token_for(client):
    """A real access token from Keycloak, by the client-credentials grant."""
    status, _, body = http(
        "POST",
        REALM + "/protocol/openid-connect/token",
        form={"grant_type": "client_credentials", "client_id": client, "client_secret": SECRETS[client]},
    )
    assert status == 200, f"Keycloak refused {client}: {status} {body}"
    return json.loads(body)["access_token"]


def refund(arguments, *, token=None, warrant=None, holder=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if warrant is not None:
        headers["X-Tenuo-Warrant"] = warrant.to_base64()
        # The holder signs this call's tool and arguments. The authorizer reads the same arguments from the body.
        signature = warrant.sign(holder, "refund", arguments, int(time.time()))
        headers["X-Tenuo-PoP"] = base64.b64encode(bytes(signature)).decode()
    status, reply_headers, body = http(
        "POST", GATEWAY + "/refunds", headers=headers, body=json.dumps(arguments).encode()
    )
    reason = {name.lower(): value for name, value in reply_headers.items()}.get("x-tenuo-deny-reason", "")
    return status, reason, body


def issuer_address():
    """Where the issuer listens so that Envoy, in a container, can reach it.

    Docker Desktop forwards host.docker.internal to this machine's loopback.
    On Linux it is the Docker bridge address, so the issuer listens there.
    """
    if os.environ.get("TENUO_ISSUER_BIND"):
        return os.environ["TENUO_ISSUER_BIND"]
    if sys.platform != "linux":
        return "127.0.0.1"
    return subprocess.check_output(
        ["docker", "network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}"], text=True
    ).strip()


def wait_for(what, ready, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if ready():
            return
        time.sleep(1)
    raise RuntimeError(f"{what} was not ready after {seconds} seconds")


def run(keep=False):
    root = SigningKey.generate()  # The issuer's signing key. The authorizer is given only its public half.
    environment = {**os.environ, "TENUO_TRUSTED_KEYS": bytes(root.public_key_bytes()).hex()}
    audits = []
    app = build(root, audits.append)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((issuer_address(), ISSUER_PORT))
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        subprocess.run([*COMPOSE, "up", "-d", "--quiet-pull"], env=environment, check=True)
        wait_for("Keycloak", lambda: http("GET", REALM + "/.well-known/openid-configuration")[0] == 200)
        support, reports = token_for("support-agent"), token_for("reports-agent")
        # Ready when the token check and the authorizer both answer: a valid token, and no warrant yet.
        wait_for("The gateway", lambda: refund(REFUND, token=support)[:2] == (401, "missing_warrant"), 60)
        exercise(root, support, reports, audits, environment)
        if keep:
            print(f"\nLeft running. Gateway: {GATEWAY}  Keycloak: {REALM}\nPress Ctrl-C to stop and remove it.")
            threading.Event().wait()
    except KeyboardInterrupt:
        pass
    except BaseException:
        subprocess.run([*COMPOSE, "logs", "--no-color", "--tail=15", "envoy", "tenuo-authorizer"], env=environment)
        raise
    finally:
        subprocess.run([*COMPOSE, "down", "-v", "--remove-orphans"], env=environment, stdout=subprocess.DEVNULL)
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        app.close()


def exercise(root, support, reports, audits, environment):
    holder = SigningKey.generate()  # The agent's own key. It never leaves the agent.
    options = dict(audience=AUDIENCE, issuer_key=root.public_key, holder_key=holder, allow_loopback_http=True)
    warrants = GATEWAY + "/warrants"

    # The gateway's token check is unchanged.
    check(refund(REFUND)[0] == 401, "no token: the gateway's own check refuses the call")
    check(refund(REFUND, token=support + "x")[0] == 401, "an altered token is refused by the gateway")

    # What changed: a valid token is no longer enough to move money.
    status, reason, _ = refund(REFUND, token=support)
    check((status, reason) == (401, "missing_warrant"), "a valid token without a warrant cannot refund")

    # The agent asks for a warrant through the same gateway, with the token it already has.
    warrant = request_warrant_oauth(warrants, token=support, task_id="refund-123", **options)
    check(
        len(audits) == 1 and audits[0].identity.client_id == "support-agent",
        "a warrant is issued for the approved task",
    )

    status, _, body = refund(REFUND, token=support, warrant=warrant, holder=holder)
    check(status == 200 and json.loads(body)["json"] == REFUND, "the approved refund reaches the payments service")

    for change, why in (
        ({"amount_cents": 6000}, "over the approved amount"),
        ({"payment_id": "payment-000"}, "for another payment"),
        ({"currency": "EUR"}, "in another currency"),
    ):
        status, reason, _ = refund({**REFUND, **change}, token=support, warrant=warrant, holder=holder)
        check(status == 403, f"a refund {why} is refused before the payments service sees it ({reason})")

    # The warrant is bound to the agent's key, and the gateway still wants the token.
    status, _, _ = refund(REFUND, token=support, warrant=warrant, holder=SigningKey.generate())
    check(status == 403, "a copied warrant is useless without the agent's key")
    check(
        refund(REFUND, warrant=warrant, holder=holder)[0] == 401,
        "a warrant without an access token is still refused by the gateway",
    )

    # Tasks nobody approved, and clients nobody named.
    for task in ("refund-pending", "refund-unknown"):
        try:
            request_warrant_oauth(warrants, token=support, task_id=task, **options)
        except OAuthError as error:
            check("HTTP 403" in str(error), f"no warrant for {task}")
        else:
            raise AssertionError(f"{task} was granted")
    check(refund(REFUND, token=reports)[:2] == (401, "missing_warrant"), "another client's valid token cannot refund")
    try:
        request_warrant_oauth(warrants, token=reports, task_id="refund-123", **options)
    except OAuthError as error:
        check("HTTP 401" in str(error), "a client the issuer does not trust gets no warrant")
    else:
        raise AssertionError("An untrusted client was granted a warrant")
    status, _, _ = refund(REFUND, token=reports, warrant=warrant, holder=SigningKey.generate())
    check(status == 403, "another client cannot use the first agent's warrant")
    try:
        request_warrant_oauth(warrants, token="", task_id="refund-123", **options)
    except OAuthError:
        check(True, "the warrant endpoint is behind the gateway's token check too")
    else:
        raise AssertionError("A warrant was issued without a token")

    # The same request as OAuth 2.0 Token Exchange, through the gateway.
    from tenuo._issuance_http import _request_body
    from tenuo.oauth import sign_oauth_holder_proof

    proof = sign_oauth_holder_proof(support, holder, audience=AUDIENCE, task_id="refund-123")
    detail = {"type": "tenuo_task", **json.loads(_request_body(holder, "refund-123", proof))}
    del detail["v"]
    status, _, body = http(
        "POST",
        warrants,
        headers={"Authorization": f"Bearer {support}"},
        form={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": support,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:tenuo:params:oauth:token-type:warrant",
            "authorization_details": json.dumps([detail]),
        },
    )
    check(
        status == 200 and json.loads(body)["issued_token_type"] == "urn:tenuo:params:oauth:token-type:warrant",
        "the same request as an RFC 8693 token exchange returns a warrant",
    )

    # If the authorizer is not there, the gateway refuses rather than letting the call through.
    subprocess.run([*COMPOSE, "stop", "tenuo-authorizer"], env=environment, check=True, capture_output=True)
    status, _, _ = refund(REFUND, token=support, warrant=warrant, holder=holder)
    check(status == 403, "with the authorizer stopped, the gateway refuses the refund")
    # Put it back, so that --keep leaves a gateway that works.
    subprocess.run([*COMPOSE, "start", "tenuo-authorizer"], env=environment, check=True, capture_output=True)
    wait_for(
        "The authorizer", lambda: refund(REFUND, token=support, warrant=warrant, holder=holder)[0] == 200, seconds=60
    )
    check(True, "with the authorizer back, the approved refund goes through again")


if __name__ == "__main__":
    run(keep="--keep" in sys.argv[1:])
