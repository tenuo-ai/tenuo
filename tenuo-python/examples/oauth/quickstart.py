"""OAuth token in, task-scoped warrant out, in one file you can run and copy from.

    pip install 'tenuo[oauth]' uvicorn
    python quickstart.py

No Docker and no identity provider needed: part 1 stands in for yours by signing
tokens with a key made on the spot. Parts 2 to 4 are what you would write. To
use your real provider, replace part 1 with its issuer, key URL and one of its
tokens, and pick the claim map for it (see docs/oauth.md).
"""

import json
import logging
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa

from tenuo import Authorizer, SigningKey
from tenuo.oauth import (
    RFC9068,
    ExactFrom,
    MaximumFrom,
    OAuthError,
    OAuthTokens,
    OAuthWarrantIssuer,
    OAuthWarrantIssuerApp,
    TaskTemplate,
    Trust,
    request_warrant_oauth,
)

AUDIENCE = "tenuo-authority"  # The name your provider gives the warrant issuer. Tokens for other APIs are refused.


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


# ---------------------------------------------------------------------------
# 1. A stand-in for your identity provider. You already have the real one.
# ---------------------------------------------------------------------------

provider_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
provider_port = free_port()
PROVIDER = f"http://127.0.0.1:{provider_port}"


class Keys(BaseHTTPRequestHandler):
    """Serves the provider's public signing key, as every OAuth provider does at its key URL."""

    def do_GET(self):
        key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(provider_key.public_key()))
        key.update(kid="key-1", alg="RS256", use="sig")
        body = json.dumps({"keys": [key]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def token_for(client_id, scope="refunds:write"):
    """What your provider returns from its token endpoint: a signed JWT access token (RFC 9068 layout)."""
    now = int(time.time())
    claims = dict(
        iss=PROVIDER,
        sub=client_id,
        aud=AUDIENCE,
        client_id=client_id,
        scope=scope,
        jti=f"t-{now}",
        iat=now,
        exp=now + 300,
    )
    return jwt.encode(claims, provider_key, algorithm="RS256", headers={"kid": "key-1", "typ": "at+jwt"})


# ---------------------------------------------------------------------------
# 2. The warrant issuer: the one service you add.
# ---------------------------------------------------------------------------

# Its signing key. Keep the private half with your other secrets. Tools get only the public half.
issuer_key = SigningKey.generate()

# Whose tokens are accepted. This is the whole trust decision.
trust = Trust(
    issuer=PROVIDER,
    audience=AUDIENCE,
    jwks_url=PROVIDER + "/keys",
    claims=RFC9068,  # Or KEYCLOAK, ENTRA_ID, GITHUB_ACTIONS, or a ClaimMap for another provider.
    clients=frozenset({"support-agent"}),
)

# What a task allows. The record comes from your own approvals, never from the agent's request.
refund_template = TaskTemplate(
    tool="refund",
    arguments={"payment_id": ExactFrom("payment_id"), "amount_cents": MaximumFrom("max_amount_cents")},
    required_scopes=frozenset({"refunds:write"}),
    owner=("issuer", "client_id"),  # A service acting for itself. For a person's task, leave the default.
)
APPROVED_TASKS = {  # Stands in for your database.
    "refund-123": dict(
        task_id="refund-123",
        issuer=PROVIDER,
        client_id="support-agent",
        status="approved",
        expires_at=int(time.time()) + 600,
        payment_id="payment-789",
        max_amount_cents=5000,
    )
}


def policy(identity, task_id):
    """Called with a verified identity. Return a grant, or None to deny."""
    return refund_template.compile(identity, task_id, APPROVED_TASKS.get(task_id))


def audit(issuance):
    """Called before each warrant is released. If this raises, no warrant is issued."""
    print(
        f"   audit: warrant {issuance.warrant_id} for task {issuance.task_id} to client {issuance.identity.client_id}"
    )


issuer_app = OAuthWarrantIssuerApp(
    OAuthWarrantIssuer(
        # allow_loopback_http is for this local demo. Your provider's URLs are https and need no flag.
        credentials=OAuthTokens(trust, allow_loopback_http=True),
        signing_key=issuer_key,
        policy=policy,
        audit=audit,
    )
)

# ---------------------------------------------------------------------------
# 3. The tool: checks the warrant before it acts.
# ---------------------------------------------------------------------------

# The tool trusts the issuer's public key and nothing else: no token, no private key.
authorizer = Authorizer(trusted_roots=[issuer_key.public_key])


REFUNDS_MADE = []  # Stands in for the payments service's ledger.


def refund(payment_id, amount_cents, *, warrant, signature):
    """Refund a payment, if the warrant allows exactly this call."""
    arguments = {"payment_id": payment_id, "amount_cents": amount_cents}  # The names the template uses.
    authorizer.authorize(warrant, "refund", arguments, signature)  # Raises unless allowed.
    REFUNDS_MADE.append((payment_id, amount_cents))  # Reached only by an allowed call.
    return f"refunded {amount_cents} cents on {payment_id}"


# ---------------------------------------------------------------------------
# 4. The agent: has a token already, asks for a warrant, calls the tool.
# ---------------------------------------------------------------------------


def run_agent(issuer_url):
    holder_key = SigningKey.generate()  # The agent's own key. It never leaves the agent.
    token = token_for("support-agent")  # In your deployment: the token the agent already gets from your provider.

    def ask(task_id, with_token=token):
        return request_warrant_oauth(
            issuer_url,
            token=with_token,
            audience=AUDIENCE,
            issuer_key=issuer_key.public_key,  # The agent accepts warrants from this issuer only.
            holder_key=holder_key,
            task_id=task_id,
            allow_loopback_http=True,  # Local demo only.
        )

    def call(warrant, payment_id, amount_cents):
        # The agent signs each call with its key. A copied warrant is useless without it.
        arguments = {"payment_id": payment_id, "amount_cents": amount_cents}
        signature = warrant.sign(holder_key, "refund", arguments, int(time.time()))
        try:
            return refund(payment_id, amount_cents, warrant=warrant, signature=signature)
        except Exception as refused:
            return f"REFUSED at the tool: {refused}"

    print("1. The agent asks for a warrant for the task it was approved for:")
    warrant = ask("refund-123")
    print("   got a warrant that expires at", warrant.expires_at())

    print("2. It refunds within the approval:")
    approved = call(warrant, "payment-789", 4000)
    print("  ", approved)

    print("3. The same warrant does not stretch:")
    too_much, another_payment = call(warrant, "payment-789", 9000), call(warrant, "payment-000", 4000)
    print("  ", too_much)
    print("  ", another_payment)

    print("4. A task nobody approved gets no warrant:")
    try:
        ask("refund-999")
    except OAuthError as refused:
        print("  ", refused)

    print("5. A client this issuer does not trust gets no warrant, and the issuer's log says why:")
    try:
        ask("refund-123", with_token=token_for("reporting-agent"))
    except OAuthError as refused:
        print("  ", refused)

    # Each call above was made once. The warrant limits what a call may be, not how many times it is made:
    # until it expires the approved refund would be allowed again, so a payments service still needs its own
    # rule for doing an operation once (an operation ID, for example).
    return "refunded" in approved and "REFUSED" in too_much and "REFUSED" in another_payment and len(REFUNDS_MADE) == 1


def main():
    sys.stdout.reconfigure(line_buffering=True)  # Keep the agent's lines and the issuer's log in order.
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="   issuer log: %(message)s")
    logging.getLogger("tenuo.oauth").setLevel(logging.INFO)
    provider = ThreadingHTTPServer(("127.0.0.1", provider_port), Keys)
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(issuer_app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        ok = run_agent(f"http://127.0.0.1:{port}/warrants")
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        provider.shutdown()
        provider.server_close()
    print("\nAll as expected." if ok else "\nSomething did not behave as expected.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
