"""The warrant issuer for the gateway recipe: one more service behind your gateway.

It trusts the same Keycloak realm the gateway does, for its own audience, and
only for the clients named here. What a caller may do comes from the approved
task, never from the token and never from the request.
"""

import time

from tenuo.oauth import (
    KEYCLOAK,
    ExactFrom,
    MaximumFrom,
    OAuthTokens,
    OAuthWarrantIssuer,
    OAuthWarrantIssuerApp,
    TaskTemplate,
    Trust,
)

REALM = "http://127.0.0.1:18190/realms/tenuo-gateway"
AUDIENCE = "tenuo-authority"

# A refund task belongs to the service that was approved to carry it out.
REFUND = TaskTemplate(
    tool="refund",
    arguments={
        "payment_id": ExactFrom("payment_id"),
        "currency": ExactFrom("currency"),
        "amount_cents": MaximumFrom("max_amount_cents"),  # Per call. Not a running total.
    },
    required_scopes=frozenset({"refunds:write"}),
    owner=("issuer", "client_id"),
    ttl_seconds=120,
)


def approved_tasks():
    """Stands in for your approvals database."""
    return {
        "refund-123": dict(
            task_id="refund-123",
            issuer=REALM,
            client_id="support-agent",
            status="approved",
            expires_at=int(time.time()) + 600,
            payment_id="payment-789",
            currency="USD",
            max_amount_cents=5000,
        ),
        "refund-pending": dict(
            task_id="refund-pending",
            issuer=REALM,
            client_id="support-agent",
            status="pending",
            expires_at=int(time.time()) + 600,
            payment_id="payment-111",
            currency="USD",
            max_amount_cents=5000,
        ),
    }


def build(signing_key, audit):
    tasks = approved_tasks()
    credentials = OAuthTokens(
        Trust(
            issuer=REALM,
            audience=AUDIENCE,
            jwks_url=REALM + "/protocol/openid-connect/certs",
            claims=KEYCLOAK,
            clients=frozenset({"support-agent"}),
        ),
        allow_loopback_http=True,  # The recipe's Keycloak is on this machine. Use HTTPS anywhere else.
    )
    issuer = OAuthWarrantIssuer(
        credentials=credentials,
        signing_key=signing_key,
        policy=lambda identity, task_id: REFUND.compile(identity, task_id, tasks.get(task_id)),
        audit=audit,
    )
    return OAuthWarrantIssuerApp(issuer)
