"""A warrant issuer behind an Istio sidecar.

The sidecar ends the agent's mutual TLS and tells this process who called in
the x-forwarded-client-cert header. See "With Istio" in docs/spiffe.md.
"""

import os
from pathlib import Path

from tenuo import Exact, Range, SigningKey
from tenuo.spiffe import SpiffeGrant, SpiffeWarrantIssuer
from tenuo.spiffe_forwarded import UNIX_SOCKET, SpiffeForwardedIdentity, SpiffeForwardedIssuerApp

forwarded = SpiffeForwardedIdentity(
    "cluster.local",  # Istio's default trust domain.
    audience=os.environ["AUDIENCE"],  # A name for this issuer. Agents sign it.
    # Where the sidecar connects from: a Unix socket here, or 127.0.0.6 when the issuer listens on TCP.
    trusted_proxies=[os.environ.get("TRUSTED_PROXY", UNIX_SOCKET)],
    # The entry must have been recorded by this pod's own sidecar.
    expected_by="spiffe://cluster.local/ns/tenuo/sa/issuer",
    # Istio always forwards a certificate's DNS names. Istio's own certificates have none; SPIRE entries may.
    allow_dns_names=os.environ.get("ALLOW_DNS_NAMES") == "1",
)

# Stand-in for your task system: which workload may work on which task.
# Under Istio a workload's SPIFFE ID is its namespace and service account.
approved_tasks = {
    "refund-task-123": {"agent": "spiffe://cluster.local/ns/tenuo/sa/agent", "customer": "123", "max_cents": 2000},
}


def policy(identity, task_id):
    task = approved_tasks.get(task_id)
    if task is None or task["agent"] != identity.spiffe_id:
        return None
    return SpiffeGrant(
        capabilities={"refund": {"customer": Exact(task["customer"]), "cents": Range(1, task["max_cents"])}},
        ttl_seconds=120,
    )


issuer = SpiffeWarrantIssuer(
    signing_key=SigningKey.from_pem(Path("/keys/tenuo-issuer.pem").read_text()),
    policy=policy,
    forwarded=forwarded,
)
app = SpiffeForwardedIssuerApp(issuer)
