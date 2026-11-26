# SPIFFE → Tenuo → protected refund tool

New to SPIFFE or Tenuo? Read [the guide](../../../docs/spiffe.md) first; it
explains the terms and walks through a real deployment. This directory is the
runnable version.

`demo.py` plays three roles in one process so the whole flow fits on a screen:

- **Issuer:** `policy()` and `SpiffeIssuerServer`. Approves one refund task and
  issues a warrant for customer `123`, up to 5000 cents, for 120 seconds.
- **Agent:** `arequest_warrant(...)`. Presents its SVID, proves its own Tenuo
  key, and receives the warrant. It then delegates 1000 cents to a worker.
- **Tool:** `refund_tool()`. Verifies every call before the simulated refund.

No model API, cloud account, or real refund service is needed.

## Quickstart: disposable development certificates

From the repository root, using Python 3.9+:

```bash
python -m venv /tmp/tenuo-spiffe-demo-venv
/tmp/tenuo-spiffe-demo-venv/bin/pip install 'tenuo==0.3.8' 'cryptography>=42'
PYTHONPATH=tenuo-python /tmp/tenuo-spiffe-demo-venv/bin/python tenuo-python/examples/spiffe/demo.py
```

The installed release supplies the native extension; `PYTHONPATH` loads this
checkout's new adapter. This mode creates a disposable CA and SVID-shaped
certificates. It exercises TLS and warrant verification, **not SPIRE attestation**.
Keys and certificates are removed when the process exits. The server binds only
to a randomly selected localhost port.

Expected result:

```text
ALLOWED: approved customer, $40
DENIED: different customer
DENIED: over $50 task limit
ALLOWED: delegated worker, $8
Verified: only the two authorized refunds reached the tool body.
```

The two denials come from the warrant, not from identity: the agent's SVID is
valid for all four calls. The worker's warrant allows 1–1000 cents for 30
seconds. These limits apply per call; they are not a total spending cap.

## Real SPIRE interoperability demo

Docker provides a disposable Linux environment with SPIRE **1.16.0** binaries
verified against their release SHA-256 checksums, and the Envoy **1.40.2**
binary from its official image, pinned by digest (AMD64 and ARM64 supported):

```bash
docker build -t tenuo-spiffe-demo:local -f tenuo-python/examples/spiffe/Dockerfile .
docker run --rm --mount "type=bind,source=$PWD,target=/work,readonly" tenuo-spiffe-demo:local
```

The harness starts a SPIRE server and agent, uses a one-time join token for node
attestation, registers `spiffe://demo.test/agent` and
`spiffe://demo.test/issuer`, and fetches their X.509-SVIDs through the Workload API.
It then runs the same exchange and tool-boundary checks. Finally it registers the
workloads with 120-second SVIDs, keeps an issuer running while SPIRE renews
them, and checks that both sides switch to the renewed SVIDs without a restart:

```text
Verified: a JWT-SVID from SPIRE was exchanged for a warrant; two improper requests were refused.
Verified: a workload from a federated trust domain was accepted over mTLS and by JWT-SVID, and refused without federation.
Verified: Envoy forwarded the agent's SPIRE identity to the issuer; an unapproved workload, three requests carrying a made-up identity, and a certificate with a crafted name got nothing extra.
Verified: issuer and agent followed a renewal straight from the Workload API.
Verified: a running issuer and agent switched to SVIDs renewed by SPIRE.
Verified: the X.509 and JWT signing authorities were rotated and the old ones revoked; all 123 exchanges during the rotation succeeded, and credentials from the old authorities were refused.
```

- The first line is the JWT-SVID exchange: the agent fetches a token from the
  SPIRE agent and posts it to the HTTP endpoint. A token for another audience
  and a workload the policy does not approve are both refused.
- The second is federation: the harness starts a second SPIRE deployment for
  `partner.test`, exchanges bundles between the two servers, and has a partner
  workload obtain a warrant from the issuer in `demo.test`.
- The third is forwarded identity: a real Envoy in front of the issuer ends
  the agent's mutual TLS with SPIRE-issued certificates and passes the agent's
  SPIFFE ID on in `x-forwarded-client-cert`. The harness then sends an
  identity header of its own through a replacing listener, an appending
  listener, and a listener without TLS; none of them lets it choose who it is.
  Last, a client with a certificate from an authority outside SPIRE, whose name
  ends in a quote, tries to pass as the approved agent and is refused.
- The fourth is an issuer and agent built with `SpiffeTLS.from_workload_api`,
  reading the SPIRE agent's socket.
- The fifth is the same pair reading credential files that the harness
  rewrites.
- The sixth rotates the trust domain's X.509 and JWT signing authorities on
  the SPIRE server (`spire-server localauthority ... prepare`, `activate`,
  `taint`, `revoke`) while an issuer serves. Warrants are requested four times
  a second throughout, so the count varies; none may fail.

Processes, SQLite
state, private keys, and sockets are temporary and cleaned up on exit. No ports
are published to the host.

For compactness, both demo identities use the same Unix UID selector and the
same process loads both credentials. This is an interoperability fixture, not a
production isolation pattern. Production issuer and agent workloads need
separate selectors and separate credential access. Likewise, the example
combines issuer and tool service roles in one process to keep the flow visible.

On Linux with SPIRE binaries and the Python dependencies already installed
(the forwarded-identity check is skipped, and says so, when `envoy` is not on
`PATH`):

```bash
PYTHONPATH=tenuo-python python tenuo-python/examples/spiffe/live_spire.py
```

The harness uses container-local ports 18081 and 18082 for SPIRE; they must be available.

## Behind Istio

`istio/` runs the forwarded-identity exchange in a real mesh: an issuer whose
callers are identified by the header its Istio sidecar sets, and an agent that
needs no SPIFFE code of its own.

```bash
python tenuo-python/examples/spiffe/istio/check.py           # Istio's own certificates
python tenuo-python/examples/spiffe/istio/check.py --spire   # SPIRE issues the mesh's certificates
```

It needs `docker`, `kubectl` and `helm`. It starts a single-node Kubernetes
(k3s) in a container, installs Istio 1.30.8, and uses a kubeconfig in a
temporary directory, so your own contexts are never read or changed.
Everything is removed afterwards; `--keep` leaves the cluster up and prints how
to reach it. Expected result:

```text
Istio generated for the issuer's inbound listener: {"connects_from": "127.0.0.6", "forward_client_cert_details": "APPEND_FORWARD", "set_current_client_cert_details": {"subject": true, "dns": true, "uri": true}}
Verified: an agent in the mesh was issued a warrant on its Istio identity, over a Unix socket and over TCP.
Verified: another workload, sending identity headers of its own around its sidecar, was refused or served as itself.
Verified: a pod without a sidecar got no identity, whatever header it sent.
Verified: inside the issuer's pod, only a process that binds the sidecar's own address reaches a TCP issuer (the documented limit); the Unix-socket issuer has no port to reach.
Verified: through an ingress gateway, a caller is the gateway's own identity over plain HTTP (refused by policy), and is refused as a second proxy hop over mutual TLS.
Verified: with STRICT mutual TLS the pod outside the mesh is cut off and the agent is still served.
```

With `--spire` the last lines are instead about a certificate that carries DNS
names: refused by default, accepted once the issuer sets `allow_dns_names`.

| File | What it is |
|---|---|
| `istio/manifests.yaml` | The issuer (on a Unix socket, through an Istio `Sidecar` resource) and an agent. A starting point for your own. |
| `istio/issuer_app.py`, `istio/agent.py` | The guide's issuer and agent, with Istio's trust domain and service-account identities. |
| `istio/checks.yaml`, `istio/probe.py` | Workloads and requests used only to show what the issuer refuses. |

["With Istio" in the guide](../../../docs/spiffe.md#with-istio) explains each
result.

## A client in another language

`clients/request_warrant.mjs` obtains a warrant over HTTP with nothing but
Node.js's standard library, for an identity forwarded by a mesh sidecar or
with a JWT-SVID. It follows the wire formats in the guide's reference section.
The Python test suite runs it against both endpoints and signs a tool call
with the key it kept.

```bash
HOLDER_KEY_FILE=holder.pem node tenuo-python/examples/spiffe/clients/request_warrant.mjs URL AUDIENCE TASK_ID [JWT_SVID]
```

The warrant works only with the holder key, so the script keeps it in the file
`HOLDER_KEY_FILE` names (created if missing, readable by you alone). In an
agent, import `requestWarrant` and pass a key you hold in memory instead.

## Use credentials from an existing SPIRE deployment

Copy the two workloads' SVIDs and their domain bundle into a protected
directory, for example from `spire-agent api fetch x509 -write DIR` run as each
workload, or from the files `spiffe-helper` maintains. The demo expects these
names (they differ from the helper's defaults used in the guide):

```text
credentials/
  bundle.pem       # Authorities for demo.test only
  issuer.pem       # PEM certificate chain: spiffe://demo.test/issuer
  issuer-key.pem   # Issuer SVID's private key, mode 0600
  agent.pem        # PEM certificate chain: spiffe://demo.test/agent
  agent-key.pem    # Agent SVID's private key, mode 0600
```

```bash
PYTHONPATH=tenuo-python python tenuo-python/examples/spiffe/demo.py --credentials /path/to/credentials
```

For another trust domain or workload naming scheme, update `DOMAIN`, `AGENT_ID`,
and `ISSUER_ID` in `demo.py` and the corresponding policy. Long-lived services should
normally skip the files and use `SpiffeTLS.from_workload_api`, which follows
renewals by itself. With files, the adapter reloads them when they change; keep
them current with a helper such as `spiffe-helper`. The guide covers both.

See [the adapter guide](../../../docs/spiffe.md) for APIs, trust boundaries,
rotation, revocation, policy integration, and production deployment constraints.
