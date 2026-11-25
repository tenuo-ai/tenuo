# SPIFFE → Tenuo → protected refund tool

This demo authenticates an agent's X.509-SVID over real mTLS, verifies its
separate Tenuo holder key, applies a server-owned task policy, and checks each
refund request at the tool boundary. It also delegates a narrower warrant to a
worker. No model API, cloud account, or real refund service is needed.

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

The policy grants customer `123`, amounts of 1–5000 cents, 120 seconds, and one
delegation level. The worker receives only 1–1000 cents for 30 seconds. The tool
checks the full warrant chain and proof of possession before its simulated
side effect. These limits apply per call; they are not an aggregate spending cap.

## Real SPIRE interoperability demo

Docker provides a disposable Linux environment with SPIRE **1.16.0** binaries
verified against their release SHA-256 checksums (AMD64 and ARM64 supported):

```bash
docker build -t tenuo-spiffe-demo:local -f tenuo-python/examples/spiffe/Dockerfile .
docker run --rm --mount "type=bind,source=$PWD,target=/work,readonly" tenuo-spiffe-demo:local
```

The harness starts a SPIRE server and agent, uses a one-time join token for node
attestation, registers `spiffe://demo.test/agent` and
`spiffe://demo.test/issuer`, and fetches their X.509-SVIDs through the Workload API.
It then runs the same mTLS exchange and tool-boundary checks. Processes, SQLite
state, private keys, and sockets are temporary and cleaned up on exit. No ports
are published to the host.

For compactness, both demo identities use the same Unix UID selector and the
same process loads both credentials. This is an interoperability fixture, not a
production isolation pattern. Production issuer and agent workloads need
separate selectors and separate credential access. Likewise, the example
combines issuer and tool service roles in one process to keep the flow visible.

On Linux with SPIRE binaries and the Python dependencies already installed:

```bash
PYTHONPATH=tenuo-python python tenuo-python/examples/spiffe/live_spire.py
```

The harness uses container-local port 18081 for SPIRE; it must be available.

## Use credentials from an existing SPIRE deployment

Export the two workloads' SVIDs and their domain bundle into a protected directory:

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
and `ISSUER_ID` in `demo.py` and the corresponding policy. This short-lived demo
loads credentials once. A long-lived service must refresh its TLS configuration
as SPIRE rotates credentials; the adapter does not watch files or subscribe to
the Workload API.

See [the adapter guide](../../../docs/spiffe.md) for APIs, trust boundaries,
rotation, revocation, policy integration, and production deployment constraints.
