# Tenuo Demo Walkthrough

This demo simulates a **Zero Trust Delegation Chain** between autonomous agents.

## Key Features Demonstrated

- **Multi-Mission Isolation**: Same worker receives Mission A (`read_file`) and Mission B (`manage_infrastructure`) warrants. Using wrong warrant → DENIED.
- **Temporal Least-Privilege**: Each mission gets its own short-lived warrant with specific constraints.
- **TTL Expiration**: Short-lived sub-warrant (2s) expires while parent remains valid.
- **Chain Verification**: Worker verifies the full delegation chain back to trusted root (under 50 μs per hop).
- **Remote Authorization**: Worker sends full `WarrantStack` to Authorizer for zero-trust verification.

## Architecture

1. **Control Plane** (Issuer): The Root of Trust. Issues a broad `root_warrant` with `tool: "*"`.
2. **Orchestrator** (Delegate): Receives root warrant, creates **mission-specific** warrants:
   - Mission A: `read_file` with `/data/*` path constraint
   - Mission B: `manage_infrastructure` with `staging-web` cluster constraint
3. **Worker** (Holder): Receives both mission warrants and demonstrates isolation.
4. **Authorizer** (Enforcer): Verifies the chain, constraints, and Proof-of-Possession (PoP) signatures.

## Running the Demo

### Quick Start (Automatic)

Run the full stack automatically:

```bash
docker compose up --build
```

### Manual Walkthrough (Secure Bootstrap)

To see the enrollment and secure hand-off process in detail, run the services sequentially:

**1. Start the Control Plane & Authorizer**

```bash
docker compose up -d control-plane authorizer
```

_This starts the infrastructure. The Control Plane will print an enrollment token to the logs._

**2. Copy Enrollment Token**

You can use the default token pre-configured in `docker-compose.yml`, or inspect the logs for a dynamic one if configured:

```bash
# Default token for dev environment
export TENUO_ENROLLMENT_TOKEN="demo-enrollment-token-2024"
```

**3. Launch the Orchestrator**

The orchestrator represents a mid-tier agent. It needs the enrollment token to prove its identity to the Control Plane and receive its initial authority.

```bash
TENUO_ENROLLMENT_TOKEN="${TENUO_ENROLLMENT_TOKEN}" docker compose up orchestrator
```

**4. Watch the Worker (Auto-Started)**

Once the Orchestrator successfully delegates a warrant chain to the shared volume, the Worker picks it up and begins its mission.

```bash
docker compose logs -f worker
```

## What to Observe

Watch the `worker` logs for a checklist of security verifications:

- [x] **Chain Verification**: Worker validates the full chain offline (under 50 μs per hop).
- [x] **Constraint Enforcement**: `manage_infrastructure` is allowed, but strictly scoped to specific resources.
- [x] **Temporal Safety**: 
  - A short-lived sub-warrant (2s TTL) works immediately.
  - After sleeping 3s, it is correctly **DENIED**.
  - The parent warrant remains valid (isolation).
- [x] **Remote Authorization**: Worker signs requests (PoP) and sends them to the Authorizer sidecar for final enforcement.
