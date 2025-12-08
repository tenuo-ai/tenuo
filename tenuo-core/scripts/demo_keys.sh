#!/bin/bash
# ============================================================================
# Identity-as-Config Demo Setup
# ============================================================================
# This script generates keypairs and exports them as environment variables,
# simulating how Kubernetes Secrets would inject identities at deploy time.
#
# In production (K8s):
#   - Keys are stored in K8s Secrets
#   - Terraform/Helm wires secrets to pods
#   - Worker gets WORKER_PRIVATE_KEY
#   - Orchestrator gets WORKER_PUBLIC_KEY (same identity, different parts)
#
# For this demo:
#   - We generate keys using the keygen tool
#   - Export them to environment
#   - Run orchestrator and worker with these env vars
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           IDENTITY-AS-CONFIG: Generating Keypairs                ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Build keygen if needed
echo "  Building keygen tool..."
cargo build --bin keygen --manifest-path "$PROJECT_DIR/Cargo.toml" --quiet 2>/dev/null || {
    echo "  (Building keygen...)"
    cargo build --bin keygen --manifest-path "$PROJECT_DIR/Cargo.toml"
}

KEYGEN="$PROJECT_DIR/target/debug/keygen"

# Generate Worker keypair
echo ""
echo "  Generating Worker identity..."
eval "$($KEYGEN -- --name WORKER)"
echo "    WORKER_PRIVATE_KEY=${WORKER_PRIVATE_KEY:0:16}..."
echo "    WORKER_PUBLIC_KEY=${WORKER_PUBLIC_KEY:0:16}..."

# Generate Admin keypair  
echo ""
echo "  Generating Admin identity..."
eval "$($KEYGEN -- --name ADMIN)"
echo "    ADMIN_PRIVATE_KEY=${ADMIN_PRIVATE_KEY:0:16}..."
echo "    ADMIN_PUBLIC_KEY=${ADMIN_PUBLIC_KEY:0:16}..."

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  ✓ Keys generated and exported to environment                    ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║                                                                  ║"
echo "║  IDENTITY-AS-CONFIG PATTERN:                                     ║"
echo "║    Worker gets:       WORKER_PRIVATE_KEY                         ║"
echo "║    Orchestrator gets: WORKER_PUBLIC_KEY                          ║"
echo "║    (Same identity, different parts - like K8s Secrets)           ║"
echo "║                                                                  ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  NOW RUN THE DEMO:                                               ║"
echo "║                                                                  ║"
echo "║  Terminal 1 - Control Plane:                                     ║"
echo "║    cd $PROJECT_DIR"
echo "║    cargo run --bin control                                       ║"
echo "║                                                                  ║"
echo "║  Terminal 2 - Orchestrator (copy ENROLLMENT_TOKEN from above):   ║"
echo "║    source scripts/demo_keys.sh                                   ║"
echo "║    TENUO_ENROLLMENT_TOKEN=<token> cargo run --bin orchestrator   ║"
echo "║                                                                  ║"
echo "║  Terminal 3 - Worker:                                            ║"
echo "║    source scripts/demo_keys.sh                                   ║"
echo "║    TENUO_TRUSTED_KEYS=<cp_pubkey> cargo run --bin worker         ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
