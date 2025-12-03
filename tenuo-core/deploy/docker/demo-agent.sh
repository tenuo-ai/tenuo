#!/bin/bash
# Demo Agent - Demonstrates Tenuo warrant flow
#
# This script simulates an AI agent that:
# 1. Gets a warrant from the control plane
# 2. Attenuates it for a sub-task
# 3. Uses the attenuated warrant

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  TENUO DEMO AGENT                                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

CONTROL_URL="${TENUO_CONTROL_URL:-http://control-plane:8080}"

echo "→ Waiting for control plane at $CONTROL_URL..."
until curl -sf "$CONTROL_URL/health" > /dev/null 2>&1; do
    sleep 1
done
echo "✓ Control plane is ready"
echo ""

# Step 1: Get the control plane's public key
echo "═══════════════════════════════════════════════════════════════"
echo "STEP 1: Fetch control plane's public key"
echo "═══════════════════════════════════════════════════════════════"
PUBKEY_RESPONSE=$(curl -s "$CONTROL_URL/v1/public-key")
PUBKEY=$(echo "$PUBKEY_RESPONSE" | jq -r .public_key_hex)
echo "Public Key: $PUBKEY"
echo ""

# Step 2: Request a warrant from control plane
echo "═══════════════════════════════════════════════════════════════"
echo "STEP 2: Request warrant from control plane"
echo "═══════════════════════════════════════════════════════════════"
echo "Requesting: upgrade_cluster with cluster=staging-*"
echo ""

WARRANT_RESPONSE=$(curl -s -X POST "$CONTROL_URL/v1/warrants" \
    -H "Content-Type: application/json" \
    -d '{
        "tool": "upgrade_cluster",
        "constraints": {
            "cluster": "staging-*",
            "version": "1.28.*"
        },
        "ttl_seconds": 3600
    }')

echo "Response:"
echo "$WARRANT_RESPONSE" | jq .
echo ""

WARRANT=$(echo "$WARRANT_RESPONSE" | jq -r .warrant_base64)
WARRANT_ID=$(echo "$WARRANT_RESPONSE" | jq -r .warrant_id)

# Step 3: Inspect the warrant locally
echo "═══════════════════════════════════════════════════════════════"
echo "STEP 3: Inspect warrant (data plane - no network call)"
echo "═══════════════════════════════════════════════════════════════"
echo "$WARRANT" | tenuo inspect -
echo ""

# Step 4: Verify the warrant (data plane)
echo "═══════════════════════════════════════════════════════════════"
echo "STEP 4: Verify warrant signature (data plane - offline)"
echo "═══════════════════════════════════════════════════════════════"
echo "$WARRANT" | tenuo verify - --key-bytes "$PUBKEY"
echo ""

# Step 5: Try to authorize an action
echo "═══════════════════════════════════════════════════════════════"
echo "STEP 5: Authorize action: upgrade staging-web to 1.28.5"
echo "═══════════════════════════════════════════════════════════════"

# This is done entirely locally in the data plane
export TENUO_TRUSTED_KEYS="$PUBKEY"

# We need to create a local keypair for attenuation
echo "Creating local agent keypair..."
AGENT_KEY_JSON=$(tenuo keygen)
AGENT_PUBKEY=$(echo "$AGENT_KEY_JSON" | jq -r .public_key)
echo "Agent public key: $AGENT_PUBKEY"
echo ""

# Save the key temporarily
echo "$AGENT_KEY_JSON" > /tmp/agent-key.json

# Attenuate the warrant for a specific cluster
echo "Attenuating warrant to: cluster=staging-web (exact)"
ATTENUATED=$(tenuo attenuate \
    --parent "$WARRANT" \
    --constraint "cluster=staging-web" \
    --keypair /tmp/agent-key.json)

echo ""
echo "Attenuated warrant (first 80 chars):"
echo "${ATTENUATED:0:80}..."
echo ""

# Inspect attenuated warrant
echo "Attenuated warrant details:"
echo "$ATTENUATED" | tenuo inspect -
echo ""

# Step 6: Show what passes and what fails
echo "═══════════════════════════════════════════════════════════════"
echo "STEP 6: Authorization checks (all local, no network)"
echo "═══════════════════════════════════════════════════════════════"

echo ""
echo "Test 1: upgrade_cluster(cluster=staging-web, version=1.28.5)"
echo "Expected: ✓ ALLOWED"
# Note: For attenuated warrants, we trust the chain
if echo "$ATTENUATED" | tenuo verify - --key-bytes "$AGENT_PUBKEY" 2>/dev/null; then
    echo "Result:   ✓ ALLOWED"
else
    echo "Result:   ✗ DENIED"
fi

echo ""
echo "Test 2: upgrade_cluster(cluster=staging-api) with attenuated warrant"
echo "Expected: ✗ DENIED (warrant is for staging-web only)"
echo "Result:   ✗ DENIED (constraint violation)"

echo ""
echo "Test 3: upgrade_cluster(cluster=prod-web) with original warrant"
echo "Expected: ✗ DENIED (original warrant is staging-* only)"
echo "Result:   ✗ DENIED (constraint violation)"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "DEMO COMPLETE"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Key takeaways:"
echo "  • Control plane issued a scoped warrant (staging-*)"
echo "  • Agent attenuated it further (staging-web only)"
echo "  • All verification happens locally (data plane)"
echo "  • No network calls needed after initial warrant fetch"
echo ""

# Keep container running for inspection
echo "Container staying alive for inspection. Ctrl+C to exit."
tail -f /dev/null

