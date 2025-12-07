#!/bin/bash
# Example script to test enrollment with the Tenuo Control Plane
# Make sure the control plane is running: python examples/control_plane.py

echo "=== Generating keypair and PoP signature ==="
# Generate keypair and signature
# Note: PoP signature is over SHA-256 hash of structured message for security
OUTPUT=$(python3 -c "
from tenuo import Keypair
import time
import hashlib

kp = Keypair.generate()
pk = kp.public_key()
pk_hex = bytes(pk.to_bytes()).hex()
ts = int(time.time())

# Create SHA-256 hash of structured message (matches control plane verification)
# Format: 'tenuo:enroll:v1:{public_key_hex}:{timestamp}'
structured_msg = f'tenuo:enroll:v1:{pk_hex}:{ts}'
msg_hash = hashlib.sha256(structured_msg.encode()).digest()

# Sign the hash
sig = kp.sign(msg_hash)
sig_hex = bytes(sig.to_bytes()).hex()

print(f'PUBKEY={pk_hex}')
print(f'SIG={sig_hex}')
print(f'TS={ts}')
")

# Extract values
PUBKEY=$(echo "$OUTPUT" | grep "PUBKEY=" | cut -d'=' -f2)
SIG=$(echo "$OUTPUT" | grep "SIG=" | cut -d'=' -f2)
TS=$(echo "$OUTPUT" | grep "TS=" | cut -d'=' -f2)

echo "Public Key: ${PUBKEY:0:32}..."
echo "Signature: ${SIG:0:32}..."
echo "Timestamp: $TS"
echo ""

echo "=== Sending enrollment request ==="
curl -X POST http://localhost:8080/v1/enroll \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"test-agent-1\",\"public_key_hex\":\"$PUBKEY\",\"pop_signature_hex\":\"$SIG\",\"timestamp\":$TS,\"enrollment_token\":\"demo-enrollment-token-2025\",\"constraints\":{\"file_path\":\"/tmp/*\"},\"ttl_seconds\":3600}" \
  | python -m json.tool

echo ""
echo "=== Done ==="

