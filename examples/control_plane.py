#!/usr/bin/env python3
"""
Tenuo Control Plane Implementation Example

This example demonstrates how to implement a Tenuo Control Plane service.
The control plane:

1. Manages a root keypair (trust anchor)
2. Enrolls agents (validates identity via Proof-of-Possession)
3. Issues root warrants at enrollment time
4. Provides public key distribution

Note: Agents receive their root warrant during enrollment. Additional
capabilities should be obtained through delegation/attenuation from
existing warrants, not by requesting new ones from the control plane.

This is a complete example using FastAPI.

Requirements:
    pip install fastapi uvicorn tenuo

Run:
    python examples/control_plane.py
"""

from tenuo import Keypair, Warrant, Pattern, Range, Exact, PublicKey, Signature
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import time
import json
import base64
import hashlib
from datetime import datetime, timedelta


def create_enrollment_pop_message(public_key_hex: str, timestamp: int) -> bytes:
    """
    Create a secure PoP message for enrollment.
    
    Instead of signing a raw string like "enroll:{public_key_hex}:{timestamp}",
    we create a structured message and hash it with SHA-256. This ensures:
    1. Fixed-length input (32 bytes) to the signing function
    2. No ambiguity from delimiters or variable-length fields
    3. Consistent canonicalization
    
    Args:
        public_key_hex: Agent's public key (hex-encoded, 64 chars)
        timestamp: Unix timestamp (integer)
    
    Returns:
        SHA-256 hash of the structured message (32 bytes)
    """
    # Create a structured message with clear field boundaries
    # Format: "tenuo:enroll:v1:" + public_key_hex (64 chars) + ":" + timestamp (as string)
    # The prefix ensures domain separation from other message types
    structured_message = f"tenuo:enroll:v1:{public_key_hex}:{timestamp}"
    
    # Hash the message to get a fixed 32-byte input for signing
    return hashlib.sha256(structured_message.encode('utf-8')).digest()

# ============================================================================
# Control Plane Service
# ============================================================================

class ControlPlaneService:
    """
    Control Plane service that issues warrants.
    
    In production:
    - Root keypair should be loaded from secure storage (K8s Secret, HSM, etc.)
    - Enrollment tokens should be rotated regularly
    - Agent enrollment should be tracked in a database
    - Audit logging should be sent to a logging service
    """
    
    def __init__(self, root_keypair: Keypair, enrollment_token: str):
        """
        Initialize control plane.
        
        Args:
            root_keypair: Root keypair for signing warrants (trust anchor)
            enrollment_token: Token for agent enrollment (should be rotated)
        """
        self.root_keypair = root_keypair
        self.public_key = root_keypair.public_key()
        self.enrollment_token = enrollment_token
        
        # Track enrolled agents (in production, use a database)
        # Maps public_key_bytes (hex) -> enrollment info
        self.enrolled_agents: Dict[str, Dict[str, Any]] = {}
    
    def get_public_key(self) -> Dict[str, str]:
        """Get the control plane's public key for distribution."""
        pub_bytes = self.public_key.to_bytes()
        return {
            "public_key_hex": bytes(pub_bytes).hex(),
            "public_key_base64": base64.b64encode(bytes(pub_bytes)).decode('utf-8')
        }
    
    def enroll_agent(
        self,
        agent_id: str,
        public_key_hex: str,
        pop_signature_hex: str,
        enrollment_token: str,
        timestamp: int,
        constraints: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 3600
    ) -> Warrant:
        """
        Enroll an agent and issue a root warrant.
        
        Enrollment process:
        1. Verify enrollment token
        2. Parse and verify public key
        3. Verify Proof-of-Possession signature (agent proves they own the keypair)
        4. Issue root warrant with specified constraints
        
        Args:
            agent_id: Unique identifier for the agent (e.g., pod name)
            public_key_hex: Agent's public key (hex-encoded)
            pop_signature_hex: Proof-of-Possession signature (hex-encoded)
            enrollment_token: Enrollment token (must match control plane's token)
            timestamp: Unix timestamp used in PoP signature (prevents replay attacks)
            constraints: Optional custom constraints (defaults to permissive)
            ttl_seconds: Warrant time-to-live in seconds
        
        Returns:
            Root warrant for the agent
        
        Raises:
            ValueError: If enrollment fails (invalid token, signature, etc.)
        """
        # 1. Verify enrollment token
        if enrollment_token != self.enrollment_token:
            raise ValueError("Invalid enrollment token")
        
        # 2. Parse public key
        try:
            pub_bytes = bytes.fromhex(public_key_hex)
            if len(pub_bytes) != 32:
                raise ValueError("Public key must be 32 bytes")
            agent_public_key = PublicKey.from_bytes(pub_bytes)
        except Exception as e:
            raise ValueError(f"Invalid public key: {e}")
        
        # 3. Verify timestamp freshness (prevents replay attacks)
        ENROLLMENT_POP_MAX_AGE_SECS = 300  # 5 minutes
        now = int(time.time())
        age = abs(now - timestamp)
        if age > ENROLLMENT_POP_MAX_AGE_SECS:
            raise ValueError(f"PoP timestamp too old: {age}s (max {ENROLLMENT_POP_MAX_AGE_SECS}s)")

        # 4. Verify Proof-of-Possession signature
        # The agent signs a SHA-256 hash of a structured message to prove keypair ownership.
        # Using SHA-256 ensures:
        # - Fixed 32-byte input to signing function
        # - No delimiter ambiguity
        # - Domain separation via "tenuo:enroll:v1:" prefix
        pop_message_hash = create_enrollment_pop_message(public_key_hex, timestamp)
        
        try:
            sig_bytes = bytes.fromhex(pop_signature_hex)
            if len(sig_bytes) != 64:
                raise ValueError("Signature must be 64 bytes")
            signature = Signature.from_bytes(sig_bytes)
        except Exception as e:
            raise ValueError(f"Invalid signature: {e}")
        
        # Verify signature against agent's public key
        # The agent should sign the PoP message hash with their private key
        # This proves they own the keypair (Proof-of-Possession)
        if not agent_public_key.verify(pop_message_hash, signature):
            raise ValueError("Invalid Proof-of-Possession signature")
        
        # 5. Build constraints (default to permissive if not specified)
        if constraints is None:
            constraints = {
                "file_path": Pattern("/tmp/*"),  # Default: only /tmp/ files
                "cluster": Pattern("staging-*"),  # Default: only staging clusters
            }
        
        # Convert string patterns to Constraint objects
        warrant_constraints = {}
        for key, value in constraints.items():
            if isinstance(value, str):
                # Assume string patterns are glob patterns
                warrant_constraints[key] = Pattern(value)
            elif isinstance(value, (Pattern, Range, Exact)):
                warrant_constraints[key] = value
            else:
                raise ValueError(f"Invalid constraint type for {key}: {type(value)}")
        
        # 6. Issue root warrant (PoP-bound to agent's public key)
        # The warrant is bound to the agent's public key - only the agent
        # with the matching private key can use it (Proof-of-Possession)
        warrant = Warrant.create(
            tool="agent_tools",  # Default tool name - agents can use this for all tools
            constraints=warrant_constraints,
            ttl_seconds=ttl_seconds,
            keypair=self.root_keypair,
            authorized_holder=agent_public_key,  # PoP binding!
        )
        
        # 7. Track enrolled agent
        self.enrolled_agents[public_key_hex] = {
            "agent_id": agent_id,
            "public_key": public_key_hex,
            "enrolled_at": datetime.utcnow().isoformat(),
            "warrant_id": warrant.id
        }
        
        print(f"✓ Enrolled agent: {agent_id} (public key: {public_key_hex[:16]}...)")
        
        return warrant


# ============================================================================
# FastAPI Application
# ============================================================================

# Initialize control plane
# HARDCODED: For demo, generate keypair. In production, load from secure storage.
# ENV VARIABLE: TENUO_SECRET_KEY (hex-encoded 32-byte key)
root_keypair = Keypair.generate() if not os.getenv("TENUO_SECRET_KEY") else Keypair.from_bytes(
    bytes.fromhex(os.getenv("TENUO_SECRET_KEY"))
)

# ENV VARIABLE: TENUO_ENROLLMENT_TOKEN
enrollment_token = os.getenv("TENUO_ENROLLMENT_TOKEN", "demo-enrollment-token-2025")

control_plane = ControlPlaneService(root_keypair, enrollment_token)

app = FastAPI(
    title="Tenuo Control Plane",
    description="Control plane service for agent enrollment and root warrant issuance",
    version="0.1.0"
)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/health")
async def health():
    """
    Health check endpoint.
    
    Example CURL:
        curl http://localhost:8080/health
    """
    return {"status": "healthy", "version": "0.1.0"}


@app.get("/v1/public-key")
async def get_public_key():
    """
    Get the control plane's public key.
    
    Agents use this to:
    - Verify warrants are signed by this control plane
    - Initialize Authorizer with trusted public key
    
    Example CURL:
        curl http://localhost:8080/v1/public-key
    """
    return control_plane.get_public_key()


class EnrollRequest(BaseModel):
    """Request to enroll an agent."""
    agent_id: str
    public_key_hex: str
    pop_signature_hex: str
    enrollment_token: str
    timestamp: int  # Unix timestamp used in PoP signature (prevents replay attacks)
    constraints: Optional[Dict[str, Any]] = None
    ttl_seconds: int = 3600


class EnrollResponse(BaseModel):
    """Response with issued root warrant (PoP-bound)."""
    warrant_id: str
    warrant_base64: str
    expires_at: str
    public_key_hex: str  # Control plane's public key
    requires_pop: bool = True  # Indicates warrant requires Proof-of-Possession


@app.post("/v1/enroll", response_model=EnrollResponse)
async def enroll(request: EnrollRequest):
    """
    Enroll an agent and issue a root warrant.
    
    Process:
    1. Agent generates keypair locally
    2. Agent signs a Proof-of-Possession message
    3. Agent sends public key + signature + enrollment token
    4. Control plane verifies and issues root warrant
    
    Example CURL:
        # Step 1: Generate keypair and PoP signature (uses SHA-256 hash of structured message)
        python -c "from tenuo import Keypair; import time, hashlib; kp = Keypair.generate(); pk = kp.public_key(); pk_hex = bytes(pk.to_bytes()).hex(); ts = int(time.time()); msg_hash = hashlib.sha256(f'tenuo:enroll:v1:{pk_hex}:{ts}'.encode()).digest(); sig = kp.sign(msg_hash); sig_hex = bytes(sig.to_bytes()).hex(); print(f'PUBKEY={pk_hex}'); print(f'SIG={sig_hex}'); print(f'TS={ts}')"
        
        # Step 2: Copy the PUBKEY, SIG, and TS values, then run:
        # (Replace YOUR_PUBKEY, YOUR_SIG, YOUR_TS with actual values from Step 1)
        curl -X POST http://localhost:8080/v1/enroll \\
          -H "Content-Type: application/json" \\
          -d '{"agent_id":"test-agent-1","public_key_hex":"YOUR_PUBKEY","pop_signature_hex":"YOUR_SIG","timestamp":YOUR_TS,"enrollment_token":"demo-enrollment-token-2025","constraints":{"file_path":"/tmp/*"},"ttl_seconds":3600}'
        
        # Or use the test script for convenience:
        # bash examples/test_enrollment.sh
    
    Example JSON:
        {
            "agent_id": "langchain-agent-pod-1",
            "public_key_hex": "a1b2c3...",
            "pop_signature_hex": "d4e5f6...",
            "timestamp": 134534,
            "enrollment_token": "demo-enrollment-token-2025",
            "constraints": {"file_path": "/tmp/*"},
            "ttl_seconds": 3600
        }
    """
    try:
        warrant = control_plane.enroll_agent(
            agent_id=request.agent_id,
            public_key_hex=request.public_key_hex,
            pop_signature_hex=request.pop_signature_hex,
            enrollment_token=request.enrollment_token,
            timestamp=request.timestamp,
            constraints=request.constraints,
            ttl_seconds=request.ttl_seconds
        )
        
        pub_key_info = control_plane.get_public_key()
        
        return EnrollResponse(
            warrant_id=warrant.id,
            warrant_base64=warrant.to_base64(),
            expires_at=warrant.expires_at,
            public_key_hex=pub_key_info["public_key_hex"],
            requires_pop=warrant.requires_pop,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


# ============================================================================
# Main
# ============================================================================

# ============================================================================
# Client Example: How to Enroll with Control Plane
# ============================================================================

def example_agent_enrollment():
    """
    Example showing how an agent would enroll with the control plane.
    
    This demonstrates the enrollment flow:
    1. Agent generates keypair
    2. Agent creates PoP signature (over SHA-256 hash of structured message)
    3. Agent sends enrollment request
    4. Agent receives root warrant
    """
    import requests
    
    # 1. Agent generates keypair
    agent_keypair = Keypair.generate()
    agent_public_key = agent_keypair.public_key()
    agent_pubkey_hex = bytes(agent_public_key.to_bytes()).hex()
    
    # 2. Create Proof-of-Possession signature
    # Sign SHA-256 hash of structured message for security:
    # - Fixed 32-byte input to signing function
    # - No delimiter ambiguity
    # - Domain separation via prefix
    timestamp = int(time.time())  # Unix timestamp as integer
    pop_message_hash = create_enrollment_pop_message(agent_pubkey_hex, timestamp)
    
    # Sign the hash with agent's private key
    pop_sig = agent_keypair.sign(pop_message_hash)
    pop_sig_hex = bytes(pop_sig.to_bytes()).hex()
    
    # 3. Send enrollment request
    control_plane_url = os.getenv("TENUO_CONTROL_URL", "http://localhost:8080")
    enrollment_token = os.getenv("TENUO_ENROLLMENT_TOKEN", "demo-enrollment-token-2025")
    
    response = requests.post(
        f"{control_plane_url}/v1/enroll",
        json={
            "agent_id": "example-agent-1",
            "public_key_hex": agent_pubkey_hex,
            "pop_signature_hex": pop_sig_hex,
            "timestamp": timestamp,  # Unix timestamp used in PoP signature
            "enrollment_token": enrollment_token,
            "constraints": {
                "file_path": "/tmp/*",
                "cluster": "staging-*"
            },
            "ttl_seconds": 3600
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        warrant = Warrant.from_base64(data["warrant_base64"])
        print(f"✓ Enrolled! Warrant ID: {warrant.id[:8]}...")
        return warrant
    else:
        print(f"✗ Enrollment failed: {response.status_code} - {response.text}")
        return None


# ============================================================================
# Testing with CURL
# ============================================================================
#
# Complete workflow example:
#
# 1. Start the server:
#    python examples/control_plane.py
#
# 2. Health check:
#    curl http://localhost:8080/health
#
# [Separate terminal]
#
# 3. Get control plane public key:
#    curl http://localhost:8080/v1/public-key
#
# 4. Enroll an agent (requires generating keypair and PoP signature):
#    # Generate keypair and PoP signature (uses SHA-256 hash of structured message):
#    python -c "
#    from tenuo import Keypair
#    import time, hashlib
#    kp = Keypair.generate()
#    pk = kp.public_key()
#    pk_hex = bytes(pk.to_bytes()).hex()
#    ts = int(time.time())
#    # Sign SHA-256 hash of structured message
#    msg_hash = hashlib.sha256(f'tenuo:enroll:v1:{pk_hex}:{ts}'.encode()).digest()
#    sig = kp.sign(msg_hash)
#    sig_hex = bytes(sig.to_bytes()).hex()
#    print(f'export AGENT_PUBKEY={pk_hex}')
#    print(f'export POP_SIG={sig_hex}')
#    print(f'export TIMESTAMP={ts}')
#    "
#
#    # Then enroll (use values from above):
#    curl -X POST http://localhost:8080/v1/enroll \\
#      -H "Content-Type: application/json" \\
#      -d "{
#        \"agent_id\": \"test-agent-1\",
#        \"public_key_hex\": \"$AGENT_PUBKEY\",
#        \"pop_signature_hex\": \"$POP_SIG\",
#        \"enrollment_token\": \"demo-enrollment-token-2025\",
#        \"constraints\": {\"file_path\": \"/tmp/*\"},
#        \"ttl_seconds\": 3600
#      }"
#
# 5. Delegate capabilities:
#    Once enrolled with a root warrant, agents should DELEGATE their capabilities
#    to sub-agents using warrant attenuation, not request new warrants.
#    See examples/decorator_example.py for delegation and context pattern examples.
#
# ============================================================================


if __name__ == "__main__":
    import uvicorn
    
    print("=" * 70)
    print("Tenuo Control Plane")
    print("=" * 70)
    pub_key_info = control_plane.get_public_key()
    print(f"Public Key (hex): {pub_key_info['public_key_hex'][:32]}...")
    print(f"Public Key (base64): {pub_key_info['public_key_base64'][:24]}...")
    print(f"Enrollment Token: {enrollment_token}")
    print()
    print("Endpoints:")
    print("  GET  /health              - Health check")
    print("  GET  /v1/public-key       - Get control plane public key")
    print("  POST /v1/enroll           - Enroll agent and get root warrant")
    print()
    print("Capability Model:")
    print("  Agents receive root warrants at enrollment. Additional capabilities")
    print("  should be obtained through delegation/attenuation, not new requests.")
    print()
    print("Security Features:")
    print("   - PoP-bound warrants: All issued warrants require Proof-of-Possession")
    print("   - PoP signature verification: Enrollment requires PoP signature")
    print("   - Enrollment token required: Shared secret for initial enrollment")
    print("   - Agent tracking for audit: Enrolled agents are tracked")
    print()
    print("Quick Test Examples:")
    print("  # Health check:")
    print("  curl http://localhost:8080/health")
    print()
    print("  # Get public key:")
    print("  curl http://localhost:8080/v1/public-key")
    print()
    print("  # See endpoint docstrings for full CURL examples with enrollment")
    print()
    print("Starting server on http://0.0.0.0:8080")
    print("=" * 70)
    print()
    
    uvicorn.run(app, host="0.0.0.0", port=8080)

