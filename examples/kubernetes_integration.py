#!/usr/bin/env python3
"""
Kubernetes Integration Example with Tenuo

This example shows how agents running in Kubernetes load, use, and delegate warrants.

Production Patterns:

1. Simple Agent (single pod):
    Control Plane → K8s Secret → Agent Pod → @lockdown tools

2. Orchestrator + Workers (delegation):
    Control Plane → K8s Secret → Orchestrator Pod
                                      │
                                      │ Attenuates warrant (OFFLINE)
                                      ▼
                               Worker Pods (via HTTP or K8s Job)

Key Concepts:
    - Control Plane contacted ONCE at enrollment
    - Orchestrator attenuates locally (no network call)
    - Workers receive narrower warrants
    - All verification is OFFLINE
"""

from tenuo import (
    Keypair, Warrant, Pattern,
    lockdown, set_warrant_context, AuthorizationError
)
from typing import Optional
import os


# ============================================================================
# Warrant Loading (Production Code)
# ============================================================================

def load_warrant() -> Optional[Warrant]:
    """
    Load warrant from Kubernetes environment.
    
    Checks (in order):
    1. TENUO_WARRANT_BASE64 env var (set from K8s Secret)
    2. /etc/tenuo/warrant.b64 file (mounted K8s Secret)
    
    Returns:
        Warrant if found, None otherwise
    """
    # Option 1: Environment variable (from K8s Secret)
    warrant_b64 = os.getenv("TENUO_WARRANT_BASE64")
    if warrant_b64:
        try:
            return Warrant.from_base64(warrant_b64)
        except Exception as e:
            print(f"Error: Invalid warrant in TENUO_WARRANT_BASE64: {e}")
            return None
    
    # Option 2: Mounted file (from K8s Secret)
    warrant_path = os.getenv("TENUO_WARRANT_PATH", "/etc/tenuo/warrant.b64")
    if os.path.exists(warrant_path):
        try:
            with open(warrant_path, 'r') as f:
                return Warrant.from_base64(f.read().strip())
        except Exception as e:
            print(f"Error: Invalid warrant in {warrant_path}: {e}")
            return None
    
    return None


# ============================================================================
# Protected Tool Functions
# ============================================================================

@lockdown(tool="read_file", extract_args=lambda file_path, **kw: {"file_path": file_path})
def read_file(file_path: str) -> str:
    """Read a file. Protected by Tenuo warrant."""
    with open(file_path, 'r') as f:
        return f.read()


@lockdown(tool="write_file", extract_args=lambda file_path, content, **kw: {"file_path": file_path})
def write_file(file_path: str, content: str) -> str:
    """Write to a file. Protected by Tenuo warrant."""
    with open(file_path, 'w') as f:
        f.write(content)
    return f"Wrote {len(content)} bytes to {file_path}"


# ============================================================================
# Orchestrator → Worker Delegation (Attenuation)
# ============================================================================

def attenuate_for_worker(
    orchestrator_warrant: Warrant,
    orchestrator_keypair: Keypair,
    worker_public_key,  # Worker's public key for PoP binding
    task_constraints: dict,
    ttl_seconds: int = 300
) -> Warrant:
    """
    Orchestrator attenuates its warrant for a specific worker task.
    
    This is an OFFLINE operation - no Control Plane call.
    The worker's warrant is NARROWER than the orchestrator's and
    PoP-bound to the worker's public key.
    
    Args:
        orchestrator_warrant: Orchestrator's root warrant (broad scope)
        orchestrator_keypair: Orchestrator's keypair (for signing)
        worker_public_key: Worker's public key (for PoP binding)
        task_constraints: Narrower constraints for this specific task
        ttl_seconds: Short TTL for task-scoped warrant
    
    Returns:
        Attenuated warrant bound to worker's public key
    """
    return orchestrator_warrant.attenuate(
        constraints=task_constraints,
        keypair=orchestrator_keypair,
        ttl_seconds=ttl_seconds,
        authorized_holder=worker_public_key  # PoP-bound to worker
    )


def demo_orchestrator_worker_delegation():
    """
    Demonstrates orchestrator delegating to worker pods.
    
    Scenario:
        - Orchestrator has broad warrant: file_path=/data/*
        - Worker has its own keypair (identity)
        - Task needs to process only /data/batch-123/*
        - Orchestrator attenuates warrant, PoP-bound to worker
        - ONLY that worker can use the warrant
    """
    print("\n=== Orchestrator → Worker Delegation ===\n")
    
    # Control Plane keypair (simulated - in production, from enrollment)
    control_keypair = Keypair.generate()
    
    # Orchestrator's keypair and root warrant
    orchestrator_keypair = Keypair.generate()
    orchestrator_warrant = Warrant.create(
        tool="process_file",
        constraints={
            "file_path": Pattern("/data/*"),  # Broad: all of /data/
        },
        ttl_seconds=86400,  # 24 hours
        keypair=control_keypair,
        authorized_holder=orchestrator_keypair.public_key()  # PoP-bound to orchestrator
    )
    print(f"1. Orchestrator warrant:")
    print(f"   Scope: file_path=/data/* (broad)")
    print(f"   Bound to: Orchestrator's public key")
    print(f"   ID: {orchestrator_warrant.id[:8]}...\n")
    
    # Worker has its own identity (keypair)
    # In production: worker loads this from K8s Secret at startup
    worker_keypair = Keypair.generate()
    worker_pubkey = worker_keypair.public_key()
    print(f"2. Worker identity:")
    print(f"   Public key: {bytes(worker_pubkey.to_bytes()).hex()[:16]}...\n")
    
    # Orchestrator attenuates warrant for THIS SPECIFIC worker
    # The warrant is PoP-bound to worker's public key
    worker_warrant = attenuate_for_worker(
        orchestrator_warrant=orchestrator_warrant,
        orchestrator_keypair=orchestrator_keypair,
        worker_public_key=worker_pubkey,  # Bind to worker's identity
        task_constraints={
            "file_path": Pattern("/data/batch-123/*"),  # Narrow: only batch-123
        },
        ttl_seconds=300  # 5 minutes for task
    )
    print(f"3. Attenuated warrant for worker:")
    print(f"   Scope: file_path=/data/batch-123/* (narrow)")
    print(f"   Bound to: Worker's public key (PoP required)")
    print(f"   ID: {worker_warrant.id[:8]}...")
    print(f"   Parent: {worker_warrant.parent_id[:8] if worker_warrant.parent_id else 'None'}...")
    print(f"   Depth: {worker_warrant.depth}")
    print(f"   TTL: 5 minutes\n")
    
    # Worker receives warrant + uses its private key to prove possession
    print("4. Worker usage:")
    print("   • Receives warrant via HTTP header or K8s Job env")
    print("   • Must sign with private key to prove identity (PoP)")
    print("   • Other pods CANNOT use this warrant (wrong key)\n")
    
    print("5. Security properties:")
    print("   ✓ Warrant PoP-bound to worker's public key")
    print("   ✓ Only THIS worker can use it (has private key)")
    print("   ✓ Scope narrowed: /data/* → /data/batch-123/*")
    print("   ✓ TTL shortened: 24h → 5 minutes")
    print("   ✓ Attenuation was OFFLINE (no Control Plane call)")
    print("   ✓ Chain: Control Plane → Orchestrator → Worker")


# ============================================================================
# FastAPI Integration (Production Pattern)
# ============================================================================

FASTAPI_EXAMPLE = '''
from fastapi import FastAPI
from tenuo import set_warrant_context
from contextlib import asynccontextmanager

# Load warrant ONCE at startup
warrant = load_warrant()
if not warrant:
    raise RuntimeError("No warrant found - agent cannot start")

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"Agent started with warrant: {warrant.id[:8]}...")
    yield

app = FastAPI(lifespan=lifespan)

@app.post("/agent/run")
async def run_agent(prompt: str):
    """Run agent with warrant protection."""
    with set_warrant_context(warrant):
        # All @lockdown tools are now protected
        result = your_agent.invoke(prompt)
        return {"result": result}
'''


# ============================================================================
# Orchestrator FastAPI Example (with delegation)
# ============================================================================

ORCHESTRATOR_FASTAPI_EXAMPLE = '''
from fastapi import FastAPI
from tenuo import Keypair, Pattern, set_warrant_context
import httpx

# Orchestrator loads its warrant and keypair at startup
orchestrator_warrant = load_warrant()
orchestrator_keypair = Keypair.from_bytes(load_keypair_bytes())  # From K8s Secret

app = FastAPI()

@app.post("/tasks/process")
async def process_task(batch_id: str, worker_pubkey_hex: str):
    """Orchestrator delegates task to a specific worker."""
    
    # Worker's public key (from request or service discovery)
    worker_pubkey = PublicKey.from_bytes(bytes.fromhex(worker_pubkey_hex))
    
    # Attenuate warrant for this specific worker and batch (OFFLINE)
    worker_warrant = orchestrator_warrant.attenuate(
        constraints={"file_path": Pattern(f"/data/{batch_id}/*")},
        keypair=orchestrator_keypair,
        ttl_seconds=300,
        authorized_holder=worker_pubkey  # PoP-bound to THIS worker
    )
    
    # Send to worker - only they can use it (has matching private key)
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://worker-service:8000/process",
            json={"batch_id": batch_id},
            headers={"X-Tenuo-Warrant": worker_warrant.to_base64()}
        )
    
    return {"status": "delegated", "batch_id": batch_id}
'''


# ============================================================================
# Kubernetes Manifests
# ============================================================================

K8S_DEPLOYMENT = '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tenuo-agent
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tenuo-agent
  template:
    metadata:
      labels:
        app: tenuo-agent
    spec:
      containers:
      - name: agent
        image: your-agent:latest
        env:
        # Option 1: Warrant from env var
        - name: TENUO_WARRANT_BASE64
          valueFrom:
            secretKeyRef:
              name: tenuo-warrant
              key: WARRANT_BASE64
        # Option 2: Warrant from mounted file
        volumeMounts:
        - name: warrant
          mountPath: /etc/tenuo
          readOnly: true
      volumes:
      - name: warrant
        secret:
          secretName: tenuo-warrant
---
apiVersion: v1
kind: Secret
metadata:
  name: tenuo-warrant
type: Opaque
stringData:
  # Warrant issued by Control Plane during enrollment
  WARRANT_BASE64: <base64-warrant-from-control-plane>
  warrant.b64: <base64-warrant-from-control-plane>
'''


# ============================================================================
# Demo
# ============================================================================

def main():
    print("=== Kubernetes Integration Demo ===\n")
    
    # In production: warrant comes from K8s Secret
    # For demo: create one
    print("1. Simulating K8s environment...")
    demo_keypair = Keypair.generate()
    demo_warrant = Warrant.create(
        tool="read_file",
        constraints={"file_path": Pattern("/tmp/*")},
        ttl_seconds=3600,
        keypair=demo_keypair
    )
    os.environ["TENUO_WARRANT_BASE64"] = demo_warrant.to_base64()
    print(f"   Set TENUO_WARRANT_BASE64 (simulating K8s Secret)\n")
    
    # Load warrant (what agent does at startup)
    print("2. Loading warrant (agent startup)...")
    warrant = load_warrant()
    if warrant:
        print(f"   ✓ Loaded warrant: {warrant.id[:8]}...")
        print(f"   ✓ Tool: {warrant.tool}")
        print(f"   ✓ Expires: {warrant.expires_at}\n")
    else:
        print("   ✗ No warrant found")
        return
    
    # Use warrant (what agent does per-request)
    print("3. Using warrant (per-request)...")
    with set_warrant_context(warrant):
        # Authorized
        try:
            read_file("/tmp/test.txt")
            print("   ✓ read_file('/tmp/test.txt'): Allowed")
        except AuthorizationError:
            print("   ✗ Unexpected denial")
        except FileNotFoundError:
            print("   ✓ read_file('/tmp/test.txt'): Allowed (file doesn't exist)")
        
        # Blocked
        try:
            read_file("/etc/passwd")
            print("   ✗ Should have been blocked!")
        except AuthorizationError:
            print("   ✓ read_file('/etc/passwd'): Blocked (constraint violation)")
    
    print("\n=== Summary (Simple Agent) ===")
    print("  • Warrant loaded from K8s Secret at startup")
    print("  • All verification is OFFLINE (no network calls)")
    print("  • @lockdown decorator enforces constraints")
    print("  • Works across all pod replicas")
    
    # Also demonstrate orchestrator → worker delegation
    demo_orchestrator_worker_delegation()
    
    print("\n=== Summary (Orchestrator → Worker) ===")
    print("  • Orchestrator attenuates warrant LOCALLY (offline)")
    print("  • Worker receives narrower, time-limited warrant")
    print("  • Delegation chain is cryptographically verifiable")
    print("  • No Control Plane call for attenuation")


if __name__ == "__main__":
    main()
