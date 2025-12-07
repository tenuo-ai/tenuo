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
    task_constraints: dict,
    ttl_seconds: int = 300
) -> Warrant:
    """
    Orchestrator attenuates its warrant for a specific worker task.
    
    This is an OFFLINE operation - no Control Plane call.
    The worker's warrant is NARROWER than the orchestrator's.
    
    Args:
        orchestrator_warrant: Orchestrator's root warrant (broad scope)
        orchestrator_keypair: Orchestrator's keypair (for signing)
        task_constraints: Narrower constraints for this specific task
        ttl_seconds: Short TTL for task-scoped warrant
    
    Returns:
        Attenuated warrant for worker
    """
    return orchestrator_warrant.attenuate(
        constraints=task_constraints,
        keypair=orchestrator_keypair,
        ttl_seconds=ttl_seconds
    )


def demo_orchestrator_worker_delegation():
    """
    Demonstrates orchestrator delegating to worker pods.
    
    Scenario:
        - Orchestrator has broad warrant: file_path=/data/*
        - Task needs to process only /data/batch-123/*
        - Orchestrator attenuates warrant for worker
        - Worker can ONLY access /data/batch-123/*
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
        authorized_holder=orchestrator_keypair.public_key()  # PoP-bound
    )
    print(f"1. Orchestrator warrant: file_path=/data/* (broad)")
    print(f"   ID: {orchestrator_warrant.id[:8]}...")
    print(f"   Expires: {orchestrator_warrant.expires_at}\n")
    
    # Orchestrator receives task: process batch-123
    # Attenuate warrant for worker (OFFLINE - no Control Plane call)
    worker_warrant = attenuate_for_worker(
        orchestrator_warrant=orchestrator_warrant,
        orchestrator_keypair=orchestrator_keypair,
        task_constraints={
            "file_path": Pattern("/data/batch-123/*"),  # Narrow: only batch-123
        },
        ttl_seconds=300  # 5 minutes for task
    )
    print(f"2. Worker warrant: file_path=/data/batch-123/* (narrow)")
    print(f"   ID: {worker_warrant.id[:8]}...")
    print(f"   Parent: {worker_warrant.parent_id[:8] if worker_warrant.parent_id else 'None'}...")
    print(f"   Depth: {worker_warrant.depth}")
    print(f"   Expires: {worker_warrant.expires_at}\n")
    
    # Worker receives warrant (e.g., via HTTP header or K8s Job env)
    print("3. Worker receives attenuated warrant:")
    print(f"   • Via HTTP: X-Tenuo-Warrant: {worker_warrant.to_base64()[:40]}...")
    print(f"   • Via K8s Job env: TENUO_WARRANT_BASE64=...")
    print()
    
    print("4. Security properties:")
    print("   ✓ Worker can ONLY access /data/batch-123/*")
    print("   ✓ Worker CANNOT access /data/other-batch/*")
    print("   ✓ Warrant expires in 5 minutes (task-scoped)")
    print("   ✓ Attenuation was OFFLINE (no Control Plane call)")
    print("   ✓ Warrant chain: Control Plane → Orchestrator → Worker")


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
from tenuo import Keypair, set_warrant_context
import httpx

# Orchestrator loads its warrant and keypair at startup
orchestrator_warrant = load_warrant()
orchestrator_keypair = Keypair.from_bytes(load_keypair_bytes())  # From K8s Secret

app = FastAPI()

@app.post("/tasks/process")
async def process_task(batch_id: str):
    """Orchestrator delegates task to worker."""
    
    # Attenuate warrant for this specific batch (OFFLINE)
    worker_warrant = orchestrator_warrant.attenuate(
        constraints={"file_path": Pattern(f"/data/{batch_id}/*")},
        keypair=orchestrator_keypair,
        ttl_seconds=300
    )
    
    # Send to worker with attenuated warrant
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
