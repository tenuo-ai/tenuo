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
# Orchestrator FastAPI Example (Identity-as-Config Pattern)
# ============================================================================

ORCHESTRATOR_FASTAPI_EXAMPLE = '''
from fastapi import FastAPI
from tenuo import Keypair, PublicKey, Warrant, Pattern
import httpx
import os

# =============================================================================
# STARTUP: Load all identities from K8s Secrets (wired by Terraform/Helm)
# =============================================================================

# Orchestrator's own identity
ORCHESTRATOR_KEYPAIR = Keypair.from_bytes(bytes.fromhex(os.getenv("ORCHESTRATOR_PRIVATE_KEY")))
ROOT_WARRANT = Warrant.from_base64(os.getenv("TENUO_WARRANT_BASE64"))

# Worker's identity (PUBLIC KEY ONLY - loaded at deploy time)
# This is "Identity-as-Config" - Orchestrator knows Worker's identity statically
SCRAPER_PUBLIC_KEY = PublicKey.from_bytes(bytes.fromhex(os.getenv("SCRAPER_PUBLIC_KEY")))

app = FastAPI()

@app.post("/tasks/scrape")
async def delegate_to_scraper(url: str):
    """Orchestrator delegates scraping task to the Scraper worker."""
    
    # Attenuate per-request (EPHEMERAL warrant)
    # - Scoped to this specific URL
    # - Bound to the Scraper's static identity
    # - Valid for only 30 seconds
    request_warrant = ROOT_WARRANT.attenuate(
        constraints={"url": Pattern(url)},
        authorized_holder=SCRAPER_PUBLIC_KEY,  # Static identity, known at deploy time
        keypair=ORCHESTRATOR_KEYPAIR,
        ttl_seconds=30  # Ephemeral!
    )
    
    # Push to worker
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://scraper-service/run",
            json={"url": url},
            headers={"X-Tenuo-Warrant": request_warrant.to_base64()}
        )
    
    return response.json()
'''


# ============================================================================
# Worker FastAPI Example (Long-Running Identity Pattern)
# ============================================================================

WORKER_FASTAPI_EXAMPLE = '''
from fastapi import FastAPI, Request, HTTPException
from tenuo import Keypair, Warrant, set_warrant_context
import os

app = FastAPI()

# =============================================================================
# STARTUP: Load long-running identity (stays in memory for days/weeks)
# =============================================================================
WORKER_KEYPAIR = Keypair.from_bytes(bytes.fromhex(os.getenv("WORKER_PRIVATE_KEY")))

@app.middleware("http")
async def verify_tenuo_auth(request: Request, call_next):
    """Verify warrant is bound to THIS worker's identity."""
    
    # 1. Extract warrant from header
    warrant_b64 = request.headers.get("X-Tenuo-Warrant")
    if not warrant_b64:
        raise HTTPException(401, "Missing Warrant")
    
    warrant = Warrant.from_base64(warrant_b64)
    
    # 2. CRITICAL: Proof-of-Possession check
    # "Is this warrant meant for ME?"
    # If someone stole this warrant, they can't use it - wrong key!
    if warrant.authorized_holder != WORKER_KEYPAIR.public_key():
        raise HTTPException(403, "Warrant not bound to my identity")
    
    # 3. Set context for @lockdown decorators
    with set_warrant_context(warrant):
        return await call_next(request)

@app.post("/run")
def run_scraper(payload: dict):
    """Execute scraping task. @lockdown decorators check constraints."""
    return scrape_tool(payload["url"])
'''


# ============================================================================
# Kubernetes Manifests
# ============================================================================

K8S_SIMPLE_AGENT = '''
# Simple Agent: Single pod with warrant
apiVersion: v1
kind: Secret
metadata:
  name: agent-identity
stringData:
  PRIVATE_KEY: <agent-private-key-hex>
  WARRANT_BASE64: <base64-warrant-from-control-plane>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tenuo-agent
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: agent
        image: your-agent:latest
        env:
        - name: AGENT_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: agent-identity
              key: PRIVATE_KEY
        - name: TENUO_WARRANT_BASE64
          valueFrom:
            secretKeyRef:
              name: agent-identity
              key: WARRANT_BASE64
'''


# ============================================================================
# K8s Manifests: Identity-as-Config (Orchestrator + Worker)
# ============================================================================

K8S_ORCHESTRATOR_WORKER = '''
# =============================================================================
# IDENTITY-AS-CONFIG PATTERN
# =============================================================================
# Worker's identity is a Secret with both keys.
# - Worker gets the PRIVATE_KEY (to prove identity)
# - Orchestrator gets the PUBLIC_KEY (to bind warrants)
# =============================================================================

# 1. Worker Identity Secret (generated by CI/CD or Terraform)
apiVersion: v1
kind: Secret
metadata:
  name: scraper-identity
stringData:
  PRIVATE_KEY: "a1b2c3..."  # For the Worker
  PUBLIC_KEY: "d4e5f6..."   # For the Orchestrator
---

# 2. Orchestrator Identity Secret
apiVersion: v1
kind: Secret
metadata:
  name: orchestrator-identity
stringData:
  PRIVATE_KEY: "x1y2z3..."
  WARRANT_BASE64: "<root-warrant-from-control-plane>"
---

# 3. Worker Deployment (gets its PRIVATE key)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scraper-worker
spec:
  template:
    spec:
      containers:
      - name: app
        image: scraper:latest
        env:
        - name: WORKER_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: scraper-identity
              key: PRIVATE_KEY
---

# 4. Orchestrator Deployment (gets Worker's PUBLIC key)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: orchestrator
spec:
  template:
    spec:
      containers:
      - name: app
        image: orchestrator:latest
        env:
        # Orchestrator's own identity
        - name: ORCHESTRATOR_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: orchestrator-identity
              key: PRIVATE_KEY
        - name: TENUO_WARRANT_BASE64
          valueFrom:
            secretKeyRef:
              name: orchestrator-identity
              key: WARRANT_BASE64
        # IDENTITY-AS-CONFIG: Orchestrator knows Scraper's public key
        - name: SCRAPER_PUBLIC_KEY
          valueFrom:
            secretKeyRef:
              name: scraper-identity
              key: PUBLIC_KEY
'''


# ============================================================================
# Demo
# ============================================================================

def main():
    print("=== Kubernetes Integration Demo ===\n")
    
    # ========================================================================
    # Simple Agent Pattern (with PoP binding)
    # ========================================================================
    
    # In production: Control Plane issues warrant bound to agent's public key
    # Agent's keypair is stored in K8s Secret alongside warrant
    print("1. Simulating K8s environment...")
    
    # Control Plane keypair (issuer)
    control_keypair = Keypair.generate()
    
    # Agent's own keypair (identity) - in production, from K8s Secret
    agent_keypair = Keypair.generate()
    agent_pubkey = agent_keypair.public_key()
    
    # Warrant issued by Control Plane, PoP-bound to THIS agent
    agent_warrant = Warrant.create(
        tool="read_file",
        constraints={"file_path": Pattern("/tmp/*")},
        ttl_seconds=3600,
        keypair=control_keypair,
        authorized_holder=agent_pubkey  # PoP-bound to agent
    )
    
    # In K8s: both warrant and agent keypair stored in Secret
    os.environ["TENUO_WARRANT_BASE64"] = agent_warrant.to_base64()
    print(f"   Agent public key: {bytes(agent_pubkey.to_bytes()).hex()[:16]}...")
    print(f"   Warrant PoP-bound to agent's key")
    print(f"   Set TENUO_WARRANT_BASE64 (simulating K8s Secret)\n")
    
    # Load warrant (what agent does at startup)
    print("2. Loading warrant (agent startup)...")
    warrant = load_warrant()
    if warrant:
        print(f"   ✓ Loaded warrant: {warrant.id[:8]}...")
        print(f"   ✓ Tool: {warrant.tool}")
        print(f"   ✓ PoP required: {warrant.requires_pop}")
        print(f"   ✓ Expires: {warrant.expires_at}\n")
    else:
        print("   ✗ No warrant found")
        return
    
    # Use warrant (agent must prove identity with its private key)
    print("3. Using warrant (per-request)...")
    print("   Agent uses private key to sign PoP when calling tools")
    with set_warrant_context(warrant):
        # Authorized
        try:
            read_file("/tmp/test.txt")
            print("   ✓ read_file('/tmp/test.txt'): Allowed")
        except AuthorizationError:
            print("   ✗ Unexpected denial")
        except FileNotFoundError:
            print("   ✓ read_file('/tmp/test.txt'): Allowed (file doesn't exist)")
        
        # Blocked by constraint
        try:
            read_file("/etc/passwd")
            print("   ✗ Should have been blocked!")
        except AuthorizationError:
            print("   ✓ read_file('/etc/passwd'): Blocked (constraint violation)")
    
    print("\n=== Summary (Simple Agent) ===")
    print("  • Agent has its own keypair (identity)")
    print("  • Warrant PoP-bound to agent's public key")
    print("  • Only THIS agent can use the warrant")
    print("  • All verification is OFFLINE")
    
    # ========================================================================
    # Orchestrator → Worker Pattern
    # ========================================================================
    demo_orchestrator_worker_delegation()
    
    print("\n=== Summary (Orchestrator → Worker) ===")
    print("  • Worker has its own keypair (identity)")
    print("  • Attenuated warrant PoP-bound to worker's public key")
    print("  • Only THAT worker can use the warrant")
    print("  • Attenuation is OFFLINE (no Control Plane call)")


if __name__ == "__main__":
    main()
