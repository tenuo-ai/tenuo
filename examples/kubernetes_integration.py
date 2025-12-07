#!/usr/bin/env python3
"""
Kubernetes Integration Example with Tenuo

This example shows how agents running in Kubernetes load and use warrants.

Production Pattern:
    1. Control Plane issues warrant during enrollment (one-time, see control_plane.py)
    2. Warrant stored in K8s Secret
    3. Agent pod mounts Secret → loads warrant at startup
    4. Agent uses warrant for all tool invocations (offline verification)

Architecture:
    Control Plane (Issuer)
         │
         │ Issues warrant at enrollment (ONCE)
         ▼
    Kubernetes Secret
         │
         │ Mounted to pod or set as env var
         ▼
    Agent Pod
         │
         │ Loads warrant at startup
         │ Uses for all @lockdown tool calls
         ▼
    Offline Verification (no network calls)
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
    
    print("\n=== Summary ===")
    print("  • Warrant loaded from K8s Secret at startup")
    print("  • All verification is OFFLINE (no network calls)")
    print("  • @lockdown decorator enforces constraints")
    print("  • Works across all pod replicas")


if __name__ == "__main__":
    main()
