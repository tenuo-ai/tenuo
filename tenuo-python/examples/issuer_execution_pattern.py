#!/usr/bin/env python3
"""
Best Practice: Separation of Planning and Execution

Demonstrates the recommended production pattern:
- Use separate warrants for planning vs execution
- Apply trust levels for organizational boundaries
- Leverage attenuation for delegation

This demonstrates the recommended production pattern using Tenuo's current API.
"""

from tenuo import (
    SigningKey, Warrant, Pattern,
    lockdown, set_warrant_context, set_keypair_context,
    AuthorizationError
)

# ============================================================================
# Setup: Three-Tier Architecture
# ============================================================================

print("="*70)
print("Multi-Tier Delegation Pattern - Best Practice")
print("="*70)

# Tier 1: Control Plane (highest authority)
print("\n1. Setting up three-tier architecture:")
control_kp = SigningKey.generate()
print("   ✓ Control Plane (root authority)")

# Tier 2: Orchestrator (planning/coordination)
orchestrator_kp = SigningKey.generate()
print("   ✓ Orchestrator (planning/coordination)")

# Tier 3: Worker (execution)
worker_kp = SigningKey.generate()
print("   ✓ Worker (execution)")

# ============================================================================
# Step 1: Control Plane Issues Root Warrant to Orchestrator
# ============================================================================

print("\n" + "="*70)
print("STEP 1: Control Plane → Orchestrator (Root Warrant)")
print("="*70)

# Control plane issues broad warrant to orchestrator
root_warrant = Warrant.issue(
    tools="file_operations",  # Broad capability
    keypair=control_kp,
    holder=orchestrator_kp.public_key,
    constraints={
        "path": Pattern("/data/*"),  # Broad path access
    },
    ttl_seconds=3600
)

print("\n✓ Issued root warrant to orchestrator")
print(f"  Tools: {root_warrant.tools}")
print(f"  Depth: {root_warrant.depth}")
print("  Constraints: path must match /data/*")
print("  TTL: 3600 seconds")
print("\n  ℹ️  Orchestrator has BROAD authority for planning")

# ============================================================================
# Step 2: Orchestrator Attenuates Warrant for Worker
# ============================================================================

print("\n" + "="*70)
print("STEP 2: Orchestrator → Worker (Attenuated Warrant)")
print("="*70)

# Orchestrator creates narrow warrant for specific task
worker_warrant = root_warrant.attenuate(
    constraints={
        "path": Pattern("/data/reports/*"),  # Narrower path
    },
    keypair=orchestrator_kp,
    parent_keypair=control_kp,  # Parent signs the chain link
    holder=worker_kp.public_key,
    ttl_seconds=60  # Much shorter TTL
)

print("\n✓ Attenuated warrant for worker")
print(f"  Tools: {worker_warrant.tools}")
print(f"  Depth: {worker_warrant.depth}")
print("  Constraints: path must match /data/reports/* (narrower!)")
print("  TTL: 60 seconds (shorter!)")
print("\n  ✓  Worker has NARROW authority for execution")
print("  ✓  Capabilities SHRUNK during delegation")

# ============================================================================
# Step 3: Worker Executes with Attenuated Warrant
# ============================================================================

print("\n" + "="*70)
print("STEP 3: Worker Executes Tools")
print("="*70)

@lockdown(tool="file_operations")
def file_operations(path: str, operation: str) -> str:
    """Simulated file operation."""
    return f"[{operation.upper()} {path}]"

print("\nTesting authorization with attenuated warrant:")

# Test 1: Allowed - within narrow constraints
print("\n  Test 1: path=/data/reports/q3.txt")
try:
    with set_warrant_context(worker_warrant), set_keypair_context(worker_kp):
        result = file_operations(path="/data/reports/q3.txt", operation="read")
        print(f"    ✓ ALLOWED: {result}")
except AuthorizationError as e:
    print(f"    ✗ BLOCKED: {e}")

# Test 2: Blocked - outside narrow constraints (but within root)
print("\n  Test 2: path=/data/secrets/passwords.txt")
try:
    with set_warrant_context(worker_warrant), set_keypair_context(worker_kp):
        result = file_operations(path="/data/secrets/passwords.txt", operation="read")
        print(f"    ✗ ALLOWED: {result} (UNEXPECTED!)")
except AuthorizationError:
    print("    ✓ BLOCKED: Outside /data/reports/* constraint")

# Test 3: Blocked - completely outside bounds
print("\n  Test 3: path=/etc/passwd")
try:
    with set_warrant_context(worker_warrant), set_keypair_context(worker_kp):
        result = file_operations(path="/etc/passwd", operation="read")
        print(f"    ✗ ALLOWED: {result} (UNEXPECTED!)")
except AuthorizationError:
    print("    ✓ BLOCKED: Outside /data/* bound")

# ============================================================================
# Step 4: Demonstrate Orchestrator's Broader Access
# ============================================================================

print("\n" + "="*70)
print("STEP 4: Orchestrator's Broader Access")
print("="*70)

print("\nOrchestrator can access paths worker cannot:")

# Orchestrator can access /data/secrets (within root constraints)
print("\n  Orchestrator accessing /data/secrets/config.json:")
try:
    with set_warrant_context(root_warrant), set_keypair_context(orchestrator_kp):
        result = file_operations(path="/data/secrets/config.json", operation="read")
        print(f"    ✓ ALLOWED: {result}")
        print("    ℹ️  Orchestrator has broader /data/* access")
except AuthorizationError as e:
    print(f"    ✗ BLOCKED: {e}")

# ============================================================================
# Key Takeaways
# ============================================================================

print("\n" + "="*70)
print("KEY TAKEAWAYS - Production Best Practices")
print("="*70)
print("""
1. SEPARATION OF CONCERNS
   - Orchestrator = planning with broad authority
   - Worker = execution with narrow authority
   - Prevents workers from exceeding task scope

2. MONOTONIC ATTENUATION
   - Capabilities ONLY shrink during delegation
   - Worker cannot access /data/secrets (only /data/reports)
   - TTL shortened from 3600s to 60s

3. CRYPTOGRAPHIC BINDING
   - Chain links cryptographically bind parent to child
   - Parent signs child's payload
   - Enables offline verification

4. RECOMMENDED PATTERN
   - Control Plane → broad warrant → Orchestrator
   - Orchestrator → narrow warrant → Worker
   - Worker executes with minimal, time-bound authority

5. SECURITY PROPERTIES
   - Proof-of-Possession prevents warrant theft
   - Attenuation prevents privilege escalation
   - Short TTLs limit blast radius
   - Offline verification (no phone home)
""")

print("="*70)
print("This is the RECOMMENDED pattern for production deployments!")
print("="*70)

