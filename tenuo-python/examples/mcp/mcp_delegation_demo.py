#!/usr/bin/env python3
"""
End-to-end MCP delegation chain demo.

Exercises the full path:
  1. Issuer mints a root warrant for an orchestrator
  2. Orchestrator attenuates it for a worker (fewer tools, shorter TTL)
  3. Worker sends the WarrantStack to a FastMCP server via _meta.tenuo
  4. TenuoMiddleware decodes the WarrantStack, calls check_chain in Rust
  5. Allowed / denied results printed

Run:
    cd tenuo-python
    .venv/bin/python examples/mcp/mcp_delegation_demo.py

Prerequisites:
    pip install "tenuo[fastmcp]"
"""

import asyncio
import base64
import sys
import time

try:
    from tenuo import Authorizer, SigningKey, Warrant
    from tenuo_core import decode_warrant_stack_base64, encode_warrant_stack
    from tenuo.mcp import MCPVerifier
except ImportError as e:
    print(f"Missing dependency: {e}", file=sys.stderr)
    print('Install with: pip install "tenuo[fastmcp]"', file=sys.stderr)
    sys.exit(1)


def main():
    print("=" * 60)
    print("  MCP Delegation Chain Demo (WarrantStack + check_chain)")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Key setup
    # ------------------------------------------------------------------
    issuer_key = SigningKey.generate()
    orchestrator_key = SigningKey.generate()
    worker_key = SigningKey.generate()

    def pk_short(key):
        return bytes(key.public_key.to_bytes()).hex()[:16]

    print("\n[Keys]")
    print(f"  issuer:       {pk_short(issuer_key)}...")
    print(f"  orchestrator: {pk_short(orchestrator_key)}...")
    print(f"  worker:       {pk_short(worker_key)}...")

    # ------------------------------------------------------------------
    # Step 1: Issuer mints root warrant for orchestrator
    # ------------------------------------------------------------------
    root = (
        Warrant.mint_builder()
        .capability("get_tasks")
        .capability("search_tasks")
        .capability("create_task")
        .capability("update_task")
        .holder(orchestrator_key.public_key)
        .ttl(3600)
        .mint(issuer_key)
    )

    print(f"\n[Step 1] Root warrant minted")
    print(f"  id:     {root.id}")
    print(f"  holder: orchestrator")
    print(f"  tools:  {root.tools}")
    print(f"  depth:  {root.depth}")

    # ------------------------------------------------------------------
    # Step 2: Orchestrator attenuates for worker (read-only)
    # ------------------------------------------------------------------
    child = (
        root.grant_builder()
        .capability("get_tasks")
        .capability("search_tasks")
        .holder(worker_key.public_key)
        .ttl(1800)
        .grant(orchestrator_key)
    )

    print(f"\n[Step 2] Worker warrant attenuated")
    print(f"  id:     {child.id}")
    print(f"  holder: worker")
    print(f"  tools:  {child.tools}")
    print(f"  depth:  {child.depth}")
    print(f"  issuer: orchestrator (NOT a trusted root)")

    # ------------------------------------------------------------------
    # Step 3: Encode as WarrantStack
    # ------------------------------------------------------------------
    chain = [root, child]
    stack_b64 = encode_warrant_stack(chain)

    print(f"\n[Step 3] WarrantStack encoded")
    print(f"  chain length: {len(chain)}")
    print(f"  base64 size:  {len(stack_b64)} chars")

    decoded = decode_warrant_stack_base64(stack_b64)
    print(f"  round-trip OK: {len(decoded)} warrants decoded")

    # ------------------------------------------------------------------
    # Step 4: MCPVerifier (server side)
    # ------------------------------------------------------------------
    authorizer = Authorizer(trusted_roots=[issuer_key.public_key])
    verifier = MCPVerifier(authorizer=authorizer)

    def make_meta(tool_name, arguments):
        """Simulate what the worker client sends in _meta.tenuo."""
        pop = child.sign(worker_key, tool_name, arguments, int(time.time()))
        return {
            "tenuo": {
                "warrant": stack_b64,
                "signature": base64.b64encode(bytes(pop)).decode(),
            }
        }

    print(f"\n[Step 4] MCPVerifier.verify() — server trusts only issuer key")
    print("-" * 60)

    tests = [
        ("get_tasks",    {"project": "demo"},                True),
        ("search_tasks", {"query": "urgent"},                True),
        ("create_task",  {"title": "x", "project": "demo"}, False),
        ("update_task",  {"task_id": "1", "status": "done"}, False),
    ]

    all_passed = True
    for tool, args, expected in tests:
        meta = make_meta(tool, args)
        result = verifier.verify(tool, args, meta=meta)

        status = "PASS" if result.allowed == expected else "FAIL"
        icon = "✓" if result.allowed else "✗"
        label = "allowed" if result.allowed else "denied"

        if result.allowed != expected:
            all_passed = False

        reason = ""
        if not result.allowed and result.denial_reason:
            reason = f"  ({result.denial_reason[:60]}...)"

        print(f"  [{status}] {icon} {tool:15s} → {label}{reason}")

    # ------------------------------------------------------------------
    # Step 5: Single root warrant (backward compat)
    # ------------------------------------------------------------------
    print(f"\n[Step 5] Single root warrant (no chain) — backward compat")
    print("-" * 60)

    pop_root = root.sign(orchestrator_key, "create_task",
                         {"title": "ok", "project": "demo"}, int(time.time()))
    meta_root = {
        "tenuo": {
            "warrant": root.to_base64(),
            "signature": base64.b64encode(bytes(pop_root)).decode(),
        }
    }
    r = verifier.verify("create_task", {"title": "ok", "project": "demo"}, meta=meta_root)
    status = "PASS" if r.allowed else "FAIL"
    if not r.allowed:
        all_passed = False
    print(f"  [{status}] {'✓' if r.allowed else '✗'} create_task (root warrant, depth 0) → {'allowed' if r.allowed else 'denied'}")

    # ------------------------------------------------------------------
    # Step 6: Orphaned child (no chain) should be rejected
    # ------------------------------------------------------------------
    print(f"\n[Step 6] Orphaned child warrant (no chain) — should be rejected")
    print("-" * 60)

    pop_orphan = child.sign(worker_key, "get_tasks", {"project": "demo"}, int(time.time()))
    meta_orphan = {
        "tenuo": {
            "warrant": child.to_base64(),
            "signature": base64.b64encode(bytes(pop_orphan)).decode(),
        }
    }
    r_orphan = verifier.verify("get_tasks", {"project": "demo"}, meta=meta_orphan)
    expected_denied = not r_orphan.allowed
    status = "PASS" if expected_denied else "FAIL"
    if not expected_denied:
        all_passed = False
    reason = r_orphan.denial_reason[:70] if r_orphan.denial_reason else ""
    print(f"  [{status}] {'✗' if expected_denied else '✓'} get_tasks (orphaned child, no parent) → {'denied' if expected_denied else 'allowed'}")
    if reason:
        print(f"         reason: {reason}...")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    if all_passed:
        print("  ALL TESTS PASSED")
    else:
        print("  SOME TESTS FAILED")
    print("=" * 60)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
