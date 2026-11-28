#!/usr/bin/env python3
"""
Multi-Hop A2A Delegation

Demonstrates warrant chain validation with 3-hop delegation:
    Orchestrator → Analyst → Responder

Each hop attenuates the warrant further, enforcing monotonic privilege reduction.

Scenario: Incident Response Pipeline
  1. Orchestrator: Broad access (read logs, query DB, block IPs)
  2. Analyst: Read-only (read logs, query DB) + can delegate block_ip
  3. Responder: Action-only (block specific IP)

Security:
  - Warrant chain validation (cryptographic proof)
  - Monotonic attenuation (child ≤ parent capabilities)
  - Chain depth limits (prevent infinite delegation)
  - Each agent validates full chain back to root

Run:
    python multi_hop_delegation.py
"""

import asyncio
import io
import sys
import time
from pathlib import Path

# Ensure we can import from tenuo
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tenuo import Cidr, Exact, SigningKey, Warrant, Wildcard
from tenuo.a2a import A2AClient, A2AServer
from tenuo.constraints import Subpath


# Colors
class C:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def log(msg: str, color: str = C.CYAN, indent: int = 0):
    print(f"{' ' * indent}{color}{msg}{C.RESET}")


def header(text: str):
    print(f"\n{C.BOLD}{C.YELLOW}{'='*70}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}{text.center(70)}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}{'='*70}{C.RESET}\n")


def chain_visual(depth: int, role: str, action: str, color: str = C.BLUE):
    """Print chain visualization."""
    indent = "  " * depth
    if depth == 0:
        symbol = "🏛️"
    elif depth == 1:
        symbol = "🔍"
    else:
        symbol = "⚡"

    log(f"{symbol} {role}: {action}", color, indent=len(indent))


# =============================================================================
# A2A Agents
# =============================================================================

def create_analyst_server(key: SigningKey, trusted: list, port: int) -> A2AServer:
    """Analyst agent: investigates incidents, can delegate response actions."""

    server = A2AServer(
        name="Analyst Agent",
        url=f"http://localhost:{port}",
        public_key=key.public_key,
        trusted_issuers=trusted,
        trust_delegated=True,  # Accept delegated warrants
        require_warrant=True,
        require_audience=False,
        require_pop=True,  # Require PoP for security
        check_replay=True,
        max_chain_depth=5,  # Allow delegation chains
        audit_log=io.StringIO(),
    )

    @server.skill("read_logs", constraints={"path": Subpath("/var/log")})
    async def read_logs(path: str) -> dict:
        """Read log files from allowed paths."""
        # Simulate log reading
        await asyncio.sleep(0.3)
        return {
            "path": path,
            "logs": [
                {"timestamp": "2024-01-15T10:30:00", "ip": "203.0.113.5", "action": "failed_login", "count": 127},
                {"timestamp": "2024-01-15T10:31:00", "ip": "203.0.113.5", "action": "port_scan", "ports": "1-1024"},
            ],
            "suspicious_ips": ["203.0.113.5"],
        }

    @server.skill("query_threat_db", constraints={"query": Wildcard(), "table": Wildcard()})
    async def query_threat_db(query: str, table: str) -> dict:
        """Query threat intelligence database."""
        # Simulate DB query
        await asyncio.sleep(0.2)
        if query == "203.0.113.5":
            return {
                "ip": query,
                "threat_level": "high",
                "category": "known_botnet",
                "confidence": 95,
                "action_recommended": "block",
            }
        return {"ip": query, "threat_level": "unknown"}

    return server


def create_responder_server(key: SigningKey, trusted: list, port: int) -> A2AServer:
    """Responder agent: executes response actions like blocking IPs."""

    server = A2AServer(
        name="Responder Agent",
        url=f"http://localhost:{port}",
        public_key=key.public_key,
        trusted_issuers=trusted,
        trust_delegated=True,  # Accept delegated warrants
        require_warrant=True,
        require_audience=False,
        require_pop=True,
        check_replay=True,
        max_chain_depth=5,
        audit_log=io.StringIO(),
    )

    @server.skill("block_ip", constraints={"ip": Cidr("0.0.0.0/0"), "duration": Wildcard()})
    async def block_ip(ip: str, duration: int) -> dict:
        """Block an IP address in the firewall."""
        # Simulate firewall update
        await asyncio.sleep(0.4)
        rule_id = f"rule_{int(time.time())}"
        return {
            "ip": ip,
            "duration": duration,
            "rule_id": rule_id,
            "status": "blocked",
            "firewall": "cloudflare",
        }

    @server.skill("quarantine_user", constraints={"user_id": Wildcard()})
    async def quarantine_user(user_id: str) -> dict:
        """Quarantine a user account."""
        await asyncio.sleep(0.3)
        return {
            "user_id": user_id,
            "status": "quarantined",
            "access_revoked": True,
        }

    return server


# =============================================================================
# Demo
# =============================================================================

async def run_demo():
    """Run the multi-hop delegation demo."""

    header("Multi-Hop A2A Delegation: Orchestrator → Analyst → Responder")

    # Setup keys
    log("🔑 Generating keys for 3-level hierarchy...")
    control_key = SigningKey.generate()
    orchestrator_key = SigningKey.generate()
    analyst_key = SigningKey.generate()
    responder_key = SigningKey.generate()

    log("   Control Plane (root authority)", indent=2)
    log("   ├─ Orchestrator (level 1)", indent=2)
    log("   ├─ Analyst (level 2)", indent=2)
    log("   └─ Responder (level 3)\n", indent=2)

    # Start A2A servers
    log("🚀 Starting A2A agents...")

    analyst_server = create_analyst_server(
        key=analyst_key,
        trusted=[control_key.public_key, orchestrator_key.public_key],  # Trust root + parent
        port=8001,
    )

    responder_server = create_responder_server(
        key=responder_key,
        trusted=[control_key.public_key],  # Only trust root for chain validation
        port=8002,
    )

    # Start servers
    import uvicorn

    async def start_server(app, port):
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical", lifespan="off")
        server = uvicorn.Server(config)
        return asyncio.create_task(server.serve())

    analyst_task = await start_server(analyst_server.app, 8001)
    responder_task = await start_server(responder_server.app, 8002)

    await asyncio.sleep(1)
    log("✅ Analyst on http://localhost:8001")
    log("✅ Responder on http://localhost:8002\n")

    try:
        # =================================================================
        # Hop 1: Control Plane → Orchestrator
        # =================================================================

        header("Hop 1: Control Plane → Orchestrator")

        chain_visual(0, "Control Plane", "Issues root warrant")

        orchestrator_warrant = (Warrant.mint_builder()
            .capability("read_logs", path=Subpath("/var/log"))
            .capability("query_threat_db", query=Wildcard(), table=Wildcard())
            .capability("block_ip", ip=Cidr("0.0.0.0/0"), duration=Wildcard())  # Can delegate
            .capability("quarantine_user", user_id=Wildcard())
            .holder(orchestrator_key.public_key)
            .ttl(3600)
            .mint(control_key))

        log("📜 Root warrant issued", C.GREEN)
        log(f"   ID: {orchestrator_warrant.id[:16]}...", indent=2)
        log(f"   Depth: {orchestrator_warrant.depth}", indent=2)
        log("   Tools: read_logs, query_threat_db, block_ip, quarantine_user", indent=2)
        log("   TTL: 3600s\n", indent=2)

        # =================================================================
        # Hop 2: Orchestrator → Analyst
        # =================================================================

        header("Hop 2: Orchestrator → Analyst (Attenuation)")

        chain_visual(1, "Orchestrator", "Attenuates warrant for Analyst")

        analyst_warrant = orchestrator_warrant.attenuate(
            signing_key=orchestrator_key,
            holder=analyst_key.public_key,
            capabilities={
                "read_logs": {"path": Subpath("/var/log")},
                "query_threat_db": {"query": Wildcard(), "table": Wildcard()},
                "block_ip": {"ip": Cidr("0.0.0.0/0"), "duration": Wildcard()},  # Can delegate further
            },
            ttl_seconds=1800,  # Shorter TTL
        )

        log("📜 Analyst warrant created", C.GREEN)
        log(f"   ID: {analyst_warrant.id[:16]}...", indent=2)
        log(f"   Depth: {analyst_warrant.depth}", indent=2)
        log("   Tools: read_logs, query_threat_db, block_ip", indent=2)
        log("   Removed: quarantine_user (narrowed scope)", indent=2, color=C.YELLOW)
        log("   TTL: 1800s (shorter than parent)\n", indent=2)

        # Orchestrator calls Analyst
        log("📞 Orchestrator delegates investigation to Analyst...")

        analyst_client = A2AClient("http://localhost:8001")

        # Check logs
        chain_visual(1, "Analyst", "Reads logs via A2A")
        logs_result = await analyst_client.send_task(
            warrant=analyst_warrant,
            skill="read_logs",
            arguments={"path": "/var/log/auth.log"},
            signing_key=orchestrator_key,
        )

        log("✅ Logs retrieved", C.GREEN)
        log(f"   Suspicious IPs: {logs_result.output.get('suspicious_ips', [])}", indent=2)

        # Query threat DB
        chain_visual(1, "Analyst", "Queries threat database")
        threat_result = await analyst_client.send_task(
            warrant=analyst_warrant,
            skill="query_threat_db",
            arguments={"query": "203.0.113.5", "table": "threats"},
            signing_key=orchestrator_key,
        )

        threat_data = threat_result.output
        log("✅ Threat intel retrieved", C.GREEN)
        log(f"   IP: {threat_data.get('ip')}", indent=2)
        log(f"   Threat Level: {threat_data.get('threat_level')}", indent=2)
        log(f"   Category: {threat_data.get('category')}", indent=2)
        log(f"   Recommended: {threat_data.get('action_recommended')}\n", indent=2)

        # =================================================================
        # Hop 3: Analyst → Responder (Further Attenuation)
        # =================================================================

        header("Hop 3: Analyst → Responder (Further Attenuation)")

        chain_visual(2, "Analyst", "Attenuates warrant for Responder")

        # Analyst attenuates to EXACT IP (not whole range)
        responder_warrant = analyst_warrant.attenuate(
            signing_key=analyst_key,
            holder=responder_key.public_key,
            capabilities={
                "block_ip": {"ip": Exact("203.0.113.5"), "duration": Wildcard()},  # Single IP only!
            },
            ttl_seconds=600,  # Even shorter TTL
        )

        log("📜 Responder warrant created", C.GREEN)
        log(f"   ID: {responder_warrant.id[:16]}...", indent=2)
        log(f"   Depth: {responder_warrant.depth}", indent=2)
        log("   Tools: block_ip (single IP only)", indent=2)
        log("   IP narrowed: Cidr(0.0.0.0/0) → Exact(203.0.113.5)", indent=2, color=C.YELLOW)
        log("   TTL: 600s (shortest)\n", indent=2)

        # Build warrant chain for Responder
        # Chain format: [root, intermediate, ...] (parent-first, excluding leaf)
        warrant_chain = [orchestrator_warrant]  # Just the root

        # Analyst calls Responder with chain
        log("📞 Analyst delegates response to Responder...")
        log(f"   Warrant chain: [{orchestrator_warrant.id[:8]}...] (root)\n", indent=2, color=C.DIM)

        responder_client = A2AClient("http://localhost:8002")

        chain_visual(2, "Responder", "Blocks IP via A2A with chain validation")

        # The responder will validate:
        # 1. Root warrant (orchestrator_warrant) is from trusted issuer (control_key)
        # 2. Analyst warrant issued by orchestrator (chain linkage)
        # 3. Responder warrant issued by analyst (chain linkage)
        # 4. Monotonic attenuation: responder ≤ analyst ≤ orchestrator

        block_result = await responder_client.send_task(
            warrant=responder_warrant,
            skill="block_ip",
            arguments={"ip": "203.0.113.5", "duration": 3600},
            warrant_chain=warrant_chain,
            signing_key=analyst_key,  # Analyst signs the request
        )

        log("✅ IP blocked successfully", C.GREEN)
        log(f"   IP: {block_result.output.get('ip')}", indent=2)
        log(f"   Rule ID: {block_result.output.get('rule_id')}", indent=2)
        log(f"   Status: {block_result.output.get('status')}", indent=2)
        log("   ✅ Chain validated (3 hops)\n", indent=2)

        # =================================================================
        # Security Demonstrations
        # =================================================================

        header("Security: Attack Scenarios")

        # Attack 1: Responder tries to block entire Internet
        log("🔒 Attack 1: Responder tries to block 0.0.0.0/0 (entire Internet)")
        chain_visual(2, "Responder", "Attempts privilege escalation", color=C.RED)

        try:
            await responder_client.send_task(
                warrant=responder_warrant,
                skill="block_ip",
                arguments={"ip": "0.0.0.0/0", "duration": 3600},
                warrant_chain=warrant_chain,
                signing_key=analyst_key,
            )
            log("   ❌ ERROR: Should have been blocked!", C.RED)
        except Exception as e:
            log("   ✅ BLOCKED: Exact(203.0.113.5) constraint", C.GREEN)
            log(f"   Reason: {str(e)[:60]}...", indent=2, color=C.DIM)

        # Attack 2: Forged warrant without proper chain
        log("\n🔒 Attack 2: Attacker creates forged warrant")

        attacker_key = SigningKey.generate()
        forged_warrant = (Warrant.mint_builder()
            .capability("block_ip", ip=Cidr("0.0.0.0/0"), duration=Wildcard())
            .holder(attacker_key.public_key)
            .ttl(3600)
            .mint(attacker_key))  # Self-signed!

        chain_visual(2, "Attacker", "Sends forged warrant", color=C.RED)

        try:
            attacker_client = A2AClient("http://localhost:8002")
            await attacker_client.send_task(
                warrant=forged_warrant,
                skill="block_ip",
                arguments={"ip": "1.1.1.1", "duration": 3600},
                signing_key=attacker_key,
            )
            log("   ❌ ERROR: Should have been blocked!", C.RED)
        except Exception as e:
            log("   ✅ BLOCKED: Untrusted issuer", C.GREEN)
            log(f"   Reason: {str(e)[:60]}...", indent=2, color=C.DIM)

        # Attack 3: Broken chain (missing intermediate)
        log("\n🔒 Attack 3: Broken warrant chain")

        chain_visual(2, "Analyst", "Sends warrant without chain", color=C.RED)

        try:
            # Send responder warrant but without the chain
            await responder_client.send_task(
                warrant=responder_warrant,
                skill="block_ip",
                arguments={"ip": "203.0.113.5", "duration": 3600},
                # warrant_chain=None,  # Missing chain!
                signing_key=analyst_key,
            )
            log("   ❌ ERROR: Should have been blocked!", C.RED)
        except Exception:
            log("   ✅ BLOCKED: Chain validation failed", C.GREEN)
            log("   Reason: Responder doesn't trust analyst directly", indent=2, color=C.DIM)

        # =================================================================
        # Summary
        # =================================================================

        header("Summary: 3-Hop Delegation Chain")

        log("Chain visualization:")
        log("")
        log("  🏛️  Control Plane", C.BLUE)
        log("      │ issues root warrant", C.DIM)
        log("      ├─ Tools: read_logs, query_threat_db, block_ip(any), quarantine", C.DIM)
        log("      └─ TTL: 3600s", C.DIM)
        log("")
        log("      ▼ attenuates", C.YELLOW)
        log("")
        log("  🔍 Analyst", C.BLUE)
        log("      │ removes quarantine_user", C.DIM)
        log("      ├─ Tools: read_logs, query_threat_db, block_ip(any)", C.DIM)
        log("      └─ TTL: 1800s", C.DIM)
        log("")
        log("      ▼ attenuates", C.YELLOW)
        log("")
        log("  ⚡ Responder", C.BLUE)
        log("      ├─ Tools: block_ip(203.0.113.5 ONLY)", C.DIM)
        log("      └─ TTL: 600s", C.DIM)
        log("")

        log("\n✅ Security Properties Verified:")
        log("  • Chain validation: Root → Analyst → Responder")
        log("  • Monotonic attenuation: Each hop reduces privileges")
        log("  • Cryptographic proof: Ed25519 signatures at each level")
        log("  • Constraint narrowing: Cidr → Exact")
        log("  • TTL reduction: 3600s → 1800s → 600s")
        log("\n✅ Attacks Blocked:")
        log("  • Privilege escalation (Exact constraint)")
        log("  • Forged warrants (signature verification)")
        log("  • Broken chains (chain validation)")

    finally:
        # Cleanup
        log("\n🧹 Shutting down agents...")
        analyst_task.cancel()
        responder_task.cancel()
        try:
            await asyncio.gather(analyst_task, responder_task)
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0.5)


async def main():
    """Entry point."""
    try:
        await run_demo()
    except KeyboardInterrupt:
        print("\n\n^C received")


if __name__ == "__main__":
    asyncio.run(main())
