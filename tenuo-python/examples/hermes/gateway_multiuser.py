"""
Hermes Agent + Tenuo: Multi-user gateway with per-session warrants

Demonstrates how a Hermes gateway (Telegram, Discord, Slack, etc.) can
enforce different permissions per user. Each user's session gets a warrant
scoped to their authorized capabilities.

How it works:
- hermes-tenuo fires on_session_start (when Hermes adds this) or:
  presently, the gateway calls guard.set_session_warrant() directly when
  a session starts, keyed by session_id
- on_session_end clears the warrant so sessions don't leak
- All tool calls in that session are enforced against the user's warrant

In production, warrants come from your policy store (database, Tenuo Cloud,
or a config file mapping user_id → capabilities).

Setup:
    # ~/.hermes/config.yaml
    plugins:
      enabled:
        - hermes-tenuo
      entries:
        hermes-tenuo:
          connect_token: tc_live_...
          # No static warrant — all warrants are per-session

For the gateway integration, call guard.set_session_warrant() from your
gateway event handler or from the hermes-tenuo on_session_start hook.
"""

from __future__ import annotations

from typing import Optional

from tenuo import SigningKey, Warrant, Subpath, Wildcard
from tenuo.hermes import HermesGuard

# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

control_key = SigningKey.generate()
gateway_signing_key = SigningKey.generate()


# ---------------------------------------------------------------------------
# Warrant factory — in production, query your policy store
# ---------------------------------------------------------------------------

def make_warrant_for_user(user_role: str) -> Optional[Warrant]:
    """Return a warrant based on user role. Returns None for unknown users."""

    if user_role == "admin":
        return (
            Warrant.mint_builder()
            .holder(gateway_signing_key.public_key)
            .capability("read_file", path=Subpath("/data"))
            .capability("write_file", path=Subpath("/data"), content=Wildcard())
            .capability("web_search", query=Wildcard())
            .capability("terminal", command=Wildcard())
            .capability("memory", action=Wildcard(), key=Wildcard())
            .ttl(3600)
            .mint(control_key)
        )
    elif user_role == "analyst":
        return (
            Warrant.mint_builder()
            .holder(gateway_signing_key.public_key)
            .capability("read_file", path=Subpath("/data/reports"))
            .capability("web_search", query=Wildcard())
            .capability("memory", action=Wildcard(), key=Wildcard())
            .ttl(1800)
            .mint(control_key)
        )
    elif user_role == "viewer":
        return (
            Warrant.mint_builder()
            .holder(gateway_signing_key.public_key)
            .capability("read_file", path=Subpath("/data/public"))
            .capability("web_search", query=Wildcard())
            .ttl(900)
            .mint(control_key)
        )
    return None  # unknown role → no warrant → audit-only (calls pass through and are logged)


# ---------------------------------------------------------------------------
# Guard (no static warrant — all warrants are per-session)
# ---------------------------------------------------------------------------

guard = HermesGuard(
    signing_key=gateway_signing_key,
    trusted_roots=[control_key.public_key],
    on_denial="block",
)


# ---------------------------------------------------------------------------
# Simulated gateway session lifecycle
# ---------------------------------------------------------------------------

def session_start(session_id: str, user_role: str) -> None:
    """Called when a user sends their first message in a gateway session."""
    warrant = make_warrant_for_user(user_role)
    if warrant:
        guard.set_session_warrant(session_id, warrant, gateway_signing_key)
        print(f"  Session {session_id} ({user_role}): warrant registered")
    else:
        print(f"  Session {session_id} (unknown): no warrant — audit-only mode (calls pass through)")


def session_end(session_id: str) -> None:
    """Called when the gateway session ends."""
    guard.clear_session_warrant(session_id)


def call(tool: str, args: dict, session_id: str) -> None:
    result = guard.pre_tool_call(tool, args, session_id=session_id)
    status = f"BLOCKED — {result['message']}" if result else "ALLOWED"
    print(f"    {tool}({args}): {status}")


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    users = [
        ("session-alice", "admin"),
        ("session-bob", "analyst"),
        ("session-carol", "viewer"),
        ("session-eve", "unknown"),
    ]

    for session_id, role in users:
        print(f"\n{role.upper()} ({session_id}):")
        session_start(session_id, role)
        call("web_search", {"query": "quarterly results"}, session_id)
        call("read_file", {"path": "/data/reports/q1.csv"}, session_id)
        call("write_file", {"path": "/data/output/x.txt", "content": "hi"}, session_id)
        call("terminal", {"command": "ls /data"}, session_id)
        session_end(session_id)
