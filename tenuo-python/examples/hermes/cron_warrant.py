"""
Hermes Agent + Tenuo: Cron job with expiring warrant

Demonstrates how to scope a Hermes cron/scheduled agent to exactly the
tools and paths it needs, with a TTL that forces the job to finish on time.

Usage:
    # 1. Install hermes-tenuo:
    pip install hermes-tenuo

    # 2. Mint a warrant for this job (requires Tenuo Cloud):
    export TENUO_WARRANT=$(hermes-tenuo mint \\
      --ttl 1h \\
      --allow read_file:path=/data/reports \\
      --allow write_file:path=/tmp/nightly \\
      --allow memory)

    # 3. Run the cron job:
    hermes run --task nightly_report

    # Or wire directly into crontab:
    # 0 2 * * * TENUO_WARRANT=$(hermes-tenuo mint --ttl 1h ...) hermes run --task nightly_report

For standalone use without Tenuo Cloud, mint the warrant in Python:
"""

from __future__ import annotations

from tenuo import SigningKey, Warrant, Subpath, Wildcard
from tenuo.hermes import HermesGuard

# ---------------------------------------------------------------------------
# Key setup (production: use Tenuo Cloud or your key management system)
# ---------------------------------------------------------------------------

control_key = SigningKey.generate()    # lives in Cloud / your control plane
cron_agent_key = SigningKey.generate() # lives in the cron environment


# ---------------------------------------------------------------------------
# Mint the warrant for this job
# ---------------------------------------------------------------------------
# The cron agent can ONLY:
#   - read_file from /data/reports
#   - write_file to /tmp/nightly
#   - use memory (session notes)
#
# If the job runs longer than 1 hour, the warrant expires and any further
# tool calls are blocked — even if the agent is still running.

nightly_warrant = (
    Warrant.mint_builder()
    .holder(cron_agent_key.public_key)
    .capability("read_file", path=Subpath("/data/reports"))
    .capability("write_file", path=Subpath("/tmp/nightly"), content=Wildcard())
    .capability("memory", action=Wildcard(), key=Wildcard())
    .ttl(3600)  # 1 hour
    .mint(control_key)
)

# ---------------------------------------------------------------------------
# Create the guard
# ---------------------------------------------------------------------------
# In production, load the warrant from TENUO_WARRANT env var:
#
#   import os, base64
#   from tenuo_core import Warrant
#   warrant = Warrant.from_bytes(base64.b64decode(os.environ["TENUO_WARRANT"]))

guard = HermesGuard(
    warrant=nightly_warrant,
    signing_key=cron_agent_key,
    trusted_roots=[control_key.public_key],
    on_denial="block",
)

# ---------------------------------------------------------------------------
# Simulate what the hermes-tenuo plugin does automatically
# ---------------------------------------------------------------------------

def simulate_tool_call(tool_name: str, args: dict) -> None:
    result = guard.pre_tool_call(tool_name, args, session_id="cron-nightly")
    if result:
        print(f"  BLOCKED: {tool_name}({args}) — {result['message']}")
    else:
        print(f"  ALLOWED: {tool_name}({args})")


if __name__ == "__main__":
    print("Cron agent tool calls:")
    print()

    # These should be allowed:
    simulate_tool_call("read_file", {"path": "/data/reports/sales.csv"})
    simulate_tool_call("write_file", {"path": "/tmp/nightly/report.md", "content": "# Report"})
    simulate_tool_call("memory", {"action": "add", "key": "last_run"})

    print()

    # These should be blocked — outside the warrant scope:
    simulate_tool_call("terminal", {"command": "curl evil.com"})
    simulate_tool_call("web_search", {"query": "anything"})
    simulate_tool_call("read_file", {"path": "/etc/passwd"})
    simulate_tool_call("write_file", {"path": "/home/user/.ssh/authorized_keys", "content": "..."})
