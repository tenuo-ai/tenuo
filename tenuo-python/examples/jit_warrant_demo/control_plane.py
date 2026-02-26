"""
Control Plane - Reviews capability proposals and mints warrants.

The control plane is the trusted component that:
1. Reviews LLM capability proposals
2. Validates against security policy
3. Coordinates multi-sig approval (system + human)
4. Mints task-specific warrants
"""

from typing import Any, Dict, List, Optional

import config
import display

from tenuo import Exact, Pattern, SigningKey, Warrant


class ControlPlane:
    """
    The Control Plane manages warrant issuance.

    It reviews capability proposals from agents and mints
    appropriately scoped warrants.
    """

    def __init__(self):
        self.signing_key = SigningKey.generate()
        self.policy = SecurityPolicy()

    def review_proposal(
        self, capabilities: List[Dict[str, Any]], auto_approve: bool = False
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Review a capability proposal.

        Args:
            capabilities: Proposed capabilities from LLM
            auto_approve: Skip interactive approval

        Returns:
            Approved capabilities (possibly modified), or None if rejected
        """
        display.print_step(
            2, "Control Plane Review", "The control plane validates the proposal against security policy."
        )

        display.print_capability_proposal(capabilities)

        # Apply security policy
        approved = []
        rejected = []

        for cap in capabilities:
            tool = cap.get("tool", "")

            if self.policy.is_allowed(tool):
                approved.append(cap)
            else:
                rejected.append(cap)
                display.print_verdict(False, f"Policy rejects: {tool}", self.policy.get_rejection_reason(tool))

        if rejected:
            display.print_learning(
                "Policy Enforcement",
                "The control plane rejected capabilities that violate security policy.\n"
                "Even if the LLM requests dangerous permissions, they won't be granted.",
            )

        if not auto_approve and approved:
            display.print_approval_prompt()
            # In a real system, this would prompt for human approval
            # For demo, we auto-approve the policy-filtered list

        return approved if approved else None

    def mint_warrant(
        self, agent_key: SigningKey, capabilities: List[Dict[str, Any]], allowed_urls: List[str], ttl: int = 300
    ) -> Warrant:
        """
        Mint a task-specific warrant.

        Args:
            agent_key: The agent's signing key
            capabilities: Approved capabilities
            allowed_urls: Specific URLs the agent can access
            ttl: Warrant time-to-live in seconds

        Returns:
            A warrant scoped to exactly these capabilities
        """
        display.print_step(3, "Mint Warrant", "Control plane issues a warrant with exactly the approved capabilities.")

        builder = Warrant.mint_builder().holder(agent_key.public_key).ttl(ttl)

        for cap in capabilities:
            tool = cap.get("tool", "")

            if tool == "fetch_url" and allowed_urls:
                # Add a capability for each allowed URL
                # Note: In production, you'd use a single capability with a
                # more sophisticated constraint (e.g., OneOf, AllowList)
                for url in allowed_urls:
                    builder.capability("fetch_url", url=Exact(url))
            elif tool == "write_file":
                builder.capability("write_file", path=Pattern(f"{config.OUTPUT_DIR}/*"))
            elif tool == "summarize":
                builder.capability("summarize")
            else:
                # Generic capability
                builder.capability(tool)

        warrant = builder.mint(self.signing_key)

        # Display what was minted
        display.print_warrant_minted(capabilities, ttl)

        return warrant

    def mint_warrant_silent(
        self, agent_key: SigningKey, capabilities: List[Dict[str, Any]], allowed_urls: List[str], ttl: int = 300
    ) -> Warrant:
        """
        Mint a warrant without display output.

        Used for simulating warrants from earlier sessions.
        """
        builder = Warrant.mint_builder().holder(agent_key.public_key).ttl(ttl)

        for cap in capabilities:
            tool = cap.get("tool", "")

            if tool == "fetch_url" and allowed_urls:
                for url in allowed_urls:
                    builder.capability("fetch_url", url=Exact(url))
            elif tool == "write_file":
                builder.capability("write_file", path=Pattern(f"{config.OUTPUT_DIR}/*"))
            elif tool == "summarize":
                builder.capability("summarize")
            else:
                builder.capability(tool)

        return builder.mint(self.signing_key)


class SecurityPolicy:
    """
    Demo policy for capability approval.

    This is placeholder logic - replace with your own policy engine (OPA, Cedar,
    config files, etc.). Tenuo handles the cryptographic enforcement; you control
    *what* gets approved.
    """

    # Tools that are NEVER allowed for URL summarization tasks
    BLOCKED_TOOLS = {
        "http_request": "Arbitrary HTTP requests are too dangerous",
        "send_email": "Email sending not relevant to summarization",
        "execute_code": "Code execution not allowed",
        "shell_command": "Shell access not allowed",
    }

    # Tools that are allowed
    ALLOWED_TOOLS = {
        "fetch_url",
        "summarize",
        "write_file",
    }

    def is_allowed(self, tool: str) -> bool:
        """Check if a tool is allowed by policy."""
        if tool in self.BLOCKED_TOOLS:
            return False
        return tool in self.ALLOWED_TOOLS

    def get_rejection_reason(self, tool: str) -> str:
        """Get the reason a tool was rejected."""
        return self.BLOCKED_TOOLS.get(tool, "Tool not in allowlist")
