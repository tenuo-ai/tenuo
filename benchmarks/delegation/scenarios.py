"""
Constraint enforcement benchmark scenarios.

Each scenario tests that Tenuo correctly enforces warrant constraints
by running identical actions against warrants with different scopes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from tenuo import SigningKey, Warrant, Pattern, Range


@dataclass
class DelegationResult:
    """Result of a delegation test."""

    scenario: str
    delegation_chain: list[str]  # [role names]
    attack_point: str  # Which agent was "compromised"
    attempted_action: dict[str, Any]
    expected: str  # "allowed" or "denied"
    actual: str  # "allowed" or "denied"

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


class BaseDelegationScenario(ABC):
    """Base class for delegation scenarios."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def setup(self) -> dict[str, Warrant]:
        """
        Create the warrants for this scenario.

        Returns:
            Dict mapping role names to their warrants.
        """
        pass

    @abstractmethod
    def get_attacks(self) -> list[dict[str, Any]]:
        """
        Get attack vectors to test.

        Returns:
            List of attack configs with:
            - attack_point: which role is compromised
            - action: tool + args being attempted
            - expected: "allowed" or "denied"
        """
        pass


class TemporalScopingScenario(BaseDelegationScenario):
    """
    Same agent, different warrants per request.

    Demonstrates that the agent's capabilities are determined by the warrant,
    not by the agent's code. This solves the "temporal mismatch" problem where
    traditional auth gives broad permissions at startup.
    """

    name = "temporal_scoping"
    description = "Same agent code, different warrants → different capabilities"

    def __init__(self):
        # One issuer, one agent (receiving different warrants)
        self.issuer_key = SigningKey.generate()
        self.agent_key = SigningKey.generate()

    def setup(self) -> dict[str, Warrant]:
        """
        Create multiple warrants for the SAME agent, each scoped differently.

        Simulates:
        - Task 1: "Email the team" → internal-only email warrant
        - Task 2: "Send partner update" → broader email warrant
        - Task 3: "Transfer funds" → payment warrant with limit
        """

        # Warrant for "email team" task - internal only
        internal_email_warrant = (
            Warrant.mint_builder()
            .capability("send_email", {"to": Pattern("*@company.com")})
            .holder(self.agent_key.public_key)
            .ttl(300)  # 5 minute task
            .mint(self.issuer_key)
        )

        # Warrant for "send partner update" - broader scope
        external_email_warrant = (
            Warrant.mint_builder()
            .capability("send_email", {"to": Pattern("*")})
            .holder(self.agent_key.public_key)
            .ttl(300)
            .mint(self.issuer_key)
        )

        # Warrant for "process refund" - $100 limit
        small_payment_warrant = (
            Warrant.mint_builder()
            .capability("transfer", {"amount": Range(0, 100)})
            .holder(self.agent_key.public_key)
            .ttl(300)
            .mint(self.issuer_key)
        )

        # Warrant for "pay vendor invoice" - $10000 limit
        large_payment_warrant = (
            Warrant.mint_builder()
            .capability("transfer", {"amount": Range(0, 10000)})
            .holder(self.agent_key.public_key)
            .ttl(300)
            .mint(self.issuer_key)
        )

        # Warrant with no email capability at all
        no_email_warrant = (
            Warrant.mint_builder()
            .capability("read_file", {"path": Pattern("docs/*")})
            .holder(self.agent_key.public_key)
            .ttl(300)
            .mint(self.issuer_key)
        )

        return {
            "internal_email": internal_email_warrant,
            "external_email": external_email_warrant,
            "small_payment": small_payment_warrant,
            "large_payment": large_payment_warrant,
            "no_email": no_email_warrant,
        }

    def get_attacks(self) -> list[dict[str, Any]]:
        """
        Test same actions with different warrants.

        Key insight: The agent code is constant. The warrant determines what's allowed.
        """
        return [
            # --- Email scenarios: Same action, different warrants ---
            # Internal email with internal-only warrant → allowed
            {
                "attack_point": "internal_email",
                "action": {"tool": "send_email", "args": {"to": "team@company.com"}},
                "expected": "allowed",
                "reason": "Internal email, internal warrant → OK",
            },
            # External email with internal-only warrant → BLOCKED
            {
                "attack_point": "internal_email",
                "action": {"tool": "send_email", "args": {"to": "attacker@evil.com"}},
                "expected": "denied",
                "reason": "External email, internal-only warrant → blocked",
            },
            # Same external email with broader warrant → allowed
            {
                "attack_point": "external_email",
                "action": {
                    "tool": "send_email",
                    "args": {"to": "partner@external.com"},
                },
                "expected": "allowed",
                "reason": "External email, external warrant → OK",
            },
            # Email action with no-email warrant → BLOCKED (no capability)
            {
                "attack_point": "no_email",
                "action": {"tool": "send_email", "args": {"to": "anyone@anywhere.com"}},
                "expected": "denied",
                "reason": "Any email, no-email warrant → blocked",
            },
            # --- Payment scenarios: Same action, different limits ---
            # Small payment with small limit → allowed
            {
                "attack_point": "small_payment",
                "action": {"tool": "transfer", "args": {"amount": 50}},
                "expected": "allowed",
                "reason": "$50 transfer, $100 limit → OK",
            },
            # Large payment with small limit → BLOCKED
            {
                "attack_point": "small_payment",
                "action": {"tool": "transfer", "args": {"amount": 500}},
                "expected": "denied",
                "reason": "$500 transfer, $100 limit → blocked",
            },
            # Same large payment with large limit → allowed
            {
                "attack_point": "large_payment",
                "action": {"tool": "transfer", "args": {"amount": 500}},
                "expected": "allowed",
                "reason": "$500 transfer, $10000 limit → OK",
            },
            # Huge payment even with large limit → BLOCKED
            {
                "attack_point": "large_payment",
                "action": {"tool": "transfer", "args": {"amount": 50000}},
                "expected": "denied",
                "reason": "$50000 transfer, $10000 limit → blocked",
            },
        ]


class RangeLimitScenario(BaseDelegationScenario):
    """
    Test that numeric Range constraints are enforced.

    Shows that warrants with Range constraints correctly bound values.
    """

    name = "range_limit"
    description = "Numeric range constraints are strictly enforced"

    def __init__(self):
        self.issuer_key = SigningKey.generate()
        self.agent_key = SigningKey.generate()

    def setup(self) -> dict[str, Warrant]:
        """Create warrants with different range limits."""

        # Small limit: 0-100
        small_warrant = (
            Warrant.mint_builder()
            .capability("transfer", {"amount": Range(0, 100)})
            .holder(self.agent_key.public_key)
            .ttl(3600)
            .mint(self.issuer_key)
        )

        # Medium limit: 0-1000
        medium_warrant = (
            Warrant.mint_builder()
            .capability("transfer", {"amount": Range(0, 1000)})
            .holder(self.agent_key.public_key)
            .ttl(3600)
            .mint(self.issuer_key)
        )

        # Large limit: 0-10000
        large_warrant = (
            Warrant.mint_builder()
            .capability("transfer", {"amount": Range(0, 10000)})
            .holder(self.agent_key.public_key)
            .ttl(3600)
            .mint(self.issuer_key)
        )

        return {
            "small": small_warrant,
            "medium": medium_warrant,
            "large": large_warrant,
        }

    def get_attacks(self) -> list[dict[str, Any]]:
        """Test range boundary enforcement."""
        return [
            # At limit - should be allowed
            {
                "attack_point": "small",
                "action": {"tool": "transfer", "args": {"amount": 100}},
                "expected": "allowed",
                "reason": "$100 = limit, should pass",
            },
            # Over limit - should be denied
            {
                "attack_point": "small",
                "action": {"tool": "transfer", "args": {"amount": 101}},
                "expected": "denied",
                "reason": "$101 > $100 limit, should fail",
            },
            # Way over limit - should be denied
            {
                "attack_point": "small",
                "action": {"tool": "transfer", "args": {"amount": 1000}},
                "expected": "denied",
                "reason": "$1000 >> $100 limit, should fail",
            },
            # Within medium limit
            {
                "attack_point": "medium",
                "action": {"tool": "transfer", "args": {"amount": 500}},
                "expected": "allowed",
                "reason": "$500 within $1000 limit",
            },
            # Over medium limit
            {
                "attack_point": "medium",
                "action": {"tool": "transfer", "args": {"amount": 5000}},
                "expected": "denied",
                "reason": "$5000 > $1000 limit",
            },
            # --- Edge cases ---
            # Zero (floor boundary)
            {
                "attack_point": "small",
                "action": {"tool": "transfer", "args": {"amount": 0}},
                "expected": "allowed",
                "reason": "$0 = floor of Range(0,100), should pass",
            },
            # Negative (below floor)
            {
                "attack_point": "small",
                "action": {"tool": "transfer", "args": {"amount": -1}},
                "expected": "denied",
                "reason": "$-1 below Range floor",
            },
            # Float just over ceiling
            {
                "attack_point": "small",
                "action": {"tool": "transfer", "args": {"amount": 100.01}},
                "expected": "denied",
                "reason": "$100.01 just above Range ceiling",
            },
        ]


class PatternMatchScenario(BaseDelegationScenario):
    """
    Test that Pattern constraints are enforced.

    Shows that warrants with glob patterns correctly filter values.
    """

    name = "pattern_match"
    description = "Glob pattern constraints are strictly enforced"

    def __init__(self):
        self.issuer_key = SigningKey.generate()
        self.agent_key = SigningKey.generate()

    def setup(self) -> dict[str, Warrant]:
        """Create warrants with different pattern scopes."""

        # Internal-only email
        internal_warrant = (
            Warrant.mint_builder()
            .capability("send_email", {"to": Pattern("*@company.com")})
            .holder(self.agent_key.public_key)
            .ttl(3600)
            .mint(self.issuer_key)
        )

        # Any email
        any_warrant = (
            Warrant.mint_builder()
            .capability("send_email", {"to": Pattern("*")})
            .holder(self.agent_key.public_key)
            .ttl(3600)
            .mint(self.issuer_key)
        )

        # Docs folder only
        docs_warrant = (
            Warrant.mint_builder()
            .capability("read_file", {"path": Pattern("docs/*")})
            .holder(self.agent_key.public_key)
            .ttl(3600)
            .mint(self.issuer_key)
        )

        return {
            "internal": internal_warrant,
            "any_email": any_warrant,
            "docs": docs_warrant,
        }

    def get_attacks(self) -> list[dict[str, Any]]:
        """Test pattern matching enforcement."""
        return [
            # Internal email with internal warrant - allowed
            {
                "attack_point": "internal",
                "action": {"tool": "send_email", "args": {"to": "alice@company.com"}},
                "expected": "allowed",
                "reason": "alice@company.com matches *@company.com",
            },
            # External email with internal warrant - denied
            {
                "attack_point": "internal",
                "action": {"tool": "send_email", "args": {"to": "attacker@evil.com"}},
                "expected": "denied",
                "reason": "attacker@evil.com doesn't match *@company.com",
            },
            # Any email with any_email warrant - allowed
            {
                "attack_point": "any_email",
                "action": {"tool": "send_email", "args": {"to": "anyone@anywhere.com"}},
                "expected": "allowed",
                "reason": "* matches anything",
            },
            # Docs file with docs warrant - allowed
            {
                "attack_point": "docs",
                "action": {"tool": "read_file", "args": {"path": "docs/readme.txt"}},
                "expected": "allowed",
                "reason": "docs/readme.txt matches docs/*",
            },
            # Non-docs file with docs warrant - denied
            {
                "attack_point": "docs",
                "action": {"tool": "read_file", "args": {"path": "/etc/passwd"}},
                "expected": "denied",
                "reason": "/etc/passwd doesn't match docs/*",
            },
            # --- Edge cases ---
            # Empty string
            {
                "attack_point": "internal",
                "action": {"tool": "send_email", "args": {"to": ""}},
                "expected": "denied",
                "reason": "Empty string should not match *@company.com",
            },
            # Degenerate match: bare domain with no local part
            {
                "attack_point": "internal",
                "action": {"tool": "send_email", "args": {"to": "@company.com"}},
                "expected": "allowed",
                "reason": "@company.com matches *@company.com (glob * matches empty)",
            },
        ]


class ToolScopingScenario(BaseDelegationScenario):
    """
    Test that tools not in the warrant are rejected.

    Shows that each warrant only authorizes specific tools.
    """

    name = "tool_scoping"
    description = "Only authorized tools are allowed"

    def __init__(self):
        self.issuer_key = SigningKey.generate()
        self.agent_key = SigningKey.generate()

    def setup(self) -> dict[str, Warrant]:
        """Create warrants for different tools."""

        # Email only
        email_warrant = (
            Warrant.mint_builder()
            .capability("send_email", {"to": Pattern("*")})
            .holder(self.agent_key.public_key)
            .ttl(3600)
            .mint(self.issuer_key)
        )

        # File read only
        file_warrant = (
            Warrant.mint_builder()
            .capability("read_file", {"path": Pattern("*")})
            .holder(self.agent_key.public_key)
            .ttl(3600)
            .mint(self.issuer_key)
        )

        # Transfer only
        transfer_warrant = (
            Warrant.mint_builder()
            .capability("transfer", {"amount": Range(0, 1000)})
            .holder(self.agent_key.public_key)
            .ttl(3600)
            .mint(self.issuer_key)
        )

        return {
            "email": email_warrant,
            "file": file_warrant,
            "transfer": transfer_warrant,
        }

    def get_attacks(self) -> list[dict[str, Any]]:
        """Test tool authorization."""
        return [
            # Correct tool - allowed
            {
                "attack_point": "email",
                "action": {"tool": "send_email", "args": {"to": "test@example.com"}},
                "expected": "allowed",
                "reason": "send_email is authorized",
            },
            # Wrong tool - denied
            {
                "attack_point": "email",
                "action": {"tool": "transfer", "args": {"amount": 100}},
                "expected": "denied",
                "reason": "transfer not authorized by email warrant",
            },
            # Wrong tool - denied
            {
                "attack_point": "email",
                "action": {"tool": "read_file", "args": {"path": "secret.txt"}},
                "expected": "denied",
                "reason": "read_file not authorized by email warrant",
            },
            # Correct tool - allowed
            {
                "attack_point": "file",
                "action": {"tool": "read_file", "args": {"path": "readme.md"}},
                "expected": "allowed",
                "reason": "read_file is authorized",
            },
            # Correct tool - allowed
            {
                "attack_point": "transfer",
                "action": {"tool": "transfer", "args": {"amount": 500}},
                "expected": "allowed",
                "reason": "transfer is authorized",
            },
        ]
