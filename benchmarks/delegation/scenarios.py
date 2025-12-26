"""
Delegation benchmark scenarios.

Each scenario tests a specific aspect of Tenuo's delegation capabilities.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import time
from tenuo import SigningKey, Warrant, Pattern, Range, AnyOf, Exact


@dataclass
class DelegationResult:
    """Result of a delegation test."""
    scenario: str
    delegation_chain: list[str]  # ["org", "manager", "assistant"]
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
        Create the warrant chain for this scenario.
        
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


class ManagerAssistantScenario(BaseDelegationScenario):
    """
    Manager delegates to assistant with narrower scope.
    
    Tests that assistant cannot exceed delegated permissions even when compromised.
    """
    
    name = "manager_assistant"
    description = "Manager delegates internal-only email access to assistant"
    
    def __init__(self):
        # Generate keys for each role
        self.org_key = SigningKey.generate()
        self.manager_key = SigningKey.generate()
        self.assistant_key = SigningKey.generate()
    
    def setup(self) -> dict[str, Warrant]:
        """Create org → manager → assistant warrant chain."""
        
        # Org issues broad warrant to manager
        # Using directory-style patterns that work with Tenuo's prefix attenuation
        manager_warrant = (
            Warrant.builder()
            .capability("send_email", {"recipients": Pattern("users/*")})
            .capability("read_file", {"path": Pattern("/data/*")})
            .capability("calendar", {"action": Pattern("*")})
            .holder(self.manager_key.public_key)
            .ttl(3600)
            .issue(self.org_key)
        )
        
        # Manager delegates narrower scope to assistant using grant_builder
        # Assistant can only:
        # - Email internal users
        # - Read docs folder
        # - View (not edit) calendar
        assistant_warrant = (
            manager_warrant.grant_builder()
            .inherit_all()  # Start with parent's capabilities
            .capability("send_email", {"recipients": Pattern("users/internal/*")})
            .capability("read_file", {"path": Pattern("/data/docs/*")})
            .capability("calendar", {"action": Exact("view")})
            .holder(self.assistant_key.public_key)
            .ttl(1800)  # Shorter TTL
            .delegate(self.manager_key)
        )
        
        return {
            "manager": manager_warrant,
            "assistant": assistant_warrant,
        }
    
    def get_attacks(self) -> list[dict[str, Any]]:
        """Attack vectors targeting the assistant."""
        return [
            # External user - should be denied
            {
                "attack_point": "assistant",
                "action": {"tool": "send_email", "args": {"recipients": "users/external/attacker"}},
                "expected": "denied",
                "reason": "Assistant only has users/internal/*",
            },
            # Sensitive file - should be denied
            {
                "attack_point": "assistant",
                "action": {"tool": "read_file", "args": {"path": "/etc/passwd"}},
                "expected": "denied",
                "reason": "Assistant only has /data/docs/*",
            },
            # Calendar edit - should be denied
            {
                "attack_point": "assistant",
                "action": {"tool": "calendar", "args": {"action": "delete"}},
                "expected": "denied",
                "reason": "Assistant only has view action",
            },
            # Valid internal email - should be allowed
            {
                "attack_point": "assistant",
                "action": {"tool": "send_email", "args": {"recipients": "users/internal/colleague"}},
                "expected": "allowed",
                "reason": "Within delegated scope",
            },
            # Valid doc read - should be allowed
            {
                "attack_point": "assistant",
                "action": {"tool": "read_file", "args": {"path": "/data/docs/report.pdf"}},
                "expected": "allowed",
                "reason": "Within delegated scope",
            },
        ]


class ChainDepthScenario(BaseDelegationScenario):
    """
    Deep delegation chain to test enforcement at depth.
    
    Tests that constraints are correctly enforced through N levels of delegation.
    """
    
    name = "chain_depth"
    description = "Test delegation chains of varying depth"
    
    def __init__(self, depth: int = 5):
        self.depth = depth
        self.keys = [SigningKey.generate() for _ in range(depth + 1)]
    
    def setup(self) -> dict[str, Warrant]:
        """Create chain: root → l1 → l2 → ... → lN."""
        
        warrants = {}
        
        # Root warrant with full access
        root_warrant = (
            Warrant.builder()
            .capability("transfer", {"amount": Range(0, 1_000_000)})
            .holder(self.keys[1].public_key)
            .ttl(3600)
            .issue(self.keys[0])
        )
        warrants["root"] = root_warrant
        
        # Each level attenuates further
        # Level 1: max 100,000
        # Level 2: max 10,000
        # Level 3: max 1,000
        # etc.
        
        current_warrant = root_warrant
        for i in range(1, self.depth):
            max_amount = 1_000_000 // (10 ** i)
            holder_key = self.keys[i + 1].public_key if i + 1 < len(self.keys) else self.keys[i].public_key
            
            next_warrant = (
                current_warrant.grant_builder()
                .inherit_all()
                .capability("transfer", {"amount": Range(0, max_amount)})
                .holder(holder_key)
                .ttl(3600 - (i * 300))  # Progressively shorter TTL
                .delegate(self.keys[i])
            )
            warrants[f"level_{i}"] = next_warrant
            current_warrant = next_warrant
        
        return warrants
    
    def get_attacks(self) -> list[dict[str, Any]]:
        """Attack at deepest level trying to use root's permissions."""
        deepest = f"level_{self.depth - 1}"
        max_at_depth = 1_000_000 // (10 ** (self.depth - 1))
        
        return [
            # Try root's max - should be denied (way over delegated max)
            {
                "attack_point": deepest,
                "action": {"tool": "transfer", "args": {"amount": 1_000_000}},
                "expected": "denied",
                "reason": f"Deepest level max is {max_at_depth}",
            },
            # Try just over depth's max - should be denied
            {
                "attack_point": deepest,
                "action": {"tool": "transfer", "args": {"amount": max_at_depth + 1}},
                "expected": "denied",
                "reason": f"Over max ({max_at_depth + 1} > {max_at_depth})",
            },
            # At depth's max - should be allowed (Range is inclusive)
            {
                "attack_point": deepest,
                "action": {"tool": "transfer", "args": {"amount": max_at_depth}},
                "expected": "allowed",
                "reason": f"At max ({max_at_depth} <= {max_at_depth})",
            },
            # Well under - should be allowed
            {
                "attack_point": deepest,
                "action": {"tool": "transfer", "args": {"amount": 1}},
                "expected": "allowed",
                "reason": "Well under max",
            },
        ]


class MixedAttackScenario(BaseDelegationScenario):
    """
    Test attacks at different points in the delegation chain.
    
    Shows that compromise at any level is bounded by that level's warrant.
    """
    
    name = "mixed_attack"
    description = "Attacks at different points in a 3-level chain"
    
    def __init__(self):
        self.org_key = SigningKey.generate()
        self.manager_key = SigningKey.generate()
        self.assistant_key = SigningKey.generate()
        self.bot_key = SigningKey.generate()
    
    def setup(self) -> dict[str, Warrant]:
        """Create org → manager → assistant → bot chain."""
        
        # Manager: department scope (using prefix-based patterns)
        manager_warrant = (
            Warrant.builder()
            .capability("send_email", {"recipients": Pattern("users/*")})
            .capability("read_file", {"path": Pattern("/data/*")})
            .holder(self.manager_key.public_key)
            .ttl(3600)
            .issue(self.org_key)
        )
        
        # Assistant: shared folder only (attenuated from manager)
        assistant_warrant = (
            manager_warrant.grant_builder()
            .inherit_all()
            .capability("send_email", {"recipients": Pattern("users/internal/*")})
            .capability("read_file", {"path": Pattern("/data/shared/*")})
            .holder(self.assistant_key.public_key)
            .ttl(1800)
            .delegate(self.manager_key)
        )
        
        # Bot: single tool, public folder only (attenuated from assistant)
        bot_warrant = (
            assistant_warrant.grant_builder()
            .capability("read_file", {"path": Pattern("/data/shared/public/*")})
            .holder(self.bot_key.public_key)
            .ttl(300)
            .delegate(self.assistant_key)
        )
        
        return {
            "manager": manager_warrant,
            "assistant": assistant_warrant,
            "bot": bot_warrant,
        }
    
    def get_attacks(self) -> list[dict[str, Any]]:
        """Attacks at each level of the chain."""
        return [
            # Manager compromised - can use full manager scope
            {
                "attack_point": "manager",
                "action": {"tool": "send_email", "args": {"recipients": "users/sales/john"}},
                "expected": "allowed",
                "reason": "Within manager's users/* scope",
            },
            {
                "attack_point": "manager",
                "action": {"tool": "send_email", "args": {"recipients": "external/attacker"}},
                "expected": "denied",
                "reason": "Outside manager's users/* scope",
            },
            
            # Assistant compromised - bounded by assistant warrant
            {
                "attack_point": "assistant",
                "action": {"tool": "send_email", "args": {"recipients": "users/sales/john"}},
                "expected": "denied",
                "reason": "Assistant only has users/internal/*",
            },
            {
                "attack_point": "assistant",
                "action": {"tool": "read_file", "args": {"path": "/data/dept/secrets.txt"}},
                "expected": "denied",
                "reason": "Assistant only has /data/shared/*",
            },
            
            # Bot compromised - most restricted
            {
                "attack_point": "bot",
                "action": {"tool": "send_email", "args": {"recipients": "users/internal/anyone"}},
                "expected": "denied",
                "reason": "Bot has no email capability",
            },
            {
                "attack_point": "bot",
                "action": {"tool": "read_file", "args": {"path": "/data/shared/internal/secret.txt"}},
                "expected": "denied",
                "reason": "Bot only has /data/shared/public/*",
            },
            {
                "attack_point": "bot",
                "action": {"tool": "read_file", "args": {"path": "/data/shared/public/readme.txt"}},
                "expected": "allowed",
                "reason": "Within bot's scope",
            },
        ]


class TTLBoundedScenario(BaseDelegationScenario):
    """
    Test that TTL limits the attack window via delegation.
    
    Even with identical capabilities, a shorter TTL means:
    - Attacker has less time to exploit a compromised agent
    - Warrant expires before sustained attack can complete
    - Forces re-authentication more frequently
    """
    
    name = "ttl_bounded"
    description = "Test TTL-based attack window limitation"
    
    def __init__(self, short_ttl: int = 2, long_ttl: int = 3600):
        """
        Args:
            short_ttl: Short TTL in seconds for delegated warrant (default: 2s)
            long_ttl: Long TTL for manager warrant (default: 1 hour)
        """
        self.short_ttl = short_ttl
        self.long_ttl = long_ttl
        
        self.org_key = SigningKey.generate()
        self.manager_key = SigningKey.generate()
        self.assistant_key = SigningKey.generate()
    
    def setup(self) -> dict[str, Warrant]:
        """Create warrants with different TTLs but same capabilities."""
        
        # Manager: long TTL (1 hour)
        manager_warrant = (
            Warrant.builder()
            .capability("transfer", {"amount": Range(0, 10000)})
            .capability("send_email", {"recipients": Pattern("*")})
            .holder(self.manager_key.public_key)
            .ttl(self.long_ttl)
            .issue(self.org_key)
        )
        
        # Assistant: SAME capabilities but SHORT TTL (2 seconds)
        # This simulates a "just-in-time" delegation for a specific task
        assistant_warrant = (
            manager_warrant.grant_builder()
            .inherit_all()  # Same capabilities as manager
            .holder(self.assistant_key.public_key)
            .ttl(self.short_ttl)  # But very short TTL!
            .delegate(self.manager_key)
        )
        
        return {
            "manager": manager_warrant,
            "assistant": assistant_warrant,
        }
    
    def get_attacks(self) -> list[dict[str, Any]]:
        """
        Test attacks before and after TTL expiry.
        
        Key insight: Same capabilities, but short TTL means
        attacks attempted after expiry will fail.
        """
        return [
            # Immediate attack - should work for both
            {
                "attack_point": "manager",
                "action": {"tool": "transfer", "args": {"amount": 5000}},
                "expected": "allowed",
                "reason": "Within manager's scope, TTL valid",
            },
            {
                "attack_point": "assistant",
                "action": {"tool": "transfer", "args": {"amount": 5000}},
                "expected": "allowed",  # Initially allowed
                "reason": "Within scope, TTL still valid",
            },
            # These are handled specially in the harness - see TTL tests below
        ]
    
    def get_ttl_attack_sequence(self) -> list[dict]:
        """
        Get attack sequence that tests TTL expiry.
        
        Returns attacks to run:
        1. Immediately (both should work)
        2. After short_ttl expires (assistant should fail)
        """
        return [
            {
                "phase": "immediate",
                "delay": 0,
                "attacks": [
                    {
                        "attack_point": "manager",
                        "action": {"tool": "transfer", "args": {"amount": 5000}},
                        "expected": "allowed",
                    },
                    {
                        "attack_point": "assistant", 
                        "action": {"tool": "transfer", "args": {"amount": 5000}},
                        "expected": "allowed",
                    },
                ],
            },
            {
                "phase": "after_assistant_expiry",
                "delay": self.short_ttl + 1,  # Wait for assistant's TTL to expire
                "attacks": [
                    {
                        "attack_point": "manager",
                        "action": {"tool": "transfer", "args": {"amount": 5000}},
                        "expected": "allowed",  # Manager's TTL still valid
                    },
                    {
                        "attack_point": "assistant",
                        "action": {"tool": "transfer", "args": {"amount": 5000}},
                        "expected": "denied",  # Assistant's TTL expired!
                    },
                ],
            },
        ]


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
            Warrant.builder()
            .capability("send_email", {"to": Pattern("*@company.com")})
            .holder(self.agent_key.public_key)
            .ttl(300)  # 5 minute task
            .issue(self.issuer_key)
        )
        
        # Warrant for "send partner update" - broader scope
        external_email_warrant = (
            Warrant.builder()
            .capability("send_email", {"to": Pattern("*")})
            .holder(self.agent_key.public_key)
            .ttl(300)
            .issue(self.issuer_key)
        )
        
        # Warrant for "process refund" - $100 limit
        small_payment_warrant = (
            Warrant.builder()
            .capability("transfer", {"amount": Range(0, 100)})
            .holder(self.agent_key.public_key)
            .ttl(300)
            .issue(self.issuer_key)
        )
        
        # Warrant for "pay vendor invoice" - $10000 limit
        large_payment_warrant = (
            Warrant.builder()
            .capability("transfer", {"amount": Range(0, 10000)})
            .holder(self.agent_key.public_key)
            .ttl(300)
            .issue(self.issuer_key)
        )
        
        # Warrant with no email capability at all
        no_email_warrant = (
            Warrant.builder()
            .capability("read_file", {"path": Pattern("docs/*")})
            .holder(self.agent_key.public_key)
            .ttl(300)
            .issue(self.issuer_key)
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
                "action": {"tool": "send_email", "args": {"to": "partner@external.com"}},
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

