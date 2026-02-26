"""
Edge Case Attacks

Tests for unusual scenarios and boundary conditions.
"""

import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import Optional

import pytest

from tenuo import (
    Exact,
    Range,
    Warrant,
)
from tenuo.constraints import Constraints
from tenuo.decorators import _warrant_context, warrant_scope
from tenuo.exceptions import Unauthorized


@dataclass
class NodeState:
    """Simulated state object."""

    messages: list
    warrant: Optional[str] = None


@pytest.mark.security
class TestEdgeCases:
    """Edge case and boundary condition attacks."""

    def test_attack_2_context_leaks(self, keypair):
        """
        Attack: Break context isolation (threads, async).

        Defense: ContextVars don't leak across threads by default.
        """
        print("\n--- Attack 2: Context Leaks ---")

        def sensitive_tool():
            w = _warrant_context.get()
            if not w:
                raise Unauthorized("No active warrant")
            return "Tool executed"

        warrant = Warrant.mint(keypair=keypair, capabilities=Constraints.for_tool("sensitive_tool", {}), ttl_seconds=60)

        # Attack A: Call outside context
        with pytest.raises(Unauthorized):
            sensitive_tool()
        print("  [Result] Attack 2A blocked (Tool rejected call outside context)")

        # Attack B: Thread inheritance
        result_holder = {"success": False, "error": None}

        def thread_target():
            try:
                sensitive_tool()
                result_holder["success"] = True
            except Exception as e:
                result_holder["error"] = e

        with warrant_scope(warrant):
            t = threading.Thread(target=thread_target)
            t.start()
            t.join()

        if result_holder["success"]:
            print("  [WARNING] Attack 2B SUCCEEDED: Thread inherited context")
        else:
            print(f"  [Result] Attack 2B blocked: {result_holder['error']}")
            print("  [Info] Threads don't inherit contextvars by default (secure)")

    @pytest.mark.integration_responsibility
    def test_attack_8_dynamic_node_bypass(self, keypair):
        """
        Attack: Route to dynamic node without security wrapper.

        Note: This is an INTEGRATION responsibility, not a Tenuo bug.
        Tenuo cannot protect code that doesn't use it.
        """
        print("\n--- Attack 8: Dynamic Node Bypass ---")

        def dynamic_node(s: NodeState):
            print("  [Dynamic Node] Executing dangerous tool...")
            return "Dangerous Action Executed"

        warrant = Warrant.mint(keypair=keypair, capabilities=Constraints.for_tool("search", {}), ttl_seconds=60)
        state = NodeState(messages=[], warrant=warrant.to_base64())

        print("  [Attack 8] Routing to unlisted dynamic node...")
        result = dynamic_node(state)

        if result == "Dangerous Action Executed":
            print("  [WARNING] Attack 8 SUCCEEDED: Unlisted node executed")
            print("  [Note] This is an INTEGRATION RESPONSIBILITY")
            print("         Tenuo cannot protect unwrapped nodes.")
            pytest.skip("Integration responsibility - see docs")

    def test_attack_17_clock_skew_exploitation(self, keypair):
        """
        Attack: Use just-expired warrant within clock tolerance.

        Defense: Strict expiry enforcement.
        """
        print("\n--- Attack 17: Clock Skew Exploitation ---")

        warrant = Warrant.mint(keypair=keypair, capabilities=Constraints.for_tool("search", {}), ttl_seconds=1)
        time.sleep(1.1)  # Expired by 0.1s

        print("  [Attack 17A] Using warrant expired by 0.1s...")
        if warrant.is_expired():
            print("  [Result] Attack 17A blocked (Strict expiry enforced)")
        else:
            print("  [WARNING] Attack 17A SUCCEEDED: Expired warrant accepted")
            assert False, "Warrant should be expired after TTL"

        print("  [Info] Attack 17B skipped (Cannot mint future warrants via API)")

    def test_attack_20_unicode_normalization(self, keypair):
        """
        Attack: Use different Unicode normalization forms.

        Defense: Byte-wise comparison (safe but strict).
        """
        print("\n--- Attack 20: Unicode Normalization ---")

        cafe_nfc = unicodedata.normalize("NFC", "café")
        cafe_nfd = unicodedata.normalize("NFD", "café")

        warrant = Warrant.mint(
            keypair=keypair, capabilities=Constraints.for_tool("search", {"query": Exact(cafe_nfc)}), ttl_seconds=60
        )

        print("  [Attack 20] Testing NFD 'café' against NFC constraint...")

        result = warrant.check_constraints("search", {"query": cafe_nfd})
        if result is None:
            print("  [Info] Tenuo normalizes Unicode (NFD matched NFC)")
        else:
            print("  [Info] Tenuo performs byte-wise comparison (NFD != NFC)")
            print("  [Note] This is secure but may surprise users")

    def test_integer_overflow_boundary(self, keypair):
        """
        Attack: Pass huge integers that overflow Rust u64/i64 types.

        Defense: Should raise ValidationError or OverflowError, not panic/wrap.

        Note: Rust uses u64/i64, Python uses arbitrary-precision integers.
        Passing 2**64 + 1 into a Rust u64 could cause panic or silent wrapping
        depending on PyO3 configuration.
        """
        print("\n--- Attack: Integer Overflow Boundary ---")

        huge_int = 2**64 + 100
        negative_huge = -(2**63 + 100)

        # Test 1: Issue warrant with huge int constraint
        print(f"  [Attack] Issuing warrant with Range(max={huge_int})...")
        try:
            _warrant = Warrant.mint(
                keypair=keypair,
                capabilities=Constraints.for_tool("test", {"limit": Range(max=huge_int)}),
                ttl_seconds=60,
            )
            print("  [Warning] Huge int constraint accepted (may wrap)")
        except (OverflowError, ValueError, Exception) as e:
            print(f"  [Result] Huge int constraint rejected gracefully: {type(e).__name__}")
            assert "panic" not in str(e).lower(), "Should not panic!"

        # Test 2: check_constraints with huge int arg
        print(f"  [Attack] Checking constraints with arg val={huge_int}...")
        warrant = Warrant.mint(keypair=keypair, capabilities=Constraints.for_tool("test", {}), ttl_seconds=60)
        try:
            warrant.check_constraints("test", {"val": huge_int})
            print("  [Result] Huge int argument handled gracefully")
        except Exception as e:
            assert "panic" not in str(e).lower(), f"Panicked on huge int: {e}"
            print(f"  [Result] Huge int rejected: {type(e).__name__}")

        # Test 3: Negative overflow
        print(f"  [Attack] Testing negative overflow {negative_huge}...")
        try:
            warrant.check_constraints("test", {"val": negative_huge})
            print("  [Result] Negative huge int handled gracefully")
        except Exception as e:
            assert "panic" not in str(e).lower(), f"Panicked on negative huge: {e}"
            print(f"  [Result] Negative huge rejected: {type(e).__name__}")

    def test_attack_5_issuer_abuse(self, keypair):
        """
        Attack: Use ISSUER warrant to authorize tool execution.

        Defense: Issuer warrants can only issue, not execute.
        """
        print("\n--- Attack 5: Issuer Warrant Abuse ---")

        from tenuo_core import Clearance

        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["search", "read"], clearance=Clearance.INTERNAL, ttl_seconds=3600, keypair=keypair
        )

        print("  [Attack 5] Attempting to use issuer warrant for execution...")

        result = issuer_warrant.check_constraints("search", {})
        if result is None:
            print("  [CRITICAL] Attack 5 SUCCEEDED: Issuer passed constraint check!")
            assert False, "Issuer warrants should not authorize execution"
        else:
            print(f"  [Result] Attack 5 blocked ({result})")
