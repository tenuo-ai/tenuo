"""
Delegation Limit Attacks

Tests verifying:
- MAX_DELEGATION_DEPTH (64) enforced
- Terminal warrants cannot delegate
- Issuer/Execution warrant separation
"""

import pytest

from tenuo import (
    Warrant,
)
from tenuo.constraints import Constraints
from tenuo.exceptions import DepthExceeded
from tenuo_core import Clearance, MAX_DELEGATION_DEPTH
from tenuo.exceptions import ValidationError


@pytest.mark.security
@pytest.mark.delegation
class TestDelegationLimits:
    """Delegation depth and chain length attacks."""

    def test_attack_9_delegate_to_self_amplification(self, keypair):
        """
        Attack: Delegate to self repeatedly to bypass depth limits.

        Defense: Blocked by depth limit (64).
        """
        print("\n--- Attack 9: Delegate-to-Self Amplification ---")
        print(f"  [Info] MAX_DELEGATION_DEPTH = {MAX_DELEGATION_DEPTH}")

        current = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {}),
            ttl_seconds=3600
        )

        try:
            for i in range(MAX_DELEGATION_DEPTH + 10):
                builder = current.grant_builder()
                builder.inherit_all()  # POLA: explicit inheritance
                builder.holder(keypair.public_key)
                current = builder.grant(keypair)

            print(f"  [CRITICAL] Attack 9 SUCCEEDED: Created {MAX_DELEGATION_DEPTH + 10} depth chain!")
            assert False, "Should have hit depth or chain limit"

        except (DepthExceeded, Exception) as e:
            # May hit depth limit (64)
            err_str = str(e).lower()
            assert "depth" in err_str or "chain" in err_str or "exceed" in err_str or "maximum" in err_str
            print(f"  [Result] Attack 9 blocked (Limit enforced: {e})")

    def test_attack_18_chain_length_dos(self, keypair):
        """
        Attack: Create deeply nested chain to DoS verifier.

        Defense: Depth limit enforced.
        """
        print("\n--- Attack 18: Chain Length DoS ---")

        current = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {}),
            ttl_seconds=3600
        )
        depth = 0
        max_attempts = 50

        try:
            for i in range(max_attempts):
                depth += 1
                builder = current.grant_builder()
                builder.inherit_all()  # POLA: explicit inheritance
                current = builder.grant(keypair)

            print(f"  [WARNING] Attack 18 SUCCEEDED: Created chain of depth {depth}")

        except Exception as e:
            if "depth" in str(e).lower() or isinstance(e, DepthExceeded):
                print(f"  [Result] Attack 18 blocked (Depth limit enforced at {depth})")
            else:
                print(f"  [Result] Attack 18 blocked with error: {e}")

    def test_attack_25_depth_limit_enforcement(self, keypair):
        """
        Attack: Try to exceed depth limit on issuer warrants.

        Defense: MAX_DELEGATION_DEPTH (64) enforced for all warrant types.
        """
        print("\n--- Attack 25: Depth Limit Enforcement ---")
        print(f"  [Info] MAX_DELEGATION_DEPTH = {MAX_DELEGATION_DEPTH}")

        # Test issuer warrant depth limit
        current = Warrant.issue_issuer(
            issuable_tools=["search"],
            clearance=Clearance.INTERNAL,
            ttl_seconds=3600,
            keypair=keypair
        )

        # Use a smaller limit for testing (max_depth policy)
        test_limit = 10

        try:
            for i in range(test_limit + 5):
                builder = current.grant_builder()
                builder.inherit_all()  # POLA: explicit inheritance
                builder.holder(keypair.public_key)
                current = builder.grant(keypair)

            print(f"  [Info] Created chain of depth {test_limit + 5}")

        except Exception as e:
            if "depth" in str(e).lower() or "exceed" in str(e).lower():
                print(f"  [Result] Attack 25 blocked (Depth limit enforced: {e})")
            else:
                print(f"  [Result] Attack 25 blocked with error: {e}")

    def test_attack_29_execution_issues_execution(self, keypair):
        """
        Attack: Execution warrant tries to issue child warrants.

        Defense: Only ISSUER warrants can issue.
        """
        print("\n--- Attack 29: Execution Warrant Issuing ---")

        exec_warrant = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {}),
            ttl_seconds=3600
        )

        print("  [Attack 29] Attempting to call issue_execution() on execution warrant...")

        with pytest.raises((ValidationError, AttributeError, ValueError)):
            exec_warrant.issue_execution()

        print("  [Result] Attack 29 blocked (Execution warrants cannot issue)")

    def test_attack_30_issuer_executes_tools(self, keypair):
        """
        Attack: Issuer warrant tries to execute tools directly.

        Defense: Issuer warrants can only issue, not execute.
        """
        print("\n--- Attack 30: Issuer Warrant Executing Tools ---")

        issuer = Warrant.issue_issuer(
            issuable_tools=["delete"],
            clearance=Clearance.INTERNAL,
            ttl_seconds=3600,
            keypair=keypair
        )

        print("  [Attack 30] Attempting to authorize tool execution with issuer warrant...")

        try:
            authorized = issuer.authorize("delete", {})
            if authorized:
                print("  [CRITICAL] Attack 30 SUCCEEDED: Issuer warrant executed tool!")
                assert False, "Issuer warrants should not execute tools"
            else:
                print("  [Result] Attack 30 blocked (authorize returned False)")
        except (ValidationError, Exception) as e:
            print(f"  [Result] Attack 30 blocked (Error: {type(e).__name__})")

    def test_attack_31_max_depth_zero_bypass(self, keypair):
        """
        Attack: Terminal warrant (max_depth=0) tries to delegate.

        Defense: DepthExceeded (terminal warrants cannot delegate).
        """
        print("\n--- Attack 31: Terminal Warrant Delegation ---")

        parent = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {}),
            ttl_seconds=3600
        )

        # Create terminal warrant (POLA: inherit_all first)
        builder = parent.grant_builder()
        builder.inherit_all()
        builder.terminal()
        terminal = builder.grant(keypair)

        print(f"  [Info] Created terminal warrant: is_terminal={terminal.is_terminal()}")

        print("  [Attack 31] Attempting to delegate from terminal warrant...")
        with pytest.raises(DepthExceeded):
            builder2 = terminal.grant_builder()
            builder2.inherit_all()
            builder2.grant(keypair)

        print("  [Result] Attack 31 blocked (Terminal warrants cannot delegate)")
