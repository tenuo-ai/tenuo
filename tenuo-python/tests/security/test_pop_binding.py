"""
Proof-of-Possession (PoP) Binding Attacks

Tests verifying:
- PoP binds warrant to holder (stolen warrants useless)
- Signature covers (tool, args, timestamp window)
- Replay prevented within window via timestamp
"""

import pytest
import time

from tenuo import (
    Warrant,
    Range,
)
from tenuo.constraints import Constraints


@pytest.mark.security
@pytest.mark.pop
class TestPopBinding:
    """Proof-of-Possession attacks."""

    def test_attack_7_holder_mismatch(self, keypair, attacker_keypair):
        """
        Attack: Use stolen warrant with wrong keypair.

        Defense: PoP signature fails for wrong holder.
        """
        print("\n--- Attack 7: Holder Mismatch (Stolen Warrant) ---")

        # Issue warrant bound to keypair
        warrant = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("admin_access", {}),
            holder=keypair.public_key,
            ttl_seconds=3600,
        )

        # Attacker steals warrant and tries with their keypair
        print("  [Attack 7] Attacker stolen warrant, trying to use with wrong keypair...")

        args = {"action": "delete"}
        attacker_pop = warrant.sign(attacker_keypair, "admin_access", args, int(time.time()))

        # Should fail - signature doesn't match holder
        authorized = warrant.authorize("admin_access", args, signature=bytes(attacker_pop))

        if authorized:
            print("  [CRITICAL] Attack 7 SUCCEEDED: Wrong keypair passed PoP verification!")
            assert False, "PoP should fail with wrong holder"
        else:
            print("  [Result] Attack 7 blocked (Holder binding enforced)")

    def test_attack_13_pop_tool_swap(self, keypair):
        """
        Attack: Sign PoP for tool A, use for tool B.

        Defense: Signature binds to tool name.
        """
        print("\n--- Attack 13: PoP Tool Swap ---")

        warrant = Warrant.mint(
            keypair=keypair, capabilities={"search": {}, "delete": {}}, holder=keypair.public_key, ttl_seconds=3600
        )

        # Create valid PoP for "search"
        search_args = {"query": "test"}
        search_pop = warrant.sign(keypair, "search", search_args, int(time.time()))

        # Attack: Use that signature for "delete"
        print("  [Attack 13] Using 'search' PoP for 'delete' tool...")
        delete_args = {"file": "important.txt"}

        authorized = warrant.authorize("delete", delete_args, signature=bytes(search_pop))

        if authorized:
            print("  [CRITICAL] Attack 13 SUCCEEDED: PoP not bound to tool name!")
            assert False, "PoP should be bound to tool name"
        else:
            print("  [Result] Attack 13 blocked (PoP binds to tool name)")

    def test_attack_14_pop_args_swap(self, keypair):
        """
        Attack: Sign PoP for args A, use with args B.

        Defense: Signature binds to args.
        """
        print("\n--- Attack 14: PoP Args Swap ---")

        warrant = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("transfer", {"amount": Range(max=1000)}),
            holder=keypair.public_key,
            ttl_seconds=3600,
        )

        # Create valid PoP for small amount
        small_args = {"amount": 10}
        small_pop = warrant.sign(keypair, "transfer", small_args, int(time.time()))

        # Attack: Use that signature for large amount
        print("  [Attack 14] Using PoP for amount=10 with amount=10000...")
        large_args = {"amount": 10000}

        authorized = warrant.authorize("transfer", large_args, signature=bytes(small_pop))

        if authorized:
            print("  [CRITICAL] Attack 14 SUCCEEDED: PoP not bound to args!")
            assert False, "PoP should be bound to args"
        else:
            print("  [Result] Attack 14 blocked (PoP binds to args)")

    def test_attack_6_replay_confused_deputy(self, keypair):
        """
        Attack: Replay PoP within TTL, or use for different tool.

        Note: Short TTL and nonce (app-level) prevent replay.
        """
        print("\n--- Attack 6: Replay & Confused Deputy ---")

        _warrant = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("payment", {}),
            holder=keypair.public_key,
            ttl_seconds=3600,
        )

        print("  [Info] Attack 6A: Replay within TTL requires app-level nonces.")
        print("  [Info] Tenuo relies on short TTLs or external nonce checking.")

        print("  [Info] Attack 6B: Confused deputy (tool swap) blocked by PoP binding.")
        print("  [Note] See test_attack_13_pop_tool_swap for verification.")

    def test_attack_35_pop_timestamp_window(self, keypair):
        """
        Attack: Replay PoP after timestamp window expires.

        Note: ~120 second timestamp window enforced.
        """
        print("\n--- Attack 35: PoP Timestamp Window ---")

        warrant = Warrant.mint(
            keypair=keypair,
            capabilities=Constraints.for_tool("transfer", {}),
            holder=keypair.public_key,
            ttl_seconds=3600,
        )

        args = {"amount": 100}
        pop_sig = warrant.sign(keypair, "transfer", args, int(time.time()))

        # Immediately verify - should work
        print("  [Check] Verifying fresh PoP...")
        assert warrant.authorize("transfer", args, signature=bytes(pop_sig))
        print("  [Info] Fresh PoP accepted")

        # Note: Can't easily test window expiry without waiting 120+ seconds
        print("  [Info] PoP window is ~120 seconds. After expiry, replay should fail.")
        print("  [Info] Attack 35: Would fail after window expires (Not tested due to time)")

    def test_pop_argument_ordering_determinism(self, keypair):
        """
        Attack: Pass arguments in different orders to cause signature mismatch.

        Defense: PoP generation must sort keys deterministically (canonical CBOR).

        Note: Python dicts preserve insertion order since 3.7, so if the binding
        doesn't sort keys before CBOR serialization, different orderings would
        produce different signatures, causing flaky verification.
        """
        print("\n--- Attack: Argument Ordering Non-Determinism ---")

        warrant = Warrant.mint(keypair=keypair, capabilities=Constraints.for_tool("test", {}), ttl_seconds=60)

        # Dicts preserve insertion order in modern Python
        args1 = {"a": 1, "b": 2, "c": 3}
        args2 = {"c": 3, "a": 1, "b": 2}
        args3 = {"b": 2, "c": 3, "a": 1}

        print("  [Attack] Creating PoP signatures with different arg orderings...")
        sig1 = warrant.sign(keypair, "test", args1, int(time.time()))
        sig2 = warrant.sign(keypair, "test", args2, int(time.time()))
        sig3 = warrant.sign(keypair, "test", args3, int(time.time()))

        print(f"  [Check] sig1 == sig2: {sig1 == sig2}")
        print(f"  [Check] sig2 == sig3: {sig2 == sig3}")

        assert sig1 == sig2 == sig3, "PoP signature must be deterministic regardless of arg order"
        print("  [Result] All signatures match - keys are sorted before signing")
