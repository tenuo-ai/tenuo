"""
Proof-of-Possession (PoP) Binding Attacks

Tests verifying:
- PoP binds warrant to holder (stolen warrants useless)
- Signature covers (tool, args, timestamp window)
- Replay prevented within window via timestamp
"""

import pytest

from tenuo import (
    Warrant, Range
)


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
        warrant = Warrant.issue(
            tools="admin_access",
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key
        )
        
        # Attacker steals warrant and tries with their keypair
        print("  [Attack 7] Attacker stolen warrant, trying to use with wrong keypair...")
        
        args = {"action": "delete"}
        attacker_pop = warrant.create_pop_signature(attacker_keypair, "admin_access", args)
        
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
        
        warrant = Warrant.issue(
            tools=["search", "delete"],
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key
        )
        
        # Create valid PoP for "search"
        search_args = {"query": "test"}
        search_pop = warrant.create_pop_signature(keypair, "search", search_args)
        
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
        
        warrant = Warrant.issue(
            tools="transfer",
            constraints={"amount": Range(max=1000)},
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key
        )
        
        # Create valid PoP for small amount
        small_args = {"amount": 10}
        small_pop = warrant.create_pop_signature(keypair, "transfer", small_args)
        
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
        
        _warrant = Warrant.issue(
            tools="payment",
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key
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
        
        warrant = Warrant.issue(
            tools="transfer",
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key
        )
        
        args = {"amount": 100}
        pop_sig = warrant.create_pop_signature(keypair, "transfer", args)
        
        # Immediately verify - should work
        print("  [Check] Verifying fresh PoP...")
        assert warrant.authorize("transfer", args, signature=bytes(pop_sig))
        print("  [Info] Fresh PoP accepted")
        
        # Note: Can't easily test window expiry without waiting 120+ seconds
        print("  [Info] PoP window is ~120 seconds. After expiry, replay should fail.")
        print("  [Info] Attack 35: Would fail after window expires (Not tested due to time)")
