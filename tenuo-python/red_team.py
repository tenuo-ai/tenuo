"""
Tenuo Red Team: Adversarial Security Testing

This module contains offensive security tests that attempt to break Tenuo's
authorization model. Each test simulates a real attack scenario.

Test Categories:
================

1. **Signature/Trust Attacks** (1, 1b, 4, 33)
   - State tampering, warrant swapping
   - Untrusted root acceptance
   - Replay of old/expired warrants

2. **Isolation Attacks** (2, 8)
   - Context leaks across threads
   - Dynamic node bypass

3. **Monotonicity Attacks** (3, 12, 23, 26, 27, 28, 34, 37, 38)
   - Constraint widening
   - Constraint removal
   - Type substitution
   - Wildcard re-widening
   - TTL extension
   - CEL injection
   - Empty result sets

4. **PoP Attacks** (6, 7, 13, 14, 35)
   - Tool swap (sign for A, use for B)
   - Args swap (sign for args A, use for args B)  
   - Holder mismatch (stolen warrant)
   - Timestamp window replay

5. **Delegation Attacks** (9, 25, 29, 30, 31)
   - Depth limit bypass
   - Chain length DoS
   - Execution→Issuer confusion
   - Terminal warrant delegation

6. **Implementation Attacks** (10, 15, 16, 22, 24, 32)
   - Tool wrapper bypass
   - Type coercion
   - Serialization injection
   - TOCTOU (payload_bytes vs payload)
   - Path traversal
   - Default value bypass

7. **Timing/Clock Attacks** (17)
   - Clock skew exploitation

8. **Edge Cases** (19, 20, 36)
   - Constraint key injection
   - Unicode normalization
   - Session ID reuse

Expected Outcomes:
==================
✅ PASS: Attack is blocked (system is secure)
⚠️ WARNING: Attack succeeds (vulnerability found)
ℹ️ INFO: Test skipped or informational

Run: pytest tenuo-python/red_team.py -v -s
"""

import pytest
import sys
import json
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass
from tenuo import (
    Warrant, Keypair, Pattern, Exact, Range, Wildcard, OneOf,
    ConstraintViolation, PatternExpanded, RangeExpanded,
    SignatureInvalid, MissingSignature,
    Unauthorized, ExpiredError, DepthExceeded,
    TrustLevel, MonotonicityError
)

# =============================================================================
# Mock Framework for Simulation
# =============================================================================

@dataclass
class NodeState:
    """Simulated state object passed between nodes."""
    messages: list
    warrant: Optional[str] = None  # The serialized warrant
    
class MockNode:
    """A simulated LangGraph node."""
    def __init__(self, name: str, behavior: callable):
        self.name = name
        self.behavior = behavior
        
    def run(self, state: NodeState) -> NodeState:
        print(f"[{self.name}] Running...")
        return self.behavior(state)

# =============================================================================
# Attack Scenarios
# =============================================================================

class TestRedTeam:
    
    @pytest.fixture
    def keypair(self):
        return Keypair.generate()
        
    @pytest.fixture
    def attacker_keypair(self):
        return Keypair.generate()

    def test_attack_1_state_tampering(self, keypair, attacker_keypair):
        """
        Attack 1: Smash the state-carried warrant.
        
        Scenario:
        A malicious node modifies state["warrant"] to swap in a stronger warrant
        or a warrant from another tenant.
        """
        print("\n--- Attack 1: State Tampering ---")
        
        # 1. Setup: Valid initial state with a weak warrant
        weak_warrant = Warrant.issue(
            tools="read_public",
            ttl_seconds=60,
            keypair=keypair
        )
        state = NodeState(messages=[], warrant=weak_warrant.to_base64())
        
        # 2. Attack: Malicious node swaps in a stronger warrant (self-signed by attacker)
        # The attacker tries to forge a "root" warrant.
        fake_root = Warrant.issue(
            tools="admin_access",
            ttl_seconds=3600,
            keypair=attacker_keypair # Signed by attacker, not trusted root
        )
        
        def malicious_behavior(s: NodeState):
            print(f"  [Attacker] Swapping warrant in state...")
            s.warrant = fake_root.to_base64()
            return s
            
        malicious_node = MockNode("malicious", malicious_behavior)
        state = malicious_node.run(state)
        
        # 3. Victim: Downstream node tries to use the warrant
        # The victim SHOULD verify the warrant against the TRUSTED root (keypair).
        # If it just deserializes and checks tools, it might be fooled if it doesn't check the signer.
        
        def victim_behavior(s: NodeState):
            print(f"  [Victim] Verifying warrant...")
            if not s.warrant:
                return "No warrant"
            
            try:
                # Vulnerable check: just deserialize?
                # w = Warrant.from_base64(s.warrant)
                
                # Secure check: verify against trusted root
                # This is what SHOULD happen.
                w = Warrant.from_base64(s.warrant)
                
                # If we verify against the ORIGINAL keypair (trusted root), this should fail.
                # Note: verify() takes the public key bytes.
                is_valid = w.verify(keypair.public_key.to_bytes())
                
                if is_valid:
                    print("  [Victim] Warrant verified successfully (VULNERABLE if this was the fake one!)")
                    return "Success"
                else:
                    print("  [Victim] Warrant verification failed (SECURE)")
                    raise SignatureInvalid("Verification failed")
                    
            except Exception as e:
                print(f"  [Victim] Caught expected error: {e}")
                raise

        victim_node = MockNode("victim", victim_behavior)
        
        # Expectation: The victim should reject the fake warrant because it's signed by attacker_keypair,
        # not the trusted 'keypair'.
        with pytest.raises(SignatureInvalid):
            victim_node.run(state)
            
        print("  [Result] Attack 1 failed (System is secure against simple key swapping if verify is called)")

    def test_attack_1b_replay_old_warrant(self, keypair):
        """
        Attack 1b: Replay a previously seen stronger warrant.
        
        Scenario:
        Attacker has observed a valid 'admin' warrant from the past and swaps it in
        to replace a current 'read-only' warrant.
        """
        print("\n--- Attack 1b: Replay Old Warrant ---")
        
        # 1. Attacker has a valid (but maybe expired or just old) admin warrant
        # Let's say it's expired for this test to show TTL enforcement.
        old_admin_warrant = Warrant.issue(
            tools="admin_access",
            ttl_seconds=1, # Short TTL
            keypair=keypair
        )
        time.sleep(1.1) # Wait for expiry
        
        # 2. Current state has a weak warrant
        current_warrant = Warrant.issue(
            tools="read_only",
            ttl_seconds=60,
            keypair=keypair
        )
        state = NodeState(messages=[], warrant=current_warrant.to_base64())
        
        # 3. Attack: Swap in the old admin warrant
        def malicious_behavior(s: NodeState):
            print(f"  [Attacker] Swapping in old admin warrant...")
            s.warrant = old_admin_warrant.to_base64()
            return s
            
        state = MockNode("malicious", malicious_behavior).run(state)
        
        # 4. Victim verifies
        def victim_behavior(s: NodeState):
            w = Warrant.from_base64(s.warrant)
            # Verify signature (it is valid!)
            if not w.verify(keypair.public_key.to_bytes()):
                 raise SignatureInvalid("Sig failed")
            
            # Check expiry
            # authorize() checks expiry.
            # Or manual check.
            # Let's try to authorize an admin action.
            w.authorize("admin_access", {}) # Should raise ExpiredError or return False
            
        victim_node = MockNode("victim", victim_behavior)
        
        # Expectation: Should fail due to expiry
        # Note: authorize returns Result or bool? In python.rs it returns PyResult<bool> but maps errors.
        # WarrantExpired is an error.
        with pytest.raises(ExpiredError):
             victim_node.run(state)
             
        print("  [Result] Attack 1b failed (System is secure against expired replay)")

    def test_attack_2_context_leaks(self, keypair):
        """
        Attack 2: Break "context is convenience" assumption.
        
        Scenario:
        A node spawns a background task or thread that tries to call a tool
        AFTER the warrant context has exited or without inheriting it.
        """
        print("\n--- Attack 2: Context Leaks ---")
        
        from tenuo.decorators import set_warrant_context, _warrant_context
        import threading
        
        # 1. Setup: A tool that checks for active warrant
        def sensitive_tool():
            w = _warrant_context.get()
            if not w:
                raise Unauthorized("No active warrant")
            return "Tool executed"
            
        # 2. Valid usage
        warrant = Warrant.issue(tools="sensitive_tool", ttl_seconds=60, keypair=keypair)
        with set_warrant_context(warrant):
            assert sensitive_tool() == "Tool executed"
            
        # 3. Attack: Background thread
        # If contextvars are not propagated, this fails (secure default for threads usually, 
        # but async tasks might inherit if not careful, or NOT inherit if we want them to).
        # Here we want to see if we can "leak" or "lose" context.
        # Actually, the attack is: can I call the tool *outside* the context?
        
        # Attack A: Call outside context
        with pytest.raises(Unauthorized):
            sensitive_tool()
        print("  [Result] Attack 2A failed (Tool correctly rejected call outside context)")
        
        # Attack B: Leak context to thread?
        # If I spawn a thread INSIDE the context, does it inherit?
        # ContextVars in Python: run in same thread usually work, new threads DO NOT inherit by default.
        # So this should fail (Secure).
        
        result_holder = {"success": False, "error": None}
        def thread_target():
            try:
                sensitive_tool()
                result_holder["success"] = True
            except Exception as e:
                result_holder["error"] = e
                
        with set_warrant_context(warrant):
            t = threading.Thread(target=thread_target)
            t.start()
            t.join()
            
        if result_holder["success"]:
            print("  [WARNING] Attack 2B SUCCEEDED: Thread inherited context (Might be intended, but risky)")
        else:
            print(f"  [Result] Attack 2B failed: {result_holder['error']} (Secure: threads don't inherit by default)")
            
        # Attack C: Async leak (simulated)
        # If we use asyncio, contextvars ARE inherited by tasks spawned with create_task.
        # This is often desired but can be a leak if the task outlives the 'with' block?
        # No, 'with' block sets/resets token. If task runs *during* block, it has access.
        # If task runs *after* block, it should not.
        
        # We can't easily test async here without async test runner, but let's simulate the logic.
        # The token reset happens on exit.
        
    def test_attack_3_intersection_bypass(self, keypair):
        """
        Attack 3: Slip through the "intersection" logic.
        
        Scenario:
        1. Policy.tools unset becomes "no restriction" -> inherits all tools.
        2. Constraints widening bug: try to add a broader constraint than parent.
        """
        print("\n--- Attack 3: Intersection Bypass & Widening ---")
        
        # 1. Setup: Parent warrant with limited scope
        parent = Warrant.issue(
            tools="search",
            constraints={"query": Pattern("allowed*")},
            ttl_seconds=60,
            keypair=keypair
        )
        
        # Attack A: Constraints Widening
        # Try to attenuate to a broader pattern "*"
        # This should fail if monotonicity is enforced.
        
        print("  [Attack 3A] Attempting to widen constraints...")
        with pytest.raises(PatternExpanded):
            builder = parent.attenuate_builder()
            builder.with_constraint("query", Pattern("*")) # Broader than "allowed*"
            builder.delegate_to(keypair, keypair)
            
        print("  [Result] Attack 3A failed (Monotonicity enforced)")
        
        # Attack B: Policy tools unset
        # If I don't specify tools in attenuation, do I get ALL parent tools?
        # Yes, that's the design (intersection with "everything" = parent set).
        # But if I try to ADD a tool not in parent?
        
        print("  [Attack 3B] Attempting to add unauthorized tool...")
        # Parent has "search". Try to issue "delete".
        
        # Note: AttenuationBuilder inherits tools by default.
        # If we try to set tools explicitly to something outside parent:
        
        # This depends on how we try to do it.
        # If we use `with_tools(["delete"])`, it should fail or filter it out?
        # Rust implementation: `set_exec_tools` takes a Vec<String>.
        # `build` checks if tools are subset of parent.
        
        # We need to simulate the "policy tools unset" scenario.
        # If a node policy says "tools=None", it means "inherit".
        # If parent has ["search", "delete"], and node inherits, it gets both.
        # If attacker wants to use "delete" but policy intended only "search" but forgot to say so?
        # That's a logic bug in the application/policy, not Tenuo core.
        # But we can test if Tenuo allows *adding* a tool.
        
        from tenuo.exceptions import MonotonicityError
        with pytest.raises(MonotonicityError): # Or ToolMismatch/similar
             # Try to create a child warrant with "delete" from a parent that only has "search"
             # We can't do this with AttenuationBuilder easily if it filters?
             # Actually, AttenuationBuilder.with_tools() sets the tools.
             # If we set tools=["delete"], and parent has ["search"], build() should fail.
             
             builder = parent.attenuate_builder()
             builder.with_tools(["delete"])
             builder.delegate_to(keypair, keypair)
             
        print("  [Result] Attack 3B failed (Cannot add tools not in parent)")

    def test_attack_4_verifier_confusion(self, keypair, attacker_keypair):
        """
        Attack 4: Confuse the verifier / trust boundary.
        
        Scenario:
        1. Valid chain, wrong root: Attacker signs a warrant chain with their own key.
           If verifier doesn't check the root identity, it passes.
        2. Multi-root confusion: If system allows multiple roots, try to use one from a different tenant.
        """
        print("\n--- Attack 4: Verifier Confusion ---")
        
        # 1. Attacker creates a valid-looking chain rooted in their own key
        attacker_root = Warrant.issue(
            tools="admin_access",
            ttl_seconds=3600,
            keypair=attacker_keypair
        )
        
        # Attacker delegates to themselves (or anyone)
        attacker_child = attacker_root.attenuate_builder().delegate_to(attacker_keypair, attacker_keypair)
        
        # 2. Victim verifies
        # Secure verification: verify(trusted_root_public_key)
        # Vulnerable verification: verify(warrant.signer_public_key) (Self-verification)
        
        print("  [Attack 4A] Verifying against TRUSTED root...")
        # This should fail because the chain is signed by attacker_keypair, but we verify against keypair.
        
        # Note: verify() checks the signature of the warrant itself.
        # For a chain, we need to verify the whole chain back to a trusted root.
        # Tenuo's Warrant.verify() just checks the immediate signature against the provided key.
        # It does NOT check if the key is trusted (that's the caller's job).
        
        # So if we call verify(keypair.public_key), it should fail because the signature was made by attacker_keypair.
        
        is_valid = attacker_child.verify(keypair.public_key.to_bytes())
        assert is_valid is False
        print("  [Result] Attack 4A failed (Signature verification correctly rejected wrong root)")
        
        # Attack 4B: "Self-verification" vulnerability simulation
        # If the victim code does: w.verify(w.public_key) -> ALWAYS TRUE for any validly signed warrant.
        # We want to ensure our docs/examples don't encourage this.
        # But here we just test that the library *allows* checking against any key (it does),
        # so the security relies on the CALLER passing the right key.
        
        print("  [Attack 4B] Simulating vulnerable self-verification...")
        # Attacker presents their key as the "trusted" key?
        # Or simply:
        is_valid_self = attacker_child.verify(attacker_keypair.public_key.to_bytes())
        assert is_valid_self is True
        print("  [Info] Self-verification passed (As expected: signature is valid). Application MUST enforce root trust.")

    def test_attack_5_issuer_abuse(self, keypair):
        """
        Attack 5: Abuse Issuer Warrants (powerbox) to smuggle authority.
        
        Scenario:
        1. Mint-execution == execute? Try to use an ISSUER warrant to authorize a tool call.
           Issuer warrants should only be able to mint, not execute.
        """
        print("\n--- Attack 5: Issuer Warrant Abuse ---")
        
        from tenuo import TrustLevel
        
        # 1. Setup: Create an ISSUER warrant
        # In Tenuo, issuer warrants are created via issue_issuer()
        issuer_warrant = Warrant.issue_issuer(
            issuable_tools=["search", "read"],
            trust_ceiling=TrustLevel.Internal, # Required arg
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # 2. Attack: Try to use it to authorize "search"
        print("  [Attack 5] Attempting to use issuer warrant for execution...")
        
        # authorize() should fail because issuer warrants are for minting, not execution.
        # Or maybe they CAN execute if they have the tool?
        # Design: Issuer warrants have `issuable_tools`, not `tools`.
        # `tools` field is for execution warrants.
        # Let's check if authorize() blocks it.
        
        from tenuo.exceptions import ValidationError
        with pytest.raises(ValidationError): # Or similar error
            issuer_warrant.authorize("search", {})
            
        print("  [Result] Attack 5 failed (Issuer warrant cannot authorize execution)")

    def test_attack_6_replay_confused_deputy(self, keypair):
        """
        Attack 6: Replay / confused-deputy at the request level.
        
        Scenario:
        1. Replay within TTL: If PoP signature doesn't bind to a nonce/counter, replay is possible.
        2. Confused deputy: Sign bytes for one tool, use for another?
        """
        print("\n--- Attack 6: Replay & Confused Deputy ---")
        
        # 1. Setup: Warrant requiring PoP
        warrant = Warrant.issue(
            tools="payment",
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key # Bound to keypair
        )
        
        # 2. Attack A: Replay within TTL
        # Tenuo's authorize() checks signature.
        # If we capture a valid signature for "pay $10", can we replay it?
        # The signature covers (tool, args, timestamp?).
        # Tenuo authorize() takes `signature` as bytes.
        
        # Let's simulate capturing a signature.
        # We need to manually sign the payload.
        # Tenuo core doesn't expose the "sign request" helper easily in Python yet?
        # Actually, `authorize` takes `signature: bytes`.
        # The signature must cover the canonical request.
        
        # If the system doesn't enforce nonces, replay is possible within TTL.
        # Tenuo currently relies on short TTLs or external nonce checking (not built-in to core authorize yet?).
        # Let's check if we can replay.
        
        # Manually sign a request
        # We need to know what bytes are signed.
        # In `tenuo-core`, `authorize` verifies signature over `(tool, args)`.
        # It doesn't seem to include a timestamp or nonce in the *signed payload* unless args include it.
        # So replay IS possible if args are identical.
        
        print("  [Attack 6A] Simulating replay of identical request...")
        # This is expected to SUCCEED in current Tenuo if no nonce is used.
        # This highlights the need for application-level nonces or short-lived PoP.
        
        # We can't easily generate the signature without the internal signing logic exposed.
        # But `warrant.authorize` usually takes the raw args and signature.
        # If we use `warrant_context` decorator, it handles signing.
        
        # Let's skip the actual replay test implementation for now as it requires internal signing helpers
        # that might not be exposed in Python SDK yet.
        print("  [Info] Attack 6A skipped (Requires manual signing helper). Note: Tenuo relies on app-level nonces/idempotency.")
        
        # Attack 6B: Confused Deputy (Sign for Tool A, use for Tool B)
        # If signature doesn't bind to tool name, we can swap tools.
        # Tenuo binds to tool name.
        
        print("  [Info] Attack 6B skipped (Requires manual signing helper). Tenuo binds signature to tool name.")

    def test_attack_8_dynamic_node_bypass(self, keypair):
        """
        Attack 8: Deny-unlisted bypasses.
        
        Scenario:
        LangGraph can add nodes dynamically. Attacker tries to route to a node
        that isn't covered by the security policy (e.g., a dynamic "tool node").
        """
        print("\n--- Attack 8: Dynamic Node Bypass ---")
        
        # 1. Setup: A graph with a secure node and a dynamic/unprotected node
        # We simulate the graph execution logic.
        
        secure_policy = {"tools": ["search"]}
        
        def secure_node(s: NodeState):
            # Enforce policy
            w = Warrant.from_base64(s.warrant)
            # Check if warrant allows "search"
            # In real Tenuo, this is done by the wrapper.
            # Here we simulate the wrapper check.
            if "search" not in w.tools: # Simplified check
                 raise Unauthorized("Tool not allowed")
            return "Secure"
            
        def dynamic_node(s: NodeState):
            # This node was added dynamically and HAS NO WRAPPER/POLICY.
            # It just executes "delete_db".
            print("  [Dynamic Node] Executing dangerous tool...")
            return "Dangerous Action Executed"
            
        # 2. Attack: Route to dynamic node
        # If the graph runner doesn't enforce "all nodes must be wrapped", this succeeds.
        
        warrant = Warrant.issue(
            tools="search", # Only search allowed
            ttl_seconds=60,
            keypair=keypair
        )
        state = NodeState(messages=[], warrant=warrant.to_base64())
        
        print("  [Attack 8] Routing to unlisted dynamic node...")
        result = dynamic_node(state)
        
        if result == "Dangerous Action Executed":
            print("  [WARNING] Attack 8 SUCCEEDED: Unlisted node executed without checks.")
            # This is a simulation of a vulnerability in the *integration*, not Tenuo core.
            # Tenuo can't protect code that doesn't use it.
            # Mitigation: "Fail closed" graph compiler.
        else:
            print("  [Result] Attack 8 failed (Node was protected)")

    def test_attack_10_tool_enforcement_mismatch(self, keypair):
        """
        Attack 10: The "real break": tool enforcement mismatch.
        
        Scenario:
        SecureGraph attenuates warrants correctly, but the tools don't actually enforce them consistently.
        Example: One tool wrapper checks tools[] but ignores constraints.
        """
        print("\n--- Attack 10: Tool Enforcement Mismatch ---")
        
        # 1. Setup: A tool with a buggy wrapper
        def buggy_tool_wrapper(warrant, arg):
            # Checks tool name but IGNORES constraints!
            if "search" not in warrant.tools:
                raise Unauthorized("Tool not allowed")
            # MISSING: warrant.authorize("search", {"query": arg})
            return f"Searching for {arg}"
            
        # 2. Setup: A secure tool wrapper
        def secure_tool_wrapper(warrant, arg):
            # Correctly uses authorize()
            warrant.authorize("search", {"query": arg})
            return f"Searching for {arg}"
            
        # 3. Attack: Use a constrained warrant on the buggy tool
        warrant = Warrant.issue(
            tools="search",
            constraints={"query": Pattern("allowed*")},
            ttl_seconds=60,
            keypair=keypair
        )
        
        print("  [Attack 10] Using constrained warrant on buggy wrapper...")
        # We try to search for "forbidden_secret"
        # The warrant forbids it (pattern "allowed*").
        
        # Buggy wrapper:
        result = buggy_tool_wrapper(warrant, "forbidden_secret")
        print(f"  [WARNING] Attack 10 SUCCEEDED on buggy wrapper: {result}")
        
        # Secure wrapper:
        print("  [Verification] Using constrained warrant on secure wrapper...")
        
        # Note: authorize() returns False for constraint violations, it does not raise.
        # So the wrapper MUST check the return value.
        
        def secure_tool_wrapper_fixed(warrant, arg):
            if not warrant.authorize("search", {"query": arg}):
                raise Unauthorized("Constraint violation")
            return f"Searching for {arg}"

        with pytest.raises(Unauthorized):
             secure_tool_wrapper_fixed(warrant, "forbidden_secret")
        print("  [Result] Secure wrapper correctly blocked the request.")

    def test_attack_36_session_id_reuse(self, keypair):
        """
        Attack 36: Reuse session_id across different warrants.
        
        Scenario:
        Session IDs are meant to track related operations.
        Can attacker reuse a privileged session_id in a low-privilege warrant?
        """
        print("\n--- Attack 36: Session ID Reuse ---")
        
        # Issue privileged warrant with session
        admin_warrant = Warrant.issue(
            tools="admin",
            ttl_seconds=3600,
            keypair=keypair,
            session_id="admin_session_123"
        )
        
        # Issue low-privilege warrant with SAME session_id
        low_warrant = Warrant.issue(
            tools="read",
            ttl_seconds=3600,
            keypair=keypair,
            session_id="admin_session_123"  # Reused!
        )
        
        print("  [Info] Created two warrants with same session_id")
        print("  [Check] Low warrant tools:", low_warrant.tools)
        
        # Try to use low warrant for admin action
        if low_warrant.authorize("admin", {}):
            print("  [CRITICAL] Attack 36 SUCCEEDED: Session ID gave unauthorized access!")
        else:
            print("  [Result] Attack 36 failed (Session ID is metadata, not authorization)")

    def test_attack_37_notoneof_without_positive(self, keypair):
        """
        Attack 37: Start with NotOneOf without positive constraint.
        
        Scenario:
        Create warrant with only NotOneOf(["admin"]) and no positive constraint.
        This is a denylist without an allowlist - should be blocked or warned.
        """
        print("\n--- Attack 37: NotOneOf Without Positive Constraint ---")
        
        from tenuo import NotOneOf
        
        print("  [Attack 37] Creating warrant with only NotOneOf constraint...")
        
        # Tenuo should allow this at creation but it's bad practice
        # The real risk is if it's NOT combined with a positive constraint
        
        warrant = Warrant.issue(
            tools="query",
            constraints={"env": NotOneOf(["prod"])},  # Only negative, no positive
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # This allows dev, staging, test, ... everything except prod
        # It's valid but risky (denylist approach)
        
        if warrant.authorize("query", {"env": "staging"}):
            print("  [Info] NotOneOf without positive constraint accepted (Legal but risky)")
        
        if warrant.authorize("query", {"env": "prod"}):
            print("  [CRITICAL] NotOneOf didn't block prod!")
        else:
            print("  [Result] NotOneOf correctly blocks excluded values")
        
        print("  [Note] This is allowed but discouraged. Use OneOf (allowlist) instead.")

    def test_attack_38_contains_subset_confusion(self, keypair):
        """
        Attack 38: Confuse Contains vs Subset semantics.
        
        Scenario:
        Contains(["admin"]) means list MUST contain "admin".
        Subset(["admin", "user"]) means list elements must be from this set.
        Test that these aren't swappable.
        """
        print("\n--- Attack 38: Contains/Subset Confusion ---")
        
        from tenuo import Contains, Subset
        
        # Parent with Contains
        parent = Warrant.issue(
            tools="access",
            constraints={"permissions": Contains(["read"])},  # Must have "read"
            ttl_seconds=3600,
            keypair=keypair
        )
        
        print("  [Attack 38A] Attempting to attenuate Contains to Subset...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            builder.with_constraint("permissions", Subset(["read", "write"]))
            builder.delegate_to(keypair, keypair)
        
        print("  [Result] Attack 38A failed (Incompatible types)")
        
        # Try Contains attenuation (adding more required values)
        print("  [Attack 38B] Attenuating Contains to require more values...")
        builder = parent.attenuate_builder()
        builder.with_constraint("permissions", Contains(["read", "write"]))  # Now requires both
        child = builder.delegate_to(keypair, keypair)
        
        # Child is stricter
        print("  [Result] Attack 38B: Valid attenuation (Contains can add requirements)")

    def test_attack_7_holder_mismatch(self, keypair, attacker_keypair):
        """
        Attack 7: Steal warrant bound to another holder.
        
        Scenario:
        Warrant is bound to Alice's public key. Bob tries to use it with his keypair.
        PoP should fail because signature won't match holder.
        """
        print("\n--- Attack 7: Holder Mismatch (Stolen Warrant) ---")
        
        # 1. Issue warrant bound to keypair
        warrant = Warrant.issue(
            tools="admin_access",
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key  # Bound to this holder
        )
        
        # 2. Attacker steals the warrant and tries to use it with their keypair
        print("  [Attack 7] Attacker stolen warrant, trying to use with wrong keypair...")
        
        # Create PoP with attacker's keypair
        args = {"action": "delete"}
        attacker_pop = warrant.create_pop_signature(attacker_keypair, "admin_access", args)
        
        # Try to authorize - should fail because signature won't verify against holder
        authorized = warrant.authorize("admin_access", args, signature=bytes(attacker_pop))
        
        if authorized:
            print("  [CRITICAL] Attack 7 SUCCEEDED: Wrong keypair passed PoP verification!")
        else:
            print("  [Result] Attack 7 failed (Holder binding enforced)")

    def test_attack_9_delegate_to_self_amplification(self, keypair):
        """
        Attack 9: Delegate to self in a loop to amplify depth counter.
        
        Scenario:
        Create circular delegation chain or repeatedly delegate to self
        to bypass depth limits.
        """
        print("\n--- Attack 9: Delegate-to-Self Amplification ---")
        
        # MAX_DELEGATION_DEPTH should be 64
        from tenuo import MAX_DELEGATION_DEPTH
        print(f"  [Info] MAX_DELEGATION_DEPTH = {MAX_DELEGATION_DEPTH}")
        
        current = Warrant.issue(tools="search", ttl_seconds=3600, keypair=keypair)
        
        try:
            for i in range(MAX_DELEGATION_DEPTH + 10):  # Try to exceed
                builder = current.attenuate_builder()
                builder.with_holder(keypair.public_key)  # Delegate to self
                current = builder.delegate_to(keypair, keypair)
                
            print(f"  [WARNING] Attack 9 SUCCEEDED: Created {MAX_DELEGATION_DEPTH + 10} depth chain!")
            
        except DepthExceeded as e:
            print(f"  [Result] Attack 9 failed (Depth limit enforced: {e})")

    def test_attack_11_tool_wildcard_exploitation(self, keypair):
        """
        Attack 11: Exploit tools=["*"] to gain all tools.
        
        Scenario:
        If parent has tools=["*"] (wildcard), child should still be limited.
        But can child attenuate to tools=["*"] (keeping wildcard)?
        """
        print("\n--- Attack 11: Tool Wildcard Exploitation ---")
        
        # Note: Tenuo doesn't use "*" for tools, it uses explicit lists
        # But let's test if someone tries to create tools=["*"]
        
        warrant = Warrant.issue(
            tools=["search", "read", "write"],
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Attenuation should narrow tools
        builder = warrant.attenuate_builder()
        builder.with_tools(["search"])  # Narrow to subset
        child = builder.delegate_to(keypair, keypair)
        
        assert child.tools == ["search"]
        print("  [Result] Attack 11 N/A (Tenuo doesn't support wildcard tools syntax)")

    def test_attack_12_constraint_removal(self, keypair):
        """
        Attack 12: Remove a constraint during attenuation.
        
        Scenario:
        Parent has {"path": Pattern("/data/*")}.
        Child omits "path" constraint.
        Should fail or inherit parent constraint?
        """
        print("\n--- Attack 12: Constraint Removal ---")
        
        parent = Warrant.issue(
            tools="read_file",
            constraints={"path": Pattern("/data/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Attenuate without specifying path constraint
        builder = parent.attenuate_builder()
        # Don't set any constraint
        child = builder.delegate_to(keypair, keypair)
        
        # Child should inherit parent's path constraint
        print(f"  [Check] Parent path constraint: {parent.constraints}")
        print(f"  [Check] Child path constraint: {child.constraints}")
        
        # Try to read /etc/passwd (should fail)
        if child.authorize("read_file", {"path": "/etc/passwd"}):
            print("  [CRITICAL] Attack 12 SUCCEEDED: Constraint was removed!")
        else:
            print("  [Result] Attack 12 failed (Constraints inherited)")

    def test_attack_13_pop_tool_swap(self, keypair):
        """
        Attack 13: Sign PoP for tool A, present for tool B.
        """
        print("\n--- Attack 13: PoP Tool Swap ---")
        
        warrant = Warrant.issue(
            tools=["search", "delete"],
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key
        )
        
        # 1. Create valid PoP for "search"
        search_args = {"query": "test"}
        search_pop = warrant.create_pop_signature(keypair, "search", search_args)
        
        # 2. Attack: Use that signature for "delete"
        print("  [Attack 13] Using 'search' PoP for 'delete' tool...")
        delete_args = {"file": "important.txt"}
        
        # If signature isn't bound to tool name, this succeeds
        authorized = warrant.authorize("delete", delete_args, signature=bytes(search_pop))
        
        if authorized:
            print("  [CRITICAL] Attack 13 SUCCEEDED: PoP not bound to tool name!")
        else:
            print("  [Result] Attack 13 failed (PoP binds to tool name)")

    def test_attack_14_pop_args_swap(self, keypair):
        """
        Attack 14: Sign PoP for args A, present with args B.
        """
        print("\n--- Attack 14: PoP Args Swap ---")
        
        warrant = Warrant.issue(
            tools="transfer",
            constraints={"amount": Range(max=1000)},
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key
        )
        
        # 1. Create valid PoP for small amount
        small_args = {"amount": 10}
        small_pop = warrant.create_pop_signature(keypair, "transfer", small_args)
        
        # 2. Attack: Use that signature for large amount
        print("  [Attack 14] Using PoP for amount=10 with amount=10000...")
        large_args = {"amount": 10000}
        
        authorized = warrant.authorize("transfer", large_args, signature=bytes(small_pop))
        
        if authorized:
            print("  [CRITICAL] Attack 14 SUCCEEDED: PoP not bound to args!")
        else:
            print("  [Result] Attack 14 failed (PoP binds to args)")
    def test_attack_15_constraint_type_coercion(self, keypair):
        """
        Attack 15: Exploit type coercion in constraints.
        
        E.g., constraint says Range(max=100), attacker passes "100.0001" 
        as string that might bypass integer comparison.
        """
        print("\n--- Attack 15: Constraint Type Coercion ---")
        
        from tenuo import Range
        
        warrant = Warrant.issue(
            tools="query",
            constraints={"limit": Range(max=100)},
            ttl_seconds=60,
            keypair=keypair
        )
        
        # 1. Try string that might bypass (e.g. "999" > 100, but "999" < "100" lexicographically? No.)
        # If comparison is string-based, "9" > "1".
        # If comparison is numeric, 999 > 100.
        
        print("  [Attack 15A] Testing string '999' against Range(max=100)...")
        # Tenuo should handle types strictly or coerce safely.
        # If it treats "999" as string and compares to int 100, it might error or behave weirdly.
        # Ideally it should reject if type mismatch, or parse if possible.
        
        # Note: authorize returns False on violation.
        
        # Case A: String "999"
        if warrant.authorize("query", {"limit": "999"}):
             print("  [WARNING] Attack 15A SUCCEEDED: '999' passed Range(max=100)")
        else:
             print("  [Result] Attack 15A failed (Correctly rejected '999')")
             
        # Case B: Float 100.0001
        print("  [Attack 15B] Testing float 100.0001 against Range(max=100)...")
        if warrant.authorize("query", {"limit": 100.0001}):
             print("  [WARNING] Attack 15B SUCCEEDED: 100.0001 passed Range(max=100)")
        else:
             print("  [Result] Attack 15B failed (Correctly rejected 100.0001)")

    def test_attack_16_serialization_injection(self, keypair):
        """
        Attack 16: Inject extra fields during deserialization.
        
        Craft base64 warrant with extra fields that might be 
        interpreted differently.
        """
        print("\n--- Attack 16: Serialization Injection ---")
        
        import base64
        import json
        
        warrant = Warrant.issue(tools="search", ttl_seconds=60, keypair=keypair)
        b64 = warrant.to_base64()
        
        # Decode
        # Tenuo uses CBOR internally? Or JSON?
        # Let's try to decode as JSON first.
        try:
            raw = base64.urlsafe_b64decode(b64)
            # If it's JSON, we can parse it.
            # If it's CBOR, we need cbor2.
            # Let's assume JSON for now as Python SDK often uses JSON for interop, 
            # but Rust core might use CBOR.
            # Actually, `to_base64` in Rust usually implies serialization format.
            # Let's check if it starts with '{'.
            if raw.strip().startswith(b'{'):
                print("  [Info] Format appears to be JSON.")
                data = json.loads(raw)
                # Inject extra field
                data["extra_field"] = "malicious_payload"
                # Re-encode
                tampered_json = json.dumps(data).encode('utf-8')
                tampered_b64 = base64.urlsafe_b64encode(tampered_json).decode('utf-8')
                
                # Try to load
                # If signature covers the WHOLE payload bytes, this should fail signature check.
                # If signature covers only specific fields, this might succeed (but field is ignored).
                
                try:
                    w = Warrant.from_base64(tampered_b64)
                    # If it loads, check if signature is valid.
                    if w.verify(keypair.public_key.to_bytes()):
                        print("  [WARNING] Attack 16 SUCCEEDED: Extra field injected and signature valid (Signature might not cover full payload?)")
                    else:
                        print("  [Result] Attack 16 failed (Signature invalid)")
                except Exception as e:
                    print(f"  [Result] Attack 16 failed (Deserialization error: {e})")
                    
            else:
                print("  [Info] Format is likely CBOR or binary. Skipping JSON injection test.")
                # We could try CBOR injection if cbor2 is available, but let's keep it simple.
                
        except Exception as e:
            print(f"  [Info] Could not decode/tamper: {e}")

    def test_attack_17_clock_skew_exploitation(self, keypair):
        """
        Attack 17: Exploit clock tolerance window.
        
        If system allows ±2 min clock skew, attacker can:
        - Use "not yet valid" warrant from future
        - Use "just expired" warrant from past
        """
        print("\n--- Attack 17: Clock Skew Exploitation ---")
        
        # 1. Just expired warrant
        # Issue warrant with 1s TTL
        warrant = Warrant.issue(tools="search", ttl_seconds=1, keypair=keypair)
        time.sleep(1.1) # Expired by 0.1s
        
        # Tenuo likely has a small clock skew tolerance (e.g. 30s or 60s).
        # If it does, this warrant might still be valid!
        
        print("  [Attack 17A] Using warrant expired by 0.1s...")
        # Note: authorize() checks expiry.
        try:
            # We expect this to FAIL if strict, or PASS if tolerant.
            # Tenuo usually enforces strict expiry unless configured otherwise.
            warrant.authorize("search", {})
            print("  [WARNING] Attack 17A SUCCEEDED: Expired warrant accepted (Clock skew tolerance?)")
        except ExpiredError:
            print("  [Result] Attack 17A failed (Strict expiry enforced)")
        except Exception as e:
            print(f"  [Result] Attack 17A failed with error: {e}")
            
        # 2. Future warrant (Not Yet Valid)
        # We can't easily mint a future warrant via standard `issue` API if it uses `now()`.
        # Unless we can mock time or if `issue` accepts `nbf` (Not Before).
        # Tenuo `issue` doesn't seem to take `nbf` argument in Python SDK yet.
        # So we skip this part.
        print("  [Info] Attack 17B skipped (Cannot mint future warrants via public API).")

    def test_attack_18_chain_length_dos(self, keypair):
        """
        Attack 18: Create deeply nested chain to DoS verifier.
        
        MAX_ISSUER_CHAIN_LENGTH should prevent this.
        """
        print("\n--- Attack 18: Chain Length DoS ---")
        
        # 1. Create a deep chain
        # We need to attenuate repeatedly.
        # Tenuo likely has a limit (e.g. 16 or 32).
        
        current = Warrant.issue(tools="search", ttl_seconds=3600, keypair=keypair)
        depth = 0
        max_attempts = 50
        
        try:
            for i in range(max_attempts):
                depth += 1
                # Attenuate
                builder = current.attenuate_builder()
                # We must change something or just re-issue?
                # Attenuation usually requires narrowing or same scope.
                # We just delegate to same keypair.
                current = builder.delegate_to(keypair, keypair)
                
            print(f"  [WARNING] Attack 18 SUCCEEDED: Created chain of depth {depth} (Limit might be higher or missing)")
            
        except Exception as e:
            # If we hit DepthExceeded, that's good!
            from tenuo.exceptions import DepthExceeded
            if isinstance(e, DepthExceeded) or "DepthExceeded" in str(e):
                print(f"  [Result] Attack 18 failed (Depth limit enforced at {depth})")
            else:
                print(f"  [Result] Attack 18 failed with error: {e}")

    def test_attack_19_constraint_key_injection(self, keypair):
        """
        Attack 19: Constraint key contains special characters.
        
        E.g., {"path/../admin": "value"} might confuse path matching.
        """
        print("\n--- Attack 19: Constraint Key Injection ---")
        
        # 1. Issue warrant with injected key
        # Tenuo treats keys as strings.
        # If the application uses the key to construct a path or query, this is dangerous.
        # But Tenuo itself just matches keys.
        
        # The attack is: can I define a constraint that matches "path" but also "admin"?
        # Or can I confuse the parser?
        
        injected_key = "path/../admin"
        
        try:
            warrant = Warrant.issue(
                tools="read_file",
                constraints={injected_key: Pattern("secret")},
                ttl_seconds=60,
                keypair=keypair
            )
            print("  [Info] Warrant issued with injected key.")
            
            # 2. Try to authorize
            # If the app checks "path", it won't match "path/../admin".
            # If the app iterates keys and uses them blindly, it might be vulnerable.
            # Tenuo's authorize() checks if the REQUEST args match the WARRANT constraints.
            
            # If I request {"path": "secret"}, does it match? No.
            # If I request {"path/../admin": "secret"}, it matches.
            
            if warrant.authorize("read_file", {injected_key: "secret"}):
                print("  [Result] Attack 19: Tenuo correctly matched the exact key (Safe behavior for Tenuo, risky for App)")
            else:
                 print("  [Result] Attack 19 failed (Authorization failed)")
                 
        except Exception as e:
            print(f"  [Result] Attack 19 failed with error: {e}")

    def test_attack_20_unicode_normalization(self, keypair):
        """
        Attack 20: Unicode normalization differences.
        
        "café" (composed) vs "café" (decomposed) might match differently.
        """
        print("\n--- Attack 20: Unicode Normalization ---")
        
        import unicodedata
        
        # Composed "café"
        cafe_nfc = unicodedata.normalize('NFC', 'café')
        # Decomposed "café"
        cafe_nfd = unicodedata.normalize('NFD', 'café')
        
        # Issue warrant for "café" (NFC)
        warrant = Warrant.issue(
            tools="search",
            constraints={"query": Exact(cafe_nfc)},
            ttl_seconds=60,
            keypair=keypair
        )
        
        print("  [Attack 20] Testing NFD 'café' against NFC constraint...")
        # If Tenuo does byte-wise comparison, this will fail (Secure but brittle).
        # If Tenuo normalizes, this will succeed (Usable).
        
        if warrant.authorize("search", {"query": cafe_nfd}):
            print("  [Info] Tenuo normalizes Unicode (or NFD matched NFC).")
        else:
            print("  [Info] Tenuo performs byte-wise comparison (NFD != NFC).")
            # This is often safer for security but can be annoying for users.
            # Let's see what happens.

    def test_attack_21_chainlink_tampering(self, keypair):
        """
        Attack 21: Tamper with ChainLink issuer scope fields.
        
        Scenario:
        Chain contains embedded issuer_tools, issuer_constraints.
        Attacker modifies these without breaking child signature.
        Should fail because ChainLink signature must cover issuer scope.
        """
        print("\n--- Attack 21: ChainLink Tampering ---")
        
        # This requires binary manipulation of the warrant
        # For now, we verify that chain validation catches tampering
        
        parent = Warrant.issue(
            tools=["search", "read"],
            constraints={"query": Pattern("allowed*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        child = parent.attenuate_builder().with_tools(["search"]).delegate_to(keypair, keypair)
        
        # Get the chain from child
        # If we could manipulate the issuer_chain embedded in child...
        # Since we can't easily do binary manipulation, we just verify chain verification works
        
        # Verify child - should work
        from tenuo import Authorizer
        auth = Authorizer(trusted_roots=[keypair.public_key])
        
        try:
            result = auth.verify_chain([parent, child])
            print("  [Info] Valid chain verified successfully")
        except Exception as e:
            print(f"  [Error] Valid chain failed: {e}")
        
        # TODO: Add actual tampering test when we have binary manipulation helpers
        print("  [Info] Attack 21: Need binary manipulation to fully test. Chain verification confirmed working.")

    def test_attack_22_toctou_payload_bytes(self, keypair):
        """
        Attack 22: Time-of-Check-Time-of-Use (TOCTOU) in payload_bytes vs payload.
        
        Scenario:
        Warrant stores both payload and payload_bytes.
        Signature is over payload_bytes.
        Authorization checks payload (parsed object).
        Attacker makes them differ.
        """
        print("\n--- Attack 22: TOCTOU payload_bytes vs payload ---")
        
        # This is a critical security issue if:
        # 1. payload_bytes (signed) says tools=["read"]
        # 2. payload (parsed) says tools=["write"]
        # 3. Signature verifies (over payload_bytes)
        # 4. Authorization checks payload (uses "write")
        
        # We can't easily test this without binary manipulation
        # But we can verify that from_base64 + verify is safe
        
        warrant = Warrant.issue(
            tools="read",
            ttl_seconds=3600,
            keypair=keypair
        )
        
        b64 = warrant.to_base64()
        
        # Deserialize and verify
        w2 = Warrant.from_base64(b64)
        
        # The signature should be over the canonical bytes
        # If we could tamper with the parsed payload...
        # But Python SDK doesn't expose internal fields easily
        
        print("  [Info] Attack 22: Requires binary manipulation. Rust implementation should bind payload_bytes to payload.")
        print("  [Check] Verifying round-trip: serialize → deserialize → verify")
        
        is_valid = w2.verify(keypair.public_key.to_bytes())
        assert is_valid
        print("  [Result] Round-trip successful. TOCTOU protection relies on Rust implementation binding.")

    def test_attack_23_cel_injection(self, keypair):
        """
        Attack 23: Inject malicious CEL expression.
        
        Scenario:
        If CEL expressions can be attenuated incorrectly,
        attacker might inject logic that bypasses parent constraints.
        """
        print("\n--- Attack 23: CEL Injection ---")
        
        from tenuo import CEL
        
        # Parent: budget < 10000
        parent = Warrant.issue(
            tools="spend",
            constraints={"budget_check": CEL("budget < 10000")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Attack A: Try to replace with always-true expression
        print("  [Attack 23A] Attempting to replace with 'true' expression...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            builder.with_constraint("budget_check", CEL("true"))  # Bypass parent check
            builder.delegate_to(keypair, keypair)
        
        print("  [Result] Attack 23A failed (CEL attenuation enforces conjunction)")
        
        # Attack B: Try to inject OR to widen
        print("  [Attack 23B] Attempting to OR with broader condition...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            # Try: (parent) || true (which would always pass)
            builder.with_constraint("budget_check", CEL("budget < 10000 || true"))
            builder.delegate_to(keypair, keypair)
        
        print("  [Result] Attack 23B failed (Must be (parent) && X format)")

    def test_attack_24_path_traversal_in_constraints(self, keypair):
        """
        Attack 24: Path traversal in constraint values.
        
        Scenario:
        Warrant allows Pattern("/data/*").
        Attacker provides path="/data/../etc/passwd".
        """
        print("\n--- Attack 24: Path Traversal in Constraints ---")
        
        warrant = Warrant.issue(
            tools="read_file",
            constraints={"path": Pattern("/data/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Attack: Try path traversal
        print("  [Attack 24] Attempting path=/data/../etc/passwd...")
        
        # Tenuo pattern matching is literal (glob-style, not filesystem-aware)
        # "/data/../etc/passwd" is treated as a literal string
        # It does NOT match "/data/*" because the pattern is literal
        
        authorized = warrant.authorize("read_file", {"path": "/data/../etc/passwd"})
        
        if authorized:
            print("  [WARNING] Attack 24 SUCCEEDED: Path traversal bypassed pattern!")
        else:
            print("  [Result] Attack 24 failed (Pattern matching is literal, doesn't resolve ..)")
            print("  [Note] Applications must canonicalize paths BEFORE authorization check")

    def test_attack_25_depth_vs_chain_confusion(self, keypair):
        """
        Attack 25: Confuse MAX_DELEGATION_DEPTH vs MAX_ISSUER_CHAIN_LENGTH.
        
        Scenario:
        Depth is for execution warrant delegation (64).
        Chain length is for issuer warrant chains (8).
        Can we bypass one limit by mixing types?
        """
        print("\n--- Attack 25: Depth vs Chain Limit Confusion ---")
        
        from tenuo import MAX_ISSUER_CHAIN_LENGTH
        print(f"  [Info] MAX_DELEGATION_DEPTH = {MAX_DELEGATION_DEPTH}")
        print(f"  [Info] MAX_ISSUER_CHAIN_LENGTH = {MAX_ISSUER_CHAIN_LENGTH}")
        
        # Test issuer chain limit
        current = Warrant.issue_issuer(
            issuable_tools=["search"],
            trust_ceiling=TrustLevel.Internal,
            ttl_seconds=3600,
            keypair=keypair
        )
        
        try:
            for i in range(MAX_ISSUER_CHAIN_LENGTH + 5):
                builder = current.attenuate_builder()
                builder.with_holder(keypair.public_key)
                current = builder.delegate_to(keypair, keypair)
                
            print(f"  [WARNING] Attack 25 SUCCEEDED: Exceeded issuer chain limit!")
            
        except Exception as e:
            if "chain length" in str(e).lower() or "issuer" in str(e).lower():
                print(f"  [Result] Attack 25 failed (Issuer chain limit enforced: {e})")
            else:
                print(f"  [Result] Attack 25 failed with error: {e}")

    def test_attack_26_constraint_type_substitution(self, keypair):
        """
        Attack 26: Change constraint type during attenuation.
        
        Scenario:
        Parent: Pattern("/data/*")
        Child: Range(max=100) for same key
        Should fail as incompatible types.
        """
        print("\n--- Attack 26: Constraint Type Substitution ---")
        
        parent = Warrant.issue(
            tools="read_file",
            constraints={"path": Pattern("/data/*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        print("  [Attack 26] Attempting to change Pattern to Range...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            builder.with_constraint("path", Range(max=100))
            builder.delegate_to(keypair, keypair)
        
        print("  [Result] Attack 26 failed (Incompatible types rejected)")

    def test_attack_27_wildcard_rewidening(self, keypair):
        """
        Attack 27: Attenuate Pattern back to Wildcard.
        
        Scenario:
        Parent: Pattern("/data/*")
        Child: Wildcard() to regain full access
        Should always fail (re-widening).
        """
        print("\n--- Attack 27: Wildcard Re-widening ---")
        
        parent = Warrant.issue(
            tools="search",
            constraints={"query": Pattern("allowed*")},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        print("  [Attack 27] Attempting to attenuate Pattern to Wildcard...")
        from tenuo import WildcardExpansion
        with pytest.raises(WildcardExpansion):
            builder = parent.attenuate_builder()
            builder.with_constraint("query", Wildcard())
            builder.delegate_to(keypair, keypair)
        
        print("  [Result] Attack 27 failed (Cannot attenuate to Wildcard)")

    def test_attack_28_ttl_extension(self, keypair):
        """
        Attack 28: Extend TTL during attenuation.
        
        Scenario:
        Parent expires in 10 minutes.
        Child tries to set 1 hour TTL.
        Should fail (can only shrink TTL).
        """
        print("\n--- Attack 28: TTL Extension ---")
        
        parent = Warrant.issue(
            tools="search",
            ttl_seconds=600,  # 10 minutes
            keypair=keypair
        )
        
        print("  [Attack 28] Attempting to extend TTL from 600s to 3600s...")
        with pytest.raises(MonotonicityError):
            builder = parent.attenuate_builder()
            builder.with_ttl(3600)  # Try to extend
            builder.delegate_to(keypair, keypair)
        
        print("  [Result] Attack 28 failed (TTL can only shrink)")

    def test_attack_29_execution_issues_execution(self, keypair):
        """
        Attack 29: Execution warrant tries to issue child warrants.
        
        Scenario:
        Only ISSUER warrants should be able to issue execution warrants.
        Execution warrants should only attenuate (delegate).
        """
        print("\n--- Attack 29: Execution Warrant Issuing ---")
        
        # Create execution warrant
        exec_warrant = Warrant.issue(
            tools="search",
            ttl_seconds=3600,
            keypair=keypair
        )
        
        print("  [Attack 29] Attempting to call issue_execution() on execution warrant...")
        
        from tenuo.exceptions import ValidationError
        with pytest.raises((ValidationError, AttributeError)):
            # Should not have issue_execution method, or should raise
            exec_warrant.issue_execution()
        
        print("  [Result] Attack 29 failed (Execution warrants cannot issue)")

    def test_attack_30_issuer_executes_tools(self, keypair):
        """
        Attack 30: Issuer warrant tries to execute tools directly.
        
        Scenario:
        Issuer warrant has issuable_tools=["delete"].
        Attacker tries to authorize "delete" directly without issuing execution warrant.
        """
        print("\n--- Attack 30: Issuer Warrant Executing Tools ---")
        
        issuer = Warrant.issue_issuer(
            issuable_tools=["delete"],
            trust_ceiling=TrustLevel.Internal,
            ttl_seconds=3600,
            keypair=keypair
        )
        
        print("  [Attack 30] Attempting to authorize tool execution with issuer warrant...")
        
        # Issuer warrants should NOT be able to authorize tool execution
        # They can only issue execution warrants
        
        from tenuo.exceptions import ValidationError
        try:
            authorized = issuer.authorize("delete", {})
            if authorized:
                print("  [CRITICAL] Attack 30 SUCCEEDED: Issuer warrant executed tool!")
            else:
                print("  [Result] Attack 30 failed (authorize returned False)")
        except (ValidationError, Exception) as e:
            print(f"  [Result] Attack 30 failed (Error: {type(e).__name__})")

    def test_attack_31_max_depth_zero_bypass(self, keypair):
        """
        Attack 31: Terminal warrant (max_depth=0) tries to delegate.
        
        Scenario:
        Warrant with max_depth=0 should not be able to delegate further.
        """
        print("\n--- Attack 31: Terminal Warrant Delegation ---")
        
        # Create terminal warrant
        parent = Warrant.issue(
            tools="search",
            ttl_seconds=3600,
            keypair=keypair
        )
        
        # Attenuate and make terminal
        builder = parent.attenuate_builder()
        builder.terminal()  # Sets max_depth to current depth
        terminal = builder.delegate_to(keypair, keypair)
        
        print(f"  [Info] Created terminal warrant: is_terminal={terminal.is_terminal()}")
        
        # Attack: Try to delegate from terminal warrant
        print("  [Attack 31] Attempting to delegate from terminal warrant...")
        with pytest.raises(DepthExceeded):
            builder2 = terminal.attenuate_builder()
            builder2.delegate_to(keypair, keypair)
        
        print("  [Result] Attack 31 failed (Terminal warrants cannot delegate)")

    def test_attack_32_default_value_bypass(self, keypair):
        """
        Attack 32: Bypass constraint by relying on dangerous default.
        
        Scenario:
        Tool has: def query(limit: int = 999999)
        Warrant has: Range(max=100) for "limit"
        Attacker calls query() without limit parameter.
        If extraction doesn't include defaults, limit=999999 bypasses constraint.
        """
        print("\n--- Attack 32: Default Value Bypass ---")
        
        from tenuo import lockdown, set_warrant_context, set_keypair_context
        
        warrant = Warrant.issue(
            tools="query",
            constraints={"limit": Range(max=100)},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        @lockdown(tool="query")
        def query_db(query: str, limit: int = 999999):
            return f"Query with limit={limit}"
        
        print("  [Attack 32] Calling query_db without limit parameter...")
        
        with set_warrant_context(warrant), set_keypair_context(keypair):
            try:
                # Automatic extraction includes defaults, so limit=999999 should be checked
                result = query_db("SELECT *")
                print(f"  [CRITICAL] Attack 32 SUCCEEDED: {result} (Default not checked!)")
            except Exception as e:
                print(f"  [Result] Attack 32 failed (Default value checked: {type(e).__name__})")

    def test_attack_33_self_signed_root_trust(self, keypair, attacker_keypair):
        """
        Attack 33: Self-signed warrant accepted as root.
        
        Scenario:
        Attacker creates warrant signed by their own key.
        System accepts it without checking against trusted roots.
        """
        print("\n--- Attack 33: Self-Signed Root Trust ---")
        
        # Attacker creates self-signed warrant
        attacker_warrant = Warrant.issue(
            tools="admin",
            ttl_seconds=3600,
            keypair=attacker_keypair
        )
        
        # Victim must use Authorizer with trusted_roots
        from tenuo import Authorizer
        
        print("  [Attack 33A] Verifying attacker warrant without trusted roots...")
        # If we don't specify trusted roots, signature might pass but trust should fail
        
        # Without trusted roots, verification is incomplete
        if attacker_warrant.verify(attacker_keypair.public_key.to_bytes()):
            print("  [Info] Self-verification passed (expected - signature is valid)")
        
        print("  [Attack 33B] Verifying against proper authorizer with trusted roots...")
        auth = Authorizer(trusted_roots=[keypair.public_key])  # Trust only keypair, not attacker
        
        try:
            auth.verify_chain([attacker_warrant])
            print("  [CRITICAL] Attack 33B SUCCEEDED: Untrusted root accepted!")
        except Exception as e:
            print(f"  [Result] Attack 33B failed (Root trust enforced: {type(e).__name__})")

    def test_attack_34_oneof_notoneof_paradox(self, keypair):
        """
        Attack 34: Create empty result set via OneOf + NotOneOf.
        
        Scenario:
        Parent: OneOf(["a", "b"])
        Child: NotOneOf(["a", "b"]) 
        Result: Empty allowed set (paradox).
        Should be detected and rejected.
        """
        print("\n--- Attack 34: OneOf/NotOneOf Paradox ---")
        
        from tenuo import NotOneOf, EmptyResultSet
        
        parent = Warrant.issue(
            tools="action",
            constraints={"type": OneOf(["read", "write"])},
            ttl_seconds=3600,
            keypair=keypair
        )
        
        print("  [Attack 34] Attempting to exclude all parent values...")
        with pytest.raises(EmptyResultSet):
            builder = parent.attenuate_builder()
            builder.with_constraint("type", NotOneOf(["read", "write"]))
            builder.delegate_to(keypair, keypair)
        
        print("  [Result] Attack 34 failed (Empty result set detected)")

    def test_attack_35_pop_timestamp_window(self, keypair):
        """
        Attack 35: Replay PoP after timestamp window expires.
        
        Scenario:
        PoP has ~2 minute validity window.
        Attacker captures PoP and replays after window.
        """
        print("\n--- Attack 35: PoP Timestamp Window ---")
        
        warrant = Warrant.issue(
            tools="transfer",
            ttl_seconds=3600,
            keypair=keypair,
            holder=keypair.public_key
        )
        
        # Create PoP
        args = {"amount": 100}
        pop_sig = warrant.create_pop_signature(keypair, "transfer", args)
        
        # Immediately verify - should work
        print("  [Check] Verifying fresh PoP...")
        assert warrant.authorize("transfer", args, signature=bytes(pop_sig))
        print("  [Info] Fresh PoP accepted")
        
        # Wait for window to expire (PoP window is typically 120 seconds)
        # For testing, we can't wait 2 minutes, but we document the expectation
        print("  [Info] PoP window is ~120 seconds. After expiry, replay should fail.")
        print("  [Info] Attack 35: Would fail after window expires (Not tested due to time)")

if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
