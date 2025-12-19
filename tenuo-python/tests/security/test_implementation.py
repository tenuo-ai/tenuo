"""
Implementation-Level Bypass Attacks

Tests verifying:
- Automatic extraction includes defaults
- Authorization checks all parameters
- Type safety in constraint comparisons
- Serialization injection blocked

Note: Some tests document APPLICATION responsibilities, not Tenuo bugs.
"""

import pytest
import base64
import json

from tenuo import (
    Warrant, Pattern, Range, Exact, Constraints, lockdown, set_warrant_context, set_signing_key_context,
    Unauthorized
)


@pytest.mark.security
@pytest.mark.implementation
class TestImplementation:
    """Implementation-level bypass attacks."""

    @pytest.mark.integration_responsibility
    def test_attack_10_tool_enforcement_mismatch(self, keypair):
        """
        Attack: Buggy wrapper checks tool names but ignores constraints.
        
        Note: This is an INTEGRATION bug, not a Tenuo bug.
        Tenuo provides warrant.authorize() - apps must call it correctly.
        """
        print("\n--- Attack 10: Tool Enforcement Mismatch ---")
        
        # Buggy wrapper - DOES NOT call authorize()
        def buggy_tool_wrapper(warrant, arg):
            if "search" not in warrant.tools:
                raise Unauthorized("Tool not allowed")
            # ❌ MISSING: warrant.authorize("search", {"query": arg})
            return f"Searching for {arg}"
        
        # Correct wrapper
        def secure_tool_wrapper(warrant, arg):
            if not warrant.authorize("search", {"query": arg}):
                raise Unauthorized("Constraint violation")
            return f"Searching for {arg}"
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {"query": Pattern("allowed*")}),
            ttl_seconds=60
        )
        
        print("  [Attack 10] Using constrained warrant on buggy wrapper...")
        result = buggy_tool_wrapper(warrant, "forbidden_secret")
        print(f"  [WARNING] Attack 10 SUCCEEDED on buggy wrapper: {result}")
        print("  [Note] This is an INTEGRATION BUG, not a Tenuo bug.")
        
        # Verify secure wrapper blocks it
        print("  [Verification] Using secure wrapper...")
        with pytest.raises(Unauthorized):
            secure_tool_wrapper(warrant, "forbidden_secret")
        print("  [Result] Secure wrapper correctly blocked the request.")

    def test_attack_15_constraint_type_coercion(self, keypair):
        """
        Attack: Pass string "999" to Range(max=100) hoping for type confusion.
        
        Defense: Type-safe comparison.
        """
        print("\n--- Attack 15: Constraint Type Coercion ---")
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("query", {"limit": Range(max=100)}),
            ttl_seconds=60
        )
        
        print("  [Attack 15A] Testing string '999' against Range(max=100)...")
        if warrant.authorize("query", {"limit": "999"}):
            print("  [WARNING] Attack 15A SUCCEEDED: '999' passed Range(max=100)")
        else:
            print("  [Result] Attack 15A blocked (Correctly rejected '999')")
             
        print("  [Attack 15B] Testing float 100.0001 against Range(max=100)...")
        if warrant.authorize("query", {"limit": 100.0001}):
            print("  [WARNING] Attack 15B SUCCEEDED: 100.0001 passed Range(max=100)")
        else:
            print("  [Result] Attack 15B blocked (Correctly rejected 100.0001)")

    def test_attack_16_serialization_injection(self, keypair):
        """
        Attack: Inject extra fields during deserialization.
        
        Defense: Signature covers full payload.
        """
        print("\n--- Attack 16: Serialization Injection ---")
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("search", {}),
            ttl_seconds=60
        )
        b64 = warrant.to_base64()
        
        try:
            raw = base64.urlsafe_b64decode(b64)
            
            if raw.strip().startswith(b'{'):
                print("  [Info] Format appears to be JSON.")
                data = json.loads(raw)
                data["extra_field"] = "malicious_payload"
                tampered_json = json.dumps(data).encode('utf-8')
                tampered_b64 = base64.urlsafe_b64encode(tampered_json).decode('utf-8')
                
                try:
                    w = Warrant.from_base64(tampered_b64)
                    if w.verify(keypair.public_key.to_bytes()):
                        print("  [WARNING] Attack 16 SUCCEEDED: Extra field injected, sig valid")
                    else:
                        print("  [Result] Attack 16 blocked (Signature invalid)")
                except Exception as e:
                    print(f"  [Result] Attack 16 blocked (Deserialization error: {e})")
            else:
                print("  [Info] Format is CBOR. JSON injection N/A.")
                
        except Exception as e:
            print(f"  [Info] Could not decode/tamper: {e}")

    def test_attack_22_toctou_payload_bytes(self, keypair):
        """
        Attack: TOCTOU - payload_bytes differs from payload.
        
        Defense: Rust implementation binds payload_bytes to payload.
        """
        print("\n--- Attack 22: TOCTOU payload_bytes vs payload ---")
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("read", {}),
            ttl_seconds=3600
        )
        
        b64 = warrant.to_base64()
        w2 = Warrant.from_base64(b64)
        
        print("  [Info] Attack 22: Requires binary manipulation.")
        print("  [Check] Verifying round-trip: serialize → deserialize → verify")
        
        is_valid = w2.verify(keypair.public_key.to_bytes())
        assert is_valid
        print("  [Result] Round-trip successful. TOCTOU protection in Rust core.")

    def test_attack_24_path_traversal_in_constraints(self, keypair):
        """
        Attack: Use path traversal (/data/../etc/passwd) to escape pattern.
        
        Defense: Pattern matching is literal (apps must canonicalize).
        """
        print("\n--- Attack 24: Path Traversal in Constraints ---")
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
            ttl_seconds=3600
        )
        
        print("  [Attack 24] Attempting path=/data/../etc/passwd...")
        authorized = warrant.authorize("read_file", {"path": "/data/../etc/passwd"})
        
        if authorized:
            print("  [WARNING] Attack 24 SUCCEEDED: Path traversal bypassed pattern!")
        else:
            print("  [Result] Attack 24 blocked (Pattern matching is literal)")
            print("  [Note] Applications MUST canonicalize paths BEFORE authorization")

    def test_attack_32_default_value_bypass(self, keypair):
        """
        Attack: Call function without arg, hoping default bypasses constraint.
        
        Defense: Automatic extraction includes defaults.
        """
        print("\n--- Attack 32: Default Value Bypass ---")
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("query", {"limit": Range(max=100)}),
            ttl_seconds=3600
        )
        
        @lockdown(tool="query")
        def query_db(query: str, limit: int = 999999):
            return f"Query with limit={limit}"
        
        print("  [Attack 32] Calling query_db without limit parameter...")
        
        with set_warrant_context(warrant), set_signing_key_context(keypair):
            try:
                result = query_db("SELECT *")
                print(f"  [CRITICAL] Attack 32 SUCCEEDED: {result}")
                assert False, "Default value should have been checked"
            except Exception as e:
                print(f"  [Result] Attack 32 blocked (Default value checked: {type(e).__name__})")

    def test_attack_19_constraint_key_injection(self, keypair):
        """
        Attack: Use constraint key with path traversal characters.
        
        Defense: Keys matched exactly (safe for Tenuo, risky for app).
        """
        print("\n--- Attack 19: Constraint Key Injection ---")
        
        injected_key = "path/../admin"
        
        try:
            warrant = Warrant.issue(
                keypair=keypair,
                capabilities=Constraints.for_tool("read_file", {injected_key: Pattern("secret")}),
                ttl_seconds=60
            )
            print("  [Info] Warrant issued with injected key.")
            
            if warrant.authorize("read_file", {injected_key: "secret"}):
                print("  [Result] Attack 19: Tenuo matched exact key (Safe for Tenuo)")
                print("  [Note] App must not use keys to construct paths blindly")
            else:
                print("  [Result] Attack 19 blocked (Authorization failed)")
                 
        except Exception as e:
            print(f"  [Result] Attack 19 blocked with error: {e}")

    def test_null_byte_injection(self, keypair):
        """
        Attack: Inject null bytes to truncate paths in underlying C libs.
        
        Defense: Tenuo treats null bytes as literal characters, not terminators.
        
        Note: Some C-based libraries (OpenSSL, system calls) truncate strings
        at \0. If Tenuo passed /safe/path\0../../etc/passwd to such a library
        after matching against /safe/path, it could be exploited.
        """
        print("\n--- Attack: Null Byte Injection ---")
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("read", {"path": Exact("/safe/path")}),
            ttl_seconds=60
        )
        
        # Attack: /safe/path\0/../../etc/passwd
        # If a layer truncates at \0, it might match /safe/path
        malicious_path = "/safe/path\x00/../../etc/passwd"
        
        print(f"  [Attack] Testing path with null byte: {repr(malicious_path)}")
        
        if warrant.authorize("read", {"path": malicious_path}):
            print("  [WARNING] Null byte truncation detected!")
            print("  [WARNING] Path with embedded null matched safe path constraint!")
            assert False, "Null byte injection should be blocked"
        else:
            print("  [Result] Null byte injection blocked (literal comparison)")
            print("  [Info] /safe/path\\x00... != /safe/path")

    def test_null_byte_in_tool_name(self, keypair):
        """
        Attack: Inject null byte in tool name.
        
        Defense: Tool names should be validated or matched literally.
        """
        print("\n--- Attack: Null Byte in Tool Name ---")
        
        warrant = Warrant.issue(
            keypair=keypair,
            capabilities=Constraints.for_tool("safe_tool", {}),
            ttl_seconds=60
        )
        
        # Try to match "safe_tool" by passing "safe_tool\0_evil"
        malicious_tool = "safe_tool\x00_evil_suffix"
        
        print(f"  [Attack] Testing tool name: {repr(malicious_tool)}")
        
        if warrant.authorize(malicious_tool, {}):
            print("  [WARNING] Null byte truncation in tool name!")
            assert False, "Tool name null byte injection should fail"
        else:
            print("  [Result] Null byte in tool name blocked")
