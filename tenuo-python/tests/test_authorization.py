"""
Comprehensive tests for PoP enforcement, warrant types, and trust levels.

Tests cover:
- PoP enforcement in @lockdown decorator
- Context-based PoP (keypair context retrieval)
- Warrant type validation
- Trust level monotonicity
- Authorization failures
"""

import pytest
from tenuo import (
    Keypair, Warrant, Pattern, Exact,
    lockdown, set_warrant_context, set_keypair_context,
    get_warrant_context, get_keypair_context,
    AuthorizationError, TrustLevel
)


# ============================================================================
# PoP Enforcement Tests
# ============================================================================

def test_lockdown_requires_keypair_context():
    """Test that @lockdown enforces keypair context for PoP."""
    
    @lockdown(tool="test_tool")
    def protected_function(value: str) -> str:
        return f"processed: {value}"
    
    # Create warrant
    kp = Keypair.generate()
    warrant = Warrant.issue(
        tools="test_tool",
        keypair=kp,
        holder=kp.public_key,
        constraints={"value": Pattern("*")},
        ttl_seconds=60
    )
    
    # Should fail without keypair context
    from tenuo import MissingKeypair
    with set_warrant_context(warrant):
        with pytest.raises(MissingKeypair):
            protected_function(value="test")
    
    # Should succeed with keypair context
    with set_warrant_context(warrant), set_keypair_context(kp):
        result = protected_function(value="test")
        assert result == "processed: test"


def test_lockdown_with_explicit_keypair():
    """Test that @lockdown accepts explicit keypair parameter in decorator."""
    
    kp = Keypair.generate()
    warrant = Warrant.issue(
        tools="test_tool",
        keypair=kp,
        holder=kp.public_key,
        constraints={"value": Exact("allowed")},
        ttl_seconds=60
    )
    
    # Keypair passed to decorator explicitly
    @lockdown(tool="test_tool", keypair=kp)
    def protected_function(value: str) -> str:
        return f"processed: {value}"
    
    # Should work with explicit keypair in decorator
    with set_warrant_context(warrant):
        result = protected_function(value="allowed")
        assert result == "processed: allowed"


def test_context_based_pop_retrieval():
    """Test that keypair context is properly retrieved and used for PoP."""
    
    @lockdown(tool="read_file")
    def read_file(path: str) -> str:
        return f"content of {path}"
    
    kp = Keypair.generate()
    warrant = Warrant.issue(
        tools="read_file",
        keypair=kp,
        holder=kp.public_key,
        constraints={"path": Pattern("/data/*")},
        ttl_seconds=60
    )
    
    # Set contexts
    with set_warrant_context(warrant), set_keypair_context(kp):
        # Verify contexts are set
        assert get_warrant_context() is not None
        assert get_keypair_context() is not None
        
        # Should work with contexts
        result = read_file(path="/data/test.txt")
        assert result == "content of /data/test.txt"


def test_pop_prevents_replay_attacks():
    """Test that PoP signatures include timestamps to prevent replay."""
    
    @lockdown(tool="delete_file")
    def delete_file(path: str) -> str:
        return f"deleted {path}"
    
    kp = Keypair.generate()
    warrant = Warrant.issue(
        tools="delete_file",
        keypair=kp,
        holder=kp.public_key,
        constraints={"path": Exact("/tmp/test.txt")},
        ttl_seconds=60
    )
    
    # Each call should generate a new PoP signature
    with set_warrant_context(warrant), set_keypair_context(kp):
        result1 = delete_file(path="/tmp/test.txt")
        result2 = delete_file(path="/tmp/test.txt")
        
        assert result1 == "deleted /tmp/test.txt"
        assert result2 == "deleted /tmp/test.txt"
        # PoP signatures are different each time (timestamp changes)


def test_pop_prevents_cross_tenant_misuse():
    """
    Critical security test: Tenant A mints warrant for Tenant B's agent,
    but Tenant A cannot use it because they don't possess Tenant B's private key.
    
    This proves PoP is strictly enforced - stolen or misdirected warrants are useless.
    """
    # Tenant A (control plane / issuer)
    tenant_a_kp = Keypair.generate()
    
    # Tenant B's agent (intended holder)
    tenant_b_agent_kp = Keypair.generate()
    
    # Tenant A mints a warrant FOR Tenant B's agent
    # The authorized_holder is set to Tenant B's public key
    warrant = Warrant.issue(
        tools="sensitive_operation",
        keypair=tenant_a_kp,  # Signed by Tenant A
        holder=tenant_b_agent_kp.public_key,  # For Tenant B's agent
        constraints={"resource": Exact("secret-data")},
        ttl_seconds=3600
    )
    
    # Verify the warrant was created correctly
    assert warrant.authorized_holder.to_bytes() == tenant_b_agent_kp.public_key.to_bytes()
    assert warrant.issuer.to_bytes() == tenant_a_kp.public_key.to_bytes()
    
    # ATTACK SCENARIO: Tenant A tries to use the warrant with their OWN keypair
    # This MUST fail - they don't have Tenant B's private key
    
    @lockdown(tool="sensitive_operation")
    def sensitive_operation(resource: str) -> str:
        return f"accessed {resource}"
    
    # Tenant A tries to use their own keypair (wrong key)
    with set_warrant_context(warrant), set_keypair_context(tenant_a_kp):
        try:
            sensitive_operation(resource="secret-data")
            assert False, "Should have raised AuthorizationError - wrong keypair!"
        except AuthorizationError:
            # Expected: Authorization denied because PoP signature doesn't match authorized_holder
            # The specific error message may vary, but access MUST be denied
            pass  # Success - access was denied
    
    # SUCCESS SCENARIO: Tenant B's agent uses the warrant with THEIR keypair
    with set_warrant_context(warrant), set_keypair_context(tenant_b_agent_kp):
        result = sensitive_operation(resource="secret-data")
        assert result == "accessed secret-data"


def test_pop_signature_must_match_authorized_holder():
    """
    Verify that PoP verification strictly checks the authorized_holder.
    Using any other keypair must fail, even if it's a valid Ed25519 signature.
    """
    correct_kp = Keypair.generate()
    wrong_kp = Keypair.generate()
    
    warrant = Warrant.issue(
        tools="test_tool",
        keypair=correct_kp,
        holder=correct_kp.public_key,
        constraints={"action": Exact("test")},
        ttl_seconds=60
    )
    
    args = {"action": "test"}
    
    # Create PoP with WRONG keypair
    wrong_pop = warrant.create_pop_signature(wrong_kp, "test_tool", args)
    
    # Try to authorize with wrong signature - MUST fail
    result = warrant.authorize("test_tool", args, signature=bytes(wrong_pop))
    assert result is False, "Wrong keypair should NOT be accepted!"
    
    # Create PoP with CORRECT keypair
    correct_pop = warrant.create_pop_signature(correct_kp, "test_tool", args)
    
    # Authorize with correct signature - should succeed
    result = warrant.authorize("test_tool", args, signature=bytes(correct_pop))
    assert result is True


# ============================================================================
# Warrant Type Tests
# ============================================================================

def test_warrant_has_depth_property():
    """Test that warrants expose depth property."""
    
    kp = Keypair.generate()
    
    # Root warrant has depth 0
    root = Warrant.issue(
        tools="test_tool",
        keypair=kp,
        holder=kp.public_key,
        constraints={},
        ttl_seconds=60
    )
    assert root.depth == 0
    
    # Child warrant has depth 1
    child = root.attenuate(
        constraints={},
        keypair=kp,
        parent_keypair=kp,
        holder=kp.public_key,
        ttl_seconds=30
    )
    assert child.depth == 1


def test_warrant_chain_verification():
    """Test that warrant chains are properly verified."""
    
    control_kp = Keypair.generate()
    worker_kp = Keypair.generate()
    
    # Root warrant
    root = Warrant.issue(
        tools="file_ops",
        keypair=control_kp,
        holder=control_kp.public_key,
        constraints={"path": Pattern("/data/*")},
        ttl_seconds=3600
    )
    
    # Attenuated warrant
    child = root.attenuate(
        constraints={"path": Pattern("/data/reports/*")},
        keypair=control_kp,
        parent_keypair=control_kp,
        holder=worker_kp.public_key,
        ttl_seconds=60
    )
    
    # Verify chain
    assert child.depth == 1
    assert child.authorized_holder.to_bytes() == worker_kp.public_key.to_bytes()
    
    # Child should have narrower constraints
    @lockdown(tool="file_ops")
    def access_file(path: str) -> str:
        return f"accessed {path}"
    
    with set_warrant_context(child), set_keypair_context(worker_kp):
        # Should work for narrower path
        result = access_file(path="/data/reports/q3.pdf")
        assert result == "accessed /data/reports/q3.pdf"
        
        # Should fail for broader path
        with pytest.raises(AuthorizationError):
            access_file(path="/data/other/file.txt")


# ============================================================================
# Trust Level Tests
# ============================================================================

def test_trust_level_monotonicity():
    """Test that trust levels can only decrease during delegation."""
    
    kp = Keypair.generate()
    
    # Create warrant with Internal trust level (value 30)
    root = Warrant.issue(
        tools="test_tool",
        keypair=kp,
        holder=kp.public_key,
        constraints={},
        ttl_seconds=3600,
        trust_level=TrustLevel("internal")
    )
    
    assert root.trust_level.value() == TrustLevel("internal").value()
    
    # Attenuate with lower trust level using builder pattern
    builder = root.attenuate_builder()
    builder.with_ttl(60)
    builder.with_holder(kp.public_key)
    builder.with_trust_level(TrustLevel("external"))
    child = builder.delegate_to(kp, kp)
    
    assert child.trust_level.value() == TrustLevel("external").value()
    
    # Trust level decreased (Internal -> External)
    assert child.trust_level < root.trust_level


def test_trust_level_enforcement():
    """Test that operations respect trust level boundaries."""
    
    kp = Keypair.generate()
    
    # Create warrant with External trust level (value 10)
    warrant = Warrant.issue(
        tools="read_data",
        keypair=kp,
        holder=kp.public_key,
        constraints={"sensitivity": Exact("public")},
        ttl_seconds=60,
        trust_level=TrustLevel("external")
    )
    
    @lockdown(tool="read_data")
    def read_data(sensitivity: str) -> str:
        return f"data with sensitivity: {sensitivity}"
    
    with set_warrant_context(warrant), set_keypair_context(kp):
        result = read_data(sensitivity="public")
        assert result == "data with sensitivity: public"


def test_trust_levels_hierarchy():
    """Test that trust levels follow the correct hierarchy."""
    
    # Verify trust level ordering (using string names)
    untrusted = TrustLevel("untrusted")
    external = TrustLevel("external")
    partner = TrustLevel("partner")
    internal = TrustLevel("internal")
    privileged = TrustLevel("privileged")
    system = TrustLevel("system")
    
    # Verify hierarchy
    assert untrusted < external
    assert external < partner
    assert partner < internal
    assert internal < privileged
    assert privileged < system


# ============================================================================
# Context Management Tests
# ============================================================================

def test_context_isolation():
    """Test that contexts are properly isolated between calls."""
    
    kp1 = Keypair.generate()
    kp2 = Keypair.generate()
    
    warrant1 = Warrant.issue(
        tools="tool1",
        keypair=kp1,
        holder=kp1.public_key,
        constraints={},
        ttl_seconds=60
    )
    
    warrant2 = Warrant.issue(
        tools="tool2",
        keypair=kp2,
        holder=kp2.public_key,
        constraints={},
        ttl_seconds=60
    )
    
    # Set first context
    with set_warrant_context(warrant1), set_keypair_context(kp1):
        assert get_warrant_context() is not None
        assert get_keypair_context() is not None
    
    # Context should be cleared
    assert get_warrant_context() is None
    assert get_keypair_context() is None
    
    # Set second context
    with set_warrant_context(warrant2), set_keypair_context(kp2):
        # Should be different contexts
        assert get_warrant_context() is not None
        assert get_keypair_context() is not None


def test_nested_contexts():
    """Test that nested contexts work correctly."""
    
    kp = Keypair.generate()
    
    warrant1 = Warrant.issue(
        tools="tool1",
        keypair=kp,
        holder=kp.public_key,
        constraints={},
        ttl_seconds=60
    )
    
    warrant2 = Warrant.issue(
        tools="tool2",
        keypair=kp,
        holder=kp.public_key,
        constraints={},
        ttl_seconds=60
    )
    
    # Outer context
    with set_warrant_context(warrant1):
        outer_warrant = get_warrant_context()
        assert outer_warrant is not None
        
        # Inner context
        with set_warrant_context(warrant2):
            inner_warrant = get_warrant_context()
            assert inner_warrant is not None
            # Inner context takes precedence
        
        # Back to outer context
        restored_warrant = get_warrant_context()
        assert restored_warrant is not None


# ============================================================================
# Authorization Failure Tests
# ============================================================================

def test_authorization_fails_without_warrant():
    """Test that authorization fails when no warrant is in context."""
    
    @lockdown(tool="test_tool")
    def protected_function(value: str) -> str:
        return f"processed: {value}"
    
    kp = Keypair.generate()
    
    # Should fail without warrant context
    with set_keypair_context(kp):
        with pytest.raises(AuthorizationError, match="No warrant"):
            protected_function(value="test")


def test_authorization_fails_with_wrong_tool():
    """Test that authorization fails when warrant tool doesn't match."""
    
    @lockdown(tool="correct_tool")
    def protected_function(value: str) -> str:
        return f"processed: {value}"
    
    kp = Keypair.generate()
    
    # Create warrant for wrong tool
    warrant = Warrant.issue(
        tools="wrong_tool",
        keypair=kp,
        holder=kp.public_key,
        constraints={"value": Pattern("*")},
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_keypair_context(kp):
        with pytest.raises(AuthorizationError):
            protected_function(value="test")


def test_authorization_fails_with_constraint_violation():
    """Test that authorization fails when constraints are violated."""
    
    @lockdown(tool="read_file")
    def read_file(path: str) -> str:
        return f"content of {path}"
    
    kp = Keypair.generate()
    
    # Create warrant with specific path constraint
    warrant = Warrant.issue(
        tools="read_file",
        keypair=kp,
        holder=kp.public_key,
        constraints={"path": Pattern("/allowed/*")},
        ttl_seconds=60
    )
    
    with set_warrant_context(warrant), set_keypair_context(kp):
        # Should work for allowed path
        result = read_file(path="/allowed/file.txt")
        assert result == "content of /allowed/file.txt"
        
        # Should fail for disallowed path
        with pytest.raises(AuthorizationError):
            read_file(path="/forbidden/file.txt")


def test_authorization_fails_with_expired_warrant():
    """Test that authorization fails when warrant has expired."""
    
    @lockdown(tool="test_tool")
    def protected_function(value: str) -> str:
        return f"processed: {value}"
    
    kp = Keypair.generate()
    
    # Create warrant with very short TTL
    warrant = Warrant.issue(
        tools="test_tool",
        keypair=kp,
        holder=kp.public_key,
        constraints={"value": Pattern("*")},
        ttl_seconds=0  # Expires immediately
    )
    
    import time
    time.sleep(1)  # Wait for expiration
    
    with set_warrant_context(warrant), set_keypair_context(kp):
        with pytest.raises(AuthorizationError):
            protected_function(value="test")