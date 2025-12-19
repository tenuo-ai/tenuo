"""Test Issuer Warrant creation and delegation."""
from tenuo import (
    Warrant,
    SigningKey,
    TrustLevel,
    Pattern,
    set_signing_key_context,
    Constraints,
)

def test_issuer_warrant_creation():
    """Test creating an Issuer Warrant."""
    issuer_kp = SigningKey.generate()
    
    # Create an Issuer Warrant
    issuer_warrant = Warrant.issue_issuer(
        issuable_tools=["read_file", "write_file"],
        trust_ceiling=TrustLevel.Internal,
        keypair=issuer_kp,
        ttl_seconds=3600,
    )
    
    assert issuer_warrant.issuable_tools == ["read_file", "write_file"]
    assert issuer_warrant.trust_ceiling == TrustLevel.Internal
    assert issuer_warrant.tools is None
    assert issuer_warrant.capabilities is None

def test_attenuate_builder_pattern():
    """Test that attenuate() returns a builder when no args are passed."""
    kp = SigningKey.generate()
    warrant = Warrant.issue(
        keypair=kp,
        capabilities=Constraints.for_tool("read_file", {}),
        ttl_seconds=3600,
    )
    
    # Should return builder
    builder = warrant.attenuate()
    assert hasattr(builder, 'with_capability')
    assert hasattr(builder, 'delegate_to')
    
    # Should perform immediate attenuation if args passed
    child = warrant.attenuate(
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        keypair=kp,
        parent_keypair=kp,
    )
    assert isinstance(child, Warrant)
    assert child.depth == 1

def test_delegate_shortcut():
    """Test the delegate() shortcut method."""
    kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    
    # Set context for delegate() to find the keypair
    set_signing_key_context(kp)
    
    parent = Warrant.issue(
        keypair=kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        ttl_seconds=3600,
    )
    
    # Delegate using shortcut within context
    with set_signing_key_context(kp):
        child = parent.delegate(
            holder=worker_kp.public_key,
            path=Pattern("/data/reports/*")
        )
    
    assert child.depth == 1
    assert child.authorized_holder.to_bytes() == worker_kp.public_key.to_bytes()
    constraints = child.capabilities.get("read_file")
    assert constraints["path"].pattern == "/data/reports/*"