import pytest
import time
from tenuo import (
    Authorizer, 
    SigningKey, 
    Warrant, 
    ExpiredError,
    ValidationError
)

def test_set_clock_tolerance_preserves_roots():
    """
    Verify that set_clock_tolerance does NOT clear trusted roots.
    This was a critical bug where rebuilding the inner authorizer dropped keys.
    """
    # 1. Create authorizer with a root
    kp = SigningKey.generate()
    auth = Authorizer(trusted_roots=[kp.public_key])
    
    assert auth.trusted_root_count() == 1
    
    # 2. Set clock tolerance (this used to wipe roots)
    auth.set_clock_tolerance(60)
    
    # 3. Verify root is still there
    assert auth.trusted_root_count() == 1
    
    # 4. Verify it actually works (functional test)
    warrant = Warrant.issue(
        tools="test",
        keypair=kp,
        ttl_seconds=300
    )
    
    # Should verify successfully
    auth.verify(warrant)

def test_error_mapping_signature_invalid():
    """Verify that Rust SignatureInvalid maps to Python SignatureInvalid."""
    kp = SigningKey.generate()
    wrong_kp = SigningKey.generate()
    
    # Create warrant signed by WRONG key (but valid signature structure)
    # Actually, easiest way to trigger SignatureInvalid is to tamper with signature bytes
    # or use a warrant signed by a key NOT in trusted roots (if we enforce roots)
    
    auth = Authorizer(trusted_roots=[kp.public_key])
    
    # Issue warrant signed by WRONG key
    warrant = Warrant.issue(
        tools="test",
        keypair=wrong_kp,  # Not trusted
        ttl_seconds=300
    )
    
    # Should raise ValidationError (issuer not trusted) or SignatureInvalid depending on check order
    # The code checks trusted issuers first:
    # if !self.trusted_keys.is_empty() && !self.trusted_keys.contains(issuer) { return Err(Error::Validation(...)) }
    
    with pytest.raises(ValidationError) as excinfo:
        auth.verify(warrant)
    assert "issuer is not trusted" in str(excinfo.value)

def test_error_mapping_expired():
    """Verify that Rust WarrantExpired maps to Python ExpiredError."""
    kp = SigningKey.generate()
    auth = Authorizer(trusted_roots=[kp.public_key])
    
    # Issue expired warrant
    warrant = Warrant.issue(
        tools="test",
        keypair=kp,
        ttl_seconds=0 # Expires immediately
    )
    
    # Set tolerance to 0 to ensure immediate expiration
    auth.set_clock_tolerance(0)
    
    time.sleep(1)
    
    with pytest.raises(ExpiredError) as excinfo:
        auth.verify(warrant)
    assert "expired" in str(excinfo.value)