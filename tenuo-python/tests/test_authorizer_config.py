import time

import pytest

from tenuo import (
    Authorizer,
    SigningKey,
    Warrant,
)
from tenuo.constraints import Constraints
from tenuo.exceptions import ExpiredError, SignatureInvalid, TenuoError


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
    warrant = Warrant.mint(keypair=kp, capabilities=Constraints.for_tool("test", {}), ttl_seconds=300)

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
    warrant = Warrant.mint(
        keypair=wrong_kp,  # Not trusted
        capabilities=Constraints.for_tool("test", {}),
        ttl_seconds=300,
    )

    # Should raise ValidationError (issuer not trusted) or SignatureInvalid depending on check order
    # The code checks trusted issuers first:
    # if !self.trusted_keys.is_empty() && !self.trusted_keys.contains(issuer) { return Err(Error::Validation(...)) }

    with pytest.raises(SignatureInvalid) as excinfo:
        auth.verify(warrant)
    assert "root warrant issuer not trusted" in str(excinfo.value)


def test_error_mapping_expired():
    """Verify that Rust WarrantExpired maps to Python ExpiredError."""
    kp = SigningKey.generate()
    auth = Authorizer(trusted_roots=[kp.public_key])

    # Issue warrant with a 1-second TTL
    warrant = Warrant.mint(
        keypair=kp,
        capabilities=Constraints.for_tool("test", {}),
        ttl_seconds=1,
    )

    time.sleep(2)  # Wait for expiry

    # authorize_one() performs the full check including expiry (unlike verify() which
    # only checks signature and trust). A missing PoP signature triggers MissingSignature
    # before expiry is checked, so we sign a PoP first and then check \u2014 expiry fires.
    import time as _time
    pop_sig = warrant.sign(kp, "test", {}, int(_time.time()))

    with pytest.raises(ExpiredError) as excinfo:
        auth.authorize_one(warrant, "test", {}, signature=bytes(pop_sig))
    assert "expired" in str(excinfo.value).lower()


# =============================================================================
# Authorizer.check_chain() with delegation chains
# =============================================================================

def test_check_chain_delegation():
    """check_chain verifies a delegation chain end-to-end."""
    from tenuo import Pattern

    root_kp = SigningKey.generate()
    delegator_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    auth = Authorizer(trusted_roots=[root_kp.public_key])

    root_warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(delegator_kp.public_key)
        .ttl(3600)
        .mint(root_kp)
    )

    child_warrant = (
        root_warrant.grant_builder()
        .capability("read_file", path=Pattern("/data/public/*"))
        .holder(worker_kp.public_key)
        .ttl(1800)
        .grant(delegator_kp)
    )

    pop = child_warrant.sign(worker_kp, "read_file", {"path": "/data/public/readme.txt"}, int(time.time()))
    result = auth.check_chain(
        [root_warrant, child_warrant],
        "read_file",
        {"path": "/data/public/readme.txt"},
        signature=bytes(pop),
    )
    assert result is not None
    assert result.chain_length == 2


def test_check_chain_rejects_broken_chain():
    """check_chain rejects a chain where warrants aren't linked."""
    root_kp = SigningKey.generate()
    other_kp = SigningKey.generate()
    auth = Authorizer(trusted_roots=[root_kp.public_key])

    w1 = Warrant.mint(keypair=root_kp, capabilities=Constraints.for_tool("test", {}), ttl_seconds=3600)
    w2 = Warrant.mint(keypair=other_kp, capabilities=Constraints.for_tool("test", {}), ttl_seconds=3600)

    with pytest.raises(TenuoError):
        auth.check_chain([w1, w2], "test", {})


def test_expired_parent_in_chain_rejected():
    """If a parent warrant expires, the entire chain is rejected.

    verify_chain enforces child.expires_at <= parent.expires_at (monotonicity).
    Since the child must expire before the parent, an expired parent implies
    an expired child. The leaf's expiry check in check_chain catches this.
    """
    from tenuo import Pattern

    root_kp = SigningKey.generate()
    delegator_kp = SigningKey.generate()
    worker_kp = SigningKey.generate()
    auth = Authorizer(trusted_roots=[root_kp.public_key])

    root_warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(delegator_kp.public_key)
        .ttl(1)
        .mint(root_kp)
    )

    child_warrant = (
        root_warrant.grant_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(worker_kp.public_key)
        .ttl(1)
        .grant(delegator_kp)
    )

    time.sleep(1.5)

    pop = child_warrant.sign(worker_kp, "read_file", {"path": "/data/test.txt"}, int(time.time()))
    with pytest.raises(TenuoError) as excinfo:
        auth.check_chain(
            [root_warrant, child_warrant],
            "read_file",
            {"path": "/data/test.txt"},
            signature=bytes(pop),
        )
    err = str(excinfo.value).lower()
    assert "expired" in err or "expir" in err
