
import pytest
import sys
import tenuo
print(f"DEBUG: tenuo file: {tenuo.__file__}")
from tenuo import Warrant, Keypair, Pattern, ConstraintViolation, TenuoError

def test_pattern_expanded_mapping():
    """
    Verify that a pattern expansion raises the specific PatternExpanded exception
    and not a generic RuntimeError.
    """
    # Setup
    issuer_key = Keypair.generate()
    
    # Issue a parent warrant
    parent = Warrant.issue(
        tools="search",
        constraints={"query": Pattern("allowed*")},
        ttl_seconds=60,
        keypair=issuer_key
    )
    
    # Trigger a violation by attenuating to a broader pattern
    print("\nTriggering PatternExpanded violation...")
    try:
        # "allowed*" -> "*" is an expansion (forbidden)
        # Note: We must use attenuate_builder or attenuate directly
        # Using attenuate_builder for clarity
        builder = parent.attenuate_builder()
        builder.with_constraint("query", Pattern("*"))
        builder.delegate_to(issuer_key, issuer_key)
        
        pytest.fail("Should have raised an exception")
    except Exception as e:
        print(f"Caught exception type: {type(e).__name__}")
        print(f"Message: {e}")
        
        # Check if it's the specific type
        from tenuo import PatternExpanded
        if isinstance(e, PatternExpanded):
            print("SUCCESS: Caught PatternExpanded")
            print(f"Details: {e.details}")
        elif isinstance(e, RuntimeError):
            print("FAILURE: Caught generic RuntimeError (fallback triggered)")
            pytest.fail(f"Expected PatternExpanded, got RuntimeError: {e}")
        else:
            print(f"FAILURE: Caught unexpected type {type(e).__name__}")
            pytest.fail(f"Expected PatternExpanded, got {type(e).__name__}: {e}")

if __name__ == "__main__":
    try:
        test_pattern_expanded_mapping()
        print("\nTest Passed!")
    except Exception as e:
        print(f"\nTest Failed: {e}")
        exit(1)
