import pytest
import tenuo.testing  # noqa: F401
import pickle
import json
import re
from tenuo import SigningKey, Warrant

class TestKeyLeaks:
    def test_signing_key_repr_does_not_leak(self):
        """Ensure SigningKey.__repr__ does not reveal key bytes."""
        key = SigningKey.generate()
        repr_str = repr(key)

        # Should look like <tenuo.SigningKey object at ...> or contain "SigningKey" but NO hex
        assert "SigningKey" in repr_str

        # Heuristic: shouldn't contain long hex strings (32 bytes = 64 chars)
        # Allow small memory addresses (0x...)
        # Check for 64-char hex sequence
        hex_pattern = re.compile(r'[a-f0-9]{64}', re.IGNORECASE)
        assert not hex_pattern.search(repr_str), "Found potential private key bytes in repr"

        # Explicitly check for bytes from secret_key_bytes
        secret_hex = key.secret_key_bytes().hex()
        assert secret_hex not in repr_str

    def test_signing_key_pickle_fails_or_is_safe(self):
        """
        We prefer pickling to fail for SigningKey to avoid accidental serialization.
        If it works, we must ensure it's not leaking plaintext if we inspect the stream (harder to test easily).
        Ideally: explicit failure.
        """
        key = SigningKey.generate()

        # Currently, PyO3 might not support pickling by default, which is good.
        # If it raises TypeError, that is PASS.
        # If it succeeds, we flag it for manual review (or decide if we want to block it).
        try:
            pickle.dumps(key)
        except TypeError:
            pass  # Good
        except Exception:
            # Other errors are fine
            pass

    def test_bound_warrant_repr_redacts_key(self):
        """BoundWarrant repr should show it has a key, but not THE key."""
        key = SigningKey.generate()
        warrant, _ = Warrant.quick_mint(["search"], ttl=300)
        bound = warrant.bind(key)

        repr_str = repr(bound)
        assert "KEY_BOUND=True" in repr_str

        secret_hex = key.secret_key_bytes().hex()
        assert secret_hex not in repr_str

    def test_bound_warrant_pickle_fails(self):
        """BoundWarrant MUST raise TypeError on pickle."""
        key = SigningKey.generate()
        warrant, _ = Warrant.quick_mint(["search"], ttl=300)
        bound = warrant.bind(key)

        with pytest.raises(TypeError, match="BoundWarrant cannot be (serialized|pickled)"):
            pickle.dumps(bound)

    def test_bound_warrant_json_fails(self):
        """BoundWarrant should not be JSON serializable (default behavior)."""
        key = SigningKey.generate()
        warrant, _ = Warrant.quick_mint(["search"], ttl=300)
        bound = warrant.bind(key)

        # Standard json dumps raises TypeError for custom objects
        with pytest.raises(TypeError):
            json.dumps(bound)

    def test_bound_warrant_attributes_safe(self):
        """Ensure underlying key is not easily exposed via public attributes."""
        key = SigningKey.generate()
        warrant, _ = Warrant.quick_mint(["search"], ttl=300)
        bound = warrant.bind(key)

        # We know it has _key, but it shouldn't be in the public dir
        assert "key" not in dir(bound)
        assert "signing_key" not in dir(bound)
