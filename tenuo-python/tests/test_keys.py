"""
Tests for key management (Phase 2).

Covers:
- SigningKey.from_env()
- SigningKey.from_file()
- Keyring
- KeyRegistry
"""

import os
import base64
import tempfile
import threading
import pytest

from tenuo import (
    SigningKey,
    load_signing_key_from_env,
    load_signing_key_from_file,
    Keyring,
    KeyRegistry,
)
from tenuo.exceptions import ConfigurationError


class TestSigningKeyFromEnv:
    """Test loading keys from environment variables."""
    
    def test_from_env_base64(self, monkeypatch):
        """Load key from base64-encoded env var."""
        key = SigningKey.generate()
        key_bytes = key.secret_key_bytes()
        b64 = base64.b64encode(key_bytes).decode()
        
        monkeypatch.setenv("TEST_KEY", b64)
        loaded = SigningKey.from_env("TEST_KEY")
        
        assert loaded.public_key == key.public_key
    
    def test_from_env_hex(self, monkeypatch):
        """Load key from hex-encoded env var."""
        key = SigningKey.generate()
        key_bytes = key.secret_key_bytes()
        hex_str = key_bytes.hex()
        
        monkeypatch.setenv("TEST_KEY_HEX", hex_str)
        loaded = SigningKey.from_env("TEST_KEY_HEX")
        
        assert loaded.public_key == key.public_key
    
    def test_from_env_missing(self):
        """Missing env var raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="not set"):
            SigningKey.from_env("NONEXISTENT_KEY_12345")
    
    def test_from_env_invalid(self, monkeypatch):
        """Invalid format raises ConfigurationError."""
        monkeypatch.setenv("BAD_KEY", "not-a-valid-key")
        
        with pytest.raises(ConfigurationError, match="Invalid key format"):
            SigningKey.from_env("BAD_KEY")


class TestSigningKeyFromFile:
    """Test loading keys from files."""
    
    def test_from_file_raw_bytes(self):
        """Load key from raw 32-byte file."""
        key = SigningKey.generate()
        key_bytes = key.secret_key_bytes()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(key_bytes)
            f.flush()
            
            loaded = SigningKey.from_file(f.name)
            assert loaded.public_key == key.public_key
            
        os.unlink(f.name)
    
    def test_from_file_base64(self):
        """Load key from base64-encoded file."""
        key = SigningKey.generate()
        key_bytes = key.secret_key_bytes()
        b64 = base64.b64encode(key_bytes).decode()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as f:
            f.write(b64)
            f.flush()
            
            loaded = SigningKey.from_file(f.name)
            assert loaded.public_key == key.public_key
            
        os.unlink(f.name)
    
    def test_from_file_hex(self):
        """Load key from hex-encoded file."""
        key = SigningKey.generate()
        key_bytes = key.secret_key_bytes()
        hex_str = key_bytes.hex()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as f:
            f.write(hex_str)
            f.flush()
            
            loaded = SigningKey.from_file(f.name)
            assert loaded.public_key == key.public_key
            
        os.unlink(f.name)
    
    def test_from_file_missing(self):
        """Missing file raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="not found"):
            SigningKey.from_file("/nonexistent/path/to/key")


class TestKeyring:
    """Test Keyring for multi-key management."""
    
    def test_basic_keyring(self):
        """Basic keyring with just root key."""
        root = SigningKey.generate()
        keyring = Keyring(root=root)
        
        assert keyring.root is root
        assert keyring.previous == []
        assert len(keyring.all_keys) == 1
        assert len(keyring.all_public_keys) == 1
    
    def test_keyring_with_previous(self):
        """Keyring with previous keys for rotation."""
        root = SigningKey.generate()
        prev1 = SigningKey.generate()
        prev2 = SigningKey.generate()
        
        keyring = Keyring(root=root, previous=[prev1, prev2])
        
        assert keyring.root is root
        assert len(keyring.previous) == 2
        assert len(keyring.all_keys) == 3
        assert len(keyring.all_public_keys) == 3
        
        # Check order (root first, then previous)
        assert keyring.all_keys[0] is root
        assert keyring.all_keys[1] is prev1
        assert keyring.all_keys[2] is prev2
    
    def test_keyring_root_public_key(self):
        """Keyring provides root public key."""
        root = SigningKey.generate()
        keyring = Keyring(root=root)
        
        assert keyring.root_public_key == root.public_key
    
    def test_keyring_repr(self):
        """Keyring repr doesn't leak keys."""
        root = SigningKey.generate()
        keyring = Keyring(root=root, previous=[SigningKey.generate()])
        
        r = repr(keyring)
        assert "Keyring" in r
        assert "previous_count=1" in r
    
    def test_keyring_slots(self):
        """Keyring uses __slots__ (no __dict__)."""
        root = SigningKey.generate()
        keyring = Keyring(root=root)
        
        assert not hasattr(keyring, '__dict__')


class TestKeyRegistry:
    """Test KeyRegistry singleton."""
    
    def setup_method(self):
        """Reset registry before each test."""
        KeyRegistry.reset_instance()
    
    def teardown_method(self):
        """Clean up after each test."""
        KeyRegistry.reset_instance()
    
    def test_singleton(self):
        """get_instance() returns same instance."""
        r1 = KeyRegistry.get_instance()
        r2 = KeyRegistry.get_instance()
        
        assert r1 is r2
    
    def test_register_and_get(self):
        """Register and retrieve a key."""
        registry = KeyRegistry.get_instance()
        key = SigningKey.generate()
        
        registry.register("test", key)
        retrieved = registry.get("test")
        
        assert retrieved is key
    
    def test_get_missing_raises(self):
        """Getting missing key raises KeyError."""
        registry = KeyRegistry.get_instance()
        
        with pytest.raises(KeyError, match="not found"):
            registry.get("nonexistent")
    
    def test_has(self):
        """Check if key exists."""
        registry = KeyRegistry.get_instance()
        key = SigningKey.generate()
        
        assert not registry.has("test")
        registry.register("test", key)
        assert registry.has("test")
    
    def test_unregister(self):
        """Remove a key from registry."""
        registry = KeyRegistry.get_instance()
        key = SigningKey.generate()
        
        registry.register("test", key)
        assert registry.has("test")
        
        registry.unregister("test")
        assert not registry.has("test")
    
    def test_clear(self):
        """Clear all keys."""
        registry = KeyRegistry.get_instance()
        registry.register("a", SigningKey.generate())
        registry.register("b", SigningKey.generate())
        
        registry.clear()
        
        assert not registry.has("a")
        assert not registry.has("b")
    
    def test_namespace(self):
        """Keys are isolated by namespace."""
        registry = KeyRegistry.get_instance()
        key1 = SigningKey.generate()
        key2 = SigningKey.generate()
        
        registry.register("worker", key1, namespace="tenant_a")
        registry.register("worker", key2, namespace="tenant_b")
        
        assert registry.get("worker", namespace="tenant_a") is key1
        assert registry.get("worker", namespace="tenant_b") is key2
    
    def test_clear_namespace(self):
        """Clear only one namespace."""
        registry = KeyRegistry.get_instance()
        registry.register("key", SigningKey.generate(), namespace="a")
        registry.register("key", SigningKey.generate(), namespace="b")
        
        registry.clear(namespace="a")
        
        assert not registry.has("key", namespace="a")
        assert registry.has("key", namespace="b")
    
    def test_list_keys(self):
        """List keys in a namespace."""
        registry = KeyRegistry.get_instance()
        registry.register("alpha", SigningKey.generate())
        registry.register("beta", SigningKey.generate())
        registry.register("gamma", SigningKey.generate(), namespace="other")
        
        keys = registry.list_keys()
        assert set(keys) == {"alpha", "beta"}
        
        other_keys = registry.list_keys(namespace="other")
        assert other_keys == ["gamma"]
    
    def test_get_public(self):
        """Get only public key."""
        registry = KeyRegistry.get_instance()
        key = SigningKey.generate()
        registry.register("test", key)
        
        pub = registry.get_public("test")
        assert pub == key.public_key
    
    def test_thread_safety(self):
        """Registry is thread-safe."""
        registry = KeyRegistry.get_instance()
        errors = []
        
        def register_keys(prefix: str, count: int):
            try:
                for i in range(count):
                    registry.register(f"{prefix}_{i}", SigningKey.generate())
            except Exception as e:
                errors.append(e)
        
        threads = [
            threading.Thread(target=register_keys, args=(f"t{i}", 10))
            for i in range(5)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert not errors
        # Should have 5 * 10 = 50 keys
        all_keys = registry.list_keys()
        assert len(all_keys) == 50
    
    def test_slots(self):
        """KeyRegistry instance uses __slots__ (no __dict__)."""
        registry = KeyRegistry()  # Direct instantiation for testing
        assert not hasattr(registry, '__dict__')


class TestFunctionExports:
    """Test that functions are properly exported."""
    
    def test_load_signing_key_from_env_exported(self):
        """load_signing_key_from_env is accessible from tenuo."""
        from tenuo import load_signing_key_from_env
        assert callable(load_signing_key_from_env)
    
    def test_load_signing_key_from_file_exported(self):
        """load_signing_key_from_file is accessible from tenuo."""
        from tenuo import load_signing_key_from_file
        assert callable(load_signing_key_from_file)
    
    def test_signing_key_from_env_method(self, monkeypatch):
        """SigningKey.from_env() works as class method."""
        key = SigningKey.generate()
        b64 = base64.b64encode(key.secret_key_bytes()).decode()
        monkeypatch.setenv("TEST_METHOD_KEY", b64)
        
        loaded = SigningKey.from_env("TEST_METHOD_KEY")
        assert loaded.public_key == key.public_key
    
    def test_signing_key_from_file_method(self):
        """SigningKey.from_file() works as class method."""
        key = SigningKey.generate()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(key.secret_key_bytes())
            f.flush()
            
            loaded = SigningKey.from_file(f.name)
            assert loaded.public_key == key.public_key
            
        os.unlink(f.name)

