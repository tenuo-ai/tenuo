"""
Key Management for Tenuo.

This module provides:
- SigningKey loading helpers (from_env, from_file)
- Keyring for multi-key management (rotation support)
- KeyRegistry singleton for thread-safe key storage

Usage:
    # Load keys
    key = load_signing_key_from_env("MY_KEY")
    key = load_signing_key_from_file("/path/to/key")

    # Keyring for rotation
    keyring = Keyring(
        root=load_signing_key_from_env("ROOT_KEY"),
        previous=[load_signing_key_from_env("ROOT_KEY_V1")]
    )

    # Registry for LangGraph
    registry = KeyRegistry.get_instance()
    registry.register("worker", worker_key)
    key = registry.get("worker")
"""

import os
import base64
import threading
from typing import Optional, List, Dict
from pathlib import Path

from tenuo_core import SigningKey, PublicKey  # type: ignore[import-untyped]

from .exceptions import ConfigurationError


# ============================================================================
# Key Loading Helpers
# ============================================================================

def load_signing_key_from_env(name: str) -> SigningKey:
    """
    Load a SigningKey from an environment variable.

    Auto-detects format (base64 or hex).

    Args:
        name: Environment variable name

    Returns:
        SigningKey

    Raises:
        ConfigurationError: If env var missing or invalid format

    Example:
        key = load_signing_key_from_env("TENUO_ROOT_KEY")
    """
    value = os.environ.get(name)
    if not value:
        raise ConfigurationError(
            f"Environment variable '{name}' not set. "
            f"Set it to a base64 or hex-encoded signing key."
        )

    return _parse_key_string(value, source=f"env:{name}")


def load_signing_key_from_file(path: str) -> SigningKey:
    """
    Load a SigningKey from a file.

    Auto-detects format (raw bytes, base64, or hex).

    Args:
        path: Path to key file

    Returns:
        SigningKey

    Raises:
        ConfigurationError: If file missing or invalid format

    Example:
        key = load_signing_key_from_file("/run/secrets/tenuo-key")
    """
    p = Path(path)
    if not p.exists():
        raise ConfigurationError(f"Key file not found: {path}")

    try:
        # Try reading as binary first (raw 32-byte key)
        data = p.read_bytes()

        # If exactly 32 bytes, treat as raw key
        if len(data) == 32:
            return SigningKey.from_bytes(data)

        # Otherwise, try to decode as text (base64 or hex)
        text = data.decode('utf-8').strip()
        return _parse_key_string(text, source=f"file:{path}")

    except Exception as e:
        raise ConfigurationError(f"Failed to load key from {path}: {e}")


def _parse_key_string(value: str, source: str = "unknown") -> SigningKey:
    """
    Parse a key string, auto-detecting format.

    Supports:
    - Base64 (43-44 chars, may have padding)
    - Hex (64 chars)
    """
    value = value.strip()

    # Try base64 first (most common)
    if len(value) in (43, 44) or value.endswith('='):
        try:
            data = base64.b64decode(value)
            if len(data) == 32:
                return SigningKey.from_bytes(data)
        except Exception:
            pass

    # Try hex (64 hex chars = 32 bytes)
    if len(value) == 64:
        try:
            data = bytes.fromhex(value)
            if len(data) == 32:
                return SigningKey.from_bytes(data)
        except Exception:
            pass

    # Try base64 again with more lenient parsing
    try:
        # Add padding if missing
        padded = value + '=' * (4 - len(value) % 4) if len(value) % 4 else value
        data = base64.b64decode(padded)
        if len(data) == 32:
            return SigningKey.from_bytes(data)
    except Exception:
        pass

    raise ConfigurationError(
        f"Invalid key format from {source}. "
        f"Expected 32-byte key as base64 (44 chars) or hex (64 chars). "
        f"Got {len(value)} characters."
    )


# ============================================================================
# Keyring (Multi-Key Management)
# ============================================================================

class Keyring:
    """
    Manages signing keys with rotation support.

    Holds a current root key and optional previous keys for verification
    of old signatures during key rotation.

    Example:
        keyring = Keyring(
            root=load_signing_key_from_env("ROOT_KEY_V2"),
            previous=[load_signing_key_from_env("ROOT_KEY_V1")]
        )

        # Use current key for signing
        warrant = Warrant.mint(keypair=keyring.root, ...)

        # Authorizer trusts all keys
        authorizer = Authorizer(trusted_roots=keyring.all_public_keys)
    """

    __slots__ = ('_root', '_previous')

    def __init__(
        self,
        root: SigningKey,
        previous: Optional[List[SigningKey]] = None
    ):
        """
        Create a Keyring.

        Args:
            root: Current active signing key
            previous: Previous keys still valid for verification
        """
        self._root = root
        self._previous = previous or []

    @property
    def root(self) -> SigningKey:
        """Current active signing key."""
        return self._root

    @property
    def previous(self) -> List[SigningKey]:
        """Previous keys (read-only copy)."""
        return list(self._previous)

    @property
    def all_keys(self) -> List[SigningKey]:
        """All keys (root + previous)."""
        return [self._root] + self._previous

    @property
    def all_public_keys(self) -> List[PublicKey]:
        """All public keys (for Authorizer trusted_roots)."""
        return [k.public_key for k in self.all_keys]

    @property
    def root_public_key(self) -> PublicKey:
        """Root key's public key."""
        return self._root.public_key

    def __repr__(self) -> str:
        return f"<Keyring root={self._root.public_key} previous_count={len(self._previous)}>"


# ============================================================================
# KeyRegistry (Thread-Safe Singleton)
# ============================================================================

class KeyRegistry:
    """
    Thread-safe singleton registry for signing keys.

    Used by LangGraph integration to store keys outside of graph state.
    Keys are accessed by string ID, never passed through state.

    Example:
        registry = KeyRegistry.get_instance()
        registry.register("orchestrator", orchestrator_key)
        registry.register("worker", worker_key)

        # In LangGraph node
        key = registry.get("worker")
        headers = warrant.headers(key, "search", args)

    Security:
        - Keys never in graph state (not checkpointed)
        - Thread-safe (uses Lock)
        - Namespace support for multi-tenant apps
    """

    _instance: Optional["KeyRegistry"] = None
    _lock: threading.Lock = threading.Lock()

    __slots__ = ('_keys', '_instance_lock')

    def __init__(self) -> None:
        """
        Create a KeyRegistry.

        Note: Use get_instance() for the singleton.
        Direct instantiation is allowed for testing.
        """
        self._keys: Dict[str, SigningKey] = {}
        self._instance_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "KeyRegistry":
        """
        Get the global KeyRegistry singleton.

        Thread-safe with double-checked locking.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """
        Reset the singleton (for testing only).
        """
        with cls._lock:
            cls._instance = None

    def register(
        self,
        key_id: str,
        key: SigningKey,
        *,
        namespace: str = "default"
    ) -> None:
        """
        Register a key with an ID.

        Args:
            key_id: Identifier for the key
            key: The SigningKey to register
            namespace: Optional namespace for multi-tenant apps
        """
        full_id = f"{namespace}:{key_id}"
        with self._instance_lock:
            self._keys[full_id] = key

    def get(
        self,
        key_id: str,
        *,
        namespace: str = "default"
    ) -> SigningKey:
        """
        Get a key by ID.

        Args:
            key_id: Identifier for the key
            namespace: Optional namespace

        Returns:
            SigningKey

        Raises:
            KeyError: If key not found
        """
        full_id = f"{namespace}:{key_id}"
        with self._instance_lock:
            if full_id not in self._keys:
                raise KeyError(
                    f"Key '{key_id}' not found in namespace '{namespace}'. "
                    f"Register it first with registry.register('{key_id}', key)"
                )
            return self._keys[full_id]

    def get_public(
        self,
        key_id: str,
        *,
        namespace: str = "default"
    ) -> PublicKey:
        """
        Get only the public key (safe to pass around).
        """
        return self.get(key_id, namespace=namespace).public_key

    def has(
        self,
        key_id: str,
        *,
        namespace: str = "default"
    ) -> bool:
        """Check if a key is registered."""
        full_id = f"{namespace}:{key_id}"
        with self._instance_lock:
            return full_id in self._keys

    def unregister(
        self,
        key_id: str,
        *,
        namespace: str = "default"
    ) -> None:
        """Remove a key from the registry."""
        full_id = f"{namespace}:{key_id}"
        with self._instance_lock:
            self._keys.pop(full_id, None)

    def clear(self, *, namespace: Optional[str] = None) -> None:
        """
        Clear keys.

        Args:
            namespace: If provided, only clear keys in that namespace.
                      If None, clear all keys.
        """
        with self._instance_lock:
            if namespace is None:
                self._keys.clear()
            else:
                prefix = f"{namespace}:"
                self._keys = {
                    k: v for k, v in self._keys.items()
                    if not k.startswith(prefix)
                }

    def list_keys(self, *, namespace: str = "default") -> List[str]:
        """List key IDs in a namespace."""
        prefix = f"{namespace}:"
        with self._instance_lock:
            return [
                k[len(prefix):] for k in self._keys.keys()
                if k.startswith(prefix)
            ]

    def __repr__(self) -> str:
        with self._instance_lock:
            count = len(self._keys)
        return f"<KeyRegistry keys={count}>"


# ============================================================================
# PublicKey Loading Helpers
# ============================================================================

def load_public_key_from_env(name: str) -> PublicKey:
    """
    Load a PublicKey from an environment variable.

    Auto-detects format (base64, hex, or PEM).

    Args:
        name: Environment variable name

    Returns:
        PublicKey

    Raises:
        ConfigurationError: If env var missing or invalid format

    Example:
        pubkey = load_public_key_from_env("AGENT_PUBKEY")
    """
    value = os.environ.get(name)
    if not value:
        raise ConfigurationError(
            f"Environment variable '{name}' not set. "
            f"Set it to a base64, hex, or PEM-encoded public key."
        )

    return _parse_public_key_string(value, source=f"env:{name}")


def _parse_public_key_string(value: str, source: str = "unknown") -> PublicKey:
    """
    Parse a public key string, auto-detecting format.

    Supports:
    - Base64 (43-44 chars for 32 bytes)
    - Hex (64 chars for 32 bytes)
    - PEM format
    """
    value = value.strip()

    # Check for PEM format
    if value.startswith("-----BEGIN"):
        try:
            return PublicKey.from_pem(value)
        except Exception as e:
            raise ConfigurationError(f"Invalid PEM public key from {source}: {e}")

    # Try base64 first (most common for compact storage)
    if len(value) in (43, 44) or value.endswith('='):
        try:
            data = base64.b64decode(value)
            if len(data) == 32:
                return PublicKey.from_bytes(data)
        except Exception:
            pass

    # Try hex (64 hex chars = 32 bytes)
    if len(value) == 64:
        try:
            data = bytes.fromhex(value)
            if len(data) == 32:
                return PublicKey.from_bytes(data)
        except Exception:
            pass

    # Try base64 again with more lenient parsing
    try:
        padded = value + '=' * (4 - len(value) % 4) if len(value) % 4 else value
        data = base64.b64decode(padded)
        if len(data) == 32:
            return PublicKey.from_bytes(data)
    except Exception:
        pass

    raise ConfigurationError(
        f"Invalid public key format from {source}. "
        f"Expected 32-byte key as base64 (44 chars), hex (64 chars), or PEM. "
        f"Got {len(value)} characters."
    )


# ============================================================================
# Convenience: Extend SigningKey with class methods
# ============================================================================

def _signing_key_from_env(name: str) -> SigningKey:
    """Load a SigningKey from an environment variable."""
    return load_signing_key_from_env(name)


def _signing_key_from_file(path: str) -> SigningKey:
    """Load a SigningKey from a file."""
    return load_signing_key_from_file(path)


# Add class methods to SigningKey
if not hasattr(SigningKey, 'from_env'):
    SigningKey.from_env = staticmethod(_signing_key_from_env)  # type: ignore[attr-defined]

if not hasattr(SigningKey, 'from_file'):
    SigningKey.from_file = staticmethod(_signing_key_from_file)  # type: ignore[attr-defined]


# ============================================================================
# Convenience: Extend PublicKey with class methods
# ============================================================================

def _public_key_from_env(name: str) -> PublicKey:
    """Load a PublicKey from an environment variable."""
    return load_public_key_from_env(name)


# Add class methods to PublicKey
if not hasattr(PublicKey, 'from_env'):
    PublicKey.from_env = staticmethod(_public_key_from_env)  # type: ignore[attr-defined]

