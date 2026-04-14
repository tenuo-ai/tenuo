"""Key resolver implementations for Tenuo-Temporal authorization.

Resolvers fetch signing keys from secure storage (Vault, KMS, HSM, etc.)
for PoP generation and verification.
"""

from __future__ import annotations

import base64
import binascii
import logging
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from tenuo.temporal.exceptions import KeyResolutionError

logger = logging.getLogger("tenuo.temporal")


class KeyResolver(ABC):
    """Abstract interface for resolving key IDs to signing keys.

    Implementations should fetch keys from secure storage
    (Vault, KMS, HSM, etc.) and cache appropriately.

    **Implementing a custom resolver for use inside Temporal workflows:**
    The outbound workflow interceptor calls ``resolve_sync()``, not ``resolve()``,
    because it runs inside the Temporal workflow sandbox where async I/O is
    restricted.  The default ``resolve_sync()`` implementation spawns a thread
    pool executor, which may behave unexpectedly inside the sandbox.

    If you implement a custom resolver, override ``resolve_sync()`` directly
    with a synchronous implementation (e.g. read from a pre-loaded in-memory
    cache populated before the worker starts).  ``EnvKeyResolver`` does this
    via ``preload_keys()``.
    """

    @abstractmethod
    async def resolve(self, key_id: str) -> Any:  # Returns SigningKey
        """Resolve a key ID to a signing key (async).

        Args:
            key_id: The key identifier

        Returns:
            The signing key (tenuo_core.SigningKey)

        Raises:
            KeyResolutionError: If key cannot be resolved
        """
        ...

    def resolve_sync(self, key_id: str) -> Any:  # Returns SigningKey
        """Resolve a key ID to a signing key (synchronous).

        This method handles the async->sync conversion and is safe to call
        from both sync and async contexts, including from within running
        event loops (e.g., Temporal workflows).

        Default implementation:
        - If no event loop is running: creates temporary loop and runs resolve()
        - If event loop is running: spawns thread pool to run resolve() in new loop

        Subclasses can override this for more efficient sync implementations.

        Args:
            key_id: The key identifier

        Returns:
            The signing key (tenuo_core.SigningKey)

        Raises:
            KeyResolutionError: If key cannot be resolved
        """
        import asyncio
        import concurrent.futures

        try:
            asyncio.get_running_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                try:
                    return pool.submit(self._resolve_in_new_loop, key_id).result(
                        timeout=30,
                    )
                except concurrent.futures.TimeoutError:
                    raise KeyResolutionError(
                        f"Key resolution timed out after 30s for key_id={key_id!r}. "
                        "Check network connectivity to the key store."
                    )
        except RuntimeError:
            return self._resolve_in_new_loop(key_id)

    def _resolve_in_new_loop(self, key_id: str) -> Any:
        """Helper to run resolve() in a new event loop."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.resolve(key_id))
        finally:
            loop.close()


class EnvKeyResolver(KeyResolver):
    """Resolves keys from environment variables.

    For development/testing only. Do not use in production.

    Expects: TENUO_KEY_{key_id}=<base64-or-hex-encoded-key>

    Args:
        prefix: Environment variable prefix (default: "TENUO_KEY_")
        warn_in_production: Emit a WARNING log at first resolution if the
            environment does not look like a development setup (i.e.
            the ``TENUO_ENV`` env var is not ``"development"`` or
            ``"test"``).  Default: True.

    For Temporal workflows:
        Call `preload_keys()` before creating the worker to cache keys
        and avoid os.environ access inside the workflow sandbox:

            resolver = EnvKeyResolver()
            resolver.preload_keys(["agent1", "agent2"])  # Cache before workflow
    """

    _DEV_ENVS = {"development", "dev", "test", "testing", "local"}

    def __init__(self, prefix: str = "TENUO_KEY_", *, warn_in_production: bool = True) -> None:
        self._prefix = prefix
        self._warn_in_production = warn_in_production
        self._warned = False
        self._key_cache: Dict[str, Any] = {}

    def _maybe_warn(self) -> None:
        """Emit a one-time production warning if not suppressed."""
        if self._warned or not self._warn_in_production:
            return
        import os
        env = os.environ.get("TENUO_ENV", "").strip().lower()
        if env not in self._DEV_ENVS:
            logger.warning(
                "EnvKeyResolver is designed for development and testing only. "
                "In production, use VaultKeyResolver, AWSSecretsManagerKeyResolver, "
                "or GCPSecretManagerKeyResolver to fetch keys from secure storage. "
                "Set TENUO_ENV=development to suppress this warning in local environments."
            )
        self._warned = True

    @staticmethod
    def _decode_key_bytes(value: str) -> bytes:
        """Decode a key value that may be base64 or hex-encoded."""
        stripped = value.strip()

        try:
            raw = base64.b64decode(stripped, validate=True)
            if len(raw) == 32:
                return raw
        except (binascii.Error, ValueError):
            pass

        try:
            raw = bytes.fromhex(stripped)
            if len(raw) == 32:
                return raw
        except ValueError:
            pass

        # Fall back to non-strict base64 (handles values without padding)
        try:
            raw = base64.b64decode(stripped)
            if len(raw) == 32:
                return raw
        except (binascii.Error, ValueError):
            pass

        raise ValueError(
            f"Cannot decode as base64 or hex (expected 32 bytes for Ed25519). "
            f"Got {len(stripped)} characters."
        )

    def _load_key_from_env(self, key_id: str) -> Any:
        """Read ``{prefix}{key_id}`` from ``os.environ`` and build a ``SigningKey``."""
        import os

        env_name = f"{self._prefix}{key_id}"
        value = os.environ.get(env_name)
        if value is None:
            raise KeyResolutionError(key_id=key_id)

        try:
            from tenuo_core import SigningKey

            return SigningKey.from_bytes(self._decode_key_bytes(value))
        except (binascii.Error, ValueError) as e:
            logger.error(f"Failed to decode key from {env_name}: {e}")
            raise KeyResolutionError(key_id=key_id)

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from environment variable."""
        self._maybe_warn()
        return self._load_key_from_env(key_id)

    def preload_keys(self, key_ids: list[str]) -> None:
        """Pre-load specific keys from environment into the cache.

        Call this before creating the Temporal worker to avoid ``os.environ``
        access inside the workflow sandbox.

        Args:
            key_ids: List of key IDs to pre-load (e.g., ["agent1", "agent2"])

        Raises:
            KeyResolutionError: If any key cannot be loaded
        """
        for key_id in key_ids:
            self._key_cache[key_id] = self._load_key_from_env(key_id)

    def preload_all(self) -> int:
        """Scan ``os.environ`` for all ``{prefix}*`` keys and cache them.

        Called automatically by :class:`~tenuo.temporal_plugin.TenuoTemporalPlugin`
        at worker init so that ``resolve_sync()`` never touches ``os.environ``
        inside the Temporal workflow sandbox.

        Returns:
            Number of keys loaded.
        """
        import os

        loaded = 0
        for name, _value in os.environ.items():
            if name.startswith(self._prefix):
                key_id = name[len(self._prefix):]
                if key_id and key_id not in self._key_cache:
                    try:
                        self._key_cache[key_id] = self._load_key_from_env(key_id)
                        loaded += 1
                    except KeyResolutionError:
                        logger.warning("EnvKeyResolver: skipping malformed key %s", name)
        if loaded:
            logger.info("EnvKeyResolver: preloaded %d key(s) from environment", loaded)
        return loaded

    def resolve_sync(self, key_id: str) -> Any:
        """Resolve key from cache or environment variable synchronously.

        .. warning::
            Falls back to ``os.environ`` if the key isn't cached.  Inside the
            Temporal workflow sandbox this will raise.  Use :meth:`preload_all`
            or :meth:`preload_keys` before worker startup, or use
            :class:`~tenuo.temporal_plugin.TenuoTemporalPlugin` which calls
            ``preload_all()`` automatically.
        """
        if key_id in self._key_cache:
            return self._key_cache[key_id]
        self._maybe_warn()
        return self._load_key_from_env(key_id)


class VaultKeyResolver(KeyResolver):
    """Resolve keys from HashiCorp Vault.

    Production-ready key resolver using Vault's KV secrets engine.

    Args:
        url: Vault server URL (e.g. "https://vault.example.com:8200")
        mount: Secrets engine mount path (default: "secret")
        path_template: Path template with {key_id} placeholder
            (default: "tenuo/keys/{key_id}")
        token: Vault token. If None, uses VAULT_TOKEN env var.
        cache_ttl: Cache TTL in seconds (default: 300)

    Example:
        resolver = VaultKeyResolver(
            url="https://vault.company.com:8200",
            path_template="production/tenuo/{key_id}",
        )
    """

    def __init__(
        self,
        url: str,
        mount: str = "secret",
        path_template: str = "tenuo/keys/{key_id}",
        token: Optional[str] = None,
        cache_ttl: int = 300,
    ) -> None:
        self._url = url.rstrip("/")
        self._mount = mount
        self._path_template = path_template
        self._token = token
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, tuple[Any, float]] = {}
        self._cache_lock = threading.Lock()

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from Vault."""
        import os
        import time

        now = time.time()
        with self._cache_lock:
            if key_id in self._cache:
                cached_key, cached_at = self._cache[key_id]
                if now - cached_at < self._cache_ttl:
                    logger.debug(f"Vault cache hit for key: {key_id}")
                    return cached_key

        token = self._token or os.environ.get("VAULT_TOKEN")
        if not token:
            raise KeyResolutionError(key_id=key_id)

        path = self._path_template.format(key_id=key_id)

        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self._url}/v1/{self._mount}/data/{path}",
                    headers={"X-Vault-Token": token},
                    timeout=10.0,
                )

                if resp.status_code == 404:
                    raise KeyResolutionError(key_id=key_id)

                resp.raise_for_status()
                data = resp.json()

                key_b64 = data["data"]["data"]["key"]
                from tenuo_core import SigningKey

                try:
                    key_bytes = base64.b64decode(key_b64)
                    key = SigningKey.from_bytes(key_bytes)
                except (binascii.Error, ValueError) as e:
                    logger.error(f"Vault returned undecodable key for {key_id}: {e}")
                    raise KeyResolutionError(key_id=key_id)

                with self._cache_lock:
                    self._cache[key_id] = (key, now)
                logger.debug(f"Vault resolved key: {key_id}")
                return key

        except KeyResolutionError:
            raise
        except Exception as e:
            logger.error(
                "Vault key resolution failed for '%s' (network/TLS/parse error): %s",
                key_id,
                e,
                exc_info=True,
            )
            raise


class AWSSecretsManagerKeyResolver(KeyResolver):
    """Resolve keys from AWS Secrets Manager.

    Secrets Manager handles both storage and encryption (via KMS under the hood).
    Store your signing key as a binary secret.

    Args:
        secret_prefix: Prefix for secret names (default: "tenuo/keys/")
            Full secret name will be: {secret_prefix}{key_id}
        region_name: AWS region (default: uses boto3 default)
        cache_ttl: Cache TTL in seconds (default: 300)

    Example:
        resolver = AWSSecretsManagerKeyResolver(
            secret_prefix="prod/tenuo/",
            region_name="us-west-2",
        )

        # Store key in AWS CLI:
        # aws secretsmanager create-secret --name prod/tenuo/my-key-id \\
        #     --secret-binary fileb://signing_key.bin
    """

    def __init__(
        self,
        secret_prefix: str = "tenuo/keys/",
        region_name: Optional[str] = None,
        cache_ttl: int = 300,
    ) -> None:
        self._secret_prefix = secret_prefix
        self._region_name = region_name
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, tuple[Any, float]] = {}
        self._cache_lock = threading.Lock()

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from AWS Secrets Manager."""
        import asyncio
        import time

        now = time.time()
        with self._cache_lock:
            if key_id in self._cache:
                cached_key, cached_at = self._cache[key_id]
                if now - cached_at < self._cache_ttl:
                    logger.debug(f"AWS Secrets Manager cache hit for key: {key_id}")
                    return cached_key

        secret_name = f"{self._secret_prefix}{key_id}"

        try:
            import boto3  # type: ignore[import-not-found, import-untyped]

            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: boto3.client(
                    "secretsmanager", region_name=self._region_name
                ).get_secret_value(SecretId=secret_name),
            )

            if "SecretBinary" in response:
                key_bytes = response["SecretBinary"]
            elif "SecretString" in response:
                try:
                    key_bytes = base64.b64decode(response["SecretString"])
                except (binascii.Error, ValueError) as e:
                    logger.error(f"AWS Secrets Manager returned undecodable key for {key_id}: {e}")
                    raise KeyResolutionError(key_id=key_id)
            else:
                raise KeyResolutionError(key_id=key_id)

            from tenuo_core import SigningKey

            signing_key = SigningKey.from_bytes(key_bytes)

            with self._cache_lock:
                self._cache[key_id] = (signing_key, now)
            logger.debug(f"AWS Secrets Manager resolved key: {key_id}")
            return signing_key

        except ImportError:
            logger.error("boto3 not installed. Install with: pip install boto3")
            raise KeyResolutionError(key_id=key_id)
        except KeyResolutionError:
            raise
        except Exception as e:
            logger.error(
                "AWS Secrets Manager key resolution failed for '%s' "
                "(network/permissions/parse error): %s",
                key_id,
                e,
                exc_info=True,
            )
            raise


class GCPSecretManagerKeyResolver(KeyResolver):
    """Resolve keys from GCP Secret Manager.

    Secret Manager handles both storage and encryption (via Cloud KMS under the hood).
    Store your signing key as a binary secret.

    Args:
        project_id: GCP project ID
        secret_prefix: Prefix for secret names (default: "tenuo-keys-")
            Full secret name will be: {secret_prefix}{key_id}
        version: Secret version (default: "latest")
        cache_ttl: Cache TTL in seconds (default: 300)

    Example:
        resolver = GCPSecretManagerKeyResolver(
            project_id="my-project-123",
            secret_prefix="prod-tenuo-",
        )

        # Store key in gcloud CLI:
        # gcloud secrets create prod-tenuo-my-key-id --data-file=signing_key.bin
    """

    def __init__(
        self,
        project_id: str,
        secret_prefix: str = "tenuo-keys-",
        version: str = "latest",
        cache_ttl: int = 300,
    ) -> None:
        self._project_id = project_id
        self._secret_prefix = secret_prefix
        self._version = version
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, tuple[Any, float]] = {}
        self._cache_lock = threading.Lock()

    async def resolve(self, key_id: str) -> Any:
        """Resolve key from GCP Secret Manager."""
        import asyncio
        import time

        now = time.time()
        with self._cache_lock:
            if key_id in self._cache:
                cached_key, cached_at = self._cache[key_id]
                if now - cached_at < self._cache_ttl:
                    logger.debug(f"GCP Secret Manager cache hit for key: {key_id}")
                    return cached_key

        secret_name = f"{self._secret_prefix}{key_id}"
        resource_name = f"projects/{self._project_id}/secrets/{secret_name}/versions/{self._version}"

        try:
            from google.cloud import secretmanager  # type: ignore[import-not-found,import-untyped]

            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: secretmanager.SecretManagerServiceClient().access_secret_version(
                    name=resource_name
                ),
            )
            key_bytes = response.payload.data

            from tenuo_core import SigningKey

            signing_key = SigningKey.from_bytes(key_bytes)

            with self._cache_lock:
                self._cache[key_id] = (signing_key, now)
            logger.debug(f"GCP Secret Manager resolved key: {key_id}")
            return signing_key

        except ImportError:
            logger.error(
                "google-cloud-secret-manager not installed. "
                "Install with: pip install google-cloud-secret-manager"
            )
            raise KeyResolutionError(key_id=key_id)
        except KeyResolutionError:
            raise
        except Exception as e:
            logger.error(
                "GCP Secret Manager key resolution failed for '%s' "
                "(network/permissions/parse error): %s",
                key_id,
                e,
                exc_info=True,
            )
            raise


class CompositeKeyResolver(KeyResolver):
    """Try multiple resolvers in order (fallback chain).

    Useful for graceful degradation:
    - Try Vault first (production)
    - Fall back to cloud secrets manager (backup)
    - Fall back to env vars (local dev)

    Args:
        resolvers: List of resolvers to try in order

    Example:
        resolver = CompositeKeyResolver([
            VaultKeyResolver(url="https://vault.prod.internal"),
            AWSSecretsManagerKeyResolver(secret_prefix="tenuo/"),
            EnvKeyResolver(),  # Fallback for local dev
        ])
    """

    def __init__(
        self,
        resolvers: List[KeyResolver],
        *,
        warn_on_fallback: bool = True,
    ) -> None:
        if not resolvers:
            raise ValueError("CompositeKeyResolver requires at least one resolver")
        self._resolvers = resolvers
        self._warn_on_fallback = warn_on_fallback

    async def resolve(self, key_id: str) -> Any:
        """Try each resolver in order until one succeeds."""
        errors: List[str] = []

        for i, resolver in enumerate(self._resolvers):
            try:
                key = await resolver.resolve(key_id)
                if i > 0 and self._warn_on_fallback:
                    failed_names = [type(self._resolvers[j]).__name__ for j in range(i)]
                    logger.warning(
                        f"CompositeKeyResolver: primary resolver(s) failed ({', '.join(failed_names)}), "
                        f"resolved {key_id} via fallback {type(resolver).__name__}. "
                        f"Errors: {errors}"
                    )
                else:
                    logger.debug(f"CompositeKeyResolver: resolved {key_id} via resolver {i} ({type(resolver).__name__})")
                return key
            except KeyResolutionError as e:
                errors.append(f"{type(resolver).__name__}: {e}")
                continue

        logger.error(f"CompositeKeyResolver: all resolvers failed for {key_id}: {errors}")
        raise KeyResolutionError(key_id=key_id)

    def resolve_sync(self, key_id: str) -> Any:
        """Try each resolver's resolve_sync() in order.

        Overrides the base class to avoid ThreadPoolExecutor, which is blocked
        by Temporal's workflow sandbox. Delegates to each sub-resolver's
        resolve_sync() so sandbox-safe resolvers (e.g. EnvKeyResolver with
        preload_keys()) work correctly inside workflows.
        """
        errors: List[str] = []

        for i, resolver in enumerate(self._resolvers):
            try:
                key = resolver.resolve_sync(key_id)
                if i > 0 and self._warn_on_fallback:
                    failed_names = [type(self._resolvers[j]).__name__ for j in range(i)]
                    logger.warning(
                        f"CompositeKeyResolver: primary resolver(s) failed ({', '.join(failed_names)}), "
                        f"resolved {key_id} via fallback {type(resolver).__name__} (sync). "
                        f"Errors: {errors}"
                    )
                else:
                    logger.debug(
                        f"CompositeKeyResolver: resolved {key_id} via resolver {i} "
                        f"({type(resolver).__name__}) (sync)"
                    )
                return key
            except KeyResolutionError as e:
                errors.append(f"{type(resolver).__name__}: {e}")
                continue
            except Exception as e:
                errors.append(f"{type(resolver).__name__}: {e}")
                continue

        logger.error(f"CompositeKeyResolver: all resolvers failed for {key_id} (sync): {errors}")
        raise KeyResolutionError(key_id=key_id)
