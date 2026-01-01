"""
Global configuration for Tenuo Tier 1 API.

This module provides a singleton configuration that controls:
- Issuer keypair (for minting warrants)
- Trusted roots (for verification)
- Default TTL
- Enforcement mode (enforce, audit, permissive)
- Development mode settings

Usage:
    from tenuo import configure, auto_configure

    # Production setup
    configure(
        issuer_key=my_keypair,
        trusted_roots=[control_plane_key],
        default_ttl=300,
    )

    # Development mode (relaxed security for testing)
    configure(
        issuer_key=my_keypair,
        dev_mode=True,
    )

    # Environment-based configuration (12-factor apps)
    auto_configure()  # Reads TENUO_* environment variables

    # Gradual adoption with audit mode
    configure(
        issuer_key=my_keypair,
        mode="audit",  # Logs violations but doesn't block
    )
"""

import base64
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Literal, Optional

from contextvars import ContextVar

from tenuo_core import SigningKey, PublicKey, Authorizer  # type: ignore[import-untyped]

from .exceptions import ConfigurationError

logger = logging.getLogger("tenuo.config")

# Default values
DEFAULT_TTL_SECONDS = 300  # 5 minutes
DEFAULT_CLOCK_TOLERANCE_SECS = 30
DEFAULT_POP_WINDOW_SECS = 30
DEFAULT_POP_MAX_WINDOWS = 4


class EnforcementMode(str, Enum):
    """Enforcement mode for authorization checks.

    - ENFORCE: Block unauthorized requests (production default)
    - AUDIT: Log violations but allow execution (for gradual adoption)
    - PERMISSIVE: Log violations and add warning header, but allow execution
    """
    ENFORCE = "enforce"
    AUDIT = "audit"
    PERMISSIVE = "permissive"


@dataclass
class TenuoConfig:
    """Global Tenuo configuration."""

    # Issuer key for minting warrants
    issuer_key: Optional[SigningKey] = None

    # Trusted root public keys for verification
    trusted_roots: List[PublicKey] = field(default_factory=list)

    # Default TTL for warrants (seconds)
    default_ttl: int = DEFAULT_TTL_SECONDS

    # Clock tolerance for expiration checks (seconds)
    clock_tolerance: int = DEFAULT_CLOCK_TOLERANCE_SECS

    # MCP configuration (for tool discovery and constraint extraction)
    mcp_config: Optional[Any] = None  # CompiledMcpConfig

    # PoP window configuration
    pop_window_secs: int = DEFAULT_POP_WINDOW_SECS
    pop_max_windows: int = DEFAULT_POP_MAX_WINDOWS

    # Enforcement mode: enforce (block), audit (log only), permissive (log + warn header)
    mode: EnforcementMode = EnforcementMode.ENFORCE

    # Development mode flags
    dev_mode: bool = False
    allow_passthrough: bool = False
    allow_self_signed: bool = False

    # Integration safety flags
    strict_mode: bool = False  # Panic on missing warrant (fail-closed enforcement)
    warn_on_missing_warrant: bool = False  # Warn loudly if tool called without warrant

    # Tripwire: flip to hard-fail after N warnings (0 = disabled)
    max_missing_warrant_warnings: int = 0

    # Error detail exposure (SECURITY: keep False in production)
    # If True, detailed constraint info is returned in error responses.
    # If False (default), errors are opaque with request_id for log correlation.
    expose_error_details: bool = False
    _missing_warrant_count: int = field(default=0, repr=False)

    # Cached authorizer (lazily created)
    _authorizer: Optional[Authorizer] = field(default=None, repr=False)

    def get_authorizer(self) -> Authorizer:
        """Get or create the authorizer with current config."""
        if self._authorizer is None:
            if not self.trusted_roots and not self.dev_mode:
                raise ConfigurationError(
                    "No trusted roots configured. "
                    "Call configure(trusted_roots=[...]) or enable dev_mode=True."
                )

            auth = Authorizer(
                trusted_roots=self.trusted_roots if self.trusted_roots else None,
                clock_tolerance_secs=self.clock_tolerance,
                pop_window_secs=self.pop_window_secs,
                pop_max_windows=self.pop_max_windows,
            )

            # In dev mode with self-signed, add issuer as trusted root
            if self.dev_mode and self.allow_self_signed and self.issuer_key:
                auth.add_trusted_root(self.issuer_key.public_key)

            self._authorizer = auth

        return self._authorizer

    def reset_authorizer(self) -> None:
        """Reset cached authorizer (call after config changes)."""
        self._authorizer = None


# Global configuration singleton
_config: TenuoConfig = TenuoConfig()

# ContextVar for config overrides (advanced usage)
_config_context: ContextVar[Optional[TenuoConfig]] = ContextVar('tenuo_config', default=None)


def configure(
    *,
    issuer_key: Optional[SigningKey] = None,
    trusted_roots: Optional[List[PublicKey]] = None,
    default_ttl: int = DEFAULT_TTL_SECONDS,
    clock_tolerance: int = DEFAULT_CLOCK_TOLERANCE_SECS,
    pop_window_secs: int = DEFAULT_POP_WINDOW_SECS,
    pop_max_windows: int = DEFAULT_POP_MAX_WINDOWS,
    mcp_config: Optional[Any] = None,
    mode: Literal["enforce", "audit", "permissive"] = "enforce",
    dev_mode: bool = False,
    allow_passthrough: bool = False,
    allow_self_signed: bool = False,
    strict_mode: bool = False,
    warn_on_missing_warrant: bool = False,
    max_missing_warrant_warnings: int = 0,
    expose_error_details: bool = False,
    audit_log: bool = True,
) -> None:
    """
    Configure Tenuo globally.

    Call this once at application startup before using mint() or grant().

    Args:
        issuer_key: SigningKey for signing warrants (required for mint)
        trusted_roots: Public keys to trust as warrant issuers
        default_ttl: Default warrant TTL in seconds (default: 300)
        clock_tolerance: Clock tolerance for expiration checks (default: 30)
        pop_window_secs: PoP window size in seconds (default: 30)
        pop_max_windows: Number of PoP windows to accept (default: 4)
        mcp_config: CompiledMcpConfig for MCP tool authorization (optional)
        mode: Enforcement mode - "enforce" (block), "audit" (log only), "permissive" (log + warn)
        dev_mode: Enable development mode (relaxed security)
        allow_passthrough: Allow tool calls without warrants (dev_mode only)
        allow_self_signed: Trust self-signed warrants (dev_mode only)
        strict_mode: Raise RuntimeError on missing warrant (fail-closed)
        warn_on_missing_warrant: Emit warnings for missing warrant contexts
        max_missing_warrant_warnings: Tripwire - auto-flip to strict after N warnings (0=disabled)
        expose_error_details: Include constraint details in error responses (SECURITY: keep False in production)
        audit_log: Enable audit logging (default: True). Set False for clean demo output.

    Raises:
        ConfigurationError: If invalid configuration

    Example:
        # Production
        configure(
            issuer_key=my_keypair,
            trusted_roots=[control_plane_key],
        )

        # Development
        configure(
            issuer_key=SigningKey.generate(),
            dev_mode=True,
            allow_self_signed=True,
        )

        # Gradual adoption (audit mode)
        configure(
            issuer_key=my_keypair,
            trusted_roots=[control_plane_key],
            mode="audit",  # Log violations but don't block
        )
    """
    global _config

    # Validate dev_mode requirements
    if allow_passthrough and not dev_mode:
        raise ConfigurationError(
            "allow_passthrough=True requires dev_mode=True. "
            "Pass-through is dangerous and should only be used in development."
        )

    if allow_self_signed and not dev_mode:
        raise ConfigurationError(
            "allow_self_signed=True requires dev_mode=True. "
            "Self-signed warrants bypass the trust chain."
        )

    # Validate production requirements
    if not dev_mode and not trusted_roots:
        raise ConfigurationError(
            "trusted_roots required in production mode. "
            "Provide trusted_roots=[...] or enable dev_mode=True for development."
        )

    # Validate strict_mode
    if strict_mode and allow_passthrough:
        raise ConfigurationError(
            "strict_mode=True is incompatible with allow_passthrough=True. "
            "Strict mode enforces warrant presence; passthrough allows missing warrants."
        )

    # Parse mode
    enforcement_mode = EnforcementMode(mode)

    # Update global config
    _config = TenuoConfig(
        issuer_key=issuer_key,
        trusted_roots=list(trusted_roots) if trusted_roots else [],
        default_ttl=default_ttl,
        clock_tolerance=clock_tolerance,
        mcp_config=mcp_config,
        pop_window_secs=pop_window_secs,
        pop_max_windows=pop_max_windows,
        mode=enforcement_mode,
        dev_mode=dev_mode,
        allow_passthrough=allow_passthrough,
        allow_self_signed=allow_self_signed,
        strict_mode=strict_mode,
        warn_on_missing_warrant=warn_on_missing_warrant,
        max_missing_warrant_warnings=max_missing_warrant_warnings,
        expose_error_details=expose_error_details,
    )

    if enforcement_mode != EnforcementMode.ENFORCE:
        logger.warning(
            f"Tenuo configured in {enforcement_mode.value} mode. "
            "Authorization violations will be logged but NOT blocked. "
            "Set mode='enforce' for production."
        )

    # Configure audit logging
    from .audit import audit_logger
    audit_logger.configure(enabled=audit_log)


def get_config() -> TenuoConfig:
    """Get the current configuration (context override or global)."""
    ctx_config = _config_context.get()
    return ctx_config if ctx_config is not None else _config


def reset_config() -> None:
    """Reset configuration to defaults (mainly for testing)."""
    global _config
    _config = TenuoConfig()


def is_configured() -> bool:
    """Check if Tenuo has been configured."""
    config = get_config()
    return config.issuer_key is not None or config.dev_mode


def is_dev_mode() -> bool:
    """Check if running in development mode."""
    return get_config().dev_mode


def allow_passthrough() -> bool:
    """Check if pass-through is allowed."""
    config = get_config()
    return config.dev_mode and config.allow_passthrough


def is_audit_mode() -> bool:
    """Check if running in audit mode (log violations, don't block)."""
    return get_config().mode == EnforcementMode.AUDIT


def is_permissive_mode() -> bool:
    """Check if running in permissive mode (log violations, add warning, don't block)."""
    return get_config().mode == EnforcementMode.PERMISSIVE


def is_enforce_mode() -> bool:
    """Check if running in enforce mode (block violations)."""
    return get_config().mode == EnforcementMode.ENFORCE


def should_block_violation() -> bool:
    """Check if authorization violations should be blocked."""
    return get_config().mode == EnforcementMode.ENFORCE


def auto_configure(
    *,
    prefix: str = "TENUO_",
    require_issuer: bool = False,
) -> bool:
    """
    Configure Tenuo from environment variables.

    Environment variables (with default TENUO_ prefix):
        TENUO_ISSUER_KEY: Base64-encoded signing key (or hex)
        TENUO_TRUSTED_ROOTS: Comma-separated base64 public keys
        TENUO_DEFAULT_TTL: Default TTL in seconds (default: 300)
        TENUO_MODE: Enforcement mode - enforce, audit, permissive (default: enforce)
        TENUO_DEV_MODE: Enable dev mode if "1" or "true"
        TENUO_CLOCK_TOLERANCE: Clock tolerance in seconds (default: 30)

    Args:
        prefix: Environment variable prefix (default: "TENUO_")
        require_issuer: If True, raise ConfigurationError if no issuer key

    Returns:
        True if configuration was applied, False if no config found

    Raises:
        ConfigurationError: If require_issuer=True and no issuer key found

    Example:
        # In your app startup
        from tenuo import auto_configure

        auto_configure()  # Reads TENUO_* environment variables

        # With custom prefix (multi-tenant)
        auto_configure(prefix="AGENT_A_TENUO_")  # Reads AGENT_A_TENUO_*

        # Require issuer key
        auto_configure(require_issuer=True)  # Raises if TENUO_ISSUER_KEY not set
    """
    issuer_key = None
    trusted_roots = None
    default_ttl = DEFAULT_TTL_SECONDS
    mode = "enforce"
    dev_mode = False
    clock_tolerance = DEFAULT_CLOCK_TOLERANCE_SECS

    found_any = False

    # Parse issuer key
    issuer_key_str = os.getenv(f"{prefix}ISSUER_KEY")
    if issuer_key_str:
        found_any = True
        try:
            # Try base64 first
            try:
                key_bytes = base64.b64decode(issuer_key_str)
                issuer_key = SigningKey.from_bytes(key_bytes)
            except Exception:
                # Try hex
                issuer_key = SigningKey.from_hex(issuer_key_str)
        except Exception as e:
            raise ConfigurationError(
                f"Invalid {prefix}ISSUER_KEY: {e}. "
                "Expected base64 or hex encoded signing key."
            )
    elif require_issuer:
        raise ConfigurationError(
            f"{prefix}ISSUER_KEY environment variable is required but not set."
        )

    # Parse trusted roots
    trusted_roots_str = os.getenv(f"{prefix}TRUSTED_ROOTS")
    if trusted_roots_str:
        found_any = True
        trusted_roots = []
        for root_str in trusted_roots_str.split(","):
            root_str = root_str.strip()
            if not root_str:
                continue
            try:
                # Try base64 first
                try:
                    key_bytes = base64.b64decode(root_str)
                    trusted_roots.append(PublicKey.from_bytes(key_bytes))
                except Exception:
                    # Try hex
                    trusted_roots.append(PublicKey.from_hex(root_str))
            except Exception as e:
                raise ConfigurationError(
                    f"Invalid public key in {prefix}TRUSTED_ROOTS: {e}"
                )

    # Parse TTL
    ttl_str = os.getenv(f"{prefix}DEFAULT_TTL")
    if ttl_str:
        found_any = True
        try:
            default_ttl = int(ttl_str)
        except ValueError:
            raise ConfigurationError(
                f"Invalid {prefix}DEFAULT_TTL: expected integer, got '{ttl_str}'"
            )

    # Parse mode
    mode_str = os.getenv(f"{prefix}MODE")
    if mode_str:
        found_any = True
        mode = mode_str.lower()
        if mode not in ("enforce", "audit", "permissive"):
            raise ConfigurationError(
                f"Invalid {prefix}MODE: expected 'enforce', 'audit', or 'permissive', "
                f"got '{mode_str}'"
            )

    # Parse dev mode
    dev_mode_str = os.getenv(f"{prefix}DEV_MODE", "").lower()
    if dev_mode_str in ("1", "true", "yes"):
        found_any = True
        dev_mode = True

    # Parse clock tolerance
    tolerance_str = os.getenv(f"{prefix}CLOCK_TOLERANCE")
    if tolerance_str:
        found_any = True
        try:
            clock_tolerance = int(tolerance_str)
        except ValueError:
            raise ConfigurationError(
                f"Invalid {prefix}CLOCK_TOLERANCE: expected integer, got '{tolerance_str}'"
            )

    if not found_any:
        logger.debug(f"No {prefix}* environment variables found, skipping auto_configure")
        return False

    # Apply configuration
    configure(
        issuer_key=issuer_key,
        trusted_roots=trusted_roots,
        default_ttl=default_ttl,
        mode=mode,  # type: ignore[arg-type]
        dev_mode=dev_mode,
        allow_self_signed=dev_mode,  # Auto-enable if dev_mode
        clock_tolerance=clock_tolerance,
    )

    logger.info(
        f"Tenuo auto-configured from environment: "
        f"mode={mode}, dev_mode={dev_mode}, "
        f"issuer={'set' if issuer_key else 'not set'}, "
        f"trusted_roots={len(trusted_roots or [])}"
    )

    return True


__all__ = [
    "configure",
    "auto_configure",
    "get_config",
    "reset_config",
    "is_configured",
    "is_dev_mode",
    "is_audit_mode",
    "is_permissive_mode",
    "is_enforce_mode",
    "should_block_violation",
    "allow_passthrough",
    "TenuoConfig",
    "EnforcementMode",
    "DEFAULT_TTL_SECONDS",
    "DEFAULT_CLOCK_TOLERANCE_SECS",
    "DEFAULT_POP_WINDOW_SECS",
    "DEFAULT_POP_MAX_WINDOWS",
]
