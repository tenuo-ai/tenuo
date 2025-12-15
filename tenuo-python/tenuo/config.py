"""
Global configuration for Tenuo Tier 1 API.

This module provides a singleton configuration that controls:
- Issuer keypair (for minting warrants)
- Trusted roots (for verification)
- Default TTL
- Development mode settings

Usage:
    from tenuo import configure
    
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
"""

from dataclasses import dataclass, field
from typing import Optional, List
from contextvars import ContextVar

from tenuo_core import Keypair, PublicKey, Authorizer  # type: ignore[import-untyped]

from .exceptions import ConfigurationError


# Default values
DEFAULT_TTL_SECONDS = 300  # 5 minutes
DEFAULT_CLOCK_TOLERANCE_SECS = 30
DEFAULT_POP_WINDOW_SECS = 30
DEFAULT_POP_MAX_WINDOWS = 4


@dataclass
class TenuoConfig:
    """Global Tenuo configuration."""
    
    # Issuer keypair for minting warrants
    issuer_keypair: Optional[Keypair] = None
    
    # Trusted root public keys for verification
    trusted_roots: List[PublicKey] = field(default_factory=list)
    
    # Default TTL for warrants (seconds)
    default_ttl: int = DEFAULT_TTL_SECONDS
    
    # Clock tolerance for expiration checks (seconds)
    clock_tolerance: int = DEFAULT_CLOCK_TOLERANCE_SECS
    
    # PoP window configuration
    pop_window_secs: int = DEFAULT_POP_WINDOW_SECS
    pop_max_windows: int = DEFAULT_POP_MAX_WINDOWS
    
    # Development mode flags
    dev_mode: bool = False
    allow_passthrough: bool = False
    allow_self_signed: bool = False
    
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
            if self.dev_mode and self.allow_self_signed and self.issuer_keypair:
                auth.add_trusted_root(self.issuer_keypair.public_key())
            
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
    issuer_key: Optional[Keypair] = None,
    trusted_roots: Optional[List[PublicKey]] = None,
    default_ttl: int = DEFAULT_TTL_SECONDS,
    clock_tolerance: int = DEFAULT_CLOCK_TOLERANCE_SECS,
    pop_window_secs: int = DEFAULT_POP_WINDOW_SECS,
    pop_max_windows: int = DEFAULT_POP_MAX_WINDOWS,
    dev_mode: bool = False,
    allow_passthrough: bool = False,
    allow_self_signed: bool = False,
) -> None:
    """
    Configure Tenuo globally.
    
    Call this once at application startup before using root_task() or scoped_task().
    
    Args:
        issuer_key: Keypair for signing warrants (required for root_task)
        trusted_roots: Public keys to trust as warrant issuers
        default_ttl: Default warrant TTL in seconds (default: 300)
        clock_tolerance: Clock tolerance for expiration checks (default: 30)
        pop_window_secs: PoP window size in seconds (default: 30)
        pop_max_windows: Number of PoP windows to accept (default: 4)
        dev_mode: Enable development mode (relaxed security)
        allow_passthrough: Allow tool calls without warrants (dev_mode only)
        allow_self_signed: Trust self-signed warrants (dev_mode only)
    
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
            issuer_key=Keypair.generate(),
            dev_mode=True,
            allow_self_signed=True,
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
    
    # Update global config
    _config = TenuoConfig(
        issuer_keypair=issuer_key,
        trusted_roots=list(trusted_roots) if trusted_roots else [],
        default_ttl=default_ttl,
        clock_tolerance=clock_tolerance,
        pop_window_secs=pop_window_secs,
        pop_max_windows=pop_max_windows,
        dev_mode=dev_mode,
        allow_passthrough=allow_passthrough,
        allow_self_signed=allow_self_signed,
    )


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
    return config.issuer_keypair is not None or config.dev_mode


def is_dev_mode() -> bool:
    """Check if running in development mode."""
    return get_config().dev_mode


def allow_passthrough() -> bool:
    """Check if pass-through is allowed."""
    config = get_config()
    return config.dev_mode and config.allow_passthrough


__all__ = [
    "configure",
    "get_config",
    "reset_config",
    "is_configured",
    "is_dev_mode",
    "allow_passthrough",
    "TenuoConfig",
    "DEFAULT_TTL_SECONDS",
]
