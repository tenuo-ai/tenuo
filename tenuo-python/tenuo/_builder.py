"""
Shared Builder Patterns for Tenuo Integrations.

This module provides base classes and utilities for building guards across
all integrations (CrewAI, AutoGen, OpenAI, Google ADK, etc.).

The goal is DRY: common patterns like allow(), with_warrant(), on_denial()
are implemented once and inherited by all integration-specific builders.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional, TypeVar, Generic, TYPE_CHECKING

from .bound_warrant import BoundWarrant
from .exceptions import ConfigurationError, ExpiredError, MissingSigningKey
from ._enforcement import DenialPolicy

if TYPE_CHECKING:
    from .approval import ApprovalHandler, ApprovalPolicy

logger = logging.getLogger("tenuo.builder")

# Type variable for the concrete builder subclass (for fluent returns)
T = TypeVar("T", bound="BaseGuardBuilder")


# =============================================================================
# Warrant Validation Utility
# =============================================================================


@dataclass
class WarrantValidationResult:
    """Result of warrant validation."""

    bound_warrant: BoundWarrant
    warrant_id: Optional[str] = None


def validate_warrant_for_binding(
    warrant: Any,
    signing_key: Any,
    *,
    check_holder: bool = True,
    check_expiry: bool = True,
) -> WarrantValidationResult:
    """
    Validate a warrant and signing key, returning a BoundWarrant.

    This centralizes the common validation logic used across all integrations:
    - Signing key is required
    - Optional holder verification (key matches warrant holder)
    - Optional expiry check

    Args:
        warrant: The warrant to validate
        signing_key: The signing key to bind with
        check_holder: If True, verify signing_key matches warrant holder
        check_expiry: If True, verify warrant is not expired

    Returns:
        WarrantValidationResult with the bound warrant

    Raises:
        MissingSigningKey: If signing_key is None
        ConfigurationError: If signing_key doesn't match warrant holder
        ExpiredError: If warrant is expired

    Example:
        result = validate_warrant_for_binding(warrant, key)
        bound = result.bound_warrant
    """
    if signing_key is None:
        raise MissingSigningKey("Signing key is required for warrant-protected guard")

    # Check holder match (optional but recommended)
    if check_holder:
        holder = getattr(warrant, "authorized_holder", None)
        pub_key = getattr(signing_key, "public_key", None)

        if holder is not None and pub_key is not None:
            try:
                # Try direct comparison first
                mismatch = holder != pub_key
            except Exception:
                # Fall back to string comparison
                mismatch = str(holder) != str(pub_key)

            if mismatch:
                raise ConfigurationError(
                    "Signing key does not match warrant holder. "
                    "The signing_key.public_key must match warrant.authorized_holder."
                )

    # Check expiry (optional)
    if check_expiry:
        if hasattr(warrant, "is_expired") and callable(warrant.is_expired):
            if warrant.is_expired():
                raise ExpiredError("Warrant is expired")

    # Bind and return
    bound = warrant.bind(signing_key)
    warrant_id = getattr(bound, "id", None) or getattr(warrant, "id", None)

    return WarrantValidationResult(bound_warrant=bound, warrant_id=warrant_id)


# =============================================================================
# Base Guard Builder
# =============================================================================


class BaseGuardBuilder(Generic[T]):
    """
    Base class for all integration guard builders.

    Provides common functionality:
    - allow(tool, **constraints) - Register tool with constraints
    - with_warrant(warrant, signing_key) - Enable Tier 2 with warrant
    - on_denial(mode) - Set denial handling mode

    Subclasses should:
    1. Call super().__init__() in their __init__
    2. Implement build() to create their specific guard type
    3. Add integration-specific methods as needed

    Example subclass:
        class MyGuardBuilder(BaseGuardBuilder["MyGuardBuilder"]):
            def __init__(self):
                super().__init__()
                self._extra_config = None

            def extra_config(self, value) -> "MyGuardBuilder":
                self._extra_config = value
                return self

            def build(self) -> MyGuard:
                bound = self._get_bound_warrant()
                return MyGuard(
                    constraints=self._constraints,
                    bound_warrant=bound,
                    on_denial=self._on_denial,
                )
    """

    def __init__(self) -> None:
        """Initialize common builder state."""
        self._constraints: Dict[str, Dict[str, Any]] = {}
        self._warrant: Optional[Any] = None
        self._signing_key: Optional[Any] = None
        self._on_denial: str = DenialPolicy.RAISE
        self._approval_policy: Optional[ApprovalPolicy] = None
        self._approval_handler: Optional[ApprovalHandler] = None
        self._approvals: Optional[list] = None

    def allow(self: T, tool_name: str, **constraints: Any) -> T:
        """
        Allow a tool with optional parameter constraints.

        Args:
            tool_name: Name of the tool to allow
            **constraints: Keyword arguments mapping param names to constraints

        Returns:
            self for method chaining

        Example:
            builder.allow("read_file", path=Subpath("/data"))
            builder.allow("search", query=Wildcard())
        """
        self._constraints[tool_name] = constraints
        return self

    def with_warrant(self: T, warrant: Any, signing_key: Any) -> T:
        """
        Enable Tier 2 authorization with warrant and signing key.

        Args:
            warrant: Cryptographic warrant authorizing tool access
            signing_key: Agent's signing key for Proof-of-Possession

        Returns:
            self for method chaining

        Raises:
            MissingSigningKey: If signing_key is None
        """
        if signing_key is None:
            raise MissingSigningKey("Signing key is required for Tier 2")
        self._warrant = warrant
        self._signing_key = signing_key
        return self

    def on_denial(self: T, mode: str) -> T:
        """
        Set how denials are handled.

        Args:
            mode: One of:
                - "raise": Raise exception on denial (default)
                - "log": Log warning and return DenialResult
                - "skip": Log at debug level only

        Returns:
            self for method chaining

        Raises:
            ValueError: If mode is not one of the valid options
        """
        valid_modes = {DenialPolicy.RAISE, DenialPolicy.LOG, DenialPolicy.SKIP}
        if mode not in valid_modes:
            raise ValueError(f"on_denial must be one of: {', '.join(valid_modes)}")
        self._on_denial = mode
        return self

    def approval_policy(self: T, policy: ApprovalPolicy) -> T:
        """Set an approval policy for human-in-the-loop authorization.

        When a tool call matches a policy rule, the approval handler is
        invoked before execution proceeds. The warrant still governs what
        is permitted; the policy governs when a human must confirm.

        Args:
            policy: ApprovalPolicy with one or more rules.

        Returns:
            self for method chaining

        Example:
            from tenuo.approval import ApprovalPolicy, require_approval

            builder.approval_policy(ApprovalPolicy(
                require_approval("transfer_funds", when=lambda a: a["amount"] > 10_000),
            ))
        """
        self._approval_policy = policy
        return self

    def on_approval(self: T, handler: ApprovalHandler) -> T:
        """Set the handler invoked when a tool call requires approval.

        Args:
            handler: Callable that receives an ApprovalRequest and returns
                a SignedApproval (or raises ApprovalDenied). Built-in
                handlers: cli_prompt(), auto_approve(), auto_deny().

        Returns:
            self for method chaining

        Example:
            from tenuo.approval import cli_prompt
            approver_key = SigningKey.generate()
            builder.on_approval(cli_prompt(approver_key=approver_key))
        """
        self._approval_handler = handler
        return self

    def with_approvals(self: T, approvals: list) -> T:
        """Provide pre-obtained SignedApproval objects (spec §6).

        Use this for cloud/async workflows where approvals were obtained
        out-of-band (e.g., from Tenuo Cloud). These take precedence
        over the approval_handler when a policy rule matches.

        Args:
            approvals: List of SignedApproval objects.

        Returns:
            self for method chaining
        """
        self._approvals = approvals
        return self

    def _get_bound_warrant(
        self,
        *,
        check_holder: bool = True,
        check_expiry: bool = True,
    ) -> Optional[BoundWarrant]:
        """
        Get bound warrant if configured, with validation.

        Subclasses should call this in their build() method.

        Returns:
            BoundWarrant if warrant is configured, None otherwise

        Raises:
            MissingSigningKey: If warrant set but no signing key
            ConfigurationError: If key doesn't match holder
            ExpiredError: If warrant is expired
        """
        if self._warrant is None:
            return None

        result = validate_warrant_for_binding(
            self._warrant,
            self._signing_key,
            check_holder=check_holder,
            check_expiry=check_expiry,
        )
        return result.bound_warrant

    @property
    def has_warrant(self) -> bool:
        """Check if warrant is configured."""
        return self._warrant is not None

    @property
    def is_tier2(self) -> bool:
        """Check if Tier 2 (warrant + key) is configured."""
        return self._warrant is not None and self._signing_key is not None


__all__ = [
    "BaseGuardBuilder",
    "WarrantValidationResult",
    "validate_warrant_for_binding",
]
