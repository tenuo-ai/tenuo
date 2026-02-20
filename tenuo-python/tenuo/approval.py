"""
Tenuo Approval Policy - Cryptographically verified human-in-the-loop authorization.

The approval layer sits between warrant authorization and tool execution.
Warrants define *what* an agent can do. Approval policies define *when*
a human must confirm before execution proceeds.

    warrant: "You can transfer up to $100K"
    policy:  "Amounts over $10K need human approval"

Every approval is cryptographically signed. There is no unsigned "approved=True"
path. The approver's SigningKey produces a SignedApproval that binds to the
exact (warrant, tool, args, holder) tuple via a SHA-256 request hash.

ALL cryptographic verification is performed by the Rust core:
- Signature validity (verify-before-deserialize)
- Approver membership in the trusted set
- Request hash binding (prevents replay across warrants/tools)
- Expiration with 30-second clock tolerance (for distributed deployments)
- Duplicate detection (one vote per approver key)
- m-of-n threshold satisfaction

Architecture:
    enforce_tool_call()  ->  warrant says OK  ->  compute request hash
                                                        |
                                    check approval policy
                                        |
                                    no rule matches: proceed
                                    rule matches: collect approvals
                                        |
                                ┌──────────────┐
                                │ Rust core     │
                                │ verify_approvals() │
                                │ (m-of-n, sigs,│
                                │  hash, expiry)│
                                └──────┬───────┘
                                       |
                                    pass: proceed
                                    fail: ApprovalVerificationError

M-of-N Multi-sig:
    Require multiple approvers to sign before execution proceeds.
    Set ``threshold`` on the policy (default 1):

        policy = ApprovalPolicy(
            require_approval("deploy_prod"),
            trusted_approvers=[alice.public_key, bob.public_key, carol.public_key],
            threshold=2,  # any 2-of-3 must approve
        )

    Handlers can return a list of SignedApprovals for m-of-n, or
    callers can provide pre-signed approvals via the ``approvals`` parameter.

TTL (Time-to-Live) Configuration:
    Controls how long a signed approval is valid. Configurable at three
    levels with a clear resolution order:

    1. Policy level (recommended for org-wide defaults):
        ApprovalPolicy(..., default_ttl=86400)  # 24 hours for async workflows

    2. Handler level (overrides policy):
        cli_prompt(approver_key=key, ttl_seconds=60)

    3. Call level (overrides everything):
        sign_approval(request, key, ttl_seconds=30)

    Resolution in sign_approval(): explicit ttl_seconds > request.suggested_ttl > 300s

    For inline handlers (cli_prompt), the TTL starts when the human approves.
    For async/cloud workflows (caller-provided approvals), the TTL starts when
    the external system signs -- use longer TTLs (hours/days) for approval
    boards, Slack bots, or ticketing systems.

Error Diagnostics:
    Verification errors are specific to help debug configuration issues:

    1-of-1 (single approval): the exact reason is surfaced:
        - "approver not in trusted set"
        - "approval expired (beyond clock tolerance)"
        - "request hash mismatch (approval was signed for a different request)"
        - "invalid signature on approval"

    m-of-n (multiple approvals): a rejection summary is included:
        - "Insufficient approvals: required 3, received 1
           [rejected: 1 expired, 1 untrusted]"

Usage:
    from tenuo import SigningKey
    from tenuo.approval import ApprovalPolicy, require_approval, cli_prompt

    approver_key = SigningKey.generate()

    # Simple: single approver, default TTL
    policy = ApprovalPolicy(
        require_approval("transfer_funds", when=lambda args: args["amount"] > 10_000),
        require_approval("delete_user"),
        trusted_approvers=[approver_key.public_key],
    )

    # Enterprise: 2-of-3 multi-sig with 1-hour approval window
    policy = ApprovalPolicy(
        require_approval("deploy_prod"),
        trusted_approvers=[alice.public_key, bob.public_key, carol.public_key],
        threshold=2,
        default_ttl=3600,
    )

    guard = (GuardBuilder(client)
        .allow("transfer_funds", amount=Range(0, 100_000))
        .approval_policy(policy)
        .on_approval(cli_prompt(approver_key=approver_key))
        .build())
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, List, Optional, Protocol, Union

if TYPE_CHECKING:
    from tenuo_core import PublicKey, SignedApproval, SigningKey

logger = logging.getLogger("tenuo.approval")


# =============================================================================
# Approval Request
# =============================================================================


@dataclass(frozen=True)
class ApprovalRequest:
    """Context passed to an approval handler when a rule triggers.

    The request_hash cryptographically binds this approval to the exact
    (warrant_id, tool, args, holder) tuple. Handlers must embed this hash
    in the ApprovalPayload they sign.

    Attributes:
        tool: Name of the tool requiring approval.
        arguments: Arguments the agent wants to pass.
        warrant_id: ID of the warrant authorizing this call.
        request_hash: SHA-256 hash binding approval to this specific call (32 bytes).
        rule: The ApprovalRule that triggered this request.
        suggested_ttl: Policy-recommended TTL in seconds for the signed approval.
            Handlers should use this unless they have a reason to override.
            Set from ApprovalPolicy.default_ttl. None means use handler default.
    """

    tool: str
    arguments: Dict[str, Any]
    warrant_id: str
    request_hash: bytes
    rule: Optional[ApprovalRule] = None
    suggested_ttl: Optional[int] = None


# =============================================================================
# Exceptions
# =============================================================================


class ApprovalRequired(Exception):
    """Raised when a tool call requires human approval but no handler is set.

    This is not an authorization failure -- the warrant permits the call.
    The approval policy requires a human to confirm before execution.

    Attributes:
        request: The ApprovalRequest with full context.
    """

    def __init__(self, request: ApprovalRequest):
        self.request = request
        super().__init__(
            f"Approval required for '{request.tool}' "
            f"(warrant: {request.warrant_id})"
        )


class ApprovalDenied(Exception):
    """Raised when a human denies an approval request.

    Attributes:
        request: The original ApprovalRequest.
        reason: Human-readable denial reason.
    """

    def __init__(self, request: ApprovalRequest, *, reason: str = "denied by approver"):
        self.request = request
        self.reason = reason
        super().__init__(f"Approval denied for '{request.tool}': {reason}")


class ApprovalTimeout(ApprovalDenied):
    """Raised when an approval request times out."""

    def __init__(self, request: ApprovalRequest, timeout_seconds: float):
        self.timeout_seconds = timeout_seconds
        super().__init__(request, reason=f"timed out after {timeout_seconds}s")


class ApprovalVerificationError(Exception):
    """Raised when a SignedApproval fails cryptographic verification.

    This indicates tampering, hash mismatch, untrusted approver key,
    or expired approval.

    Attributes:
        request: The original ApprovalRequest.
        reason: What failed verification.
    """

    def __init__(self, request: ApprovalRequest, *, reason: str):
        self.request = request
        self.reason = reason
        super().__init__(
            f"Approval verification failed for '{request.tool}': {reason}"
        )


# =============================================================================
# Approval Rules
# =============================================================================


@dataclass(frozen=True)
class ApprovalRule:
    """A single rule that triggers an approval request.

    Attributes:
        tool: Tool name this rule applies to.
        when: Predicate on args. If None, always requires approval.
        description: Human-readable description shown to the approver.
    """

    tool: str
    when: Optional[Callable[[Dict[str, Any]], bool]] = None
    description: Optional[str] = None

    def matches(self, tool_name: str, args: Dict[str, Any]) -> bool:
        """Check if this rule triggers for the given call."""
        if tool_name != self.tool:
            return False
        if self.when is None:
            return True
        try:
            return bool(self.when(args))
        except Exception:
            logger.warning(
                f"Approval rule predicate failed for '{tool_name}', "
                "requiring approval as a safety default",
                exc_info=True,
            )
            return True


def require_approval(
    tool: str,
    *,
    when: Optional[Callable[[Dict[str, Any]], bool]] = None,
    description: Optional[str] = None,
) -> ApprovalRule:
    """Create an approval rule.

    Args:
        tool: Tool name that requires approval.
        when: Optional predicate -- if provided, approval is only required
            when the predicate returns True. If omitted, approval is
            always required for this tool.
        description: Human-readable description shown to the approver.

    Examples:
        require_approval("delete_user")
        require_approval("transfer_funds", when=lambda args: args["amount"] > 10_000)
        require_approval("send_email",
            when=lambda args: not args["to"].endswith("@company.com"),
            description="External emails require approval")
    """
    return ApprovalRule(tool=tool, when=when, description=description)


# =============================================================================
# Approval Policy
# =============================================================================


class ApprovalPolicy:
    """Collection of approval rules with trusted approver keys.

    The policy does not affect what an agent *can* do (that's the warrant).
    It gates *when* a human must confirm before execution proceeds.
    Trusted approvers define *whose* signature is accepted, and
    ``threshold`` specifies how many must sign (m-of-n multi-sig).

    Args:
        *rules: One or more ApprovalRule instances.
        trusted_approvers: Public keys of trusted approvers. If set,
            only SignedApprovals from these keys are accepted.
            If None, any valid signature is accepted.
        threshold: Minimum number of valid approvals required (m-of-n).
            Defaults to 1. Must be <= len(trusted_approvers) when set.
        default_ttl: Default TTL in seconds for signed approvals created
            by handlers. Propagated to handlers via ApprovalRequest.suggested_ttl.
            None means handlers use their own default (typically 300s).
            Set to longer values for async/cloud workflows (e.g. 86400 for 24h).

    Example:
        # 1-of-1 (single approver)
        policy = ApprovalPolicy(
            require_approval("delete_user"),
            trusted_approvers=[admin_key.public_key],
        )

        # 2-of-3 multi-sig with 1-hour approval window
        policy = ApprovalPolicy(
            require_approval("transfer_funds", when=lambda a: a["amount"] > 10_000),
            trusted_approvers=[alice.public_key, bob.public_key, carol.public_key],
            threshold=2,
            default_ttl=3600,
        )
    """

    def __init__(
        self,
        *rules: ApprovalRule,
        trusted_approvers: Optional[List[PublicKey]] = None,
        threshold: int = 1,
        default_ttl: Optional[int] = None,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        if trusted_approvers is not None and threshold > len(trusted_approvers):
            raise ValueError(
                f"threshold ({threshold}) exceeds number of "
                f"trusted_approvers ({len(trusted_approvers)})"
            )
        if default_ttl is not None and default_ttl < 1:
            raise ValueError("default_ttl must be >= 1 second")
        self._rules: List[ApprovalRule] = list(rules)
        self._trusted_approvers = list(trusted_approvers) if trusted_approvers else None
        self._threshold = threshold
        self._default_ttl = default_ttl

    def check(
        self,
        tool_name: str,
        args: Dict[str, Any],
        warrant_id: str,
        request_hash: bytes,
    ) -> Optional[ApprovalRequest]:
        """Check if a tool call requires approval.

        Returns:
            ApprovalRequest if approval is needed, None otherwise.
        """
        for rule in self._rules:
            if rule.matches(tool_name, args):
                return ApprovalRequest(
                    tool=tool_name,
                    arguments=args,
                    warrant_id=warrant_id,
                    request_hash=request_hash,
                    rule=rule,
                    suggested_ttl=self._default_ttl,
                )
        return None

    @property
    def trusted_approvers(self) -> Optional[List[PublicKey]]:
        """Public keys of trusted approvers, or None if any key is accepted."""
        return list(self._trusted_approvers) if self._trusted_approvers else None

    @property
    def threshold(self) -> int:
        """Minimum number of valid approvals required (m-of-n)."""
        return self._threshold

    @property
    def default_ttl(self) -> Optional[int]:
        """Default TTL in seconds for signed approvals, or None for handler default."""
        return self._default_ttl

    @property
    def rules(self) -> List[ApprovalRule]:
        return list(self._rules)

    def __len__(self) -> int:
        return len(self._rules)


# =============================================================================
# Approval Handler Protocol
# =============================================================================


class ApprovalHandler(Protocol):
    """Protocol for approval handlers.

    Handlers receive an ApprovalRequest and MUST return a SignedApproval.
    To deny, raise ApprovalDenied. There is no unsigned approval path.

    The handler is responsible for:
    1. Presenting the request to a human (or automated policy)
    2. If approved: creating an ApprovalPayload with the request_hash,
       signing it with the approver's SigningKey -> SignedApproval
    3. If denied: raising ApprovalDenied

    Handlers can be sync or async -- the enforcement layer handles both.
    """

    def __call__(self, request: ApprovalRequest) -> Union[
        SignedApproval, Awaitable[SignedApproval]
    ]: ...


# =============================================================================
# Helper: create a SignedApproval from a request
# =============================================================================


def sign_approval(
    request: ApprovalRequest,
    approver_key: SigningKey,
    *,
    external_id: str = "",
    ttl_seconds: Optional[int] = None,
) -> SignedApproval:
    """Create a SignedApproval for the given request.

    This is the canonical way to produce a signed approval. It:
    - Creates an ApprovalPayload with the request_hash
    - Generates a random nonce (replay protection)
    - Sets approved_at to now, expires_at to now + ttl_seconds
    - Signs with the approver's key

    TTL resolution order:
    1. Explicit ``ttl_seconds`` argument (highest priority)
    2. ``request.suggested_ttl`` from the ApprovalPolicy.default_ttl
    3. 300 seconds (5 minutes) as the fallback default

    Args:
        request: The ApprovalRequest to approve.
        approver_key: The approver's SigningKey.
        external_id: Identity of the approver (e.g., email).
        ttl_seconds: How long the signed approval is valid. None uses
            the policy's suggested TTL, or 300s as fallback.

    Returns:
        A SignedApproval (from tenuo_core).
    """
    from tenuo_core import ApprovalPayload, SignedApproval

    effective_ttl = ttl_seconds or request.suggested_ttl or 300

    now = int(time.time())
    nonce = os.urandom(16)

    payload = ApprovalPayload(
        request_hash=request.request_hash,
        nonce=nonce,
        external_id=external_id,
        approved_at=now,
        expires_at=now + effective_ttl,
    )

    return SignedApproval.create(payload, approver_key)


# =============================================================================
# Built-in Handlers
# =============================================================================


def cli_prompt(
    *,
    approver_key: SigningKey,
    show_args: bool = True,
    ttl_seconds: Optional[int] = None,
) -> ApprovalHandler:
    """Create a CLI-based approval handler for local development.

    Displays the tool call details in the terminal and waits for
    the user to type 'y' or 'n'. If approved, produces a SignedApproval.

    Args:
        approver_key: The approver's signing key (used to sign approvals).
        show_args: Whether to display tool arguments (may contain PII).
        ttl_seconds: How long the signed approval is valid. None uses
            the policy's default_ttl, or 300s as fallback.

    Returns:
        An ApprovalHandler that prompts in the terminal.
    """

    def _handle(request: ApprovalRequest) -> SignedApproval:
        print(f"\n{'=' * 60}", file=sys.stderr)
        print("  APPROVAL REQUIRED", file=sys.stderr)
        print(f"{'=' * 60}", file=sys.stderr)
        print(f"  Tool:    {request.tool}", file=sys.stderr)
        if show_args and request.arguments:
            for k, v in request.arguments.items():
                print(f"  {k:>8s}: {v}", file=sys.stderr)
        if request.rule and request.rule.description:
            print(f"  Reason:  {request.rule.description}", file=sys.stderr)
        print(f"  Warrant: {request.warrant_id}", file=sys.stderr)
        print(f"  Hash:    {request.request_hash.hex()[:16]}...", file=sys.stderr)
        print(f"{'=' * 60}", file=sys.stderr)

        try:
            answer = input("  Approve? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        if answer not in ("y", "yes"):
            raise ApprovalDenied(request, reason="denied via CLI")

        return sign_approval(
            request,
            approver_key,
            external_id="cli",
            ttl_seconds=ttl_seconds,
        )

    return _handle


def auto_approve(
    *,
    approver_key: SigningKey,
    ttl_seconds: Optional[int] = None,
) -> ApprovalHandler:
    """Create a handler that auto-approves everything. For testing only.

    Args:
        approver_key: The approver's signing key (produces real SignedApprovals).
        ttl_seconds: How long the signed approval is valid. None uses
            the policy's default_ttl, or 300s as fallback.
    """

    _warned = False

    def _handle(request: ApprovalRequest) -> SignedApproval:
        nonlocal _warned
        if not _warned:
            logger.warning(
                "AUTO-APPROVE HANDLER ACTIVE — DO NOT USE IN PRODUCTION. "
                "All approval requests are being automatically approved. "
                "Replace with cli_prompt() or a custom handler before deploying."
            )
            _warned = True
        logger.info(f"Auto-approving '{request.tool}' (testing mode)")
        return sign_approval(
            request,
            approver_key,
            external_id="auto-approve",
            ttl_seconds=ttl_seconds,
        )

    return _handle


def auto_deny(*, reason: str = "auto-denied by policy") -> ApprovalHandler:
    """Create a handler that auto-denies everything. For dry-run / audit mode."""

    def _handle(request: ApprovalRequest) -> SignedApproval:
        logger.info(f"Auto-denying '{request.tool}' (dry-run mode)")
        raise ApprovalDenied(request, reason=reason)

    return _handle


def webhook(
    url: str,
    *,
    timeout: float = 300,
    headers: Optional[Dict[str, str]] = None,
) -> ApprovalHandler:
    """Create a webhook-based approval handler (placeholder).

    Posts the approval request to a URL and polls for a SignedApproval.
    Full implementation requires Tenuo Cloud.

    Args:
        url: Webhook URL to POST the approval request to.
        timeout: Timeout in seconds waiting for approval.
        headers: Optional HTTP headers (e.g., auth tokens).
    """

    def _handle(request: ApprovalRequest) -> SignedApproval:
        raise NotImplementedError(
            "Webhook approval handler is a placeholder. "
            "Use tenuo.cloud or implement a custom handler."
        )

    return _handle


__all__ = [
    "ApprovalPolicy",
    "ApprovalRequest",
    "ApprovalRequired",
    "ApprovalDenied",
    "ApprovalTimeout",
    "ApprovalVerificationError",
    "ApprovalRule",
    "ApprovalHandler",
    "require_approval",
    "sign_approval",
    "cli_prompt",
    "auto_approve",
    "auto_deny",
    "webhook",
]
