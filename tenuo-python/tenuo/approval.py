"""
Human-in-the-loop approvals — ``SignedApproval`` and handlers.

Warrants define *what* an agent can do. **Warrant approval gates** (signed into
the token) define *when* a ``SignedApproval`` is required for a tool/args class.
``enforce_tool_call`` / the Rust authorizer collect and verify approvals.

Every approval is cryptographically signed. The approver's key produces a
``SignedApproval`` bound to the exact (warrant_id, tool, args, holder) via a
SHA-256 request hash. Verification is performed by the Rust core
(``verify_approvals``): signatures, approver set, hash, expiry, duplicates,
m-of-n threshold.

Use :func:`sign_approval` or built-in handlers such as :func:`cli_prompt` /
:func:`auto_approve` when a warrant approval gate fires or when integrating a
control plane that returns ``SignedApproval`` blobs.
"""

from __future__ import annotations

import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Awaitable, Dict, List, Optional, Protocol, Union

if TYPE_CHECKING:
    from tenuo_core import SignedApproval, SigningKey

logger = logging.getLogger("tenuo.approval")


# =============================================================================
# Approval Request
# =============================================================================


def _new_approval_request_id_bytes() -> bytes:
    """Opaque 16-byte correlation id (UUIDv7 when available, else UUIDv4)."""
    try:
        u7 = getattr(uuid, "uuid7", None)
        if u7 is not None:
            return u7().bytes  # type: ignore[union-attr,misc]
    except Exception:
        pass
    return uuid.uuid4().bytes


def warrant_expires_at_unix(warrant: Any) -> Optional[int]:
    """Best-effort Unix expiry from a Warrant-like object (RFC3339 string or int)."""
    exp = getattr(warrant, "expires_at", None)
    if exp is None:
        return None
    if callable(exp):
        exp = exp()
    if isinstance(exp, int):
        return int(exp)
    s = str(exp).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


@dataclass(frozen=True)
class ApprovalRequest:
    """Context passed to an approval handler when a warrant approval gate fires.

    The request_hash cryptographically binds this approval to the exact
    (warrant_id, tool, args, holder) tuple. Handlers must embed this hash
    in the ApprovalPayload they sign.

    Attributes:
        tool: Name of the tool requiring approval.
        arguments: Arguments the agent wants to pass.
        warrant_id: ID of the warrant authorizing this call.
        request_hash: SHA-256 hash binding approval to this specific call (32 bytes).
        holder_key: Public key of the warrant holder (participates in request_hash).
        request_id: 16-byte opaque id for control-plane idempotency / audit (optional).
        required_approvers: Warrant-configured approver keys when known (optional).
        min_approvals: Effective m-of-n threshold when known (optional).
        warrant_expires_at_unix: Warrant expiry as Unix seconds when known (optional).
        created_at_unix: When this request was constructed (optional).
    """

    tool: str
    arguments: Dict[str, Any]
    warrant_id: str
    request_hash: bytes
    holder_key: Optional[Any] = None
    request_id: Optional[bytes] = None
    required_approvers: Optional[List[Any]] = None
    min_approvals: Optional[int] = None
    warrant_expires_at_unix: Optional[int] = None
    created_at_unix: Optional[int] = None

    @staticmethod
    def for_warrant_gate(
        tool: str,
        arguments: Dict[str, Any],
        warrant: Any,
        request_hash: bytes,
        holder_key: Optional[Any] = None,
    ) -> "ApprovalRequest":
        """Build a request aligned with Rust ``approval::ApprovalRequest`` context."""
        warrant_id = getattr(warrant, "id", None) or ""
        req_approvers = getattr(warrant, "required_approvers", None)
        approvers_list: Optional[List[Any]] = None
        if callable(req_approvers):
            raw = req_approvers()
            if raw is not None:
                approvers_list = list(raw)
        min_ap = getattr(warrant, "approval_threshold", None)
        min_approvals: Optional[int] = None
        if callable(min_ap):
            min_approvals = int(min_ap())
        return ApprovalRequest(
            tool=tool,
            arguments=arguments,
            warrant_id=warrant_id,
            request_hash=request_hash,
            holder_key=holder_key,
            request_id=_new_approval_request_id_bytes(),
            required_approvers=approvers_list,
            min_approvals=min_approvals,
            warrant_expires_at_unix=warrant_expires_at_unix(warrant),
            created_at_unix=int(time.time()),
        )


# =============================================================================
# Exceptions
# =============================================================================


class ApprovalRequired(Exception):
    """Raised when an approval gate requires approval but no handler/approvals are set.

    This is not an authorization failure — the warrant permits the call, but a
    ``SignedApproval`` is required and was not provided.

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
# Approval Handler Protocol
# =============================================================================


class ApprovalHandler(Protocol):
    """Protocol for approval handlers.

    Handlers receive an ApprovalRequest and MUST return a SignedApproval
    (or a list for m-of-n). To deny, raise ApprovalDenied.
    There is no unsigned approval path.

    The handler is responsible for:
    1. Presenting the request to a human (or automated policy)
    2. If approved: creating an ApprovalPayload with the request_hash,
       signing it with the approver's SigningKey -> SignedApproval
    3. If denied: raising ApprovalDenied

    Return types:
    - Single approver: return ``SignedApproval``
    - M-of-N multi-sig: return ``List[SignedApproval]``

    Handlers can be sync or async -- the enforcement layer handles both.
    """

    def __call__(self, request: ApprovalRequest) -> Union[
        SignedApproval,
        List[SignedApproval],
        Awaitable[SignedApproval],
        Awaitable[List[SignedApproval]],
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

    TTL resolution: explicit ``ttl_seconds``, else 300 seconds (5 minutes).

    Args:
        request: The ApprovalRequest to approve.
        approver_key: The approver's SigningKey.
        external_id: Identity of the approver (e.g., email).
        ttl_seconds: How long the signed approval is valid. None uses 300s.

    Returns:
        A SignedApproval (from tenuo_core).
    """
    from tenuo_core import ApprovalPayload, SignedApproval

    if ttl_seconds is not None:
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be >= 1")
        effective_ttl = ttl_seconds
    else:
        effective_ttl = 300

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
        ttl_seconds: How long the signed approval is valid. None uses 300s.

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
        ttl_seconds: How long the signed approval is valid. None uses 300s.
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


def auto_deny(*, reason: str = "auto-denied") -> ApprovalHandler:
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
            "Implement a custom handler or use the control plane approval API."
        )

    return _handle


__all__ = [
    "warrant_expires_at_unix",
    "ApprovalRequest",
    "ApprovalRequired",
    "ApprovalDenied",
    "ApprovalTimeout",
    "ApprovalVerificationError",
    "ApprovalHandler",
    "sign_approval",
    "cli_prompt",
    "auto_approve",
    "auto_deny",
    "webhook",
]
