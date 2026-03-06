"""
Server-side MCP Warrant Verification for Tenuo.

Framework-agnostic helper for verifying Tenuo warrants inside MCP server tool
handlers. Works with fastmcp, the raw MCP SDK, or any custom server that
receives tool call arguments as a plain dict.

Usage pattern
-------------
1. Build an ``MCPVerifier`` once at server startup:

    from tenuo import Authorizer, CompiledMcpConfig, McpConfig, PublicKey
    from tenuo.mcp import MCPVerifier

    authorizer = Authorizer(
        trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_PUBLIC_KEY_HEX))]
    )
    config = CompiledMcpConfig.compile(McpConfig.from_file("mcp-config.yaml"))
    verifier = MCPVerifier(authorizer=authorizer, config=config)

2. Call ``verify()`` or ``verify_or_raise()`` inside each tool handler:

    # fastmcp example — tool receives _tenuo from the injecting client
    @mcp.tool()
    async def read_file(path: str, **kwargs) -> str:
        clean = verifier.verify_or_raise("read_file", {"path": path, **kwargs})
        return open(clean["path"]).read()

3. For raw JSON-RPC servers, handle errors explicitly:

    try:
        result = verifier.verify(tool_name, arguments)
        result.raise_if_denied()
    except MCPAuthorizationError as e:
        return {"jsonrpc": "2.0", "id": req_id, "error": e.to_jsonrpc_error()}
    execute_tool(result.clean_arguments)

``CompiledMcpConfig`` and PoP signatures
-----------------------------------------
When using ``CompiledMcpConfig`` for field-name extraction (e.g., mapping
``maxSize`` → ``max_size``), the PoP signature must be computed over the
**extracted** (renamed) constraint dict, not the raw MCP body.  Both the
client and server must share the same config so their constraint views agree.
``SecureMCPClient`` does this automatically when given a ``config_path``.

Warrant transport
-----------------
Clients inject warrants via ``SecureMCPClient(inject_warrant=True)``, which
embeds a ``_tenuo`` field in the tool arguments::

    {
      "path": "/data/log.txt",
      "_tenuo": {
        "warrant":   "<base64-encoded warrant>",
        "signature": "<base64-encoded PoP signature>",
        "approvals": ["<base64-encoded SignedApproval>", ...]  // optional
      }
    }

``MCPVerifier.verify()`` strips ``_tenuo`` before returning ``clean_arguments``,
so tool handlers never see the authorization envelope.

Approval gate flow
------------------
If a warrant embeds approval gates and the tool call triggers one::

    result = verifier.verify("transfer", arguments)
    # result.allowed             → False
    # result.is_approval_required → True
    # result.jsonrpc_error_code  → -32002

The client must obtain ``SignedApproval`` objects from authorized approvers and
re-submit the call with those approvals serialized into ``_tenuo.approvals``.

JSON-RPC error codes
--------------------
- ``-32602`` — Invalid params (missing required extraction field)
- ``-32001`` — Access denied (constraint violation, expired, bad signature …)
- ``-32002`` — Approval required (approval gate triggered, re-submit with approvals)
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..exceptions import (
    ApprovalGateTriggered,
    ConstraintViolation,
    ExpiredError,
    MissingSignature,
    SignatureInvalid,
    TenuoError,
    ToolNotAuthorized,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result and exception types
# ---------------------------------------------------------------------------


@dataclass
class MCPVerificationResult:
    """Result of server-side MCP warrant verification.

    Returned by :class:`MCPVerifier` and :func:`verify_mcp_call`.

    On success ``allowed`` is ``True`` and ``clean_arguments`` is safe to
    pass directly to the tool handler.  On failure ``allowed`` is ``False``
    and ``denial_reason`` / ``jsonrpc_error_code`` carry the details.
    """

    allowed: bool
    """Whether the tool call is authorized."""

    tool: str
    """MCP tool name."""

    clean_arguments: Dict[str, Any]
    """Tool arguments with ``_tenuo`` stripped — safe to pass to the tool handler."""

    constraints: Dict[str, Any]
    """Constraint values that were checked against the warrant."""

    warrant_id: Optional[str] = field(default=None)
    """Warrant ID for audit logging, extracted from the warrant when available."""

    denial_reason: Optional[str] = field(default=None)
    """Human-readable denial reason, populated when ``allowed`` is ``False``."""

    jsonrpc_error_code: Optional[int] = field(default=None)
    """JSON-RPC 2.0 error code:

    - ``-32602`` — Invalid params (extraction failed, missing required field)
    - ``-32001`` — Access denied (constraint violation, expired, bad signature …)
    - ``-32002`` — Approval required (approval gate triggered)
    """

    @property
    def is_approval_required(self) -> bool:
        """``True`` when an approval gate fired and approvals must be supplied."""
        return self.jsonrpc_error_code == -32002

    def raise_if_denied(self) -> "MCPVerificationResult":
        """Raise :exc:`MCPAuthorizationError` if this result represents a denial.

        Returns *self* when the call is authorized, enabling fluent chaining::

            clean = verifier.verify("read_file", arguments).raise_if_denied().clean_arguments
        """
        if not self.allowed:
            raise MCPAuthorizationError(self)
        return self

    def to_jsonrpc_error(self) -> Dict[str, Any]:
        """Return a JSON-RPC 2.0 ``error`` object for this denial.

        Only meaningful when ``allowed`` is ``False``::

            return {"jsonrpc": "2.0", "id": req_id, "error": result.to_jsonrpc_error()}
        """
        return {
            "code": self.jsonrpc_error_code or -32001,
            "message": self.denial_reason or "Authorization denied",
        }


class MCPAuthorizationError(Exception):
    """Raised by :meth:`MCPVerificationResult.raise_if_denied` on a denial.

    Carries the full :class:`MCPVerificationResult` for structured error
    handling and JSON-RPC response construction.
    """

    def __init__(self, result: MCPVerificationResult) -> None:
        self.result = result
        super().__init__(result.denial_reason or "Authorization denied")

    @property
    def jsonrpc_error_code(self) -> int:
        """JSON-RPC 2.0 error code for this denial."""
        return self.result.jsonrpc_error_code or -32001

    def to_jsonrpc_error(self) -> Dict[str, Any]:
        """Return a JSON-RPC 2.0 ``error`` object for this denial."""
        return self.result.to_jsonrpc_error()


# ---------------------------------------------------------------------------
# MCPVerifier
# ---------------------------------------------------------------------------


class MCPVerifier:
    """Server-side Tenuo warrant verifier for MCP tool calls.

    Framework-agnostic — works with fastmcp, the raw MCP SDK, or any server
    that receives tool call arguments as a plain Python dict.  Construct once
    at startup and reuse across every tool call.

    Basic setup (no extraction config):

        from tenuo_core import Authorizer, PublicKey
        from tenuo.mcp import MCPVerifier

        authorizer = Authorizer(
            trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
        )
        verifier = MCPVerifier(authorizer=authorizer)

    With extraction config (recommended — maps tool argument field names to
    warrant constraint names):

        from tenuo_core import Authorizer, CompiledMcpConfig, McpConfig, PublicKey

        authorizer = Authorizer(trusted_roots=[...])
        config = CompiledMcpConfig.compile(McpConfig.from_file("mcp-config.yaml"))
        verifier = MCPVerifier(authorizer=authorizer, config=config)

    fastmcp server example:

        @mcp.tool()
        async def read_file(path: str, **kwargs) -> str:
            clean = verifier.verify_or_raise("read_file", {"path": path, **kwargs})
            return open(clean["path"]).read()

    Approval-gate flow:

        result = verifier.verify("transfer", arguments)
        if result.is_approval_required:
            # Client must obtain approvals and re-submit with _tenuo.approvals
            return jsonrpc_error(-32002, result.denial_reason)
    """

    def __init__(
        self,
        authorizer: Any,
        config: Optional[Any] = None,
        require_warrant: bool = True,
    ) -> None:
        """
        Args:
            authorizer: ``tenuo_core.Authorizer`` configured with trusted issuer
                public keys. Build one with
                ``Authorizer(trusted_roots=[issuer_public_key])``.
            config: Optional ``tenuo_core.CompiledMcpConfig`` for constraint
                extraction.  When provided, argument field names are mapped to
                warrant constraint names according to the YAML config (type
                coercion, defaults, and nested-path extraction all apply).
                When omitted, raw tool arguments are used directly as
                constraints — the field name must then match the warrant
                constraint name exactly.
            require_warrant: If ``True`` (default), calls that do not include
                ``_tenuo.warrant`` are denied with ``-32001``.  Set ``False``
                only in mixed deployments where some tool calls legitimately
                arrive without a Tenuo warrant (e.g., during gradual rollout).
        """
        self._authorizer = authorizer
        self._config = config
        self._require_warrant = require_warrant

    def verify(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]],
    ) -> MCPVerificationResult:
        """Verify a tool call against the embedded Tenuo warrant.

        Extracts the warrant from ``_tenuo.warrant``, verifies the
        Proof-of-Possession signature, satisfies guards with any pre-supplied
        approvals from ``_tenuo.approvals``, and checks all constraints.

        This method never raises — all failures are returned as a denial result.

        Args:
            tool_name: The MCP tool name being called.
            arguments: Full tool arguments dict, including ``_tenuo`` if the
                client used ``inject_warrant=True``.  ``None`` is treated as
                an empty dict.

        Returns:
            :class:`MCPVerificationResult` with ``allowed=True`` on success,
            or ``allowed=False`` with ``denial_reason`` and
            ``jsonrpc_error_code`` on failure.
        """
        args: Dict[str, Any] = arguments or {}

        # ------------------------------------------------------------------
        # Step 1: extract constraints and _tenuo envelope
        # ------------------------------------------------------------------
        clean_arguments: Dict[str, Any]
        constraints: Dict[str, Any]
        warrant_b64: Optional[str]
        signature_b64: Optional[str]
        approvals_b64: List[str]

        if self._config is not None:
            try:
                extraction = self._config.extract_constraints(tool_name, args)
            except Exception as exc:
                # ExtractionError — missing required field or unknown tool
                clean_arguments = {k: v for k, v in args.items() if k != "_tenuo"}
                return MCPVerificationResult(
                    allowed=False,
                    tool=tool_name,
                    clean_arguments=clean_arguments,
                    constraints={},
                    denial_reason=str(exc),
                    jsonrpc_error_code=-32602,
                )
            clean_arguments = {k: v for k, v in args.items() if k != "_tenuo"}
            constraints = dict(extraction.constraints)
            warrant_b64 = extraction.warrant_base64
            signature_b64 = extraction.signature_base64
            # ExtractionResult doesn't expose approvals — read from raw _tenuo
            tenuo_raw = args.get("_tenuo")
            raw_approvals = tenuo_raw.get("approvals") if isinstance(tenuo_raw, dict) else None
            approvals_b64 = list(raw_approvals) if isinstance(raw_approvals, list) else []
        else:
            # Raw mode: strip _tenuo, use remaining arguments as constraints
            clean_arguments = {k: v for k, v in args.items() if k != "_tenuo"}
            constraints = dict(clean_arguments)
            tenuo = args.get("_tenuo")
            if isinstance(tenuo, dict):
                warrant_b64 = tenuo.get("warrant")
                signature_b64 = tenuo.get("signature")
                raw_approvals = tenuo.get("approvals")
                approvals_b64 = list(raw_approvals) if isinstance(raw_approvals, list) else []
            else:
                warrant_b64 = None
                signature_b64 = None
                approvals_b64 = []

        # ------------------------------------------------------------------
        # Step 2: handle missing warrant
        # ------------------------------------------------------------------
        if not warrant_b64:
            if self._require_warrant:
                return MCPVerificationResult(
                    allowed=False,
                    tool=tool_name,
                    clean_arguments=clean_arguments,
                    constraints=constraints,
                    denial_reason=(
                        "No warrant provided. Set inject_warrant=True on the "
                        "SecureMCPClient, or include _tenuo.warrant in tool arguments."
                    ),
                    jsonrpc_error_code=-32001,
                )
            # require_warrant=False — unauthenticated call allowed by policy
            logger.debug(
                "Unauthenticated call allowed for '%s' (require_warrant=False)", tool_name
            )
            return MCPVerificationResult(
                allowed=True,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
            )

        # ------------------------------------------------------------------
        # Step 3: decode warrant
        # ------------------------------------------------------------------
        try:
            from tenuo_core import Warrant

            warrant = Warrant.from_base64(warrant_b64)
        except Exception as exc:
            return MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                denial_reason=f"Malformed warrant: {exc}",
                jsonrpc_error_code=-32001,
            )

        warrant_id: Optional[str] = getattr(warrant, "id", None)

        # ------------------------------------------------------------------
        # Step 4: decode PoP signature
        # ------------------------------------------------------------------
        pop_sig: Optional[bytes] = None
        if signature_b64:
            try:
                pop_sig = base64.b64decode(signature_b64)
            except Exception as exc:
                return MCPVerificationResult(
                    allowed=False,
                    tool=tool_name,
                    clean_arguments=clean_arguments,
                    constraints=constraints,
                    warrant_id=warrant_id,
                    denial_reason=f"Malformed signature: {exc}",
                    jsonrpc_error_code=-32001,
                )

        # ------------------------------------------------------------------
        # Step 5: decode approvals
        # ------------------------------------------------------------------
        approvals: List[Any] = []
        for a_b64 in approvals_b64:
            try:
                from tenuo_core import SignedApproval

                approvals.append(SignedApproval.from_bytes(base64.b64decode(a_b64)))
            except Exception as exc:
                return MCPVerificationResult(
                    allowed=False,
                    tool=tool_name,
                    clean_arguments=clean_arguments,
                    constraints=constraints,
                    warrant_id=warrant_id,
                    denial_reason=f"Malformed approval: {exc}",
                    jsonrpc_error_code=-32001,
                )

        # ------------------------------------------------------------------
        # Step 6: authorize
        # ------------------------------------------------------------------
        try:
            self._authorizer.authorize_one(
                warrant, tool_name, constraints, pop_sig, approvals
            )
        except ApprovalGateTriggered:
            logger.info(
                "Approval required for '%s' (warrant=%s) — approvals required",
                tool_name,
                warrant_id,
            )
            return MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                warrant_id=warrant_id,
                denial_reason=(
                    f"Approval required for '{tool_name}'. "
                    "Re-submit the call with approvals in _tenuo.approvals."
                ),
                jsonrpc_error_code=-32002,
            )
        except (
            ConstraintViolation,
            ExpiredError,
            MissingSignature,
            SignatureInvalid,
            ToolNotAuthorized,
        ) as exc:
            logger.info(
                "MCP call denied for '%s' (warrant=%s): %s",
                tool_name,
                warrant_id,
                exc,
            )
            return MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                warrant_id=warrant_id,
                denial_reason=f"Access denied: {exc}",
                jsonrpc_error_code=-32001,
            )
        except TenuoError as exc:
            logger.info(
                "MCP call denied for '%s' (warrant=%s): %s",
                tool_name,
                warrant_id,
                exc,
            )
            return MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                warrant_id=warrant_id,
                denial_reason=f"Access denied: {exc}",
                jsonrpc_error_code=-32001,
            )
        except Exception as exc:
            logger.error(
                "Unexpected error during MCP verification for '%s': %s",
                tool_name,
                exc,
                exc_info=True,
            )
            return MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                warrant_id=warrant_id,
                denial_reason=f"Internal verification error: {exc}",
                jsonrpc_error_code=-32001,
            )

        logger.debug("MCP call authorized for '%s' (warrant=%s)", tool_name, warrant_id)
        return MCPVerificationResult(
            allowed=True,
            tool=tool_name,
            clean_arguments=clean_arguments,
            constraints=constraints,
            warrant_id=warrant_id,
        )

    def verify_or_raise(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Verify and return clean arguments, or raise on any denial.

        Convenience wrapper around ``verify(...).raise_if_denied().clean_arguments``.

        Args:
            tool_name: The MCP tool name.
            arguments: Full tool arguments dict, including ``_tenuo``.

        Returns:
            Clean arguments dict (``_tenuo`` stripped) if authorized.

        Raises:
            MCPAuthorizationError: If the call is not authorized.

        Example::

            @mcp.tool()
            async def read_file(path: str, **kwargs) -> str:
                clean = verifier.verify_or_raise("read_file", {"path": path, **kwargs})
                return open(clean["path"]).read()
        """
        return self.verify(tool_name, arguments).raise_if_denied().clean_arguments


# ---------------------------------------------------------------------------
# Standalone convenience function
# ---------------------------------------------------------------------------


def verify_mcp_call(
    tool_name: str,
    arguments: Optional[Dict[str, Any]],
    *,
    authorizer: Any,
    config: Optional[Any] = None,
    require_warrant: bool = True,
) -> MCPVerificationResult:
    """Verify a single MCP tool call — convenience wrapper around :class:`MCPVerifier`.

    For servers that handle only a few tools, this avoids the boilerplate of
    constructing an ``MCPVerifier`` explicitly.  For high-throughput servers
    prefer constructing ``MCPVerifier`` once at startup and reusing it.

    Args:
        tool_name: The MCP tool name being called.
        arguments: Full tool arguments dict, including ``_tenuo`` if the client
            injected a warrant.  ``None`` is treated as an empty dict.
        authorizer: ``tenuo_core.Authorizer`` configured with trusted issuer keys.
        config: Optional ``tenuo_core.CompiledMcpConfig`` for constraint extraction.
        require_warrant: If ``True`` (default), calls without ``_tenuo.warrant``
            are denied.

    Returns:
        :class:`MCPVerificationResult`.

    Example::

        from tenuo_core import Authorizer, PublicKey
        from tenuo.mcp import verify_mcp_call

        authorizer = Authorizer(
            trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
        )

        result = verify_mcp_call("read_file", arguments, authorizer=authorizer)
        result.raise_if_denied()
        return read_file(result.clean_arguments["path"])
    """
    return MCPVerifier(
        authorizer=authorizer,
        config=config,
        require_warrant=require_warrant,
    ).verify(tool_name, arguments)


__all__ = [
    "MCPVerificationResult",
    "MCPAuthorizationError",
    "MCPVerifier",
    "verify_mcp_call",
]
