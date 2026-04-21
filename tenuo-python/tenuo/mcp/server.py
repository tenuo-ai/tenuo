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

2. Call ``verify()`` or ``verify_or_raise()`` inside each tool handler.

   For raw ``@server.call_tool`` handlers that receive the full request object,
   pass ``req.params._meta`` so the verifier can read the warrant from
   ``params._meta["tenuo"]``::

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list:
        # ``req`` is the full CallToolRequest — use the low-level handler form
        meta = req.params._meta  # MCP SDK exposes this on the raw request
        result = verifier.verify(name, arguments, meta=meta)
        result.raise_if_denied()
        return execute_tool(result.clean_arguments)

   Note: ``fastmcp`` does not pass ``_meta`` into Python tool parameters. Use
   :class:`tenuo.mcp.fastmcp_middleware.TenuoMiddleware` (re-exported as
   ``tenuo.mcp.TenuoMiddleware`` when the ``tenuo[fastmcp]`` extra is installed) to verify using
   the same :class:`MCPVerifier` path while reading metadata from the wire
   request context, or use the raw MCP SDK handler form above.

3. For raw JSON-RPC servers, handle errors explicitly:

    try:
        result = verifier.verify(tool_name, arguments, meta=meta)
        result.raise_if_denied()
    except MCPAuthorizationError as e:
        return {"jsonrpc": "2.0", "id": req_id, "error": e.to_jsonrpc_error()}
    execute_tool(result.clean_arguments)

``CompiledMcpConfig`` and PoP signatures
-----------------------------------------
The PoP signature is **always** computed over the raw MCP ``arguments``
dict (with :func:`tenuo._pop_canonicalize.strip_none_values` applied).
``CompiledMcpConfig`` extraction — field renaming, coercion, defaults — runs
separately and feeds only the constraint-matching path. This means a server
can enforce constraint mappings independently of whether the client has the
same config loaded: PoP parity depends only on the wire args, not on the
extraction schema. ``SecureMCPClient`` signs the raw wire args automatically.

Warrant transport
-----------------
Clients inject warrants via ``SecureMCPClient(inject_warrant=True)``, which
embeds Tenuo metadata in ``params._meta`` — the MCP spec's designated
extension point::

    {
      "name": "read_file",
      "arguments": {"path": "/data/log.txt"},
      "_meta": {
        "tenuo": {
          "warrant":   "<base64>",
          "signature": "<base64>",
          "approvals": ["<base64>", ...]
        }
      }
    }

Tool arguments are never polluted with authorization metadata.

On the server, ``MCPVerifier.verify()`` accepts the ``_meta`` dict via its
``meta`` parameter.  Pass ``req.params._meta`` when using a raw
``@server.call_tool`` handler that receives the full ``CallToolRequest``.

Approval gate flow
------------------
If a warrant embeds approval gates and the tool call triggers one::

    result = verifier.verify("transfer", arguments)
    # result.allowed             → False
    # result.is_approval_required → True
    # result.jsonrpc_error_code  → -32002

The client must obtain ``SignedApproval`` objects from authorized approvers and
re-submit the call with those approvals serialized into ``_meta.tenuo.approvals``.

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

from .._pop_canonicalize import strip_none_values
from ..exceptions import (
    ApprovalGateTriggered,
    ConstraintViolation,
    ExpiredError,
    MissingSignature,
    SignatureInvalid,
    SignatureMismatch,
    TenuoError,
    ToolNotAuthorized,
)

logger = logging.getLogger(__name__)

MAX_WARRANT_B64_BYTES = 64 * 1024
MAX_SIGNATURE_B64_BYTES = 4 * 1024
MAX_APPROVAL_B64_BYTES = 8 * 1024
MAX_APPROVALS_COUNT = 64


def _access_denial_reason(exc: BaseException) -> str:
    """Human-facing denial with hints for the most common integration mistakes."""
    base = f"Access denied: {exc}"
    if isinstance(exc, SignatureInvalid):
        return (
            f"{base} PoP covers the raw tool arguments (with None values stripped). "
            "Check that the client signs with the same key bound in the warrant and "
            "that the timestamp has not drifted beyond the PoP window."
        )
    if isinstance(exc, SignatureMismatch):
        return (
            f"{base} PoP was verified structurally but does not match this warrant/holder "
            "or the raw wire-args view. Confirm the client and server agree on argument "
            "canonicalization (both apply tenuo._pop_canonicalize.strip_none_values)."
        )
    if isinstance(exc, MissingSignature):
        return f"{base} Ensure the client sends a PoP signature in _meta.tenuo.signature."
    return base


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
    """Tool arguments safe to pass to the tool handler."""

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

    request_hash: Optional[str] = field(default=None)
    """Rust-computed request hash (hex), populated when an approval gate fires (``-32002``).

    Clients need this to submit the correct hash to the approval service without
    re-deriving it from ``(warrant_id, tool, args, holder_key)``.
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

        When ``request_hash`` is present (``-32002``), the hash is included in
        ``error.data`` so clients can pass it to the approval service directly.
        """
        error: Dict[str, Any] = {
            "code": self.jsonrpc_error_code or -32001,
            "message": self.denial_reason or "Authorization denied",
        }
        if self.request_hash:
            error["data"] = {"request_hash": self.request_hash}
        return error


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


class MCPApprovalRequired(MCPAuthorizationError):
    """Server returned ``-32002``: an approval gate fired.

    Raised by :class:`~tenuo.mcp.client.SecureMCPClient` when a ``call_tool``
    response carries the ``-32002`` error code, allowing callers to handle
    approval-required flows with a typed ``except`` instead of string-matching::

        try:
            result = await client.call_tool("transfer", {"amount": 500})
        except MCPApprovalRequired as e:
            approvals = await collect_approvals(e.tool_name)
            result = await client.call_tool("transfer", {"amount": 500}, approvals=approvals)
    """

    def __init__(
        self,
        tool_name: str,
        message: str,
        *,
        result: Optional[MCPVerificationResult] = None,
        raw_error: Optional[Any] = None,
        request_hash: Optional[str] = None,
    ) -> None:
        self.tool_name = tool_name
        self.raw_error = raw_error
        self.request_hash = request_hash
        if result is not None:
            if request_hash and not result.request_hash:
                result = MCPVerificationResult(
                    allowed=result.allowed,
                    tool=result.tool,
                    clean_arguments=result.clean_arguments,
                    constraints=result.constraints,
                    warrant_id=result.warrant_id,
                    denial_reason=result.denial_reason,
                    jsonrpc_error_code=result.jsonrpc_error_code,
                    request_hash=request_hash,
                )
            super().__init__(result)
        else:
            _result = MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments={},
                constraints={},
                denial_reason=message,
                jsonrpc_error_code=-32002,
                request_hash=request_hash,
            )
            super().__init__(_result)


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
            # Client must obtain approvals and re-submit with _meta.tenuo.approvals
            return jsonrpc_error(-32002, result.denial_reason)
    """

    def __init__(
        self,
        authorizer: Any,
        config: Optional[Any] = None,
        require_warrant: bool = True,
        control_plane: Optional[Any] = None,
        nonce_store: Optional[Any] = None,
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
            require_warrant: If ``True`` (default), calls without a warrant
                in ``_meta.tenuo`` are denied with ``-32001``.  Set ``False``
                only in mixed deployments where some tool calls legitimately
                arrive without a Tenuo warrant (e.g., during gradual rollout).
            nonce_store: Optional ``tenuo.nonce.NonceStore`` for PoP replay
                prevention.  When provided (recommended for mutating tools),
                each PoP signature is checked against the store; exact replays
                within the store's TTL window are rejected.  Use
                ``enable_default_nonce_store()`` at startup or pass an explicit
                ``NonceStore(backend=RedisNonceBackend(...))`` for distributed
                deployments.
        """
        self._authorizer = authorizer
        self._config = config
        self._require_warrant = require_warrant
        if control_plane is None:
            from ..control_plane import get_or_create
            control_plane = get_or_create()
        self._control_plane = control_plane
        self._nonce_store = nonce_store

    def verify(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]],
        meta: Optional[Dict[str, Any]] = None,
    ) -> MCPVerificationResult:
        """Verify a tool call against the embedded Tenuo warrant.

        Extracts the warrant and PoP signature, verifies them, satisfies any
        approval gates, and checks all constraints.

        Authorization metadata is read from ``params._meta["tenuo"]``.  Pass
        the ``_meta`` dict when your server framework exposes the full
        ``CallToolRequest`` (e.g. raw ``@server.call_tool`` handlers).

        This method never raises — all failures are returned as a denial result.

        Args:
            tool_name: The MCP tool name being called.
            arguments: Tool arguments dict.  ``None`` is treated as an empty
                dict.
            meta: Contents of ``params._meta`` from the MCP request.
                Must contain ``meta["tenuo"]`` with warrant and PoP signature.

        Returns:
            :class:`MCPVerificationResult` with ``allowed=True`` on success,
            or ``allowed=False`` with ``denial_reason`` and
            ``jsonrpc_error_code`` on failure.
        """
        args: Dict[str, Any] = arguments or {}
        # PoP bytes cover the wire-args view. Both client and server apply
        # strip_none_values to that view so optional arguments with None
        # defaults don't crash the Rust canonicalizer and don't silently
        # diverge the signed-bytes shape between sides.
        pop_args: Dict[str, Any] = strip_none_values(args)

        def _emit_and_return(
            result: MCPVerificationResult,
            chain_result: Any = None,
            latency_us: int = 0,
        ) -> MCPVerificationResult:
            if self._control_plane:
                try:
                    self._control_plane.emit_for_enforcement(
                        result, chain_result=chain_result, latency_us=latency_us
                    )
                except Exception:
                    logger.warning("Control plane emission failed for '%s'; audit event lost", result.tool, exc_info=True)
            return result

        # ------------------------------------------------------------------
        # Step 1: extract Tenuo envelope from params._meta
        # ------------------------------------------------------------------
        tenuo_envelope: Dict[str, Any] = {}
        if meta is not None and isinstance(meta.get("tenuo"), dict):
            tenuo_envelope = meta["tenuo"]

        clean_arguments: Dict[str, Any]
        constraints: Dict[str, Any]
        warrant_b64: Optional[str]
        signature_b64: Optional[str]
        approvals_b64: List[str]

        approvals_b64 = list(tenuo_envelope.get("approvals") or [])

        if self._config is not None:
            try:
                extraction = self._config.extract_constraints(tool_name, args)
            except Exception as exc:
                # ExtractionError — missing required field or unknown tool
                return _emit_and_return(MCPVerificationResult(
                    allowed=False,
                    tool=tool_name,
                    clean_arguments=dict(args),
                    constraints={},
                    denial_reason=str(exc),
                    jsonrpc_error_code=-32602,
                ))
            clean_arguments = dict(args)
            # Strip None from constraints too: extraction may propagate None
            # defaults, which the Rust canonicalizer rejects.
            constraints = strip_none_values(dict(extraction.constraints))

            # Note: PoP covers the raw wire args (pop_args), not the extracted
            # constraint view. That means every wire arg is covered by the
            # signature regardless of extraction mapping. The extraction is
            # only used for warrant-constraint matching.
            warrant_b64 = tenuo_envelope.get("warrant")
            signature_b64 = tenuo_envelope.get("signature")
        else:
            # Raw mode: arguments are the constraints. Strip None there too.
            clean_arguments = dict(args)
            constraints = strip_none_values(dict(args))
            warrant_b64 = tenuo_envelope.get("warrant")
            signature_b64 = tenuo_envelope.get("signature")

        # ------------------------------------------------------------------
        # Step 2: handle missing warrant
        # ------------------------------------------------------------------
        if not warrant_b64:
            if self._require_warrant:
                return _emit_and_return(MCPVerificationResult(
                    allowed=False,
                    tool=tool_name,
                    clean_arguments=clean_arguments,
                    constraints=constraints,
                    denial_reason=(
                        "No warrant provided. Use SecureMCPClient(inject_warrant=True), "
                        "or pass params._meta with tenuo metadata into MCPVerifier.verify. "
                        "On FastMCP, register TenuoMiddleware(verifier) so _meta from the "
                        "wire request reaches the verifier (tool handlers alone do not "
                        "receive _meta)."
                    ),
                    jsonrpc_error_code=-32001,
                ))
            # require_warrant=False — unauthenticated call allowed by policy.
            logger.warning(
                "Unauthenticated MCP call allowed for '%s' (require_warrant=False). "
                "Set require_warrant=True once rollout is complete.",
                tool_name,
            )
            return _emit_and_return(MCPVerificationResult(
                allowed=True,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
            ))

        # ------------------------------------------------------------------
        # Step 2b: payload size limits (DoS prevention)
        # ------------------------------------------------------------------
        if warrant_b64 and len(warrant_b64) > MAX_WARRANT_B64_BYTES:
            return _emit_and_return(MCPVerificationResult(
                allowed=False, tool=tool_name,
                clean_arguments=clean_arguments, constraints=constraints,
                denial_reason=(
                    f"Warrant payload too large ({len(warrant_b64)} bytes, "
                    f"limit {MAX_WARRANT_B64_BYTES})"
                ),
                jsonrpc_error_code=-32602,
            ))
        if signature_b64 and len(signature_b64) > MAX_SIGNATURE_B64_BYTES:
            return _emit_and_return(MCPVerificationResult(
                allowed=False, tool=tool_name,
                clean_arguments=clean_arguments, constraints=constraints,
                denial_reason=(
                    f"Signature payload too large ({len(signature_b64)} bytes, "
                    f"limit {MAX_SIGNATURE_B64_BYTES})"
                ),
                jsonrpc_error_code=-32602,
            ))
        if len(approvals_b64) > MAX_APPROVALS_COUNT:
            return _emit_and_return(MCPVerificationResult(
                allowed=False, tool=tool_name,
                clean_arguments=clean_arguments, constraints=constraints,
                denial_reason=(
                    f"Too many approvals ({len(approvals_b64)}, "
                    f"limit {MAX_APPROVALS_COUNT})"
                ),
                jsonrpc_error_code=-32602,
            ))
        for _ab64 in approvals_b64:
            if isinstance(_ab64, str) and len(_ab64) > MAX_APPROVAL_B64_BYTES:
                return _emit_and_return(MCPVerificationResult(
                    allowed=False, tool=tool_name,
                    clean_arguments=clean_arguments, constraints=constraints,
                    denial_reason=(
                        f"Individual approval payload too large "
                        f"({len(_ab64)} bytes, limit {MAX_APPROVAL_B64_BYTES})"
                    ),
                    jsonrpc_error_code=-32602,
                ))

        # ------------------------------------------------------------------
        # Step 3: decode warrant (single warrant or WarrantStack)
        # ------------------------------------------------------------------
        _chain_parents: Optional[List[Any]] = None
        try:
            from tenuo_core import Warrant

            # Try WarrantStack (CBOR array) first, then single warrant.
            # Only fall back to single-warrant decode when the bytes genuinely
            # are not a CBOR array — not when the stack is corrupted.
            stack_decoded = False
            try:
                from tenuo_core import decode_warrant_stack_base64
                stack_warrants = decode_warrant_stack_base64(warrant_b64)
                stack_decoded = True
                if len(stack_warrants) > 1:
                    warrant = stack_warrants[-1]
                    _chain_parents = stack_warrants[:-1]
                elif len(stack_warrants) == 1:
                    warrant = stack_warrants[0]
                else:
                    raise ValueError("Empty warrant stack")
            except ImportError:
                # decode_warrant_stack_base64 not available in this build
                warrant = Warrant.from_base64(warrant_b64)
            except Exception as stack_exc:
                if stack_decoded:
                    # Stack decoded structurally but contents are invalid
                    # (empty, corrupt warrant inside array) — don't silently
                    # fall back to single-warrant; propagate the real error.
                    raise
                # Not a CBOR array — try single warrant
                try:
                    warrant = Warrant.from_base64(warrant_b64)
                except Exception:
                    # Neither format worked; report the stack error since it
                    # was tried first and is the preferred format.
                    raise stack_exc from None
        except Exception as exc:
            return _emit_and_return(MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                denial_reason=f"Malformed warrant: {exc}",
                jsonrpc_error_code=-32001,
            ))

        warrant_id: Optional[str] = getattr(warrant, "id", None)

        # ------------------------------------------------------------------
        # Step 4: decode PoP signature
        # ------------------------------------------------------------------
        pop_sig: Optional[bytes] = None
        if signature_b64:
            try:
                pop_sig = base64.b64decode(signature_b64)
            except Exception as exc:
                return _emit_and_return(MCPVerificationResult(
                    allowed=False,
                    tool=tool_name,
                    clean_arguments=clean_arguments,
                    constraints=constraints,
                    warrant_id=warrant_id,
                    denial_reason=f"Malformed signature: {exc}",
                    jsonrpc_error_code=-32001,
                ))

        # ------------------------------------------------------------------
        # Step 5: decode approvals
        # ------------------------------------------------------------------
        approvals: List[Any] = []
        for a_b64 in approvals_b64:
            try:
                from tenuo_core import SignedApproval

                approvals.append(SignedApproval.from_bytes(base64.b64decode(a_b64)))
            except Exception as exc:
                return _emit_and_return(MCPVerificationResult(
                    allowed=False,
                    tool=tool_name,
                    clean_arguments=clean_arguments,
                    constraints=constraints,
                    warrant_id=warrant_id,
                    denial_reason=f"Malformed approval: {exc}",
                    jsonrpc_error_code=-32001,
                ))

        # ------------------------------------------------------------------
        # Step 6: authorize
        # ------------------------------------------------------------------
        import time
        start_ns = time.perf_counter_ns()
        chain_result = None
        result: MCPVerificationResult

        try:
            if _chain_parents:
                full_chain = list(_chain_parents) + [warrant]
                chain_result = self._authorizer.check_chain_with_pop_args(
                    full_chain,
                    tool_name,
                    pop_args,
                    constraints,
                    pop_sig,
                    approvals,
                )
            else:
                chain_result = self._authorizer.authorize_one_with_pop_args(
                    warrant,
                    tool_name,
                    pop_args,
                    constraints,
                    pop_sig,
                    approvals,
                )

            # ── Replay prevention ────────────────────────────────────────
            # Ed25519 PoP is deterministic, so an exact replay of the same
            # (key, tool, args, timestamp) triple produces the same bytes.
            # Reject duplicates within the nonce store's TTL window.
            _ns = self._nonce_store
            if _ns is None:
                from ..nonce import get_default_nonce_store as _get_ns
                _ns = _get_ns()
            if _ns is not None and pop_sig is not None and not _ns.check_and_record(pop_sig):
                logger.warning(
                    "PoP replay rejected for '%s' (warrant=%s)",
                    tool_name,
                    warrant_id,
                )
                return _emit_and_return(
                    MCPVerificationResult(
                        allowed=False,
                        tool=tool_name,
                        clean_arguments=clean_arguments,
                        constraints=constraints,
                        warrant_id=warrant_id,
                        denial_reason=(
                            "PoP replay detected — this exact authorization token "
                            "was already consumed. Generate a new PoP with a fresh "
                            "timestamp for each tool call."
                        ),
                        jsonrpc_error_code=-32001,
                    ),
                    latency_us=(time.perf_counter_ns() - start_ns) // 1000,
                )

            logger.debug("MCP call authorized for '%s' (warrant=%s)", tool_name, warrant_id)
            result = MCPVerificationResult(
                allowed=True,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                warrant_id=warrant_id,
            )
        except ApprovalGateTriggered as gate_exc:
            logger.info(
                "Approval required for '%s' (warrant=%s) — approvals required",
                tool_name,
                warrant_id,
            )
            result = MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                warrant_id=warrant_id,
                request_hash=gate_exc.request_hash or None,
                denial_reason=(
                    f"Approval required for '{tool_name}'. "
                    "Re-submit the call with approvals in _meta.tenuo.approvals."
                ),
                jsonrpc_error_code=-32002,
            )
        except (
            ConstraintViolation,
            ExpiredError,
            MissingSignature,
            SignatureInvalid,
            SignatureMismatch,
            ToolNotAuthorized,
        ) as exc:
            logger.info(
                "MCP call denied for '%s' (warrant=%s): %s",
                tool_name,
                warrant_id,
                exc,
            )
            result = MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                warrant_id=warrant_id,
                denial_reason=_access_denial_reason(exc),
                jsonrpc_error_code=-32001,
            )
        except TenuoError as exc:
            logger.info(
                "MCP call denied for '%s' (warrant=%s): %s",
                tool_name,
                warrant_id,
                exc,
            )
            result = MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                warrant_id=warrant_id,
                denial_reason=_access_denial_reason(exc),
                jsonrpc_error_code=-32001,
            )
        except Exception as exc:
            logger.error(
                "Unexpected error during MCP verification for '%s': %s",
                tool_name,
                exc,
                exc_info=True,
            )
            result = MCPVerificationResult(
                allowed=False,
                tool=tool_name,
                clean_arguments=clean_arguments,
                constraints=constraints,
                warrant_id=warrant_id,
                denial_reason=f"Internal verification error: {exc}",
                jsonrpc_error_code=-32001,
            )

        latency_us = (time.perf_counter_ns() - start_ns) // 1000
        return _emit_and_return(result, chain_result=chain_result, latency_us=latency_us)

    def verify_or_raise(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]],
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Verify and return clean arguments, or raise on any denial.

        Convenience wrapper around ``verify(...).raise_if_denied().clean_arguments``.

        Args:
            tool_name: The MCP tool name.
            arguments: Tool arguments dict.
            meta: Contents of ``params._meta`` from the MCP request, when
                available.  See :meth:`verify` for extraction priority.

        Returns:
            Clean arguments dict if authorized.

        Raises:
            MCPAuthorizationError: If the call is not authorized.

        Example::

            @mcp.tool()
            async def read_file(path: str, **kwargs) -> str:
                clean = verifier.verify_or_raise("read_file", {"path": path, **kwargs})
                return open(clean["path"]).read()
        """
        return self.verify(tool_name, arguments, meta=meta).raise_if_denied().clean_arguments


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
    meta: Optional[Dict[str, Any]] = None,
    control_plane: Optional[Any] = None,
) -> MCPVerificationResult:
    """Verify a single MCP tool call — convenience wrapper around :class:`MCPVerifier`.

    For servers that handle only a few tools, this avoids the boilerplate of
    constructing an ``MCPVerifier`` explicitly.  For high-throughput servers
    prefer constructing ``MCPVerifier`` once at startup and reusing it.

    Args:
        tool_name: The MCP tool name being called.
        arguments: Tool arguments dict.  ``None`` is treated as an empty dict.
        authorizer: ``tenuo_core.Authorizer`` configured with trusted issuer keys.
        config: Optional ``tenuo_core.CompiledMcpConfig`` for constraint extraction.
        require_warrant: If ``True`` (default), calls without a warrant are denied.
        meta: Contents of ``params._meta`` from the MCP request, when available.
            See :meth:`MCPVerifier.verify` for extraction priority.

    Returns:
        :class:`MCPVerificationResult`.

    Example::

        from tenuo_core import Authorizer, PublicKey
        from tenuo.mcp import verify_mcp_call

        authorizer = Authorizer(
            trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
        )

        result = verify_mcp_call("read_file", arguments, authorizer=authorizer, meta=meta)
        result.raise_if_denied()
        return read_file(result.clean_arguments["path"])
    """
    return MCPVerifier(
        authorizer=authorizer,
        config=config,
        require_warrant=require_warrant,
        control_plane=control_plane,
    ).verify(tool_name, arguments, meta=meta)


__all__ = [
    "MCPVerificationResult",
    "MCPAuthorizationError",
    "MCPVerifier",
    "verify_mcp_call",
]
