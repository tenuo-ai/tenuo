"""
Tenuo Control Plane Integration.
Provides ControlPlaneClient — a thin Python wrapper around the Rust
PyControlPlaneClient that handles env-var discovery and optional
process-level singleton for integrations that don't manage lifecycle.
"""
import json
import logging
import os
import time
import uuid
import atexit
import platform
from typing import Optional, Any

from tenuo import receipts as _receipts

logger = logging.getLogger(__name__)

_global_client: Optional["ControlPlaneClient"] = None

def connect(
    *,
    token: Optional[str] = None,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    authorizer_name: Optional[str] = None,
    signing_key=None,
    **kwargs,
) -> "ControlPlaneClient":
    """
    Connect to the Tenuo control plane and return a singleton client.
    On first call, starts the background heartbeat loop. Subsequent calls
    return the same client.

    Accepts either a connect token (from the dashboard's Quick Connect) or
    individual parameters. The connect token encodes endpoint, API key,
    agent ID, and registration secret in a single string.

    Parameters fall back to env vars:
        TENUO_CONNECT_TOKEN   (single token from Quick Connect)
        TENUO_CONTROL_PLANE_URL
        TENUO_API_KEY
        TENUO_AUTHORIZER_NAME
        TENUO_SIGNING_KEY  (base64-encoded Ed25519 private key)
    """
    global _global_client
    if _global_client is None:
        _global_client = ControlPlaneClient(
            token=token, url=url, api_key=api_key,
            authorizer_name=authorizer_name,
            signing_key=signing_key, **kwargs,
        )
    return _global_client

def get_client() -> Optional["ControlPlaneClient"]:
    """Return the singleton client, or None if connect() was never called."""
    return _global_client


def get_or_create() -> Optional["ControlPlaneClient"]:
    """Return the singleton client, auto-creating from env vars if needed.

    Resolution order:

    1. Singleton from a previous ``connect()`` call.
    2. New client from ``TENUO_CONNECT_TOKEN`` / ``TENUO_CONTROL_PLANE_URL`` +
       ``TENUO_API_KEY`` + ``TENUO_AUTHORIZER_NAME`` env vars (via ``from_env``).

    Returns ``None`` when no credentials are available. Adapters use this as
    the fallback when ``control_plane=None`` so operators only need env vars
    (or a single ``connect()`` call) to enable telemetry everywhere.
    """
    global _global_client
    if _global_client is not None:
        return _global_client
    client = ControlPlaneClient.from_env()
    if client is not None:
        _global_client = client
    return client


# Receipt payload key 10 carries a canonical kebab-case error name drawn from
# the Rust `Error::name()` vocabulary, the same one WASM emits. Python's
# EnforcementResult.error_type is a coarser category, so it is mapped rather
# than case-converted — `expired` alone would not match `warrant-expired`, and
# two runtimes disagreeing on this field makes it useless for correlation.
#
# denial_reason is deliberately not used: it is human prose that may quote
# argument values, and key 10 is signed and widely shared.
_DECISION_CODE_BY_ERROR_TYPE = {
    "expired": "warrant-expired",
    "revoked": "warrant-revoked",
    "invalid_pop": "pop-signature-invalid",
    "constraint_violation": "constraint-violation",
    "tool_not_allowed": "tool-not-authorized",
    "policy_violation": "constraint-violation",
    "insufficient_approvals": "insufficient-approvals",
    "approval_gate_misconfigured": "approval-invalid",
    "untrusted_issuer": "untrusted-root",
    # Python-side categories with no Rust counterpart; not in Error::name()'s
    # vocabulary, and kept kebab-case so they cannot be mistaken for it.
    "authorization_failed": "authorization-failed",
    "internal_error": "internal-error",
    "tenuo_error": "authorization-failed",
}


# Failures that can only be reached once possession was established. Mirrors
# `pop_established_before_error` in the wasm SDK: a receipt asserting a
# proof-of-possession that was never checked, or denying one that was, are both
# false claims, so the PoP is attached only for this set.
_POP_ESTABLISHED_ERROR_TYPES = frozenset(
    {
        "constraint_violation",
        "policy_violation",
        "insufficient_approvals",
        "approval_gate_misconfigured",
    }
)


def _decision_code(result) -> str:
    """Canonical kebab-case name for a denial, for receipt payload key 10."""
    error_type = getattr(result, "error_type", None)
    if not error_type:
        return "authorization-failed"
    return _DECISION_CODE_BY_ERROR_TYPE.get(error_type, error_type.replace("_", "-"))


class ControlPlaneClient:
    """
    Thin Python wrapper around tenuo_core.ControlPlaneClient.

    Token parsing, agent claiming, and signing key generation are all
    delegated to the Rust core. This wrapper adds Python-specific metadata
    (detected frameworks, runtime version) and convenience helpers like
    ``emit_for_enforcement``.
    """
    def __init__(self, *, token=None, url=None, api_key=None,
                 authorizer_name=None, signing_key=None,
                 receipt_sink=None, on_receipt_error=None,
                 receipt_emitter=None, **kwargs):
        try:
            from tenuo_core import ControlPlaneClient as _Rust
        except ImportError:
            raise RuntimeError("tenuo_core python-server build not available. Please install tenuo_core with server support.")

        resolved_token = token or os.environ.get("TENUO_CONNECT_TOKEN") or None
        resolved_url = url or os.environ.get("TENUO_CONTROL_PLANE_URL") or None
        resolved_key = api_key or os.environ.get("TENUO_API_KEY") or None
        resolved_name = (
            authorizer_name
            or os.environ.get("TENUO_AUTHORIZER_NAME")
            # When using a connect token, derive a name from the environment
            # so operators don't need TENUO_AUTHORIZER_NAME separately.
            # K8s downward API → Docker/plain hostname → stable fallback.
            or (resolved_token and (
                os.environ.get("POD_NAME")
                or os.environ.get("HOSTNAME")
                or platform.node()
                or "tenuo-python-sdk"
            ))
            or None
        )

        if signing_key is None:
            raw = os.environ.get("TENUO_SIGNING_KEY")
            if raw:
                import base64
                from tenuo_core import SigningKey
                try:
                    signing_key = SigningKey.from_base64(raw)
                except AttributeError:
                    # Older tenuo_core builds lack from_base64 — decode manually
                    signing_key = SigningKey.from_bytes(base64.b64decode(raw))

        meta = kwargs.pop("metadata", {}) or {}
        meta.setdefault("sdk_language", "python")
        meta.setdefault("sdk_runtime_version", platform.python_version())

        for mod_name, meta_key in [
            ("langgraph", "framework_langgraph"),
            ("langchain", "framework_langchain"),
            ("temporalio", "framework_temporal"),
            ("mcp", "framework_mcp"),
            ("fastmcp", "framework_fastmcp"),
            ("google.adk", "framework_adk"),
            ("crewai", "framework_crewai"),
            ("openai", "framework_openai"),
            ("autogen", "framework_autogen"),
            ("fastapi", "framework_fastapi"),
            ("starlette", "framework_starlette"),
            ("hermes_agent", "framework_hermes"),
        ]:
            try:
                mod = __import__(mod_name)
                meta.setdefault(meta_key, getattr(mod, "__version__", "unknown"))
            except Exception:
                logger.debug("Optional framework %r not installed, skipping metadata", mod_name)

        # Delegate everything to Rust core: token parsing, key generation,
        # agent claiming, and heartbeat loop startup.
        # Receipts are evidence and go to their own outlet, not the
        # best-effort audit channel: a dropped audit event costs a data point,
        # a dropped receipt costs the ability to prove what happened.
        self._receipt_sink = receipt_sink
        self._on_receipt_error = on_receipt_error
        # Emission posture. The two differ only in when signing happens; the
        # chain and the artifact are identical. A bare sink defaults to the
        # deferred posture (~0.5 µs on the hot path measured through this
        # client, crash loss bounded by its maxsize=256); pass
        # JournalEmitter(...) for the evidence-strict one (~17 µs p50 measured
        # through this client, ~13 µs Rust floor, zero process-crash loss).
        if receipt_emitter is None and receipt_sink is not None:
            receipt_emitter = _receipts.DeferredEmitter(receipt_sink)
        self._receipt_emitter = receipt_emitter
        self._receipt_unbound_warned = False
        self._inner = _Rust(
            url=resolved_url,
            api_key=resolved_key,
            authorizer_name=resolved_name,
            signing_key=signing_key,
            token=resolved_token,
            metadata=meta,
            **kwargs,
        )

        if self._receipt_emitter is not None:
            self._receipt_emitter._attach(self._inner, on_receipt_error)

    @classmethod
    def from_env(cls) -> Optional["ControlPlaneClient"]:
        """Return a client from env vars, or None if vars are absent.

        A connect token alone is sufficient — authorizer name is derived from
        POD_NAME / HOSTNAME when TENUO_AUTHORIZER_NAME is not set.
        """
        if os.environ.get("TENUO_CONNECT_TOKEN"):
            return cls()
        if not all(v in os.environ for v in (
            "TENUO_CONTROL_PLANE_URL", "TENUO_API_KEY", "TENUO_AUTHORIZER_NAME",
        )):
            return None
        return cls()

    def bind_authorizer(self, authorizer) -> None:
        """Copy the enforcement point's trust context from its authorizer.

        Receipts commit to the trusted root set and the revocation list in
        force. Reading those from the authorizer rather than accepting them as
        configuration is what stops a receipt claiming a trust context this
        enforcement point never had. Call again after installing a new
        revocation list, or receipts will keep committing to the old one.

        Until this is called no receipts are produced: an enforcement point
        that cannot say what it trusted has nothing worth signing.
        """
        self._inner.bind_authorizer(authorizer)

    @property
    def receipt_signer_key(self) -> str:
        """Hex public key receipts from this enforcement point are signed under.

        The same key the control plane already knows this authorizer by, so
        resolving a receipt's signer needs no separate registration.
        """
        return self._inner.receipt_signer_key

    def emit_for_enforcement(
        self,
        result: Any,
        chain_result: Optional[Any] = None,
        *,
        latency_us: int = 0,
        request_id: Optional[str] = None,
        warrant_stack_override: Optional[str] = None,
    ) -> None:
        """
        Emit an authorization event from any integration's result object.
        Works with EnforcementResult (LangGraph), MCPVerificationResult (MCP),
        and TemporalAuditEvent (Temporal).

        When ``chain_result`` is a Rust ``ChainVerificationResult`` and the
        call was authorized, uses ``emit_authorized`` so all trust-critical
        fields (approvals, warrant stack, chain depth, root issuer) are
        extracted in Rust — Python stays out of the signing trust path.
        """
        request_id = request_id or str(uuid.uuid4())
        allowed = getattr(result, "allowed", False)
        tool = getattr(result, "tool", "") or ""

        # Resolve arguments — EnforcementResult uses .arguments,
        # MCPVerificationResult uses .clean_arguments / .constraints.
        arguments_dict = getattr(result, "arguments", None)
        if arguments_dict is None:
            arguments_dict = getattr(result, "clean_arguments", None)
        arguments_json = None
        if arguments_dict is not None:
            try:
                arguments_json = json.dumps(arguments_dict)
            except Exception:
                arguments_json = str(arguments_dict)

        # Trusted allow path: let Rust extract all fields from the
        # ChainVerificationResult it produced.  Python only supplies
        # tool name, serialized args, and timing metadata.
        if allowed and chain_result is not None:
            self._inner.emit_authorized(
                chain_result, tool, arguments_json,
                latency_us, request_id,
            )
            self._bind_for_receipts_from_result(result)
            self._emit_receipt(chain_result, tool, True, request_id, None)
            return

        # Fallback path: no chain_result (e.g., require_warrant=False allows,
        # all denials).  Python supplies the fields from the result object.
        warrant_id = getattr(result, "warrant_id", None) or ""
        chain_depth = 1
        root_principal = None
        warrant_stack = warrant_stack_override

        if chain_result is not None:
            chain_depth = chain_result.leaf_depth
            ri = getattr(chain_result, "root_issuer", None)
            if isinstance(ri, (bytes, list)):
                root_principal = bytes(ri).hex()
            elif isinstance(ri, str):
                root_principal = ri
            warrant_stack = getattr(chain_result, "warrant_stack_b64", None) or warrant_stack

        if allowed:
            self._inner.emit_allow(
                warrant_id, tool, chain_depth, root_principal,
                warrant_stack, latency_us, request_id, arguments_json,
            )
        else:
            deny_reason = getattr(result, "denial_reason", "") or ""
            failed = getattr(result, "constraint_violated", None)
            self._inner.emit_deny(
                warrant_id, tool, deny_reason, failed,
                chain_depth, root_principal, warrant_stack,
                latency_us, request_id, arguments_json,
            )
            self._bind_for_receipts_from_result(result)
            self._emit_denial_receipt(result, tool, request_id)

    def _bind_for_receipts_from_result(self, result: Any) -> None:
        """Best-effort receipt trust binding from the authorizer that decided.

        EnforcementResult carries the Rust Authorizer that produced the
        ChainVerificationResult. Binding from that object keeps receipt setup
        automatic for existing integrations while preserving the important
        invariant: receipts commit to the trust context the enforcement point
        actually used.
        """
        if getattr(self, "_receipt_emitter", None) is None:
            return
        authorizer = getattr(result, "authorizer", None)
        if authorizer is None:
            if not getattr(self, "_receipt_unbound_warned", False):
                logger.warning(
                    "receipt sink is configured but no authorizer was available "
                    "for automatic trust binding; no receipt will be emitted for "
                    "this decision"
                )
                self._receipt_unbound_warned = True
            return
        try:
            self.bind_authorizer(authorizer)
        except Exception as exc:  # noqa: BLE001 - receipt setup must not fail auth
            logger.warning("failed to bind authorizer for receipt emission", exc_info=exc)

    def _emit_denial_receipt(self, result, tool, request_id) -> None:
        """Sign a receipt for a denial, from the chain that was presented.

        Denials have no ``chain_result`` — ``check_chain`` raises for expiry,
        revocation, an untrusted root or a constraint miss — so this builds from
        the presented chain instead. Without it the receipt stream is a
        contiguous run of allows with every refusal silently absent, which is
        the incompleteness the chain link exists to make visible.

        Structural refusals are deliberately not receipted: a call carrying no
        warrant, or bytes that would not decode, was turned away at the door
        rather than authorized against anything, so there is no chain for a
        receipt to commit to. Signing them would also let an unauthenticated
        caller compel signatures and sink writes. They stay in the audit
        stream, and the boundary is that receipts cover decisions made over
        presented authority.
        """
        emitter = getattr(self, "_receipt_emitter", None)
        if emitter is None:
            return
        chain = getattr(result, "presented_chain", None)
        if not chain:
            return
        # Key 7 must commit to what the holder signed over. Allows hash the
        # pop_args view inside check_chain; a denial hashing the original
        # tool_args instead would fail a later --args check against the wire
        # payload on any split-view path. An empty stripped view is a real
        # value, so this is an explicit None test, not a truthiness fallback.
        args_for_hash = getattr(result, "pop_auth_args", None)
        if args_for_hash is None:
            args_for_hash = getattr(result, "arguments", None) or {}
        try:
            emitter.emit_denial(
                list(chain),
                tool,
                args_for_hash,
                int(time.time()),
                request_id,
                _decision_code(result),
                (
                    getattr(result, "verified_pop", None)
                    if getattr(result, "error_type", None) in _POP_ESTABLISHED_ERROR_TYPES
                    else None
                ),
            )
        except Exception as exc:  # noqa: BLE001 - must not fail the caller
            logger.warning("failed to emit denial receipt for %r", tool, exc_info=exc)

    def _emit_receipt(self, chain_result, tool, allowed, request_id, decision_code) -> None:
        """Sign a receipt for this decision and hand it to the sink.

        Returns quietly when no sink is configured, when the client is not
        bound to an authorizer, or when the verification carries no warrant
        stack — a receipt without the chain it decided over is not worth
        signing.
        """
        emitter = getattr(self, "_receipt_emitter", None)
        if emitter is None or chain_result is None:
            return
        try:
            emitter.emit_allow(
                chain_result, tool, allowed, int(time.time()), request_id, decision_code,
            )
        except Exception as exc:  # noqa: BLE001 - must not fail the caller
            logger.warning("failed to emit receipt for %r", tool, exc_info=exc)

    def flush_receipts(self, timeout: float = 10.0) -> bool:
        """Wait until every receipt emitted so far is signed and delivered.

        For the journal posture the receipts are already durable against
        process death before ``emit`` returns; flush additionally fsyncs, so
        machine death cannot take the tail either. Returns False on timeout
        rather than raising.
        """
        emitter = getattr(self, "_receipt_emitter", None)
        return True if emitter is None else emitter.flush(timeout)

    def shutdown(self, timeout_secs: float = 5.0) -> None:
        emitter = getattr(self, "_receipt_emitter", None)
        if emitter is not None:
            try:
                emitter.close(timeout_secs)
            except Exception:  # noqa: BLE001 - shutdown must not raise
                logger.warning("receipt emitter did not drain cleanly")
        self._inner.shutdown(timeout_secs)

    @property
    def authorizer_id(self) -> Optional[str]:
        return self._inner.authorizer_id

def _auto_shutdown():
    client = get_client()
    if client:
        try:
            client.shutdown(timeout_secs=2.0)
        except BaseException:
            pass

atexit.register(_auto_shutdown)

__all__ = ["connect", "get_client", "get_or_create", "ControlPlaneClient"]
