"""
Tenuo Control Plane Integration.
Provides ControlPlaneClient — a thin Python wrapper around the Rust
PyControlPlaneClient that handles env-var discovery and optional
process-level singleton for integrations that don't manage lifecycle.
"""
import json
import os
import uuid
import atexit
import platform
from typing import Optional, Any

_global_client: Optional["ControlPlaneClient"] = None

def connect(
    *,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    authorizer_name: Optional[str] = None,
    signing_key=None,
    **kwargs,
) -> "ControlPlaneClient":
    """
    Connect to the Tenuo control plane and return a singleton client.
    On first call, starts the background heartbeat loop. Subsequent calls
    return the same client. All parameters fall back to env vars:
        TENUO_CONTROL_PLANE_URL
        TENUO_API_KEY
        TENUO_AUTHORIZER_NAME
        TENUO_SIGNING_KEY  (base64-encoded Ed25519 private key)
    """
    global _global_client
    if _global_client is None:
        _global_client = ControlPlaneClient(
            url=url, api_key=api_key, authorizer_name=authorizer_name,
            signing_key=signing_key, **kwargs,
        )
    return _global_client

def get_client() -> Optional["ControlPlaneClient"]:
    """Return the singleton client, or None if connect() was never called."""
    return _global_client

class ControlPlaneClient:
    """
    Thin Python wrapper around tenuo_core.ControlPlaneClient.
    Provides convenience helpers (emit_for_enforcement, from_env) so integrations
    can emit events with a single call rather than destructuring chain results.
    """
    def __init__(self, *, url=None, api_key=None, authorizer_name=None,
                 signing_key=None, **kwargs):
        try:
            from tenuo_core import ControlPlaneClient as _Rust, SigningKey
        except ImportError:
            raise RuntimeError("tenuo_core python-server build not available. Please install tenuo_core with server support.")

        if signing_key is None:
            raw = os.environ.get("TENUO_SIGNING_KEY")
            if raw:
                signing_key = SigningKey.from_base64(raw)
        if signing_key is None:
            raise ValueError(
                "signing_key required (or set TENUO_SIGNING_KEY)"
            )

        meta = kwargs.pop("metadata", {}) or {}
        meta.setdefault("sdk_language", "python")
        meta.setdefault("sdk_runtime_version", platform.python_version())

        try:
            import langgraph
            meta.setdefault("framework_langgraph", langgraph.__version__)
        except Exception:
            pass
        try:
            import temporalio
            meta.setdefault("framework_temporal", temporalio.__version__)
        except Exception:
            pass
        try:
            import mcp
            meta.setdefault("framework_mcp", getattr(mcp, "__version__", "unknown"))
        except Exception:
            pass

        self._inner = _Rust(
            url=url or os.environ["TENUO_CONTROL_PLANE_URL"],
            api_key=api_key or os.environ["TENUO_API_KEY"],
            authorizer_name=authorizer_name or os.environ["TENUO_AUTHORIZER_NAME"],
            signing_key=signing_key,
            metadata=meta,
            **kwargs,
        )

    @classmethod
    def from_env(cls) -> Optional["ControlPlaneClient"]:
        """Return a client from env vars, or None if vars are absent."""
        if not all(v in os.environ for v in (
            "TENUO_CONTROL_PLANE_URL", "TENUO_API_KEY",
            "TENUO_AUTHORIZER_NAME", "TENUO_SIGNING_KEY",
        )):
            return None
        return cls()

    def emit_for_enforcement(
        self,
        result: Any,           # EnforcementResult or MCPVerificationResult
        chain_result: Optional[Any] = None,  # PyChainVerificationResult if available
        *,
        latency_us: int = 0,
        request_id: Optional[str] = None,
        warrant_stack_override: Optional[str] = None,
    ) -> None:
        """
        Emit an authorization event from any integration's result object.
        Works with EnforcementResult (LangGraph), MCPVerificationResult (MCP),
        and TemporalAuditEvent (Temporal).

        ``warrant_stack_override`` lets callers supply a pre-encoded base64 CBOR
        warrant stack when ``chain_result`` is unavailable (e.g. denial events in
        Temporal where check_chain never returned).
        """
        request_id = request_id or str(uuid.uuid4())
        warrant_id = getattr(result, "warrant_id", None) or ""
        tool = getattr(result, "tool", "") or ""
        allowed = getattr(result, "allowed", False)

        chain_depth = 1
        root_principal = None
        warrant_stack = warrant_stack_override  # caller-supplied fallback

        arguments_dict = getattr(result, "arguments", None)
        arguments_json = None
        if arguments_dict is not None:
            try:
                arguments_json = json.dumps(arguments_dict)
            except Exception:
                arguments_json = str(arguments_dict)

        if chain_result is not None:
            chain_depth = chain_result.leaf_depth
            ri = getattr(chain_result, "root_issuer", None)
            if isinstance(ri, (bytes, list)):
                root_principal = bytes(ri).hex()
            elif isinstance(ri, str):
                root_principal = ri  # already hex or identifier string
            # chain_result warrant_stack takes precedence over the override
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

    def shutdown(self, timeout_secs: float = 5.0) -> None:
        self._inner.shutdown(timeout_secs)

    @property
    def authorizer_id(self) -> Optional[str]:
        return self._inner.authorizer_id

def _auto_shutdown():
    client = get_client()
    if client:
        try:
            client.shutdown(timeout_secs=2.0)
        except Exception:
            pass

atexit.register(_auto_shutdown)

__all__ = ["connect", "get_client", "ControlPlaneClient"]
