"""
Tenuo Control Plane Integration.
Provides ControlPlaneClient — a thin Python wrapper around the Rust
PyControlPlaneClient that handles env-var discovery and optional
process-level singleton for integrations that don't manage lifecycle.
"""
import json
import logging
import os
import uuid
import atexit
import platform
from typing import Optional, Any

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


class ControlPlaneClient:
    """
    Thin Python wrapper around tenuo_core.ControlPlaneClient.

    Token parsing, agent claiming, and signing key generation are all
    delegated to the Rust core. This wrapper adds Python-specific metadata
    (detected frameworks, runtime version) and convenience helpers like
    ``emit_for_enforcement``.
    """
    def __init__(self, *, token=None, url=None, api_key=None,
                 authorizer_name=None, signing_key=None, **kwargs):
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
                from tenuo_core import SigningKey
                signing_key = SigningKey.from_base64(raw)

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
        ]:
            try:
                mod = __import__(mod_name)
                meta.setdefault(meta_key, getattr(mod, "__version__", "unknown"))
            except Exception:
                logger.debug("Optional framework %r not installed, skipping metadata", mod_name)

        # Delegate everything to Rust core: token parsing, key generation,
        # agent claiming, and heartbeat loop startup.
        self._inner = _Rust(
            url=resolved_url,
            api_key=resolved_key,
            authorizer_name=resolved_name,
            signing_key=signing_key,
            token=resolved_token,
            metadata=meta,
            **kwargs,
        )

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
            logger.debug("Control plane shutdown failed at exit", exc_info=True)

atexit.register(_auto_shutdown)

__all__ = ["connect", "get_client", "get_or_create", "ControlPlaneClient"]
