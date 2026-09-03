"""Verify-only GitHub Actions gateway. I3 and I6; no GitHub API calls."""

from __future__ import annotations

import base64
import os
from typing import Any, Dict, Optional

from tenuo import Authorizer, PublicKey, SigningKey
from tenuo.mcp import MCPVerificationResult, MCPVerifier, TENUO_TOOL_NOT_AUTHORIZED
from tenuo.receipts import FileReceiptSink, ReceiptSigner

from .catalog import TRIPWIRE_NAMES, ToolSpec, tools_for_packs
from .config import ConfigError, GatewayConfig


def _public_key(value: str) -> PublicKey:
    raw = value.strip()
    if raw.startswith("hex:"):
        raw = raw[4:]
    try:
        return PublicKey.from_bytes(bytes.fromhex(raw))
    except Exception:
        return PublicKey.from_bytes(base64.b64decode(raw))


def _signing_key(config: GatewayConfig) -> SigningKey:
    raw = config.receipt_signing_key
    if not raw:
        if config.signing_provider == "memory":
            return SigningKey.generate()
        raise ConfigError("TENUO_RECEIPT_SIGNING_KEY is required")
    try:
        return SigningKey.from_base64(raw)
    except AttributeError:
        return SigningKey.from_bytes(base64.b64decode(raw))
    except Exception:
        return SigningKey.from_bytes(bytes.fromhex(raw))


class Gateway:
    """In-process gateway used by tests and by the HTTP entrypoint."""

    def __init__(self, config: GatewayConfig) -> None:
        if config.signing_provider == "kms":
            raise ConfigError("KMS signing is M3; this image is verify-only")
        self.config = config
        self.tools = tools_for_packs(config.packs)
        roots = [_public_key(item) for item in config.root_public_keys]
        self.authorizer = Authorizer(trusted_roots=roots)
        self.config.receipt_path.parent.mkdir(parents=True, exist_ok=True)
        self.signer = ReceiptSigner(
            _signing_key(config),
            FileReceiptSink(self.config.receipt_path),
            authorizer=self.authorizer,
        )
        # Tripwires are decided here, after a warrant decode and before any
        # allow receipt, so a warrant that names a tripwire never produces
        # an allow followed by a deny.
        self._raw = MCPVerifier(authorizer=self.authorizer, control_plane=False)
        self.verifier = MCPVerifier(
            authorizer=self.authorizer,
            control_plane=self.signer,
        )

    def verify(
        self,
        tool: str,
        arguments: Optional[Dict[str, Any]],
        meta: Any = None,
    ) -> MCPVerificationResult:
        if tool in TRIPWIRE_NAMES:
            result = self._raw.verify(tool, arguments, meta=meta)
            if not result.allowed and not result.presented_chain:
                return result
            denied = MCPVerificationResult(
                allowed=False,
                tool=tool,
                clean_arguments=dict(arguments or {}),
                constraints=dict(arguments or {}),
                warrant_id=result.warrant_id,
                denial_reason="gateway ceiling: tripwire tools cannot be enabled",
                jsonrpc_error_code=-32001,
                error_type="tool_not_allowed",
                error_code=TENUO_TOOL_NOT_AUTHORIZED,
                presented_chain=result.presented_chain,
                verified_pop=result.verified_pop,
                pop_auth_args=result.pop_auth_args,
                authorizer=self.authorizer,
            )
            self.signer.emit_for_enforcement(denied)
            return denied
        return self.verifier.verify(tool, arguments, meta=meta)

    def flush_receipts(self) -> bool:
        return self.signer.flush()


def build_mcp(gateway: Gateway):
    """FastMCP app: middleware verifies, handlers never call GitHub."""
    from fastmcp import FastMCP
    from fastmcp.server.middleware.middleware import CallNext, Middleware, MiddlewareContext
    import mcp.types as mt
    from tenuo.mcp.fastmcp_middleware import _denial_tool_return, resolve_tool_call_meta_for_verify

    class _Ceiling(Middleware):
        async def on_call_tool(
            self,
            context: MiddlewareContext[mt.CallToolRequestParams],
            call_next: CallNext[mt.CallToolRequestParams, Any],
        ) -> Any:
            params = context.message
            result = gateway.verify(
                params.name,
                params.arguments or {},
                meta=resolve_tool_call_meta_for_verify(params, context.fastmcp_context),
            )
            if not result.allowed:
                return _denial_tool_return(result)
            return await call_next(context)

    mcp = FastMCP("tenuo-github-actions", middleware=[_Ceiling()])

    def _register(spec: ToolSpec) -> None:
        async def _handler(**kwargs: Any) -> Dict[str, Any]:
            return {"executed": False, "mode": "verify_only", "tool": spec.name}

        _handler.__name__ = spec.name.replace(".", "_")
        _handler.__doc__ = spec.description
        mcp.tool(name=spec.name)(_handler)

    for spec in gateway.tools:
        _register(spec)
    return mcp


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Tenuo for GitHub Actions (verify-only)")
    parser.add_argument("--config", default=os.environ.get("TENUO_GATEWAY_CONFIG", "/etc/tenuo/gateway.yaml"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    config = GatewayConfig.from_yaml(args.config)
    gateway = Gateway(config)
    mcp = build_mcp(gateway)
    mcp.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
