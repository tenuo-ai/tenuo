"""GitHub Actions gateway: warrant verify, file receipts, optional GitHub calls."""

from __future__ import annotations

import base64
import os
from contextvars import ContextVar
from typing import Any, Dict, Optional

from tenuo import Authorizer, PublicKey, SigningKey
from tenuo.mcp import MCPVerificationResult, MCPVerifier, TENUO_CONSTRAINT_VIOLATION, TENUO_TOOL_NOT_AUTHORIZED

_verified: ContextVar[Optional[MCPVerificationResult]] = ContextVar("tenuo_gha_verified", default=None)
from tenuo.receipts import FileReceiptSink, ReceiptSigner

from .catalog import TRIPWIRE_NAMES, ToolSpec, comment_digest_matches, spec_by_name, tools_for_packs
from .config import ConfigError, GatewayConfig
from .exchange import Exchange
from .github import GitHubError
from .http import build_http


def _public_key(value: str) -> PublicKey:
    raw = value.strip()
    if raw.startswith("hex:"):
        raw = raw[4:]
    try:
        return PublicKey.from_bytes(bytes.fromhex(raw))
    except Exception:
        return PublicKey.from_bytes(base64.b64decode(raw))


def _signing_key(config: GatewayConfig) -> SigningKey:
    if config.signing_provider == "secret":
        if config.secret_mount is None or not config.secret_receipt_key:
            raise ConfigError("receipt_key is required under signing.secret.mount")
        from .secrets import signing_key_from_mount

        return signing_key_from_mount(config.secret_mount, config.secret_receipt_key)
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


def _github_client(config: GatewayConfig, github: Any, *, client: Any = None) -> Any:
    if github is not None:
        return github
    if not config.github_app_id:
        return None
    if config.signing_provider != "secret":
        raise ConfigError("GitHub App signing is not configured")
    if config.secret_mount is None or not config.secret_github_app_key:
        raise ConfigError("github_app_key is required under signing.secret.mount")
    from .github import GitHubApp
    from .secrets import app_jwt_signer_from_mount

    return GitHubApp(
        config,
        client=client,
        sign_app_jwt=app_jwt_signer_from_mount(config.secret_mount, config.secret_github_app_key),
    )


class Gateway:
    """In-process gateway used by tests and by the HTTP entrypoint."""

    def __init__(self, config: GatewayConfig, *, github: Any = None, github_http: Any = None) -> None:
        if config.signing_provider == "kms":
            raise ConfigError("signing.provider=kms is not supported")
        self.config = config
        self.github = _github_client(config, github, client=github_http)
        self.tools = tools_for_packs(config.packs)
        roots = [_public_key(item) for item in config.root_public_keys]
        self.authorizer = Authorizer(trusted_roots=roots)
        self.config.receipt_path.parent.mkdir(parents=True, exist_ok=True)
        self._receipt_key = _signing_key(config)
        self.signer = ReceiptSigner(
            self._receipt_key,
            FileReceiptSink(self.config.receipt_path),
            authorizer=self.authorizer,
        )
        # Ceiling tools are checked after decode and before an allow receipt.
        self._raw = MCPVerifier(authorizer=self.authorizer, control_plane=False)
        self.verifier = MCPVerifier(
            authorizer=self.authorizer,
            control_plane=self.signer,
        )
        self.self_test()

    def self_test(self) -> None:
        """Sign with the receipt key and, if configured, the App PEM. Never log material."""
        try:
            self._receipt_key.sign_raw(b"tenuo-gha-ready")
        except Exception as exc:
            raise ConfigError("receipt key self-test failed") from exc
        signer = getattr(self.github, "_sign_app_jwt", None) if self.github is not None else None
        if callable(signer) and self.config.github_app_id:
            try:
                token = signer(self.config.github_app_id)
            except Exception as exc:
                raise ConfigError("GitHub App JWT self-test failed") from exc
            if not token:
                raise ConfigError("GitHub App JWT self-test failed")

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
                denial_reason="gateway ceiling: tool is not enabled",
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
        result = self.verifier.verify(tool, arguments, meta=meta)
        if not result.allowed:
            return result
        result = self._apply_repository_ceiling(result)
        if not result.allowed:
            return result
        result = self._apply_terminal_leaf(result)
        if not result.allowed:
            return result
        return self._apply_body_digest(result)

    def _deny_after_allow(self, result: MCPVerificationResult, reason: str, error_code: str) -> MCPVerificationResult:
        denied = MCPVerificationResult(
            allowed=False,
            tool=result.tool,
            clean_arguments=dict(result.clean_arguments or {}),
            constraints=dict(result.constraints or {}),
            warrant_id=result.warrant_id,
            denial_reason=reason,
            jsonrpc_error_code=-32001,
            error_type="constraint_violation" if error_code == TENUO_CONSTRAINT_VIOLATION else "tool_not_allowed",
            error_code=error_code,
            presented_chain=result.presented_chain,
            verified_pop=result.verified_pop,
            pop_auth_args=result.pop_auth_args,
            authorizer=self.authorizer,
        )
        self.signer.emit_for_enforcement(denied)
        return denied

    def _apply_repository_ceiling(self, result: MCPVerificationResult) -> MCPVerificationResult:
        repository = (result.clean_arguments or {}).get("repository")
        if repository is None:
            return result
        allowed = {str(item) for item in self.config.repositories}
        if str(repository) in allowed:
            return result
        return self._deny_after_allow(
            result,
            "gateway ceiling: repository is not enabled",
            TENUO_TOOL_NOT_AUTHORIZED,
        )

    def _apply_terminal_leaf(self, result: MCPVerificationResult) -> MCPVerificationResult:
        chain = result.presented_chain or []
        leaf = chain[-1] if chain else None
        check = getattr(leaf, "is_terminal", None)
        if callable(check) and check():
            return result
        return self._deny_after_allow(
            result,
            "gateway: presented warrant is not a terminal leaf",
            TENUO_CONSTRAINT_VIOLATION,
        )

    def _apply_body_digest(self, result: MCPVerificationResult) -> MCPVerificationResult:
        if result.tool != "github.add_comment":
            return result
        if comment_digest_matches(result.clean_arguments or {}):
            return result
        return self._deny_after_allow(
            result,
            "gateway: comment body digest does not match",
            TENUO_CONSTRAINT_VIOLATION,
        )

    def flush_receipts(self) -> bool:
        return self.signer.flush()

    def dispatch(self, result: MCPVerificationResult) -> Optional[Dict[str, Any]]:
        """Call GitHub with the verifier's cleaned arguments after an allow."""
        if not result.allowed:
            return None
        spec = spec_by_name(result.tool, self.tools)
        if spec is None or spec.tripwire:
            return {"executed": False, "tool": result.tool}
        if self.github is None:
            return {"executed": False, "tool": result.tool}
        if spec.name == "github.add_comment" and not comment_digest_matches(result.clean_arguments or {}):
            return {"executed": False, "tool": result.tool, "error": "body digest does not match"}
        try:
            payload = self.github.call(spec, result.clean_arguments)
        except GitHubError as exc:
            return {"executed": False, "tool": result.tool, "error": str(exc)}
        return payload if isinstance(payload, dict) else {"result": payload}

    def execute(
        self,
        tool: str,
        arguments: Optional[Dict[str, Any]],
        meta: Any = None,
    ) -> tuple[MCPVerificationResult, Optional[Dict[str, Any]]]:
        result = self.verify(tool, arguments, meta=meta)
        if not result.allowed:
            return result, None
        return result, self.dispatch(result)


def build_mcp(gateway: Gateway):
    """FastMCP app: middleware verifies; handlers call GitHub only after allow."""
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
            token = _verified.set(result)
            fastmcp = context.fastmcp_context
            if fastmcp is not None and hasattr(fastmcp, "set_state"):
                fastmcp.set_state("tenuo_verified", result)
            try:
                return await call_next(context)
            finally:
                _verified.reset(token)

    mcp = FastMCP("tenuo-github-actions", middleware=[_Ceiling()])

    def _register(spec: ToolSpec) -> None:
        async def _handler(**kwargs: Any) -> Dict[str, Any]:
            result = _verified.get()
            if result is None:
                return {"executed": False, "tool": spec.name}
            return gateway.dispatch(result) or {"executed": False, "tool": spec.name}

        _handler.__name__ = spec.name.replace(".", "_")
        _handler.__doc__ = spec.description
        mcp.tool(name=spec.name)(_handler)

    for spec in gateway.tools:
        _register(spec)
    return mcp


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="Tenuo for GitHub Actions")
    parser.add_argument("--config", default=os.environ.get("TENUO_GATEWAY_CONFIG", "/etc/tenuo/gateway.yaml"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    config = GatewayConfig.from_yaml(args.config)

    exchange = None
    gateway = None
    mcp_app = None
    if config.role in {"exchange", "both"}:
        exchange = Exchange(config)
    if config.role in {"gateway", "both"}:
        gateway = Gateway(config)
        mcp_app = build_mcp(gateway).http_app()

    uvicorn.run(
        build_http(config, exchange=exchange, gateway=gateway, mcp_app=mcp_app),
        host=args.host,
        port=args.port,
    )


if __name__ == "__main__":
    main()
