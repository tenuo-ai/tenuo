"""Stdio MCP shim. Talks to the holder socket; holds no secret."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

import httpx

from .holder import HolderClient, assert_no_holder_secret


class ShimError(RuntimeError):
    """Shim could not complete a call. Never includes holder material."""


def call_gateway(
    gateway_url: str,
    tool: str,
    arguments: Dict[str, Any],
    envelope: Dict[str, str],
    *,
    client: Optional[httpx.Client] = None,
) -> Dict[str, Any]:
    """POST the holder envelope to the gateway. Logs no arguments."""
    if isinstance(envelope.get("arguments"), dict):
        arguments = dict(envelope["arguments"])
    own = client is None
    http = client or httpx.Client(timeout=20.0)
    try:
        response = http.post(
            gateway_url.rstrip("/") + "/v1/call",
            json={
                "tool": tool,
                "arguments": arguments,
                "meta": {"tenuo": envelope},
            },
        )
    finally:
        if own:
            http.close()
    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise ShimError(f"gateway returned non-JSON ({response.status_code})") from exc
    if response.status_code >= 400 or not payload.get("allowed", False):
        code = payload.get("error_code") or payload.get("error") or "denied"
        _log_line(tool, allowed=False, code=str(code))
        return {
            "allowed": False,
            "error_code": code,
            "message": f"DENIED ({code}): {payload.get('detail') or payload.get('denial_reason') or 'denied'}",
        }
    _log_line(tool, allowed=True, code="allow")
    return {"allowed": True, "result": payload.get("result") or {}}


def _log_line(tool: str, *, allowed: bool, code: str) -> None:
    sys.stderr.write(
        json.dumps({"tool": tool, "outcome": "allow" if allowed else "deny", "code": code}) + "\n"
    )


def build_mcp(holder: HolderClient, gateway_url: str, *, client: Optional[httpx.Client] = None):
    from fastmcp import FastMCP

    mcp = FastMCP("tenuo")
    for name in holder.tools():

        def _bind(tool_name: str):
            async def _handler(**kwargs: Any) -> Dict[str, Any]:
                envelope = holder.envelope(tool_name, kwargs)
                outcome = call_gateway(gateway_url, tool_name, kwargs, envelope, client=client)
                if not outcome.get("allowed"):
                    return {"isError": True, "error_code": outcome.get("error_code"), "message": outcome.get("message")}
                result = outcome.get("result")
                return result if isinstance(result, dict) else {"result": result}

            _handler.__name__ = tool_name.replace(".", "_")
            return _handler

        mcp.tool(name=name)(_bind(name))
    return mcp


def main() -> None:
    import argparse

    assert_no_holder_secret()
    parser = argparse.ArgumentParser(description="Tenuo MCP shim")
    parser.add_argument("--socket", default=os.environ.get("TENUO_HOLDER_SOCKET"))
    parser.add_argument("--gateway-url", default=os.environ.get("TENUO_GATEWAY_URL"))
    args = parser.parse_args()
    if not args.socket:
        raise SystemExit("TENUO_HOLDER_SOCKET is required")
    if not args.gateway_url:
        raise SystemExit("TENUO_GATEWAY_URL is required")
    holder = HolderClient(args.socket)
    build_mcp(holder, args.gateway_url).run(transport="stdio")


if __name__ == "__main__":
    main()
