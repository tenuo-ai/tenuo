"""ASGI app: exchange routes, health, and optional MCP."""

from __future__ import annotations

import json
from typing import Any, Optional

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from .config import GatewayConfig
from .exchange import Exchange, ExchangeError


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def build_http(
    config: GatewayConfig,
    *,
    exchange: Optional[Exchange] = None,
    gateway: Any = None,
    mcp_app: Any = None,
) -> Starlette:
    ready = {
        "exchange": exchange is not None,
        "gateway": gateway is not None or mcp_app is not None,
    }

    async def health(_request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def ready_probe(_request: Request) -> Response:
        return JSONResponse({"status": "ready", "role": config.role})

    async def exchange_handler(request: Request) -> Response:
        if exchange is None:
            return JSONResponse({"error": "not_found", "detail": "exchange is not served"}, status_code=404)
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            return JSONResponse({"error": "outside_ceiling", "detail": "body must be JSON"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "outside_ceiling", "detail": "body must be a mapping"}, status_code=400)
        try:
            result = exchange.mint(_bearer(request), body)
        except ExchangeError as exc:
            return JSONResponse({"error": exc.code, "detail": exc.detail}, status_code=exc.status)
        payload = {
            "warrant": result.warrant,
            "warrant_id": result.warrant_id,
            "expires_at": result.expires_at,
            "root_public_keys": result.root_public_keys,
        }
        if result.task_context is not None:
            payload["task_context"] = result.task_context
        return JSONResponse(payload)

    async def call_handler(request: Request) -> Response:
        if gateway is None:
            return JSONResponse({"error": "not_found", "detail": "gateway is not served"}, status_code=404)
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            return JSONResponse({"error": "outside_ceiling", "detail": "body must be JSON"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "outside_ceiling", "detail": "body must be a mapping"}, status_code=400)
        tool = body.get("tool")
        arguments = body.get("arguments") or {}
        if not isinstance(tool, str) or not tool:
            return JSONResponse({"error": "outside_ceiling", "detail": "tool is required"}, status_code=400)
        if not isinstance(arguments, dict):
            return JSONResponse({"error": "outside_ceiling", "detail": "arguments must be a mapping"}, status_code=400)
        result, payload = gateway.execute(tool, arguments, meta=body.get("meta"))
        if not result.allowed:
            return JSONResponse(
                {
                    "allowed": False,
                    "error_code": result.error_code,
                    "error_type": result.error_type,
                    "denial_reason": result.denial_reason,
                    "detail": result.denial_reason,
                },
                status_code=403,
            )
        return JSONResponse({"allowed": True, "result": payload or {}})

    routes = [
        Route("/health", health, methods=["GET"]),
        Route("/ready", ready_probe, methods=["GET"]),
        Route("/v1/exchange", exchange_handler, methods=["POST"]),
        Route("/v1/exchange/github", exchange_handler, methods=["POST"]),
        Route("/v1/call", call_handler, methods=["POST"]),
    ]
    if mcp_app is not None:
        routes.append(Mount("/", app=mcp_app))
    app = Starlette(routes=routes)
    app.state.ready = ready
    return app
