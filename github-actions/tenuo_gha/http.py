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
    mcp_app: Any = None,
) -> Starlette:
    ready = {"exchange": exchange is not None, "gateway": mcp_app is not None}

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
        return JSONResponse(
            {
                "warrant": result.warrant,
                "warrant_id": result.warrant_id,
                "expires_at": result.expires_at,
                "root_public_keys": result.root_public_keys,
            }
        )

    routes = [
        Route("/health", health, methods=["GET"]),
        Route("/ready", ready_probe, methods=["GET"]),
        Route("/v1/exchange", exchange_handler, methods=["POST"]),
        Route("/v1/exchange/github", exchange_handler, methods=["POST"]),
    ]
    if mcp_app is not None:
        routes.append(Mount("/", app=mcp_app))
    app = Starlette(routes=routes)
    app.state.ready = ready
    return app
