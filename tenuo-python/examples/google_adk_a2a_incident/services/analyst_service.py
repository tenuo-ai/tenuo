#!/usr/bin/env python3
"""
Analyst A2A Service

Runs as a separate process, exposing threat intelligence tools via A2A protocol.
Receives delegated warrant from orchestrator, validates it, and provides
access to query_threat_db capability.

Security: Uses warrant.authorize() for Tier 2 (PoP) validation.
"""

import asyncio
import argparse
import sys
from pathlib import Path
from typing import Dict, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tenuo import SigningKey, Warrant
from tenuo.exceptions import AuthorizationError, ConstraintViolation

# Import tools
from tools import query_threat_db


class AnalystService:
    """Analyst agent running as A2A service with Tier 2 authorization."""

    def __init__(self, port: int = 8001):
        self.port = port
        self.signing_key: Optional[SigningKey] = None
        self.warrant: Optional[Warrant] = None
        self.app = None

    async def initialize(self, warrant_b64: str, signing_key_hex: str):
        """
        Initialize service with delegated warrant.

        Args:
            warrant_b64: Base64-encoded warrant from orchestrator
            signing_key_hex: Hex-encoded signing key for this agent
        """
        # Deserialize signing key
        self.signing_key = SigningKey.from_bytes(bytes.fromhex(signing_key_hex))

        # Deserialize warrant
        self.warrant = Warrant.from_base64(warrant_b64)

        print("✓ Analyst service initialized with warrant")
        print(f"  Capabilities: {list(self.warrant.capabilities.keys())}")
        print(f"  Holder: {self.signing_key.public_key.to_hex()[:16]}...")

    def _create_app(self):
        """Create Starlette ASGI application."""
        try:
            from starlette.applications import Starlette
            from starlette.routing import Route
            from starlette.responses import JSONResponse
            from starlette.requests import Request
        except ImportError:
            raise ImportError("starlette is required: pip install starlette uvicorn")

        async def handle_task(request: Request) -> JSONResponse:
            """Handle incoming A2A task request."""
            try:
                body = await request.json()

                skill = body.get("skill")
                params = body.get("params", {})

                if skill == "query_threat_db":
                    result = await self._handle_query_threat_db(params)
                    return JSONResponse(result)
                else:
                    return JSONResponse({
                        "error": "unknown_skill",
                        "message": f"Unknown skill: {skill}"
                    }, status_code=400)

            except AuthorizationError as e:
                return JSONResponse({
                    "error": "authorization_denied",
                    "message": str(e)
                }, status_code=403)
            except ConstraintViolation as e:
                return JSONResponse({
                    "error": "constraint_violation",
                    "message": str(e)
                }, status_code=403)
            except Exception as e:
                return JSONResponse({
                    "error": "internal_error",
                    "message": str(e)
                }, status_code=500)

        async def health(request: Request) -> JSONResponse:
            """Health check endpoint."""
            return JSONResponse({"status": "healthy", "service": "analyst"})

        routes = [
            Route("/tasks/send", handle_task, methods=["POST"]),
            Route("/health", health, methods=["GET"]),
        ]

        return Starlette(routes=routes)

    async def _handle_query_threat_db(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle threat DB query request.

        Uses warrant.authorize() for Tier 2 validation with PoP.
        """
        query = params.get("query")
        table = params.get("table")

        if not query or not table:
            raise ValueError("Missing required parameters: query, table")

        # TIER 2 AUTHORIZATION: Use warrant.authorize() with PoP signature
        # This validates:
        # 1. Warrant grants the skill
        # 2. Arguments satisfy constraints
        # 3. Warrant is not expired
        # 4. Signature chain is valid
        try:
            pop_signature = self.signing_key.sign(
                f"query_threat_db:{query}:{table}".encode()
            )
            self.warrant.authorize(
                tool="query_threat_db",
                args={"query": query, "table": table},
                signature=pop_signature,
            )
        except Exception as e:
            # Re-raise as AuthorizationError for consistent handling
            raise AuthorizationError(f"Authorization failed: {e}")

        # Authorized - execute tool
        result = query_threat_db(query, table)

        # Get warrant ID for audit trail
        jti = self.warrant.jti
        jti_str = jti.hex() if hasattr(jti, 'hex') else str(jti)

        return {
            "success": True,
            "data": result,
            "warrant_jti": jti_str,
            "authorized_by": "warrant.authorize()",  # Proof of Tier 2
        }

    async def start(self):
        """Start the A2A server."""
        try:
            import uvicorn
        except ImportError:
            raise ImportError("uvicorn is required: pip install uvicorn")

        self.app = self._create_app()
        print(f"🚀 Analyst service starting on port {self.port}")

        config = uvicorn.Config(
            self.app,
            host="0.0.0.0",
            port=self.port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        await server.serve()


async def main():
    """Run analyst service."""
    parser = argparse.ArgumentParser(description="Analyst A2A Service")
    parser.add_argument("--port", type=int, default=8001, help="Service port")
    parser.add_argument("--warrant", required=True, help="Base64-encoded warrant")
    parser.add_argument("--key", required=True, help="Hex-encoded signing key")
    args = parser.parse_args()

    service = AnalystService(port=args.port)
    await service.initialize(args.warrant, args.key)

    try:
        await service.start()
    except KeyboardInterrupt:
        print("\n🛑 Analyst service shutting down...")


if __name__ == "__main__":
    asyncio.run(main())
