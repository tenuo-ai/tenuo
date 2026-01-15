#!/usr/bin/env python3
"""
Responder A2A Service

Runs as a separate process, exposing blocking/quarantine tools via A2A protocol.
Receives attenuated warrant from analyst, validates it, and provides
access to block_ip and quarantine_user capabilities.

Security: Uses warrant.authorize() for Tier 2 (PoP) validation.
This is CRITICAL for the attenuated warrant - the IP constraint (Exact vs Cidr)
must be checked at the wire level, not in Python if-statements.
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
from tools import block_ip, quarantine_user


class ResponderService:
    """Responder agent running as A2A service with Tier 2 authorization."""

    def __init__(self, port: int = 8002):
        self.port = port
        self.signing_key: Optional[SigningKey] = None
        self.warrant: Optional[Warrant] = None
        self.app = None

    async def initialize(self, warrant_b64: str, signing_key_hex: str):
        """
        Initialize service with attenuated warrant.

        Args:
            warrant_b64: Base64-encoded attenuated warrant from analyst
            signing_key_hex: Hex-encoded signing key for this agent
        """
        # Deserialize signing key
        self.signing_key = SigningKey.from_bytes(bytes.fromhex(signing_key_hex))

        # Deserialize warrant
        self.warrant = Warrant.from_base64(warrant_b64)

        print("✓ Responder service initialized with warrant")
        print(f"  Capabilities: {list(self.warrant.capabilities.keys())}")
        print(f"  Holder: {self.signing_key.public_key.to_hex()[:16]}...")

        # Log constraint info (important for attenuated warrants)
        for cap_name, cap in self.warrant.capabilities.items():
            constraints = getattr(cap, 'constraints', {})
            if constraints:
                print(f"  {cap_name} constraints: {list(constraints.keys())}")

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

                if skill == "block_ip":
                    result = await self._handle_block_ip(params)
                    return JSONResponse(result)
                elif skill == "quarantine_user":
                    result = await self._handle_quarantine_user(params)
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
            return JSONResponse({"status": "healthy", "service": "responder"})

        routes = [
            Route("/tasks/send", handle_task, methods=["POST"]),
            Route("/health", health, methods=["GET"]),
        ]

        return Starlette(routes=routes)

    async def _handle_block_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle IP blocking request.

        CRITICAL: Uses warrant.authorize() for Tier 2 validation.
        This is where the attenuated constraint (Exact vs Cidr) is enforced!

        If warrant has Exact("203.0.113.5"), only that IP can be blocked.
        Attempts to block 0.0.0.0/0 will fail at the Rust core level.
        """
        ip = params.get("ip")
        duration = params.get("duration", 3600)

        if not ip:
            raise ValueError("Missing required parameter: ip")

        # TIER 2 AUTHORIZATION: Use warrant.authorize() with PoP signature
        # This is the SECURITY BOUNDARY - constraint checking happens in Rust!
        try:
            pop_signature = self.signing_key.sign(
                f"block_ip:{ip}:{duration}".encode()
            )
            self.warrant.authorize(
                tool="block_ip",
                args={"ip": ip, "duration": duration},
                signature=pop_signature,
            )
        except Exception as e:
            # Re-raise as AuthorizationError for consistent handling
            raise AuthorizationError(f"Authorization failed: {e}")

        # Authorized - execute tool
        result = block_ip(ip, duration)

        # Get warrant ID for audit trail
        jti = self.warrant.jti
        jti_str = jti.hex() if hasattr(jti, 'hex') else str(jti)

        return {
            "success": True,
            "data": result,
            "warrant_jti": jti_str,
            "authorized_by": "warrant.authorize()",  # Proof of Tier 2
        }

    async def _handle_quarantine_user(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle user quarantine request with Tier 2 authorization."""
        user_id = params.get("user_id")

        if not user_id:
            raise ValueError("Missing required parameter: user_id")

        # TIER 2 AUTHORIZATION
        try:
            pop_signature = self.signing_key.sign(
                f"quarantine_user:{user_id}".encode()
            )
            self.warrant.authorize(
                tool="quarantine_user",
                args={"user_id": user_id},
                signature=pop_signature,
            )
        except Exception as e:
            raise AuthorizationError(f"Authorization failed: {e}")

        # Authorized - execute tool
        result = quarantine_user(user_id)

        jti = self.warrant.jti
        jti_str = jti.hex() if hasattr(jti, 'hex') else str(jti)

        return {
            "success": True,
            "data": result,
            "warrant_jti": jti_str,
            "authorized_by": "warrant.authorize()",
        }

    async def start(self):
        """Start the A2A server."""
        try:
            import uvicorn
        except ImportError:
            raise ImportError("uvicorn is required: pip install uvicorn")

        self.app = self._create_app()
        print(f"🚀 Responder service starting on port {self.port}")

        config = uvicorn.Config(
            self.app,
            host="0.0.0.0",
            port=self.port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        await server.serve()


async def main():
    """Run responder service."""
    parser = argparse.ArgumentParser(description="Responder A2A Service")
    parser.add_argument("--port", type=int, default=8002, help="Service port")
    parser.add_argument("--warrant", required=True, help="Base64-encoded warrant")
    parser.add_argument("--key", required=True, help="Hex-encoded signing key")
    args = parser.parse_args()

    service = ResponderService(port=args.port)
    await service.initialize(args.warrant, args.key)

    try:
        await service.start()
    except KeyboardInterrupt:
        print("\n🛑 Responder service shutting down...")


if __name__ == "__main__":
    asyncio.run(main())
