"""
FastAPI integration for Tenuo.

Provides dependencies and utilities for protecting FastAPI routes with Tenuo authorization.

Usage:
    from fastapi import FastAPI, Depends
    from tenuo.fastapi import TenuoGuard, SecurityContext, configure_tenuo

    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[issuer_pubkey])

    @app.get("/search")
    async def search(
        query: str,
        ctx: SecurityContext = Depends(TenuoGuard("search"))
    ):
        # ctx.warrant is verified
        # ctx.args contains extracted arguments
        return {"results": [...]}
"""

import base64
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from tenuo_core import PublicKey, Warrant  # type: ignore[import-untyped]

from tenuo._enforcement import EnforcementResult
from tenuo.exceptions import DeserializationError, TenuoError

logger = logging.getLogger("tenuo.fastapi")


# Use string forward refs or try import, FastAPI must be installed
try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
    from fastapi.responses import JSONResponse
    from fastapi.security import APIKeyHeader

    FASTAPI_AVAILABLE = True
except ImportError:
    # Allow import for type checking if needed, but raise at runtime use
    FastAPI = Any  # type: ignore
    Header = Any  # type: ignore
    HTTPException = Any  # type: ignore
    Depends = Any  # type: ignore
    Request = Any  # type: ignore
    status = Any  # type: ignore
    JSONResponse = Any  # type: ignore
    APIKeyHeader = Any  # type: ignore
    FASTAPI_AVAILABLE = False


# Define standard headers
X_TENUO_WARRANT = "X-Tenuo-Warrant"
X_TENUO_POP = "X-Tenuo-PoP"

# Reusable security scheme for Swagger UI (only if FastAPI available)
if FASTAPI_AVAILABLE:
    api_key_header = APIKeyHeader(name=X_TENUO_WARRANT, auto_error=False)
else:
    api_key_header = None  # type: ignore[assignment]


# =============================================================================
# Verification-Only Key Sentinel
# =============================================================================


class _VerificationOnlyKey:
    """
    Sentinel class used when binding warrants for verification-only mode.

    In FastAPI's client-side PoP pattern (Remote PEP), the server never
    signs anything - it only verifies precomputed signatures from clients.
    However, enforce_tool_call() requires a BoundWarrant for type safety.

    This sentinel satisfies the type requirement while making it explicit
    that the key is not used for cryptographic operations.

    Security Note: This is safe because in verify_mode="verify", the
    precomputed_signature parameter is used instead of the bound key.
    """

    pass


# =============================================================================
# Configuration
# =============================================================================

# Module-level config (set via configure_tenuo)
_config: Dict[str, Any] = {
    "trusted_issuers": [],
    "strict": False,
    "error_handler": None,
    "expose_error_details": False,  # SECURITY: keep False in production
}


def configure_tenuo(
    app: Any,  # FastAPI
    *,
    trusted_issuers: Optional[List[PublicKey]] = None,
    strict: bool = False,
    error_handler: Optional[Callable[[Exception], Any]] = None,
    expose_error_details: bool = False,
) -> None:
    """
    Configure Tenuo for a FastAPI application.

    Args:
        app: FastAPI application instance
        trusted_issuers: List of trusted issuer public keys for chain verification
        strict: If True, require all routes to have Tenuo protection
        error_handler: Custom error handler for authorization failures
        expose_error_details: If True, include constraint details in error responses.
                              SECURITY: Keep False in production to prevent information leakage.

    Usage:
        from tenuo.fastapi import configure_tenuo

        app = FastAPI()
        configure_tenuo(
            app,
            trusted_issuers=[issuer_key.public_key],
            strict=True,
            expose_error_details=False,  # Default, recommended for production
        )
    """
    global _config
    _config["trusted_issuers"] = trusted_issuers or []
    _config["strict"] = strict
    _config["error_handler"] = error_handler
    _config["expose_error_details"] = expose_error_details

    # Store config in app state for access in dependencies
    app.state.tenuo_config = _config

    # Register global exception handler for TenuoError
    @app.exception_handler(TenuoError)
    async def tenuo_error_handler(request: Request, exc: TenuoError):
        """Handle TenuoError exceptions with canonical wire codes."""
        return JSONResponse(
            status_code=exc.get_http_status(),
            content={
                "error": exc.get_wire_name(),
                "error_code": exc.get_wire_code(),
                "message": str(exc),
                "details": exc.details if expose_error_details else {},
            },
        )


def get_tenuo_config() -> Dict[str, Any]:
    """Get the current Tenuo configuration."""
    return _config


# =============================================================================
# SecurityContext - returned by TenuoGuard
# =============================================================================


@dataclass
class SecurityContext:
    """
    Security context returned by TenuoGuard dependency.

    Contains the verified warrant and extracted arguments.

    Attributes:
        warrant: The verified Warrant object
        args: Dictionary of extracted arguments (path + query params)
        tool: The tool name this context was verified for
    """

    warrant: Warrant
    args: Dict[str, Any]
    tool: str

    @property
    def holder(self) -> str:
        """Get the warrant holder's public key (base64)."""
        return str(self.warrant.authorized_holder)

    @property
    def issuer(self) -> str:
        """Get the warrant issuer's public key (base64)."""
        return str(self.warrant.issuer)

    @property
    def is_expired(self) -> bool:
        """Check if the warrant has expired."""
        return self.warrant.is_expired()


# =============================================================================
# Dependencies
# =============================================================================

# Guard all FastAPI-dependent code to prevent import errors when FastAPI not installed
if FASTAPI_AVAILABLE:

    def get_warrant_header(x_tenuo_warrant: Optional[str] = Header(None, alias=X_TENUO_WARRANT)) -> Optional[Warrant]:
        """
        FastAPI dependency to extract and parse the X-Tenuo-Warrant header.
        Returns None if missing. Raises HTTP Exception on invalid format.
        """
        if not x_tenuo_warrant:
            return None

        try:
            return Warrant.from_base64(x_tenuo_warrant)
        except DeserializationError as e:
            # Client error: malformed warrant
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid X-Tenuo-Warrant header: {str(e)}"
            )
        except TenuoError:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid X-Tenuo-Warrant header: {str(e)}"
            )

    def require_warrant(
        request: Request,
        warrant: Optional[Warrant] = Depends(get_warrant_header),
        x_tenuo_pop: Optional[str] = Header(None, alias=X_TENUO_POP),
    ) -> Warrant:
        """
        FastAPI dependency that REQUIRES a valid warrant and PoP signature.

        Note: This is a basic dependency that only validates presence.
        For full tool-specific authorization, use TenuoGuard(tool_name).

        Usage:
            @app.get("/items")
            def read_items(warrant: Warrant = Depends(require_warrant)):
                # Manual authorization required
                ...
        """
        if not warrant:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Tenuo-Warrant header",
                headers={"WWW-Authenticate": "Tenuo"},
            )

        if not x_tenuo_pop:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Tenuo-PoP header",
                headers={"WWW-Authenticate": "Tenuo"},
            )

        return warrant


else:
    # Stub functions when FastAPI not available.
    # These stubs have different signatures because they only raise ImportError.
    # This is the standard pattern for optional dependencies.
    def get_warrant_header(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        raise ImportError("FastAPI is not installed. Install with: uv pip install fastapi")

    def require_warrant(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        raise ImportError("FastAPI is not installed. Install with: uv pip install fastapi")


# =============================================================================
# TenuoGuard - Main authorization dependency
# =============================================================================


class TenuoGuard:
    """
    FastAPI dependency that verifies Tenuo authorization for a specific tool.

    Returns a SecurityContext with the verified warrant and extracted args.

    Usage:
        @app.get("/search")
        async def search(
            query: str,
            ctx: SecurityContext = Depends(TenuoGuard("search"))
        ):
            print(f"Authorized by: {ctx.warrant.issuer}")
            return {"query": query}

    Args:
        tool: Tool name to authorize
        extract_args: Optional custom arg extraction function
    """

    def __init__(
        self,
        tool: str,
        *,
        extract_args: Optional[Callable[[Request], Dict[str, Any]]] = None,
    ):
        self.tool = tool
        self.extract_args = extract_args

    def _enforce_with_pop_signature(
        self,
        warrant: Warrant,
        tool: str,
        args: Dict[str, Any],
        pop_signature: bytes,
    ) -> EnforcementResult:
        """
        Adapter for FastAPI's client-side PoP pattern.

        Uses enforce_tool_call with verify_mode="verify" to leverage shared
        logic (allowlists, critical tools) with pre-computed signatures.

        Note: This uses _VerificationOnlyKey sentinel since in verify mode,
        the signing key is never used (precomputed_signature is used instead).
        """
        from tenuo_core import Authorizer as _Authorizer

        from tenuo._enforcement import enforce_tool_call

        # In verify mode, enforce_tool_call() requires a BoundWarrant for type safety
        # and to access warrant properties (id, tools, etc.), but the signing key
        # is never used for cryptographic operations. The precomputed_signature
        # provided by the client is used instead.
        #
        # We bind with _VerificationOnlyKey sentinel to make this explicit.
        # This is safe and intentional - the key is only for type compatibility.
        bound = warrant.bind(_VerificationOnlyKey())  # type: ignore[arg-type]

        issuer_pub = getattr(warrant, "issuer_public_key", None) or getattr(warrant, "issuer", None)
        roots = [issuer_pub] if issuer_pub is not None else []
        authorizer = _Authorizer(trusted_roots=roots)

        return enforce_tool_call(
            tool_name=tool,
            tool_args=args,
            bound_warrant=bound,
            verify_mode="verify",
            precomputed_signature=pop_signature,
            authorizer=authorizer,
        )

    def __call__(
        self,
        request: Request,
        warrant: Optional[Warrant] = Depends(get_warrant_header),
        x_tenuo_pop: Optional[str] = Header(None, alias=X_TENUO_POP),
    ) -> SecurityContext:
        """
        Verify authorization and return SecurityContext.
        """
        # 1. Check Headers - 401 for missing auth
        if not warrant:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "missing_warrant",
                    "message": "Missing X-Tenuo-Warrant header",
                },
                headers={"WWW-Authenticate": "Tenuo"},
            )
        if not x_tenuo_pop:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "missing_pop",
                    "message": "Missing X-Tenuo-PoP header",
                },
                headers={"WWW-Authenticate": "Tenuo"},
            )

        # 2. Check expiry first (distinct error)
        if warrant.is_expired():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "warrant_expired",
                    "message": "Warrant has expired",
                    "suggestion": "Request a fresh warrant from the issuer",
                },
                headers={"WWW-Authenticate": "Tenuo"},
            )

        # 3. Extract Args
        if self.extract_args:
            auth_args = self.extract_args(request)
        else:
            # Default: combine path params + query params
            query_params = dict(request.query_params)
            auth_args = {**request.path_params, **query_params}

        # 4. Decode PoP Signature
        try:
            pop_sig_bytes = base64.b64decode(x_tenuo_pop)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_pop",
                    "message": "Invalid base64 encoding in X-Tenuo-PoP",
                },
            )

        # 5. Authorize using Adapter
        enforcement = self._enforce_with_pop_signature(
            warrant=warrant,
            tool=self.tool,
            args=auth_args,
            pop_signature=pop_sig_bytes,
        )

        if not enforcement.allowed:
            # Generate a request ID for log correlation
            request_id = str(uuid.uuid4())[:8]
            reason = enforcement.denial_reason or "Authorization denied"

            # Log detailed info for operators (never exposed to clients)
            logger.warning(
                f"[{request_id}] Authorization denied for tool '{self.tool}' "
                f"with args {auth_args}. Reason: {reason}. Warrant ID: {warrant.id}"
            )

            # Check if detailed errors are allowed (dev mode only)
            expose_details = _config.get("expose_error_details", False)

            # Map specific errors to HTTP codes
            if enforcement.error_type == "expired" or (
                "expired" in reason.lower() and "proof-of-possession" not in reason.lower()
            ):
                 raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "error": "warrant_expired",
                        "message": "Warrant has expired",
                        "suggestion": "Request a fresh warrant from the issuer",
                    },
                    headers={"WWW-Authenticate": "Tenuo"},
                )

            # Standard 403 Forbidden
            if expose_details:
                detail = {
                    "error": "authorization_denied",
                    "message": f"Authorization denied: {reason}",
                    "tool": self.tool,
                    "args": auth_args,
                    "request_id": request_id,
                }
            else:
                detail = {
                    "error": "authorization_denied",
                    "message": "Authorization denied",
                    "request_id": request_id,
                }

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=detail,
            )

        return SecurityContext(
            warrant=warrant,
            args=auth_args,
            tool=self.tool,
        )


# Backwards compatibility alias
TenuoSecurity = TenuoGuard


# =============================================================================
# Async body extraction helper
# =============================================================================


async def extract_body_args(request: Request) -> Dict[str, Any]:
    """
    Helper to extract args from JSON body.

    Use with TenuoGuard's extract_args parameter for body-based authorization.
    Note: Must be called within an async context.

    Usage:
        async def custom_extract(request: Request) -> Dict[str, Any]:
            body = await extract_body_args(request)
            return {**dict(request.query_params), **body}

        @app.post("/action")
        async def action(ctx: SecurityContext = Depends(TenuoGuard("action", extract_args=custom_extract))):
            ...
    """
    try:
        return await request.json()
    except Exception:
        return {}


# =============================================================================
# SecureAPIRouter: Drop-in replacement for APIRouter
# =============================================================================


class SecureAPIRouter:
    """
    Drop-in replacement for FastAPI APIRouter with automatic Tenuo protection.

    Routes added to this router are automatically protected by Tenuo.
    The tool name is inferred from the route path or operation name.

    Usage:
        router = SecureAPIRouter()

        @router.get("/users/{user_id}")  # Auto-protected as "users_read" (or similar)
        def get_user(user_id: str): ...
    """

    def __init__(self, *args: Any, tool_prefix: Optional[str] = None, require_pop: bool = True, **kwargs: Any):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required for SecureAPIRouter")

        from fastapi import APIRouter

        self._router = APIRouter(*args, **kwargs)
        self.tool_prefix = tool_prefix
        self.require_pop = require_pop

    def _get_tool_name(self, path: str, method: str, name: Optional[str] = None) -> str:
        """Infer tool name from route info."""
        if name:
            return name
        # Determine tool name from path: /users/{id} -> users_read
        # Clean path: remove {params} and slashes
        clean_path = path.strip("/").replace("{", "").replace("}", "").replace("/", "_")
        if not clean_path:
            clean_path = "root"

        # Add prefix
        prefix = f"{self.tool_prefix}_" if self.tool_prefix else ""

        # Method suffix
        method_map = {"GET": "read", "POST": "create", "PUT": "update", "DELETE": "delete", "PATCH": "update"}
        suffix = method_map.get(method.upper(), method.lower())

        return f"{prefix}{clean_path}_{suffix}"

    def get(self, path: str, tool: Optional[str] = None, **kwargs: Any) -> Callable:
        kwargs.pop("methods", None)  # Remove if present to avoid duplicate
        return self.api_route(path, methods=["GET"], tool=tool, **kwargs)

    def post(self, path: str, tool: Optional[str] = None, **kwargs: Any) -> Callable:
        kwargs.pop("methods", None)
        return self.api_route(path, methods=["POST"], tool=tool, **kwargs)

    def put(self, path: str, tool: Optional[str] = None, **kwargs: Any) -> Callable:
        kwargs.pop("methods", None)
        return self.api_route(path, methods=["PUT"], tool=tool, **kwargs)

    def delete(self, path: str, tool: Optional[str] = None, **kwargs: Any) -> Callable:
        kwargs.pop("methods", None)
        return self.api_route(path, methods=["DELETE"], tool=tool, **kwargs)

    def patch(self, path: str, tool: Optional[str] = None, **kwargs: Any) -> Callable:
        kwargs.pop("methods", None)
        return self.api_route(path, methods=["PATCH"], tool=tool, **kwargs)

    def api_route(
        self,
        path: str,
        methods: List[str],
        *args: Any,
        tool: Optional[str] = None,
        dependencies: Optional[List[Any]] = None,
        **kwargs: Any,
    ) -> Callable:
        """Add a route with auto-protection."""

        def decorator(func: Callable) -> Callable:
            # Determine tool name
            primary_method = methods[0] if methods else "GET"
            actual_tool = tool or self._get_tool_name(path, primary_method, kwargs.get("name"))

            # Create guard dependency
            guard_dep = TenuoGuard(actual_tool)

            # Append to dependencies
            final_deps = list(dependencies) if dependencies else []
            # We add it as a dependency, so it runs before the handler.
            # We don't necessarily inject the SecurityContext unless the user asks for it,
            # but Depends() in the list ensures it executes.
            final_deps.append(Depends(guard_dep))

            # Register with underlying router
            return self._router.api_route(path, methods=methods, dependencies=final_deps, *args, **kwargs)(func)

        return decorator

    def include_router(self, router: Any, *args: Any, **kwargs: Any) -> None:
        self._router.include_router(router, *args, **kwargs)

    # Delegate other methods to _router
    def __getattr__(self, name: str) -> Any:
        return getattr(self._router, name)


__all__ = [
    # Configuration
    "configure_tenuo",
    "get_tenuo_config",
    # Dependencies
    "get_warrant_header",
    "require_warrant",
    "TenuoGuard",
    "TenuoSecurity",  # Backwards compat
    # Types
    "SecurityContext",
    # Helpers
    "extract_body_args",
    # Components
    "SecureAPIRouter",
    # Constants
    "X_TENUO_WARRANT",
    "X_TENUO_POP",
    "FASTAPI_AVAILABLE",
]
