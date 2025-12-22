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

from dataclasses import dataclass
from typing import Optional, Any, Dict, List, Callable
import base64
import uuid
import logging

from tenuo_core import Warrant, PublicKey  # type: ignore[import-untyped]

logger = logging.getLogger("tenuo.fastapi")

# Use string forward refs or try import, FastAPI must be installed
try:
    from fastapi import FastAPI, Header, HTTPException, Depends, Request, status
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
    APIKeyHeader = Any  # type: ignore
    FASTAPI_AVAILABLE = False


# Define standard headers
X_TENUO_WARRANT = "X-Tenuo-Warrant"
X_TENUO_POP = "X-Tenuo-PoP"

# Reusable security scheme for Swagger UI
api_key_header = APIKeyHeader(name=X_TENUO_WARRANT, auto_error=False)


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

def get_warrant_header(
    x_tenuo_warrant: Optional[str] = Header(None, alias=X_TENUO_WARRANT)
) -> Optional[Warrant]:
    """
    FastAPI dependency to extract and parse the X-Tenuo-Warrant header.
    Returns None if missing. Raises HTTPException on invalid format.
    """
    if not x_tenuo_warrant:
        return None
        
    try:
        return Warrant.from_base64(x_tenuo_warrant)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid X-Tenuo-Warrant header: {str(e)}"
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

        # 5. Authorize - 403 for authorization failure
        if not warrant.authorize(self.tool, auth_args, pop_sig_bytes):
            # Generate a request ID for log correlation
            request_id = str(uuid.uuid4())[:8]
            
            # Log detailed info for operators (never exposed to clients)
            logger.warning(
                f"[{request_id}] Authorization denied for tool '{self.tool}' "
                f"with args {auth_args}. Warrant ID: {warrant.id}"
            )
            
            # Check if detailed errors are allowed (dev mode only)
            expose_details = _config.get("expose_error_details", False)
            
            if self.tool not in (warrant.tools or []):
                if expose_details:
                    detail = {
                        "error": "tool_not_authorized",
                        "message": f"Warrant does not authorize tool '{self.tool}'",
                        "authorized_tools": warrant.tools,
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
            else:
                if expose_details:
                    detail = {
                        "error": "authorization_denied",
                        "message": f"Authorization denied for tool '{self.tool}'",
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
    # Constants
    "X_TENUO_WARRANT",
    "X_TENUO_POP",
    "FASTAPI_AVAILABLE",
]
